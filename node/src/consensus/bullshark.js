/**
 * @file @tip-protocol/node/src/consensus/bullshark.js
 * @description Bullshark ordering protocol for TIP consensus.
 *
 * Takes the certificate DAG produced by Narwhal and outputs a deterministic
 * total order of all transactions. Every node running the same algorithm on
 * the same certificate DAG produces the exact same transaction order.
 *
 * How it works:
 *   - Rounds are grouped into waves of 2 (odd = propose, even = vote)
 *   - Each wave has a leader (round-robin by sorted node IDs)
 *   - The leader's certificate in the odd round is the "anchor candidate"
 *   - If 2/3+ of even-round certificates reference the anchor → it's COMMITTED
 *   - Committed anchor → walk DAG backwards → collect all unreached txs → output in order
 *
 * The ordering is deterministic because:
 *   1. Leader selection: sorted node IDs, round-robin
 *   2. Commit rule: 2/3+ threshold (same on all nodes)
 *   3. DAG walk: BFS with deterministic ordering (by round, then author_node_id)
 *   4. Tx ordering within certificate: preserved from batch (mempool drain order)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { computeQuorum } = require("./certificate");
const { computeStateMerkleRoot, computeTxsMerkleRoot } = require("./state-root");
const { CONSENSUS } = require("../../../shared/protocol-constants");
const { TX_TYPES } = require("../../../shared/constants");
const { shake256, canonicalJson, mldsaSign, computeTxId } = require("../../../shared/crypto");
const { deriveLiveCommittee } = require("./participants");
const { getLogger } = require("../logger");

const log = getLogger("tip.bullshark");

/**
 * Create the Bullshark ordering layer.
 *
 * @param {Object} options
 * @param {Object}   options.dag            DAG store (read certificates)
 * @param {Function} options.getNodeIds     () => sorted array of registered node IDs
 * @param {Function} options.onOrderedTxs   (txs, round) => called with deterministically ordered txs
 * @param {Object}   [options.proposer]     Optional rotation proposer config. When
 *                                          present, bullshark fires committee rotations
 *                                          per §4 + #34 (event-driven + 7d backstop).
 *                                          Required fields:
 *                                            - nodeId: own TIP node_id
 *                                            - nodePrivateKey: ML-DSA-65 sk for signing
 *                                            - nodePublicKey: ML-DSA-65 pk (to include in
 *                                              new_committee — own pubkey for the rotation)
 *                                            - submitTx: (tx) => Promise — pushes the
 *                                              built rotation tx into the mempool/consensus
 *                                              so it goes through the normal Bullshark path
 *                                          Optional:
 *                                            - getNodePublicKey(nodeId) => string|null —
 *                                              looks up other committee members' pubkeys
 *                                              for the new_committee field. Defaults to
 *                                              dag.getNode(nodeId)?.public_key.
 * @returns {Object} Bullshark instance
 */
function createBullshark({ dag, getNodeIds, onOrderedTxs, proposer }) {
  // Track which certificates have already been ordered (by hash)
  const _orderedCertHashes = new Set();

  // Track last committed round to avoid re-processing
  let _lastCommittedRound = 0;

  // Bullshark counters — cumulative over process lifetime.
  const _metrics = {
    anchors_committed: 0,
    anchors_no_support: 0,
    txs_committed: 0,
    certs_pruned: 0,
    gc_runs: 0,
    gc_failures: 0,
    gc_skipped_disabled: 0,
    // §4 + #34: rotation proposer fired (regardless of whether the
    // tx eventually commits). Increments each time _maybeProposeCommitteeRotation
    // builds + submits a COMMITTEE_ROTATION tx. Pairs with the dag-level
    // committee_history row count to compute success rate.
    committee_rotation_proposals: 0,
  };

  // Monotonic commit sequence number (§15). One per successful anchor
  // commit, regardless of round. Restored from persisted commits on boot so
  // the index survives restarts. Exposed downstream via saveCommit so
  // indexers / audit tools can resume from "give me everything after N".
  // #44: prefer the persisted consensus_meta value (anchor count, exact
  // even on idle restarts). Fall back to max(commits.consensus_index)
  // for legacy DBs that pre-date consensus_meta — that floor is at least
  // as high as the last tx-bearing commit's index, so we don't go
  // backwards. May temporarily under-report on idle until the next
  // anchor commit re-anchors via setConsensusMeta.
  let _consensusIndex = 0;
  try {
    const meta = dag.getConsensusMeta ? dag.getConsensusMeta("last_consensus_index") : null;
    if (meta != null) {
      _consensusIndex = Number(meta) || 0;
    } else if (dag.getLatestConsensusIndex) {
      _consensusIndex = dag.getLatestConsensusIndex() || 0;
    }
  } catch { _consensusIndex = 0; }

  // BFT Time — last successfully-committed anchor cert timestamp. Used to
  // enforce strict monotonicity across anchors: every new anchor's
  // `cert.timestamp` must be greater than this value or it is rejected
  // (deterministic across nodes since they all see the same cert).
  // Initialised from the latest persisted commit row so the bound survives
  // restart. On a fresh chain (no prior commit), the floor is
  // BFT_TIME_GENESIS_MS — every node parses the genesis ISO string into
  // the same integer ms anchor.
  let _lastAnchorTimestamp = 0;
  try {
    const latestCommit = dag.getLatestCommit ? dag.getLatestCommit() : null;
    if (latestCommit && latestCommit.cert_timestamp) {
      _lastAnchorTimestamp = Number(latestCommit.cert_timestamp) || 0;
    }
  } catch { _lastAnchorTimestamp = 0; }

  // Initialize from persisted state
  function _initFromDAG() {
    try {
      const latestRound = dag.getLatestRound();
      if (latestRound === 0) return;

      // Mark all existing certificates as ordered so they won't be re-collected.
      // On restart, Narwhal resumes from latestRound+1 — Bullshark only processes new rounds.
      _lastCommittedRound = latestRound;
      for (let r = 1; r <= latestRound; r++) {
        try {
          const certs = dag.getCertificatesByRound(r);
          for (const cert of certs) _orderedCertHashes.add(cert.hash);
        } catch (err) {
          log.warn(`Failed to load certificates for round ${r}: ${err.message}`);
        }
      }

      log.info(`Bullshark initialized: last committed round ${latestRound}, ${_orderedCertHashes.size} certificates`);
    } catch (err) {
      log.error(`Bullshark initialization failed: ${err.message}`);
    }
  }

  _initFromDAG();

  /**
   * Called by Narwhal when a round completes (2/3+ certificates collected).
   * Checks if this round triggers an anchor commit. If so, orders all
   * uncommitted txs reachable from the anchor.
   *
   * @param {Array} certificates   Certificates from the completed round
   * @param {number} round         The completed round number
   */
  function onRoundComplete(certificates, round) {
    if (!certificates || !Array.isArray(certificates) || round <= 0) {
      log.warn(`onRoundComplete: invalid args (round=${round}, certs=${certificates?.length})`);
      return;
    }

    if (round <= _lastCommittedRound) return;

    // Only check for anchor on even rounds (vote rounds)
    if (round % 2 !== 0) return;

    try {
      _checkAnchorCommit(round);
    } catch (err) {
      log.error(`Anchor check failed at round ${round}: ${err.message}`);
    }
  }

  /**
   * Check if the leader's certificate from the propose round is committed.
   */
  function _checkAnchorCommit(voteRound) {
    const proposeRound = voteRound - 1;
    const leader = _getLeader(proposeRound);
    if (!leader) {
      log.warn(`Round ${voteRound}: no leader for propose round ${proposeRound}`);
      return;
    }

    // Get leader's certificate
    let leaderCert;
    try {
      leaderCert = dag.getCertificateByAuthorRound(leader, proposeRound);
    } catch (err) {
      log.error(`Failed to read leader cert ${leader} round ${proposeRound}: ${err.message}`);
      return;
    }
    if (!leaderCert) {
      log.debug(`Round ${voteRound}: leader ${leader} has no cert in round ${proposeRound}`);
      return;
    }

    // Check commit rule: 2/3+ of vote round certs reference the leader's cert
    let voteCerts;
    try {
      voteCerts = dag.getCertificatesByRound(voteRound);
    } catch (err) {
      log.error(`Failed to read vote certs for round ${voteRound}: ${err.message}`);
      return;
    }

    // Committee is wave-stable — use voteRound's wave (same as proposeRound's)
    // so quorum matches what the vote-round cert authors were computing when
    // they signed. Deterministic across nodes regardless of current round.
    const nodeIds = getNodeIds(voteRound);
    if (!nodeIds || nodeIds.length === 0) {
      log.warn(`Round ${voteRound}: no registered nodes`);
      return;
    }
    const quorum = computeQuorum(nodeIds.length);

    let supportCount = 0;
    for (const voteCert of voteCerts) {
      if (_referencesAncestor(voteCert, leaderCert.hash, proposeRound)) {
        supportCount++;
      }
    }

    if (supportCount < quorum) {
      _metrics.anchors_no_support++;
      log.debug(`Round ${voteRound}: anchor ${leader} not committed (${supportCount}/${quorum} support)`);
      return;
    }

    // BFT-Time monotonicity gate — enforced HERE (after support check, before
    // any state mutation) so a bad-timestamp anchor is rejected without
    // touching `_consensusIndex`, `_metrics`, or commit row state. The
    // anchor's `cert.timestamp` was already verified at cert level
    // (median of acks.signed_at, signature-bound). Cross-anchor monotonicity
    // is the one invariant cert verification can't see — needs the global
    // commit history. The `commits` table is never GC'd, so prev anchor's
    // timestamp is always available.
    //
    // On floor failure (round 1, no prior anchor): use BFT_TIME_GENESIS_MS.
    // This blocks pre-launch anchors and guards against `cert.timestamp = 0`
    // regressions. After the first anchor lands, _lastAnchorTimestamp moves
    // forward and the genesis floor never matters again.
    //
    // On rejection: log loudly, return early. The anchor is not committed,
    // _lastCommittedRound does not advance — Bullshark will pick this up
    // again next vote round and either still reject (operator must
    // investigate / halt-gate trips) or accept if the next anchor's
    // timestamp is healthier. This is deterministic across nodes — every
    // node sees the same cert with the same timestamp and makes the same
    // decision.
    const certTs = leaderCert.timestamp;
    const floor = _lastAnchorTimestamp || CONSENSUS.BFT_TIME_GENESIS_MS;
    if (!Number.isInteger(certTs) || certTs <= floor) {
      _metrics.bft_time_violations = (_metrics.bft_time_violations || 0) + 1;
      log.error(
        `BFT-Time monotonicity violation at round ${voteRound}: ` +
        `anchor cert.timestamp=${certTs} (leader=${leader}), floor=${floor} ` +
        `(${_lastAnchorTimestamp ? "prev anchor" : "genesis"}). Skipping anchor commit.`
      );
      return;
    }

    // ANCHOR COMMITTED
    _metrics.anchors_committed++;
    log.debug(`Round ${voteRound}: anchor COMMITTED — leader ${leader}, support ${supportCount}/${nodeIds.length}`);

    // #44: consensus_index ticks on EVERY successful anchor commit, not
    // just tx-bearing ones. Matches Mysten's sub_dag_index semantics —
    // a monotonic counter of consensus events that's meaningful for
    // liveness ("network advancing?") regardless of activity level.
    // Persisted via consensus_meta so the value survives restart on
    // idle federations (where commit rows are sparse and the column-on-
    // commits recovery path would under-report).
    _consensusIndex += 1;
    if (dag.setConsensusMeta) {
      try { dag.setConsensusMeta("last_consensus_index", _consensusIndex); }
      catch (err) { log.warn(`Round ${voteRound}: consensus_meta write failed: ${err.message}`); }
    }

    const orderedTxs = _collectOrderedTxs(leaderCert);

    // Commit row writes are still gated on tx-bearing rounds. Empty
    // anchors carry no new state — writing a row per anchor would make
    // the commits table grow wall-clock-driven (~3 GB/year on 2s rounds)
    // instead of activity-driven (~hundreds of MB/year). Each commit row
    // still stamps the current `consensus_index` so commit-row indices
    // are monotonic with GAPS for the empty rounds — the
    // `idx_commits_index` UNIQUE constraint allows gaps.
    //
    // Under future GC (§2 in narwhal-parity-gap.md), empty-round certs
    // can be pruned freely because no commit row references them.
    if (orderedTxs.length > 0) {
      _metrics.txs_committed += orderedTxs.length;
      log.info(`Round ${voteRound}: committing ${orderedTxs.length} ordered txs`);
      // Only advance committed round AFTER successful processing.
      // If onOrderedTxs throws, we don't advance — will retry next round.
      // Pass cert.timestamp so commit-handler / downstream derived-state
      // logic uses the BFT consensus clock, not local Date.now().
      if (onOrderedTxs) onOrderedTxs(orderedTxs, voteRound, certTs);

      // §15 + §14 commit checkpoint.
      //
      // Roots are computed AFTER onOrderedTxs so derived state reflects
      // this round's applied txs (state_merkle_root commits to the post-
      // state; txs_merkle_root commits to the ordered tx_ids of this
      // round only).
      //
      // Ack signers/signatures come straight from the leader's anchor
      // cert. By Narwhal's 2f+1 certification rule, the anchor already
      // carries supermajority attestations over its batch hash — we
      // persist them so new joiners can verify the commit row without
      // replaying the DAG (§14 Byzantine-robust state sync).
      try {
        if (dag.saveCommit) {
          const stateRoot = computeStateMerkleRoot(dag);
          const txsRoot = computeTxsMerkleRoot(orderedTxs);
          const acks = leaderCert.acknowledgments || [];
          const ackSignerIds = acks.map(a => a.acker_node_id);
          const ackSignatures = acks.map(a => a.signature);
          // BFT-Time: persist each ack's `signed_at` alongside the
          // signature in the SAME order as ack_signer_ids/ack_signatures.
          // Snapshot replay reconstructs the payload as
          // `ack:${batch_hash}:${signer}:${signed_at}` and verifies
          // against the signer's pubkey — without this, joiners can't
          // verify any commit's acks once the source cert is GC'd.
          const ackSignedAts = acks.map(a => a.signed_at);

          dag.saveCommit({
            round: voteRound,
            anchor_cert_hash: leaderCert.hash,
            // #50: persist the anchor cert's batch_hash directly so the
            // commit row stays self-contained for snapshot verification
            // even after cert GC prunes leaderCert. Without this, idle
            // federations whose latest commit drifts past gc_depth rounds
            // become un-snapshotable (server can't reconstruct the
            // payload each ack signed: "ack:${batch_hash}:${signer}:${signed_at}").
            anchor_batch_hash: leaderCert.batch?.hash || null,
            leader_node_id: leader,
            committee: [...nodeIds].sort(),
            support_count: supportCount,
            consensus_index: _consensusIndex,
            committed_at: new Date().toISOString(),
            state_merkle_root: stateRoot,
            txs_merkle_root: txsRoot,
            ack_signer_ids: ackSignerIds,
            ack_signatures: ackSignatures,
            ack_signed_ats: ackSignedAts,
            cert_timestamp: certTs,
          });
        }
      } catch (err) {
        // Checkpoint write is best-effort — a failure here doesn't invalidate
        // the commit itself (txs already applied), but we need to know.
        log.warn(`Round ${voteRound}: commit checkpoint save failed: ${err.message}`);
      }
    }

    // BFT-Time: advance the monotonicity floor only AFTER successful commit
    // (saveCommit may have failed silently above, but the anchor was still
    // accepted by consensus — the floor advances on consensus success, not
    // on persistence success). Future rounds' anchors must beat this value.
    _lastAnchorTimestamp = certTs;
    _lastCommittedRound = voteRound;
    _pruneOrderedCache();
    _maybeRunCertGC();

    // §4 + #34: rotation proposer. Runs after successful anchor commit so
    // we know consensus is healthy (quorum reached) before adding more
    // load. Only the anchor-commit leader fires — natural round-robin via
    // wave leader rotation, no extra coordination needed.
    if (proposer && proposer.nodeId === leader) {
      try {
        _maybeProposeCommitteeRotation(voteRound);
      } catch (err) {
        log.warn(`Round ${voteRound}: rotation proposer threw — ${err.message}`);
      }
    }
  }

  /**
   * §4 + #34 — Option B trigger (event-driven + 7d periodic backstop).
   *
   * Compares the would-be committee (current producing set) against the
   * latest rotation in committee_history. If they differ — or if the
   * 7-day re-attestation window has elapsed since the last rotation —
   * builds and submits a COMMITTEE_ROTATION tx.
   *
   * Fires on every anchor commit where THIS node is the leader. Other
   * nodes skip; we don't want N concurrent proposals racing on every
   * wave. The leader-of-wave naturally rotates round-robin so any
   * committee member's perspective gets considered over time.
   *
   * Sig collection limitation: this MVP signs only with our own key
   * (1 sig). Works for genesis bootstrap (rotation 0 → 1, where prev
   * committee = [founding_node], quorum = 1). Subsequent rotations
   * (committee size > 1, quorum ≥ 2) need multi-sig coordination —
   * tracked as a follow-up to this PR. For now, post-bootstrap
   * rotations propose but fail commit-handler quorum check;
   * federation continues running with the rotation 1 committee.
   */
  function _maybeProposeCommitteeRotation(currentRound) {
    if (!dag.getLatestRotation || !dag.getCommitteeRotation) return;  // chain-of-trust not wired

    const latest = dag.getLatestRotation();
    if (!latest) return;  // initDAG bootstrap should've written rotation 0; defensive

    // Cert-history guard: refuse to propose unless we have at least
    // COMMITTEE_ROTATION_HYSTERESIS_ROUNDS rounds of cert history in our
    // local DAG. After a snapshot install, certs from before snapshot.round
    // are structurally absent (snapshot ships state + commits + rotations,
    // NOT raw certs — see issues.md Consensus #18). A fresh joiner's
    // deriveLiveCommittee would see ONLY post-join producers and disagree
    // with peers who have full history — proposing rotations that drop
    // legitimately-active peers from the committee → flap storm.
    //
    // The guard waits until the joiner has accumulated K rounds of certs
    // (~10 min at K=300) before allowing it to propose. Existing nodes
    // (running since round 1, or with GC depth > K) always pass.
    // Joiners can still BE in the committee, ack things, and serve
    // snapshots — they just can't fire rotation proposals during their
    // catch-up window.
    if (typeof dag.getEarliestCertRound === "function") {
      const earliest = dag.getEarliestCertRound() || 0;
      const historyRounds = earliest > 0 ? currentRound - earliest : currentRound;
      if (historyRounds < CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS) {
        return;
      }
    }

    const wouldBe = deriveLiveCommittee(dag, currentRound, CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS);
    const currentNodeIds = latest.committee.map(m => m.node_id).sort();

    const setsEqual = wouldBe.length === currentNodeIds.length
      && wouldBe.every((id, i) => id === currentNodeIds[i]);

    // Time-since-last guard: 7-day periodic re-attestation. Uses round
    // count rather than wall-clock for determinism — every node sees the
    // same elapsed-round count.
    const roundsSinceLast = Math.max(0, currentRound - (latest.effective_round || 0));
    const periodicElapsed = roundsSinceLast >= CONSENSUS.COMMITTEE_ROTATION_INTERVAL_ROUNDS;

    if (setsEqual && !periodicElapsed) return;  // no rotation needed

    // Build new_committee with pubkeys. Pubkeys come from the nodes table
    // — at this point we trust our local nodes table because the rotation
    // tx will go through commit-handler which validates that the pubkeys
    // signed off on subsequent rotations transitively. (For the chain-of-
    // trust walker on a fresh joiner's snapshot, what matters is that
    // each rotation's pubkeys come from the previous rotation's chain
    // entry — which they do because `_verifyTxSignature` looks up sigs
    // against `dag.getCommitteeRotation(rn-1).committee`, NOT the nodes
    // table.)
    const lookupPubkey = proposer.getNodePublicKey || ((id) => dag.getNode(id)?.public_key);
    const newCommittee = wouldBe.map(node_id => ({
      node_id,
      public_key: lookupPubkey(node_id) || "",
    })).filter(m => m.public_key);
    if (newCommittee.length === 0) {
      log.warn(`Rotation ${latest.rotation_number + 1}: cannot propose — no pubkeys for would-be committee`);
      return;
    }

    // Sort committee canonically by node_id (matches commit-handler's
    // canonical-hash expectations and the schema contract).
    newCommittee.sort((a, b) => a.node_id.localeCompare(b.node_id));

    const rotation_number = latest.rotation_number + 1;
    const effective_round = currentRound + 1;  // takes effect from the next round forward
    const payload_hash = shake256(canonicalJson({
      rotation_number, effective_round, committee: newCommittee,
    }));

    // MVP: sign only with our own key. The commit-handler accepts the tx
    // if previous-committee quorum is met by the sigs included; for the
    // bootstrap case (prev committee = single founding_node), our 1 sig
    // is the full quorum.
    const message = `rotation:${payload_hash}:${proposer.nodeId}`;
    const signature = mldsaSign(message, proposer.nodePrivateKey);

    const txData = {
      rotation_number,
      effective_round,
      new_committee: newCommittee,
      payload_hash,
      signer_node_ids: [proposer.nodeId],
      signatures: [signature],
    };

    const tx = {
      tx_type: TX_TYPES.COMMITTEE_ROTATION,
      timestamp: new Date().toISOString(),
      // Genesis-bridged prev so validateTransaction's "non-genesis must
      // have prev refs" rule passes. The rotation tx is structurally
      // metadata-only — no semantic dependency on a specific prior tx,
      // so any committed tx is a fine prev (we use whatever the dag
      // proposes via its recent-tx ring; if dag exposes it).
      prev: dag.getRecentPrev ? dag.getRecentPrev() : [],
      data: txData,
    };
    tx.tx_id = computeTxId(tx);

    // Counter increments BEFORE submitTx so the metric reflects every
    // proposal attempt — including ones that throw synchronously
    // (consensus not yet wired) or get rejected at mempool admission.
    // Operators care about "did the leader try to propose?" regardless
    // of downstream outcome.
    _metrics.committee_rotation_proposals++;

    try {
      const r = proposer.submitTx(tx);
      // submitTx may be async — fire-and-forget; failures land in the
      // mempool reject path or commit-handler drop path with their own
      // logging, no need to await.
      if (r && typeof r.catch === "function") {
        r.catch(err => log.warn(`Rotation ${rotation_number} submitTx rejected: ${(err && err.message) || err}`));
      }
      log.info(
        `Rotation ${rotation_number} proposed at round ${currentRound}: ` +
        `committee size ${currentNodeIds.length} → ${newCommittee.length}, ` +
        `${periodicElapsed && setsEqual ? "periodic re-attest" : "membership change"}`
      );
    } catch (err) {
      // submitTx throws on consensus-not-wired (503 from triggerSubmitter),
      // mempool full, or other downstream rejection. Log + swallow —
      // the counter is already incremented; future waves' leaders will
      // try again. Never propagate up to the anchor commit path.
      log.warn(`Rotation ${rotation_number} submit failed synchronously: ${(err && err.message) || err}`);
    }
  }

  /**
   * Cert GC (§2 in narwhal-parity-gap.md). Pruned cadence: every
   * GC_INTERVAL_COMMITS consensus commits, drop every cert with
   * `round < lastCommittedRound - GC_DEPTH` from the SQLite certs table.
   *
   * Safety:
   *   - Commits checkpoint table (§15) survives — one row per real
   *     commit with anchor_cert_hash, committee, state_merkle_root.
   *     Audit queries ("what happened at round R") still work without
   *     the cert body.
   *   - Transactions table is NOT pruned. Every committed tx lives
   *     there forever as the authoritative state-of-record.
   *   - Derived state tables (identities, content, scores) untouched.
   *   - GC_DEPTH default 500 = ~17 min at 2s rounds, enough for
   *     active consensus parent refs, cert waiter, brief-offline
   *     recovery. Longer gaps are handled by §14 snapshot-sync
   *     (fresh joiners) and §7 anti-entropy (briefly-offline nodes).
   *
   * Throttled to avoid SQLite churn: only runs on every Nth commit
   * (GC_INTERVAL_COMMITS default 10), so ~20-60s between prune calls
   * depending on commit rate.
   */
  function _maybeRunCertGC() {
    const interval = CONSENSUS.GC_INTERVAL_COMMITS;
    if (!interval || interval <= 0) return;
    if (_metrics.anchors_committed % interval !== 0) return;

    // Throttle gate passed — we're at a GC tick. Check runtime disable
    // here so `gc_skipped_disabled` counts tick-aligned skips (useful for
    // ops dashboards: "how many prune cycles did we skip?") rather than
    // raw commit count.
    if (process.env.TIP_GC_DISABLED === "1") {
      _metrics.gc_skipped_disabled++;
      return;
    }

    const gcDepth = CONSENSUS.GC_DEPTH;
    if (!gcDepth || gcDepth <= 0) return;

    const cutoff = _lastCommittedRound - gcDepth;
    if (cutoff <= 0) return;

    try {
      if (typeof dag.pruneCertificatesBefore !== "function") return;
      const n = dag.pruneCertificatesBefore(cutoff);
      _metrics.gc_runs++;
      if (n > 0) {
        _metrics.certs_pruned += n;
        log.info(`Cert GC: pruned ${n} certs with round < ${cutoff} (retaining last ${gcDepth} rounds)`);

        // Reclaim freed SQLite pages back to the filesystem. Without this
        // the DB file keeps growing even with row count bounded — DELETE
        // only returns pages to the internal free-list. Bounded to 1000
        // pages per call (~4 MB) to cap the blocking time at tens of ms.
        // Best-effort: MemoryStore is a no-op, and a failure here doesn't
        // invalidate the prune — accounted in gc_failures so ops can see.
        try {
          if (typeof dag.incrementalVacuum === "function") {
            dag.incrementalVacuum(1000);
          }
        } catch (err) {
          _metrics.gc_failures++;
          log.warn(`Cert GC: incremental_vacuum failed: ${err.message}`);
        }
      }
    } catch (err) {
      _metrics.gc_failures++;
      log.warn(`Cert GC prune failed at cutoff ${cutoff}: ${err.message}`);
    }
  }

  /**
   * Prune _orderedCertHashes to prevent unbounded memory growth.
   * Keeps only the most recent hashes up to CONSENSUS.ORDERED_HASH_CACHE_SIZE.
   */
  function _pruneOrderedCache() {
    const maxSize = CONSENSUS.ORDERED_HASH_CACHE_SIZE;
    if (_orderedCertHashes.size <= maxSize) return;
    const excess = _orderedCertHashes.size - maxSize;
    const iter = _orderedCertHashes.values();
    for (let i = 0; i < excess; i++) {
      _orderedCertHashes.delete(iter.next().value);
    }
  }

  /**
   * Check if a certificate (or its ancestors) references a specific cert hash.
   * Iterative DFS with visited set — safe for deep DAGs, no stack overflow.
   *
   * @param {Object} cert        Certificate to check
   * @param {string} targetHash  Hash we're looking for
   * @param {number} targetRound Round of the target (stop searching below this)
   * @returns {boolean}
   */
  function _referencesAncestor(cert, targetHash, targetRound) {
    const visited = new Set();
    const stack = [cert];

    while (stack.length > 0) {
      const current = stack.pop();
      if (!current || !current.hash || visited.has(current.hash)) continue;
      visited.add(current.hash);

      const parents = current.parent_hashes || [];
      if (parents.includes(targetHash)) return true;

      // Don't descend below target round
      if (current.round <= targetRound) continue;

      for (const parentHash of parents) {
        if (visited.has(parentHash)) continue;
        try {
          const parentCert = dag.getCertificate(parentHash);
          if (parentCert) stack.push(parentCert);
        } catch (err) {
          log.warn(`Failed to read parent cert ${parentHash.slice(0, 16)}: ${err.message}`);
        }
      }
    }

    return false;
  }

  /**
   * Collect all txs from uncommitted certificates reachable from the anchor.
   * BFS walk of the certificate DAG, ordered deterministically.
   *
   * Order: by round (ascending), then by author_node_id (ascending)
   * Within a certificate: tx order preserved from batch
   */
  function _collectOrderedTxs(anchorCert) {
    const toVisit = [anchorCert];
    const visited = new Set();
    const collectedCerts = [];

    // BFS through the certificate DAG
    while (toVisit.length > 0) {
      const cert = toVisit.shift();
      if (!cert || !cert.hash || visited.has(cert.hash)) continue;
      visited.add(cert.hash);

      // Only collect if not already ordered in a previous anchor commit
      if (!_orderedCertHashes.has(cert.hash)) {
        collectedCerts.push(cert);
        _orderedCertHashes.add(cert.hash);
      }

      for (const parentHash of (cert.parent_hashes || [])) {
        if (visited.has(parentHash)) continue;
        try {
          const parentCert = dag.getCertificate(parentHash);
          if (parentCert) toVisit.push(parentCert);
        } catch (err) {
          log.warn(`Failed to read parent cert ${parentHash.slice(0, 16)}: ${err.message}`);
        }
      }
    }

    // Deterministic sort: round ASC, then author_node_id ASC
    collectedCerts.sort((a, b) => {
      if (a.round !== b.round) return a.round - b.round;
      return a.author_node_id.localeCompare(b.author_node_id);
    });

    // Extract txs in order
    const orderedTxs = [];
    for (const cert of collectedCerts) {
      for (const tx of (cert.batch?.txs || [])) {
        if (tx && tx.tx_id) orderedTxs.push(tx);
      }
    }

    return orderedTxs;
  }

  /**
   * Get the leader node for a given round.
   *
   * Narwhal/Bullshark groups rounds into waves of 2 (propose + vote). Leader
   * rotates per wave, not per round — this guarantees every node gets a turn
   * regardless of N. A per-round formula biases for even N (only nodes at
   * even indices ever lead, since anchors run on odd propose rounds and
   * `(odd - 1) % even_N` only yields even residues).
   *
   * @param {number} round
   * @returns {string|null}
   */
  function _getLeader(round) {
    // Committee is wave-stable, so use this round's wave to pick leader
    // consistently across both propose and vote rounds of the wave.
    const nodeIds = getNodeIds(round);
    if (!nodeIds || nodeIds.length === 0) return null;
    const wave = Math.floor((round - 1) / 2);
    return nodeIds[wave % nodeIds.length];
  }

  return {
    onRoundComplete,

    /** Get the leader for a specific round */
    getLeader: _getLeader,

    /** Get the last committed round */
    lastCommittedRound: () => _lastCommittedRound,

    /**
     * Mark all certificates up to a round as already ordered.
     * Called after certificate sync + tx replay so Bullshark
     * doesn't re-commit txs that were already applied.
     */
    markOrderedUpTo(round) {
      for (let r = 1; r <= round; r++) {
        try {
          const certs = dag.getCertificatesByRound(r);
          for (const cert of certs) _orderedCertHashes.add(cert.hash);
        } catch { /* ignore */ }
      }
      if (round > _lastCommittedRound) _lastCommittedRound = round;
      log.info(`Bullshark: marked certificates as ordered up to round ${round}`);
    },

    /**
     * Adopt peer's bullshark consensus_index after a snapshot install.
     * Monotonic — only advances forward. Persisted via consensus_meta
     * so subsequent restarts pick up the inherited value.
     *
     * Called by peer-sync.js tryFastSyncSnapshot after the snapshot's
     * verified to install peer's anchor counter, putting the joiner
     * on the same network-wide counter as peer (Cosmos/Sui/Aptos
     * pattern) instead of each node tracking its own local value.
     */
    setConsensusIndex(value) {
      const n = Number(value) || 0;
      if (n <= _consensusIndex) return _consensusIndex;
      _consensusIndex = n;
      if (dag.setConsensusMeta) {
        try { dag.setConsensusMeta("last_consensus_index", _consensusIndex); }
        catch (err) { log.warn(`setConsensusIndex: consensus_meta write failed: ${err.message}`); }
      }
      log.info(`Bullshark: consensus_index advanced to ${_consensusIndex} (from snapshot peer)`);
      return _consensusIndex;
    },

    /** Stats for monitoring */
    stats: () => ({
      lastCommittedRound: _lastCommittedRound,
      orderedCertificates: _orderedCertHashes.size,
      nodeCount: getNodeIds().length,
      consensusIndex: _consensusIndex,
      metrics: { ..._metrics },
    }),
  };
}

module.exports = { createBullshark };
