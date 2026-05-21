/**
 * @file @tip-protocol/node/src/consensus/index.js
 * @description Consensus layer orchestrator for TIP Protocol.
 *
 * Wires together:
 *   - Mempool (persistent, crash-safe tx queue)
 *   - Narwhal (data availability — certificate creation + broadcast)
 *   - Bullshark (ordering — anchor commit + deterministic tx ordering)
 *   - Commit handler (validates + writes ordered txs to DAG atomically)
 *   - Sync handler (Merkle tree + certificate catch-up protocol)
 *   - Peer sync (auto-sync on peer connect)
 *   - Participant tracking (active quorum management)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { createMempool } = require("./mempool");
const { createNarwhal } = require("./narwhal");
const { createBullshark } = require("./bullshark");
const { createRotationCoordinator } = require("./rotation-coordinator");
const { createCommitHandler } = require("./commit-handler");
const { createSyncHandler } = require("../sync/sync-handler");
const { createSnapshotHandler } = require("../sync/snapshot-handler");
const { computeHaltStatus } = require("./halt-status");
const { computeStateMerkleRoot } = require("./state-root");
const { getActiveCommittee, getNodeCount } = require("./participants");
const { onPeerAuthorized } = require("./peer-sync");
const { createConsensusSummary } = require("./summary");
const { createAntiEntropy } = require("./anti-entropy");
const { createVerdictTrigger } = require("./verdict-trigger");
const { createCleanRecordTrigger } = require("./clean-record-trigger");
const { createPrescanReviewTrigger } = require("./prescan-review-trigger");
const { createTxSubmitter } = require("../services/helpers");
const jury = require("../jury");
const { CONSENSUS } = require("../../../shared/protocol-constants");
const { encode, decode } = require("../network/proto");
const { getLogger } = require("../logger");

const log = getLogger("tip.consensus");

/**
 * Look up a node's public key from the DAG registry.
 * Used by Narwhal for batch/cert signature verification.
 *
 * @param {Object} dag     DAG store
 * @param {string} nodeId  Node ID to look up
 * @returns {string|null}  Public key or null if not found
 */
function getNodeKey(dag, nodeId) {
  const n = dag.getNode(nodeId);
  return n?.public_key || null;
}

/**
 * Initialize the consensus layer.
 *
 * @param {Object} options
 * @param {Object}   options.dag              DAG store
 * @param {Object}   options.scoring          Scoring engine
 * @param {Object}   options.config           Node config
 * @param {Object}   options.network          libp2p network node
 * @param {Function} options.isAuthorizedPeer (peerId) => boolean
 * @returns {Object} Consensus interface
 */
function initConsensus({ dag, scoring, config, network, isAuthorizedPeer = () => false }) {
  const nodeId = config.nodeRegisteredId || config.nodeId;

  // ── Create mempool (persistent) ───────────────────────────────────────────
  // Pass nodeId so mempool drop sites stamp tx_rejection rows with the
  // observing node — needed for multi-node forensics / replay tooling.
  const mempool = createMempool(dag, { nodeId });
  log.info(`Mempool initialized (${mempool.size()} pending txs restored)`);

  // Active committee is derived deterministically from DAG state: registered +
  // produced a cert in the last K rounds. Every node reading the same DAG
  // computes the same committee, so leader rotation and quorum match.
  // `narwhalRef.current` is populated below; this closure is called from
  // Bullshark / Narwhal after both are wired, AND from the post-round
  // triggers' leader-gate logic (`committee[round % N]` for verdicts,
  // `committee[day % N]` for clean-record).
  const narwhalRef = { current: null };
  const getCommittee = (round) => {
    const r = round != null ? round : (narwhalRef.current ? narwhalRef.current.currentRound() : 1);
    return getActiveCommittee(dag, r);
  };

  // ── Post-round triggers (Commit 3 of #13/#15) ─────────────────────────
  // Both run inside commit-handler's post-round phase, build batches via
  // the same jury / scoring builders, submit through consensus mempool.
  // Leader-gated to keep mempool flood bounded:
  //   - verdict-trigger: round-modulo (one node per round fires)
  //   - clean-record-trigger: day-modulo (one node per UTC day fires)
  // Failover is automatic via natural rotation — if today's leader is
  // offline, next round/day's leader picks up the slack.
  //
  // Submitter targets the same consensus instance we're constructing
  // below — the `consensusForTrigger` ref is populated at the end of
  // initConsensus so the closure resolves at call time.
  const consensusForTrigger = { current: null };
  const triggerSubmitter = createTxSubmitter(consensusForTrigger);
  const verdictTrigger = createVerdictTrigger({
    dag, jury, scoring, config,
    submitBatch: triggerSubmitter.submitBatch,
    getCommittee,
  });
  // Rehydrate the heap from any committed-but-unresolved disputes so we
  // pick up where we left off across restart. Boot-time scan is bounded
  // by `pending disputes`, not chain length — `getTxsByType` is indexed.
  verdictTrigger.rehydrate();

  const cleanRecordTrigger = createCleanRecordTrigger({
    dag, scoring, config,
    submitBatch: triggerSubmitter.submitBatch,
    getCommittee,
  });

  const prescanReviewTrigger = createPrescanReviewTrigger({
    dag, scoring, config,
    submitTx: triggerSubmitter.submitTx,
    getCommittee,
  });

  // ── Create commit handler ─────────────────────────────────────────────────
  const commitHandler = createCommitHandler({
    dag, scoring, config,
    verdictTrigger, cleanRecordTrigger, prescanReviewTrigger,
  });

  // ── Create sync handler (Merkle tree + catch-up protocol) ──────────────────
  const syncHandler = createSyncHandler({ dag, network, isAuthorizedPeer });

  // ── Create snapshot handler (§14 state-snapshot fast-sync) ─────────────────
  // Serves the latest committed state + 2f+1 acks to new joiners so they
  // can catch up in O(state size) instead of O(chain length). Orthogonal to
  // sync-handler (which does cert replay) — a joiner typically tries
  // snapshot first and falls back to cert sync if no peer has a recent enough
  // commit. Fallback wiring lives in the join flow (not in this orchestrator).
  // Construction is deferred to after bullshark is created so the snapshot
  // server can ship peer's bullshark.lastCommittedRound to joiners (lets the
  // joiner advance its own committed_round counter past the snapshot anchor
  // when the network's been idle for many rounds).

  const bullshark = createBullshark({
    dag,
    getNodeIds: getCommittee,
    onMissingCertsTimeout: (voteRound, missingCount) => {
      if (antiEntropyForResync && typeof antiEntropyForResync.triggerSnapshotResync === "function") {
        // Stagger resync by node_id so all nodes don't simultaneously enter
        // snapshot-install when BULLSHARK_DEFER_MS fires cluster-wide (e.g.
        // all 4 non-paused nodes waiting on the same paused node's certs).
        const _id = nodeId || "";
        const _h = _id.split("").reduce((acc, c) => (acc * 31 + c.charCodeAt(0)) >>> 0, 0);
        const _staggerMs = (_h % 4) * 3000; // 0, 3000, 6000, 9000 ms
        setTimeout(() => {
          antiEntropyForResync.triggerSnapshotResync(voteRound, missingCount).catch(err => {
            log.warn(`Bullshark.onMissingCertsTimeout: snapshot resync failed: ${err.message}`);
          });
        }, _staggerMs);
      } else {
        log.warn(`Bullshark.onMissingCertsTimeout: anti-entropy not ready — falling back to force-commit at round ${voteRound}`);
      }
    },
    // BFT-Time — bullshark passes the anchor cert's timestamp (median of
    // acks.signed_at, deterministic across nodes) so commit-handler can
    // use it as the canonical wall-clock for derived state, audit logs,
    // and post-round verdict triggers (Commit 3). Threaded through `opts`
    // so additional flags can be added without breaking call sites.
    onOrderedTxs: (orderedTxs, round, certTimestamp) => {
      const result = commitHandler.commitOrderedTxs(orderedTxs, round, { certTimestamp });
      log.info(`Bullshark round ${round}: ${result.committed} committed, ${result.dropped} dropped`);
      // #73: surface accept/drop counts so bullshark can gate `saveCommit`
      // on actual state-change presence — a rotation-only round where the
      // tx was rejected at commit-handler must NOT inflate the commits
      // table with a no-state-change row.
      return result;
    },
    // §4 + #34: rotation proposer. Wired only when the node has a
    // signing identity (config.nodePrivateKey present). The submitTx
    // closure routes the rotation tx through consensus.addTx — same
    // path user-submitted txs and verdict-trigger / clean-record-trigger
    // batches take (mempool → narwhal batch → bullshark order →
    // commit-handler). Reuses the shared `triggerSubmitter` helper so
    // the rotation flow has a SINGLE code path through consensus —
    // never writes to dag.transactions directly. Closes the same
    // architectural class issues.md Consensus #13 closes for
    // schedulers ("scheduler writes bypass consensus").
    proposer: (config.nodeId && config.nodePrivateKey) ? {
      nodeId: config.nodeRegisteredId || config.nodeId,
      nodePrivateKey: config.nodePrivateKey,
      nodePublicKey: config.nodePublicKey,
      submitTx: (tx) => triggerSubmitter.submitTx(tx),
      // #68 multi-sig coordinator: bullshark's _maybeProposeCommitteeRotation
      // hands the proposal off to this coordinator instead of submitting a
      // 1-of-N tx directly. Coordinator broadcasts a RotationProposal,
      // collects ≥ ceil(2n/3) RotationSignatures from the previous committee,
      // builds the aggregated COMMITTEE_ROTATION tx, and routes it through
      // submitTx. For solo committees (n=1) the proposer's own sig is the
      // full quorum so submission is synchronous.
      coordinator: (network && network.publish) ? createRotationCoordinator({
        dag,
        network,
        proto: { encode, decode },
        identity: {
          nodeId: config.nodeRegisteredId || config.nodeId,
          privateKey: config.nodePrivateKey,
          publicKey: config.nodePublicKey,
        },
        submitTx: (tx) => triggerSubmitter.submitTx(tx),
      }) : null,
    } : null,
  });

  // Deferred AE ref — narwhal needs to call AE's isPeerDivergent at batch-
  // ack time, but AE is constructed AFTER narwhal (it takes narwhal as a
  // dep). Closure-over-let resolves the cycle: the function is called on
  // each batch arrival, by which point the let has been assigned.
  // Same pattern used for bullshark → AE: bullshark's onMissingCertsTimeout
  // calls antiEntropyForResync.triggerSnapshotResync() after antiEntropy is
  // assigned (deferred anchor timer fires seconds later, never at create-time).
  let antiEntropyForFiltering = null;
  let antiEntropyForResync = null;

  const narwhal = createNarwhal({
    dag, mempool, network, config,
    getNodeKey: (nId) => getNodeKey(dag, nId),
    getNodeCount: () => getNodeCount(dag),
    getCommittee,
    onCommit: (certificates, round) => bullshark.onRoundComplete(certificates, round),
    // Rebuild Merkle tree whenever ANY cert is saved (own, peer, or synced),
    // so the root always reflects canonical DAG state. Also notify bullshark
    // so it can unblock any parked anchor commit waiting on this cert hash
    // (Option A — DAG completeness gate).
    onCertSaved: (cert) => {
      syncHandler.onCertificateCommitted(cert.hash);
      if (bullshark && typeof bullshark.onCertSaved === "function") {
        bullshark.onCertSaved(cert.hash);
      }
    },
    // Producer-pause notifier — breaks the deadlock where rotation tx
    // never lands because no rounds advance because rotation tx is
    // missing. Bullshark.tryRotationProposal re-checks DAG and forces
    // a proposal attempt (multi-aggregator + commit-handler dedup
    // ensure exactly one tx commits).
    onProducerPaused: (round, missingRotation) => {
      if (bullshark && typeof bullshark.tryRotationProposal === "function") {
        bullshark.tryRotationProposal(round, missingRotation);
      }
    },
    // Ack-filter — defense layer that denies attestation to peers whose
    // state has diverged from ours. Implemented in AE; threaded here via
    // the deferred ref above. peerJoinState is the sibling getter narwhal
    // uses to skip the refusal during the brief AE-cache-stale window
    // where a peer just transitioned catching_up → ready (cache lag
    // ≤ ANTI_ENTROPY_INTERVAL_MS). Persistent malicious-non-ready peers
    // are handled by AE's time-bounded halt escalation, not by the ack-
    // filter, so this gate stays a simple cache-lag race guard.
    isPeerDivergent: (peerNodeId) => {
      try { return antiEntropyForFiltering ? antiEntropyForFiltering.isPeerDivergent(peerNodeId) : false; }
      catch { return false; }
    },
    peerJoinState: (peerNodeId) => {
      try { return antiEntropyForFiltering ? antiEntropyForFiltering.peerJoinState(peerNodeId) : "ready"; }
      catch { return "ready"; }
    },
    divergentPeers: () => {
      try { return antiEntropyForFiltering ? antiEntropyForFiltering.divergentPeers() : []; }
      catch { return []; }
    },
  });
  narwhalRef.current = narwhal;

  // §14 snapshot handler — created here (after bullshark) so it can ship
  // peer's bullshark.lastCommittedRound in SnapshotHeader. The joiner
  // uses this to advance its own committed_round counter past the
  // snapshot anchor when the network's been idle, so anti-entropy
  // doesn't false-positive a "behind" gap and loop.
  const snapshotHandler = createSnapshotHandler({
    dag, network, isAuthorizedPeer, bullshark, narwhal,
    // Called synchronously inside snapshot-handler, right after narwhal.markSnapshotInstalled,
    // so cancelPendingCommit + resetBftTimeFloor fire before any anti-entropy tick
    // can re-detect a stale deferred commit or BFT-time violation (SI-2 / CI-1).
    // peerCommittedRound (not snapshotRound) is passed so _lastCommittedRound
    // advances to the true peer head (SI-5).
    onSnapshotInstalled: (peerCommittedRound) => {
      if (bullshark) {
        if (typeof bullshark.cancelPendingCommit === "function") {
          bullshark.cancelPendingCommit(peerCommittedRound || 0);
        }
        if (typeof bullshark.resetBftTimeFloor === "function") {
          bullshark.resetBftTimeFloor();
        }
        // A snapshot may have been built from a different DAG view than any
        // in-flight rotation proposal, causing payload_hash divergence across
        // nodes and silent proposal merge failures. Clearing here lets all
        // nodes re-propose from a fresh, consistent DAG after the snapshot
        // settles — fixing the rotation-47-class deadlock (SI-6).
        const coord = bullshark.rotationCoordinator?.();
        if (coord && typeof coord.resetInflight === "function") {
          coord.resetInflight();
        }
      }
    },
  });

  // Periodic heartbeat summary — emits one INFO line per interval with
  // deltas, stays silent during true idle. Per-round events are debug-level.
  const summary = createConsensusSummary({
    narwhal, bullshark,
    intervalMs: CONSENSUS.CONSENSUS_SUMMARY_INTERVAL_MS,
  });

  // §28 anti-entropy reconciliation loop. Pull-side safety net: every
  // ANTI_ENTROPY_INTERVAL_MS each authorized peer is probed for its
  // committed_round + state_merkle_root. Self-behind → pull gap via
  // /tip/sync/1.0.0; equal round but divergent root → byzantine fork
  // signal (log + metric, no auto-resolve). Pairs with cert GC (§2)
  // which otherwise leaves briefly-offline nodes unable to recover
  // via GossipSub retention alone.
  const antiEntropy = createAntiEntropy({
    network, syncHandler,
    // #46: snapshot fallback when peer's GC horizon prunes the round we
    // need. Without these the AE loop spins forever on lagging nodes
    // that fell past gc_depth rounds behind.
    snapshotHandler,
    narwhal,
    isAuthorizedPeer,
    getSelfNodeId: () => nodeId,
    getConsensusState: () => ({
      round: narwhal.currentRound(),
      committed_round: bullshark.lastCommittedRound(),
      consensus_index: bullshark.stats().consensusIndex || 0,
      // Live-computed from the in-memory canonical state, NOT cached from
      // the latest commit row. Reading from the commit row only refreshes
      // when bullshark commits an anchor; on idle federations that can be
      // minutes between updates, leaving mirror divergence invisible until
      // the next commit fires (the lag we hit on the 2026-05-06 test).
      // Computing fresh on every AE poll makes divergence detection
      // independent of commit cadence — fires at the next AE cycle (~4s)
      // regardless of whether anyone has committed in the meantime.
      // Cost: one iterateCanonicalState walk per /sync-status request,
      // sub-millisecond at small federation sizes.
      state_merkle_root: computeStateMerkleRoot(dag),
      txs_merkle_root: (() => {
        const latest = dag.getLatestCommit && dag.getLatestCommit();
        return latest?.txs_merkle_root || "";
      })(),
      cert_merkle_root: syncHandler.merkleRoot(),
    }),
    // Bug 3: cancel any deferred anchor timer on snapshot install failure.
    // On success, onSnapshotInstalled (in snapshotHandler) calls cancelPendingCommit.
    // On failure, nothing did — the stale timer could fire later and trigger another
    // resync→install→fail loop or commit partial state.
    cancelPendingCommit: (round) => {
      if (bullshark && typeof bullshark.cancelPendingCommit === "function") {
        bullshark.cancelPendingCommit(round || 0);
      }
    },
  });
  antiEntropyForFiltering = antiEntropy;
  antiEntropyForResync = antiEntropy;

  // ── Wire network events ────────────────────────────────────────────────

  if (network) {
    // Auto-sync after handshake completes
    network.onPeerAuthorized(async (peerId, tipNodeId) => {
      await onPeerAuthorized(peerId, tipNodeId, {
        syncHandler, snapshotHandler, commitHandler, dag, narwhal, bullshark, nodeId,
        queryPeerStatus: antiEntropy.queryPeer,
      });
    });

    log.info("Consensus network handlers wired");
  } else {
    log.warn("No network node — consensus running in local-only mode");
  }

  // ── Direct-stream protocol handlers (#46, #48) ─────────────────────────

  // Incoming BatchAck messages from batch authors arrive as one-shot streams
  // instead of gossipsub CONSENSUS topic messages. Closes the sub_quorum
  // halt class where a lost gossip mesh edge dropped acks silently (#13).
  // Auth-check uses the same isAuthorizedPeer gate as every other stream
  // protocol; payload is the raw BatchAck encoding (unchanged wire shape).
  async function _registerAckReceiver() {
    if (!network || !network.CONSENSUS_ACK_PROTOCOL) return;
    await network.handle(network.CONSENSUS_ACK_PROTOCOL, async ({ stream, connection }) => {
      const peerId = connection?.remotePeer?.toString();
      if (!isAuthorizedPeer(peerId)) {
        log.warn(`Rejected ack stream from unauthorized peer ${peerId?.slice(0, 12)}`);
        try { stream.close(); } catch { /* ignore */ }
        return;
      }
      try {
        const chunks = [];
        for await (const chunk of stream.source) {
          chunks.push(chunk.subarray ? chunk.subarray() : chunk);
        }
        const data = Buffer.concat(chunks.map(c => Buffer.isBuffer(c) ? c : Buffer.from(c)));
        narwhal.handleIncomingAck(data);
      } catch (err) {
        log.debug(`Ack stream read failed from ${peerId?.slice(0, 12)}: ${err.message}`);
      } finally {
        try { stream.close(); } catch { /* ignore */ }
      }
    });
  }

  // Explicit ack-request handler — requester asks for this node's cached ack
  // for a specific batch (identified by hex hash). Responds with the encoded
  // BatchAck bytes or an empty buffer if not cached. Used by the per-stuck-
  // round retry path in narwhal to recover from a missed ack without
  // rebroadcasting the entire batch (#48).
  async function _registerAckRequestHandler() {
    if (!network || !network.CONSENSUS_ACK_REQUEST_PROTOCOL) return;
    await network.handle(network.CONSENSUS_ACK_REQUEST_PROTOCOL, async ({ stream, connection }) => {
      const peerId = connection?.remotePeer?.toString();
      if (!isAuthorizedPeer(peerId)) {
        log.warn(`Rejected ack-request from unauthorized peer ${peerId?.slice(0, 12)}`);
        try { stream.close(); } catch { /* ignore */ }
        return;
      }
      try {
        const chunks = [];
        for await (const chunk of stream.source) {
          chunks.push(chunk.subarray ? chunk.subarray() : chunk);
        }
        const batchHashHex = Buffer.concat(chunks.map(c => Buffer.isBuffer(c) ? c : Buffer.from(c))).toString("utf8");
        const ackBuf = narwhal.getCachedAckBuf(batchHashHex, nodeId);
        await stream.sink([ackBuf || Buffer.alloc(0)]);
      } catch (err) {
        log.debug(`Ack-request stream failed from ${peerId?.slice(0, 12)}: ${err.message}`);
      } finally {
        try { stream.close(); } catch { /* ignore */ }
      }
    });
  }

  // ── Public interface ───────────────────────────────────────────────────

  const consensus = {
    /**
     * Add a validated transaction to the mempool.
     * Called by API services after validation.
     * @param {Object} tx  Validated tx (must have tx_id)
     * @returns {{ added: boolean, reason?: string }}
     */
    addTx: (tx) => mempool.add(tx),

    /**
     * Start consensus rounds (Narwhal + Bullshark) and sync protocol.
     * Pass { awaitPeers: true } for joiner nodes so production is gated on
     * the first peer handshake + sync, preventing premature batch/ack
     * broadcasts that would be rejected by peers whose node registries
     * haven't yet incorporated us via consensus.
     */
    async start({ awaitPeers = false } = {}) {
      await syncHandler.registerProtocol();
      await snapshotHandler.registerProtocol();
      await antiEntropy.start();
      const coord = bullshark.rotationCoordinator?.();
      if (coord && typeof coord.registerProtocol === "function") await coord.registerProtocol();
      await _registerAckReceiver();
      await _registerAckRequestHandler();
      if (awaitPeers) narwhal.enterSyncMode();
      narwhal.start();
      summary.start();
      log.notice(`Consensus started${awaitPeers ? " — awaiting peer sync" : ""}`);
    },

    /**
     * Stop consensus gracefully.
     */
    stop() {
      antiEntropy.stop();
      summary.stop();
      narwhal.stop();
      const coord = bullshark.rotationCoordinator?.();
      if (coord && typeof coord.stop === "function") coord.stop();
      log.notice("Consensus stopped");
    },

    /**
     * Get the network handlers for libp2p topic subscriptions.
     * Returned as an object so the network node can wire them up.
     */
    handlers: {
      onBatch: (data) => narwhal.handleIncomingBatch(data),
      onAck: (data) => narwhal.handleIncomingAck(data),
      onCertificate: (data) => narwhal.handleIncomingCertificate(data),
      // RotationProposal / RotationSignature dispatch is now via direct
      // libp2p stream (/tip/rotation-coord/1.0.0); see coord.registerProtocol.
    },

    /** Access to mempool (for API services to check pending status) */
    mempool,

    /**
     * "Can we make forward progress right now?" Returns
     * `{ halted, reason, lastAdvanceAt, staleMs, [message] }`. Halted when
     * consensus is running but hasn't advanced a round in > 3× ROUND_TIMEOUT_MS
     * (quorum unreachable — peers offline, partition). Loud, honest signal
     * used by the /v1 write gate to 503 new requests and by /health to
     * surface degraded status.
     *
     * Implementation delegates to `computeHaltStatus` — see that file for
     * the full decision tree. Accepts an injectable `now` for tests.
     */
    isConsensusHalted({ now } = {}) {
      return computeHaltStatus(narwhal.stats(), {
        roundTimeoutMs: CONSENSUS.ROUND_TIMEOUT_MS,
        now,
      });
    },

    /** Sync: request certificates from a peer */
    syncFromPeer: (peerId) => syncHandler.syncFromPeer(peerId),

    /** §14: fast-sync derived state from a peer via the snapshot protocol */
    requestSnapshotFromPeer: (peerId, opts) => snapshotHandler.requestSnapshotFromPeer(peerId, opts),

    /** Current Merkle root of certificate DAG */
    merkleRoot: () => syncHandler.merkleRoot(),

    /** §28 anti-entropy cluster sync view — for GET /v1/sync-status */
    getSyncStatus: () => antiEntropy.getStatus(),

    /** Stats for monitoring / health endpoint */
    stats() {
      return {
        narwhal: narwhal.stats(),
        bullshark: bullshark.stats(),
        mempool: mempool.stats(),
        merkleRoot: syncHandler.merkleRoot(),
        antiEntropy: antiEntropy.stats(),
        verdictTrigger: { pending: verdictTrigger.size() },
        // §4 + #34: chain-walk failure counter for /metrics. Empty
        // object on legacy snapshot-handler implementations that
        // don't expose stats.
        snapshotHandler: typeof snapshotHandler.stats === "function"
          ? snapshotHandler.stats() : { metrics: {} },
      };
    },
  };

  // Late-bind the ref the verdict-trigger's submitter closes over.
  // Trigger is constructed before the public consensus object exists;
  // we wire it up here so post-round verdict batches can hit `addTx`.
  consensusForTrigger.current = consensus;

  return consensus;
}

module.exports = { initConsensus };