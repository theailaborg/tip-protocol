/**
 * @file @tip-protocol/node/src/consensus/rotation-coordinator.js
 * @description #68 multi-sig committee-rotation coordination.
 *
 * Solves the under-quorum-rotation problem: bullshark's
 * `_maybeProposeCommitteeRotation` no longer submits a 1-of-N tx directly.
 * Instead, it asks this coordinator to broadcast a `RotationProposal` to
 * the previous committee over the `tip/rotation-coordination` gossip topic;
 * every previous-committee member verifies the proposal locally, signs the
 * `payload_hash`, and replies with a `RotationSignature`. The proposer
 * aggregates ≥ ceil(2n/3) distinct signatures from the previous committee
 * and only THEN submits the COMMITTEE_ROTATION tx with the aggregated
 * `signer_node_ids` + `signatures` arrays.
 *
 * State model (per (rotation_number) key, in memory only):
 *   {
 *     proposal,          // RotationProposal we received or originated
 *     sigs,              // Map<signer_node_id, signature_bytes>
 *     prevCommittee,     // Set<node_id> — previous committee at proposal-build time
 *     prevPubkeys,       // Map<node_id, public_key>
 *     submittedAt,       // ms when we submitted the tx (null until then)
 *     deadline,          // ms — drop in-flight after this; next leader retries
 *   }
 *
 * Anti-spam: drop proposals whose rotation_number != latest+1; drop
 * signatures for proposals not seen; drop sigs from non-previous-committee
 * signers.
 *
 * Why per-node aggregation (not just proposer-side): every prev-committee
 * member runs the same aggregation logic in parallel. The first one to
 * cross quorum + leader-gate submits the tx. Robust to proposer churn —
 * if the original proposer goes offline mid-aggregation, another
 * prev-committee member with quorum can submit. Validator dedupes by
 * rotation_number; only the first tx wins.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs } = require("../../../shared/time");
const { safeSetInterval } = require("../safe-timer");

const { mldsaSign, mldsaVerify, computeTxId, shake256, canonicalJson } = require("../../../shared/crypto");
const { TX_TYPES } = require("../../../shared/constants");
const { CONSENSUS } = require("../../../shared/protocol-constants");
const { GENESIS_TIMESTAMP } = require("../genesis");
const { hexToBytes, bytesToHex } = require("../network/proto");
const { computeQuorum } = require("./certificate");
const { getLogger } = require("../logger");

const log = getLogger("tip.rotation-coord");

/**
 * Build the COMMITTEE_ROTATION tx from an aggregated proposal + signatures.
 * Single source of truth for rotation-tx shape: every callsite needs the
 * SAME field set, the SAME canonicalization for tx_id, and the SAME prev-
 * chain handling. Centralizing here prevents the wire-format from drifting
 * between the coordinator's normal aggregation path and bullshark's legacy
 * single-sig fallback path (used by tests/legacy mode without a coordinator).
 *
 * Signatures ride as `tx.data.cosignatures = [{signer_kind:"node",
 * signer_ref:<node_id>, signature:<hex>}, ...]`, sorted by signer_ref ASC.
 * Each entry signs the chain-of-trust message `rotation:<payload_hash>:<node_id>`
 * with the signer's previous-committee node key. tx.signature stays null
 * (multi-aggregator submission requires byte-identical tx_id across all
 * honest submitters; an envelope sig would break that).
 *
 * @param {object} dag      — read latest committed cert.timestamp (BFT-Time
 *                            anchor for the rotation tx timestamp)
 * @param {object} proposal — { rotation_number, effective_round, new_committee, payload_hash }
 * @param {string[]} signer_node_ids   — sorted ASC
 * @param {string[]} signatures        — parallel to signer_node_ids
 * @returns {object} tx with tx_id computed
 */
function buildRotationTx(dag, proposal, signer_node_ids, signatures) {
  const cosignatures = [];
  for (let i = 0; i < signer_node_ids.length; i++) {
    cosignatures.push({
      signer_kind: "node",
      signer_ref: signer_node_ids[i],
      signature: signatures[i],
    });
  }
  cosignatures.sort((a, b) => a.signer_ref < b.signer_ref ? -1 : a.signer_ref > b.signer_ref ? 1 : 0);
  const data = {
    rotation_number: proposal.rotation_number,
    effective_round: proposal.effective_round,
    new_committee: proposal.new_committee,
    payload_hash: proposal.payload_hash,
    cosignatures,
  };
  // Deterministic outer envelope — every honest node building a rotation
  // tx for the same (rotation_number, effective_round, committee, sigs)
  // produces the IDENTICAL tx_id. COMMITTEE_ROTATION is a SYSTEM tx (same
  // class as GENESIS): tamper-evidence comes from content-addressed tx_id +
  // 2f+1 committee sigs over payload_hash + chain-of-trust walker over
  // committee_history.prev_rotation. It is NOT part of the user-tx prev
  // chain.
  //
  //   timestamp: anchored at the latest committed cert's BFT-Time (median
  //              of acks.signed_at). This is BOTH deterministic across
  //              nodes (every node has committed the same certs in order)
  //              AND a real wall-clock reading from the most recent
  //              consensus moment — not a synthetic round-derived value.
  //              Fallback to GENESIS_TIMESTAMP for the very first rotation
  //              when no commits exist yet.
  //   prev:      [] — no user-tx prev refs. Anchoring to GENESIS_TX_ID
  //              would require every node to share the EXACT same genesis
  //              tx_id, which is not true in practice across DB-drifted
  //              federations. Treating rotation as a system tx avoids
  //              that coupling entirely.
  //
  // tx-validator.js permits empty prev for the system-tx set (GENESIS,
  // COMMITTEE_ROTATION). Both timestamp and prev fall OUTSIDE the
  // chain-of-trust signature payload (`rotation:${payload_hash}:${signer}`),
  // so the change has no impact on signature verification.
  const latestCommit = dag && typeof dag.getLatestCommit === "function"
    ? dag.getLatestCommit()
    : null;
  const timestamp = (latestCommit && latestCommit.cert_timestamp)
    ? latestCommit.cert_timestamp
    : GENESIS_TIMESTAMP;
  const tx = {
    tx_type: TX_TYPES.COMMITTEE_ROTATION,
    timestamp,
    prev: [],
    data,
  };
  tx.tx_id = computeTxId(tx);
  return tx;
}

/**
 * Build a coordinator wired to the given dag + network + signing identity.
 * Returns: { proposeRotation, handleIncoming, _state (test only) }.
 *
 * Caller responsibilities:
 *   - Subscribe `network.TOPICS.ROTATION_COORDINATION` to `handleIncoming`.
 *     Done by network.js dispatcher; coordinator only wires in.
 *   - Provide `submitTx(tx)` to actually publish the COMMITTEE_ROTATION tx
 *     once aggregation reaches quorum.
 *
 * @param {object} opts
 * @param {object} opts.dag
 * @param {object} opts.network         — provides .publish(topic, bytes)
 * @param {object} opts.proto           — { encode, decode } from ./network/proto
 * @param {object} opts.identity        — { nodeId, privateKey, publicKey }
 * @param {Function} opts.submitTx      — (tx) => promise/result, used to publish COMMITTEE_ROTATION when quorum reached
 * @param {number} opts.deadlineMs      — drop in-flight after this many ms (default 30s)
 */
function createRotationCoordinator({ dag, network, proto, identity, submitTx, mempool = null, deadlineMs = 30_000 }) {
  if (!dag) throw new Error("rotation-coordinator: dag required");
  if (!network || typeof network.publish !== "function") throw new Error("rotation-coordinator: network.publish required");
  if (!proto || typeof proto.encode !== "function" || typeof proto.decode !== "function") {
    throw new Error("rotation-coordinator: proto required");
  }
  if (!identity || !identity.nodeId || !identity.privateKey) {
    throw new Error("rotation-coordinator: identity (nodeId+privateKey) required");
  }
  if (typeof submitTx !== "function") throw new Error("rotation-coordinator: submitTx required");

  // rotation_number → in-flight aggregation. Bounded by max one in-flight at
  // a time in practice (one rotation submission window per epoch); we still
  // map-key to support late RotationSignature for already-submitted proposals
  // (cheap dedup) and the rare case of two consecutive boundaries firing
  // close together.
  const _inFlight = new Map();

  // Direct-stream broadcast — bypasses gossipsub topic mesh by opening a
  // one-shot stream to each authorized peer. Replaces the original
  // network.publish(topic, buf) path which empirically dropped large
  // RotationProposal messages on cold meshes (live observed 2026-05-04
  // rotation 13 halt). A test-only fallback to network.publish stays
  // available so unit tests that stub a minimal { publish } network keep
  // working without re-implementing the libp2p protocol layer.
  async function _broadcast(buf) {
    if (network && typeof network.broadcastToAuthorized === "function" && network.ROTATION_COORD_PROTOCOL) {
      try { await network.broadcastToAuthorized(buf, network.ROTATION_COORD_PROTOCOL); }
      catch (err) { log.debug(`broadcastToAuthorized failed: ${(err && err.message) || err}`); }
      return;
    }
    if (typeof network?.publish === "function") {
      try { await network.publish("tip/rotation-coord-test", buf); }
      catch (err) { log.debug(`publish fallback failed: ${(err && err.message) || err}`); }
    }
  }

  // ── Proposer side ──────────────────────────────────────────────────────────
  /**
   * Originate a rotation proposal. Builds the proposal, signs it with our
   * own key, broadcasts to the coordination topic, and seeds the in-flight
   * aggregation with our own signature (the proposer always self-counts).
   *
   * Caller (bullshark `_maybeProposeCommitteeRotation`) must guard with
   * proposer.nodeId === leader before calling.
   *
   * @param {object} args
   * @param {number} args.rotation_number
   * @param {number} args.effective_round
   * @param {Array<{node_id, public_key}>} args.new_committee
   * @param {string} args.payload_hash    — hex; what every signer signs
   * @param {Array<string>} args.prevCommitteeNodeIds   — node_id list of previous committee
   * @param {Object<string,string>} args.prevPubkeys    — node_id → public_key (hex)
   * @returns {boolean} true if the proposal was broadcast, false if a duplicate or rejected
   */
  function proposeRotation({ rotation_number, effective_round, new_committee, payload_hash, prevCommitteeNodeIds, prevPubkeys }) {
    const existing = _inFlight.get(rotation_number);
    if (existing && existing.submittedAt != null) return false;

    // Reuse only while unexpired AND still the same committee everyone signs.
    // Past the deadline, or if our recomputed payload_hash changed (DAG healed
    // under us), the accrued sigs are dead, so rebuild fresh below.
    const reusable = existing
      && nowMs() <= existing.deadline
      && existing.proposal.payload_hash === payload_hash;
    if (reusable) {
      // Preserve accumulated sigs across bullshark's per-anchor retries.
      _broadcast(_encodeProposal(existing.proposal));
      log.debug(`Rotation ${rotation_number}: re-broadcast proposal (sigs ${existing.sigs.size}/${existing.prevCommittee.size})`);
      _maybeSubmit(rotation_number);
      return true;
    }
    if (existing) {
      // Rebuilds track the committee as the DAG converges; once it stabilizes
      // the hash stops changing and sigs accumulate, so the boundary self-heals.
      log.warn(`Rotation ${rotation_number}: in-flight stale (expired or committee changed) at ${existing.sigs.size}/${existing.prevCommittee.size} sigs; rebuilding fresh proposal`);
      _inFlight.delete(rotation_number);
    }

    const message = `rotation:${payload_hash}:${identity.nodeId}`;
    const proposerSig = mldsaSign(message, identity.privateKey);

    const sigs = new Map();
    sigs.set(identity.nodeId, proposerSig);

    const proposal = { rotation_number, effective_round, new_committee, payload_hash, proposer_node_id: identity.nodeId, proposer_signature: proposerSig };
    _inFlight.set(rotation_number, {
      proposal,
      sigs,
      prevCommittee: new Set(prevCommitteeNodeIds),
      prevPubkeys: new Map(Object.entries(prevPubkeys || {})),
      submittedAt: null,
      deadline: nowMs() + deadlineMs,
    });

    _broadcast(_encodeProposal(proposal));
    log.info(`Rotation ${rotation_number} proposal broadcast (proposer=${identity.nodeId.slice(-12)}, prevCommitteeSize=${prevCommitteeNodeIds.length}, quorum=${computeQuorum(prevCommitteeNodeIds.length)})`);

    _startRebroadcast();
    _maybeSubmit(rotation_number);
    return true;
  }

  function _encodeProposal(p) {
    return proto.encode("RotationCoordMessage", {
      proposal: {
        rotationNumber: p.rotation_number,
        effectiveRound: p.effective_round,
        newCommittee: p.new_committee.map(m => ({ nodeId: m.node_id, publicKey: m.public_key })),
        payloadHash: p.payload_hash,
        proposerNodeId: p.proposer_node_id,
        proposerSignature: hexToBytes(p.proposer_signature),
      },
    });
  }

  function _encodeSignature(rotation_number, payload_hash, signer_node_id, signature) {
    return proto.encode("RotationCoordMessage", {
      signature: {
        rotationNumber: rotation_number,
        payloadHash: payload_hash,
        signerNodeId: signer_node_id,
        signature: hexToBytes(signature),
      },
    });
  }

  // ── Receiver side ──────────────────────────────────────────────────────────
  /**
   * Dispatched from network.js when a message lands on the
   * `tip/rotation-coordination` topic. The message is a `RotationCoordMessage`
   * envelope whose `oneof` tells us unambiguously whether it carries a
   * proposal or a signature. This replaced an earlier trial-decode that
   * guessed the type by decoding as a proposal first: because the two inner
   * messages collide on field 2 (proposal.effective_round varint vs
   * signature.payload_hash string), decoding a signature as a proposal
   * misaligned the reader into the randomized ML-DSA signature bytes and
   * ~2-3% of the time produced a garbage-but-plausible "proposal", silently
   * dropping the vote and stalling rotations at the 2f+1 boundary.
   * Failure to decode the envelope = malformed; logged at debug + dropped.
   */
  function handleIncoming(buf, peerId) {
    let msg = null;
    try { msg = proto.decode("RotationCoordMessage", buf); }
    catch (e) {
      log.debug(`Drop rotation-coordination message from ${peerId?.slice(0, 12)} — undecodable envelope (${buf.length} bytes): ${e.message?.slice(0, 80)}`);
      return;
    }
    if (msg.proposal && msg.proposal.rotationNumber != null && msg.proposal.payloadHash) {
      _onProposal(msg.proposal);
      return;
    }
    if (msg.signature && msg.signature.rotationNumber != null && msg.signature.payloadHash && msg.signature.signerNodeId) {
      _onSignature(msg.signature);
      return;
    }
    log.debug(
      `Unrecognized rotation-coordination message from ${peerId?.slice(0, 12)} ` +
      `(${buf.length} bytes; hasProposal=${!!msg.proposal}, hasSignature=${!!msg.signature})`
    );
  }

  function _onProposal(p) {
    const rotation_number = Number(p.rotationNumber);
    const payload_hash = p.payloadHash;
    const proposer_node_id = p.proposerNodeId;
    const proposer_signature = bytesToHex(p.proposerSignature);

    // Anti-spam: rotation must equal latest+1.
    const latest = (typeof dag.getLatestRotation === "function") ? dag.getLatestRotation() : null;
    const expectedNext = latest ? latest.rotation_number + 1 : 1;
    if (rotation_number !== expectedNext) {
      log.debug(`Drop proposal: rotation_number=${rotation_number} expected ${expectedNext}`);
      return;
    }
    // Anti-replay: if we've already submitted for this rotation, ignore.
    const existing = _inFlight.get(rotation_number);
    if (existing && existing.submittedAt != null) return;

    // Build prevCommittee + prevPubkeys from latest CH row (every node has the
    // same source of truth here — the just-committed previous rotation).
    const prevCommitteeArr = Array.isArray(latest?.committee) ? latest.committee : [];
    const prevCommitteeNodeIds = prevCommitteeArr.map(m => m.node_id);
    const prevPubkeys = new Map();
    for (const m of prevCommitteeArr) prevPubkeys.set(m.node_id, m.public_key);

    // Verify proposer is in previous committee, and proposer's signature is valid.
    if (!prevPubkeys.has(proposer_node_id)) {
      log.warn(`Drop proposal: proposer ${proposer_node_id} not in previous committee`);
      return;
    }
    const proposerMessage = `rotation:${payload_hash}:${proposer_node_id}`;
    if (!mldsaVerify(proposerMessage, proposer_signature, prevPubkeys.get(proposer_node_id))) {
      log.warn(`Drop proposal: proposer signature invalid (rotation ${rotation_number})`);
      return;
    }

    // Seed in-flight if first sighting; otherwise merge the incoming
    // proposer's sig into our existing inflight. Multi-proposer race
    // (every prev-committee member fires proposeRotation under Fix D) means
    // we'll receive multiple proposals for the same rotation, each carrying
    // a different proposer's signature. Without merging, we'd only ever
    // have our own sig in inflight and never reach quorum.
    if (!_inFlight.has(rotation_number)) {
      const new_committee = (p.newCommittee || []).map(m => ({ node_id: m.nodeId, public_key: m.publicKey }));
      _inFlight.set(rotation_number, {
        proposal: {
          rotation_number,
          effective_round: Number(p.effectiveRound),
          new_committee,
          payload_hash,
          proposer_node_id,
          proposer_signature,
        },
        sigs: new Map([[proposer_node_id, proposer_signature]]),
        prevCommittee: new Set(prevCommitteeNodeIds),
        prevPubkeys,
        submittedAt: null,
        deadline: nowMs() + deadlineMs,
      });
    } else {
      const inflight = _inFlight.get(rotation_number);
      if (!inflight.sigs.has(proposer_node_id)
        && inflight.proposal.payload_hash === payload_hash) {
        inflight.sigs.set(proposer_node_id, proposer_signature);
        log.debug(`Rotation ${rotation_number}: merged peer ${proposer_node_id.slice(-12)}'s proposer sig (sigs ${inflight.sigs.size}/${inflight.prevCommittee.size})`);
      }
    }

    // Sign + broadcast our own RotationSignature if we're in the previous
    // committee and haven't signed yet. The merged-proposer-sig branch
    // above may have just bumped sigs over quorum even when we don't sign
    // here — call _maybeSubmit at the end either way.
    if (prevPubkeys.has(identity.nodeId)
      && !_inFlight.get(rotation_number).sigs.has(identity.nodeId)) {
      const ourMsg = `rotation:${payload_hash}:${identity.nodeId}`;
      const ourSig = mldsaSign(ourMsg, identity.privateKey);
      _inFlight.get(rotation_number).sigs.set(identity.nodeId, ourSig);

      _broadcast(_encodeSignature(rotation_number, payload_hash, identity.nodeId, ourSig));
      log.debug(`Rotation ${rotation_number}: signed proposal as ${identity.nodeId.slice(-12)}`);
    }

    _startRebroadcast();
    _maybeSubmit(rotation_number);
  }

  function _onSignature(s) {
    const rotation_number = Number(s.rotationNumber);
    const payload_hash = s.payloadHash;
    const signer_node_id = s.signerNodeId;
    const signature = bytesToHex(s.signature);

    const inflight = _inFlight.get(rotation_number);
    if (!inflight) {
      log.debug(`Drop signature: no in-flight proposal for rotation ${rotation_number}`);
      return;
    }
    if (inflight.submittedAt != null) return; // already submitted; sig is late
    if (inflight.proposal.payload_hash !== payload_hash) {
      log.warn(`Drop signature: payload_hash mismatch on rotation ${rotation_number}`);
      return;
    }
    if (!inflight.prevCommittee.has(signer_node_id)) {
      log.warn(`Drop signature: ${signer_node_id} not in previous committee`);
      return;
    }
    if (inflight.sigs.has(signer_node_id)) return; // duplicate sig from same signer

    const message = `rotation:${payload_hash}:${signer_node_id}`;
    const pubkey = inflight.prevPubkeys.get(signer_node_id);
    if (!pubkey || !mldsaVerify(message, signature, pubkey)) {
      log.warn(`Drop signature: invalid sig from ${signer_node_id} on rotation ${rotation_number}`);
      return;
    }

    inflight.sigs.set(signer_node_id, signature);
    log.debug(`Rotation ${rotation_number}: collected sig ${inflight.sigs.size}/${inflight.prevCommittee.size} (signer=${signer_node_id.slice(-12)})`);

    _maybeSubmit(rotation_number);
  }

  // ── Submission ─────────────────────────────────────────────────────────────
  /**
   * If quorum reached and we haven't submitted yet, build the COMMITTEE_ROTATION
   * tx and call submitTx(). Every prev-committee member runs this; the first
   * one to cross the threshold submits. Validator dedupes by rotation_number.
   *
   * Single-aggregator simplification: only the proposer submits. Avoids a
   * race where multiple prev-committee members each submit duplicate txs
   * with slightly different signer subsets — saves dedup churn at the
   * commit-handler. If the proposer goes offline mid-aggregation, the
   * deadline-based retry on the next anchor's leader covers it.
   */
  function _maybeSubmit(rotation_number) {
    const inflight = _inFlight.get(rotation_number);
    if (!inflight || inflight.submittedAt != null) return;

    const required = computeQuorum(inflight.prevCommittee.size);
    if (inflight.sigs.size < required) return;

    // Multi-aggregator: any prev-committee member that reaches quorum
    // submits. Removes the dependency on the original proposer also being
    // the one whose inflight reaches quorum first — under uneven sig
    // propagation (bursty rotation-coord topic, cold mesh) the proposer
    // may end up below quorum while a peer's inflight has enough sigs.
    // Duplicate submissions are deduped at the commit-handler layer:
    // committee_history.rotation_number is unique, second-arriver rejected.

    // Deterministic order: signer_node_ids sorted ASC, signatures parallel.
    const signer_node_ids = [...inflight.sigs.keys()].sort();
    const signatures = signer_node_ids.map(id => inflight.sigs.get(id));

    let tx;
    try {
      tx = buildRotationTx(dag, inflight.proposal, signer_node_ids, signatures);
    } catch (err) {
      log.error(`Rotation ${rotation_number}: tx build failed — ${err.message}`);
      return;
    }
    inflight.submittedAt = nowMs(); // set first to guard re-entrant double-submit; rolled back below on failure

    try {
      const r = submitTx(tx);
      if (r && typeof r.catch === "function") {
        r.catch(err => {
          log.warn(`Rotation ${rotation_number} submit rejected: ${(err && err.message) || err}`);
          inflight.submittedAt = null; // async reject: let the next retry re-submit (commit-handler dedups)
        });
      }
      log.info(`Rotation ${rotation_number}: submitted with ${signer_node_ids.length}/${inflight.prevCommittee.size} sigs (quorum=${required})`);
    } catch (err) {
      log.warn(`Rotation ${rotation_number} submitTx threw: ${(err && err.message) || err}`);
      inflight.submittedAt = null; // sync throw: same, so the wedge clears on the next retry not after pruneExpired
    }
    // NOTE: keep the re-broadcast timer running after submission. Peers may
    // still be below quorum (e.g., late-connecting node missed our initial
    // broadcast); they need the proposal + accumulated sigs to reach their
    // own quorum, build the same deterministic tx, and inject it into THEIR
    // mempool so they can carve out the rotation-only batch. Without this
    // post-submit re-broadcast, a fast submitter goes silent before the
    // first tick fires (REBROADCAST_INTERVAL_MS ≥ submit-latency under good
    // conditions), and lagging peers stay stuck below quorum forever — the
    // 2026-05-04 rotation 13 halt where n3+n4 submitted in 1.2 s but n1+n2
    // capped at 2/4 sigs and never carved out. pruneExpired drops the
    // submitted entry deadlineMs*2 later, which naturally bounds rebroadcast.
  }

  // ── Housekeeping ───────────────────────────────────────────────────────────
  /**
   * Drop in-flight aggregations past their deadline. Caller should invoke
   * this periodically (e.g., from bullshark anchor commit). Cheap: typically
   * 0–1 entries.
   */
  function pruneExpired() {
    const now = nowMs();
    for (const [rotation, inflight] of _inFlight) {
      if (inflight.submittedAt != null && now - inflight.submittedAt > deadlineMs * 2) {
        _inFlight.delete(rotation); // long-submitted; safe to forget
      } else if (inflight.submittedAt == null && now > inflight.deadline) {
        log.warn(`Rotation ${rotation}: aggregation timed out at ${inflight.sigs.size}/${inflight.prevCommittee.size} sigs (need ${computeQuorum(inflight.prevCommittee.size)}); dropping`);
        _inFlight.delete(rotation);
      }
    }
    if (_hasOpenInFlight() === false) _stopRebroadcast();
  }

  /**
   * Discard ALL in-flight aggregation state and stop the re-broadcast timer.
   * Must be called whenever a snapshot is installed: the snapshot may have
   * been built from a different DAG view than the in-flight proposal, so
   * payload_hashes diverge and proposals from peers are silently dropped.
   * Clearing here lets every node re-propose from a fresh, consistent DAG
   * after the snapshot settles.
   */
  function resetInflight() {
    _stopRebroadcast();
    _inFlight.clear();
    log.notice("rotation-coord: in-flight state cleared after snapshot install");
  }

  // Periodic re-broadcast of open inflights. Defends against gossipsub mesh
  // dropping bursty rotation-coord traffic — proposals + accumulated sigs
  // are re-sent every REBROADCAST_INTERVAL_MS until the rotation submits or
  // its deadline expires. Mirrors the per-batch retry loop in narwhal.
  let _rebroadcastTimer = null;

  function _hasOpenInFlight() {
    // "Open" = still in _inFlight at all. Submitted entries also count
    // because we keep rebroadcasting them post-submit so lagging peers can
    // catch up to quorum (see _maybeSubmit comment). pruneExpired removes
    // entries deadlineMs past their natural lifetime.
    return _inFlight.size > 0;
  }

  function _startRebroadcast() {
    if (_rebroadcastTimer) return;
    _rebroadcastTimer = safeSetInterval(_rebroadcastTick, CONSENSUS.ROTATION_COORD_REBROADCAST_INTERVAL_MS, "consensus.rotation.rebroadcast");
  }

  function _stopRebroadcast() {
    if (_rebroadcastTimer) { clearInterval(_rebroadcastTimer); _rebroadcastTimer = null; }
  }

  function _rebroadcastTick() {
    // Age out inflights on our own timer too: a node that carved out never
    // re-enters the producer-pause nudge, the only other prune trigger.
    pruneExpired();
    const now = nowMs();
    let anyAlive = false;
    for (const [rotation, inflight] of _inFlight) {
      // Keep broadcasting submitted entries too — peers below quorum still
      // need our proposal + sigs to reach their own quorum and carve out.
      // pruneExpired drops submitted entries deadlineMs*2 after submittedAt;
      // unsubmitted entries are bounded by deadline.
      if (inflight.submittedAt == null && now > inflight.deadline) continue;
      anyAlive = true;
      try {
        _broadcast(_encodeProposal(inflight.proposal));
        for (const [signer_node_id, sig] of inflight.sigs) {
          if (signer_node_id === inflight.proposal.proposer_node_id) continue;
          _broadcast(_encodeSignature(rotation, inflight.proposal.payload_hash, signer_node_id, sig));
        }
      } catch (err) {
        log.debug(`Rotation ${rotation}: re-broadcast failed — ${(err && err.message) || err}`);
      }
    }
    if (!anyAlive) _stopRebroadcast();
  }

  // libp2p direct-stream handler. One message per stream: the peer dials,
  // writes one length-prefixed buffer (proposal or signature), closes.
  // We read all bytes (libp2p chunks them as needed), pass to handleIncoming.
  let _protocolRegistered = false;
  async function _handleIncomingStream({ stream, connection }) {
    const remotePeerId = connection?.remotePeer?.toString?.() || "";
    try {
      const chunks = [];
      for await (const chunk of stream.source) {
        chunks.push(chunk.subarray());
      }
      if (chunks.length === 0) {
        log.debug(`rotation-coord stream from ${remotePeerId.slice(0, 12)}: empty payload`);
        return;
      }
      const buf = Buffer.concat(chunks);
      log.debug(`rotation-coord stream from ${remotePeerId.slice(0, 12)}: ${buf.length} bytes (chunks=${chunks.length})`);
      handleIncoming(buf, remotePeerId);
    } catch (err) {
      log.debug(`rotation-coord stream from ${remotePeerId.slice(0, 12)} failed: ${err.message}`);
    } finally {
      try { await stream.close(); } catch { /* ignore */ }
    }
  }

  async function registerProtocol() {
    if (_protocolRegistered) return;
    if (!network || typeof network.handle !== "function" || !network.ROTATION_COORD_PROTOCOL) return;
    await network.handle(network.ROTATION_COORD_PROTOCOL, _handleIncomingStream);
    if (network.ROTATION_REPAIR_PROTOCOL) {
      await network.handle(network.ROTATION_REPAIR_PROTOCOL, _handleRepairRequest);
    }
    _protocolRegistered = true;
    log.info(`rotation-coord protocol registered: ${network.ROTATION_COORD_PROTOCOL}`);
  }

  // ── Pull-repair ──────────────────────────────────────────────────────────────
  // A node below quorum recovers from a peer over the answer-direction (survives
  // a broken push): FETCH the assembled tx if a peer has it (F3), else pull the
  // peer's collected SIGNATURES to reach quorum and build the tx itself (F1).

  // Serve: reply with our mempool's rotation-N tx (or null), plus our collected
  // sigs when our inflight matches the requester's payload_hash.
  async function _handleRepairRequest({ stream, connection }) {
    const remotePeerId = connection?.remotePeer?.toString?.() || "";
    try {
      const chunks = [];
      for await (const chunk of stream.source) chunks.push(chunk.subarray ? chunk.subarray() : chunk);
      let req = null;
      try { req = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { req = null; }
      const rotation_number = req ? Number(req.rotation_number) : null;
      let tx = null;
      const sigs = [];
      if (rotation_number) {
        if (mempool && typeof mempool.peekRotationTx === "function") tx = mempool.peekRotationTx(rotation_number) || null;
        const inflight = _inFlight.get(rotation_number);
        if (inflight && req.payload_hash && inflight.proposal.payload_hash === req.payload_hash) {
          for (const [signer, sig] of inflight.sigs) sigs.push({ signer_node_id: signer, signature: sig });
        }
      }
      await stream.sink([Buffer.from(JSON.stringify({ rotation_number, tx, sigs }), "utf8")]);
    } catch (err) {
      log.debug(`rotation-repair serve from ${remotePeerId.slice(0, 12)} failed: ${err.message}`);
    } finally {
      try { await stream.close(); } catch { /* ignore */ }
    }
  }

  // Dial peers in turn. Accept a fetched tx (F3); otherwise merge a peer's sigs
  // into our inflight (F1) until we cross quorum and build the tx ourselves.
  let _repairInFlight = false;
  async function requestTxRepair() {
    if (_repairInFlight) return false;   // the pause nudge fires every ~1.5s; don't stack dial storms
    if (!network || typeof network.openStream !== "function" || !network.ROTATION_REPAIR_PROTOCOL) return false;
    // Fetch latest+1, NOT epochOf(round): rotations apply in order and that is
    // the tx peers hold. Mirrors the carve-out's min(latest+1, targetRotation).
    const latest = (typeof dag.getLatestRotation === "function") ? dag.getLatestRotation() : null;
    const rotation_number = (latest ? latest.rotation_number : 0) + 1;
    const existing = _inFlight.get(rotation_number);
    if (existing && existing.submittedAt != null) return false;   // we already built + submitted it
    _repairInFlight = true;
    try {
      const peers = (typeof network.peers === "function") ? network.peers() : [];
      const myHash = existing ? existing.proposal.payload_hash : null;
      const reqBody = Buffer.from(JSON.stringify({ rotation_number, payload_hash: myHash }), "utf8");
      for (const peerId of peers) {
        let stream;
        try { stream = await network.openStream(peerId, network.ROTATION_REPAIR_PROTOCOL); }
        catch (err) { log.debug(`rotation-repair: dial ${peerId.slice(0, 12)} failed: ${err.message}`); continue; }
        try {
          await stream.sink([reqBody]);
          const resp = await _readRepairResponse(stream);
          if (resp && resp.tx && _acceptRepairedTx(resp.tx, rotation_number)) {
            log.notice(`rotation-repair: fetched rotation ${rotation_number} tx from ${peerId.slice(0, 12)} -> mempool`);
            return true;
          }
          if (resp && Array.isArray(resp.sigs) && resp.sigs.length && myHash) {
            for (const s of resp.sigs) _mergePulledSig(rotation_number, myHash, s.signer_node_id, s.signature);
            if (_inFlight.get(rotation_number)?.submittedAt != null) {
              log.notice(`rotation-repair: reached quorum via pulled sigs from ${peerId.slice(0, 12)} -> rotation ${rotation_number} submitted`);
              return true;
            }
          }
        } catch (err) {
          log.debug(`rotation-repair: request to ${peerId.slice(0, 12)} failed: ${err.message}`);
        } finally {
          try { await stream.close(); } catch { /* ignore */ }
        }
      }
      return false;
    } finally {
      _repairInFlight = false;
    }
  }

  // F1: merge a peer's pulled signature into our inflight (same checks as
  // _onSignature, but from a hex sig). Crossing quorum triggers _maybeSubmit.
  function _mergePulledSig(rotation_number, payload_hash, signer_node_id, signatureHex) {
    const inflight = _inFlight.get(rotation_number);
    if (!inflight || inflight.submittedAt != null) return;
    if (inflight.proposal.payload_hash !== payload_hash) return;
    if (!signer_node_id || !inflight.prevCommittee.has(signer_node_id) || inflight.sigs.has(signer_node_id)) return;
    const pubkey = inflight.prevPubkeys.get(signer_node_id);
    let ok = false;
    try { ok = pubkey && mldsaVerify(`rotation:${payload_hash}:${signer_node_id}`, signatureHex, pubkey); }
    catch { ok = false; }
    if (!ok) return;
    inflight.sigs.set(signer_node_id, signatureHex);
    _maybeSubmit(rotation_number);
  }

  async function _readRepairResponse(stream) {
    const maxBytes = CONSENSUS.ROTATION_REPAIR_MAX_RESPONSE_BYTES;
    const timeoutMs = CONSENSUS.ROTATION_REPAIR_TIMEOUT_MS;
    const readPromise = (async () => {
      const chunks = [];
      let total = 0;
      for await (const chunk of stream.source) {
        const c = chunk.subarray ? chunk.subarray() : chunk;
        total += c.length;
        if (total > maxBytes) throw new Error(`repair response exceeded ${maxBytes} bytes`);
        chunks.push(c);
      }
      return chunks;
    })();
    let timer;
    const timeout = new Promise((_resolve, reject) => {
      timer = setTimeout(() => { try { stream.close(); } catch { /* ignore */ } reject(new Error(`repair timeout ${timeoutMs}ms`)); }, timeoutMs);
    });
    let chunks;
    try { chunks = await Promise.race([readPromise, timeout]); }
    finally { clearTimeout(timer); }
    if (!chunks.length) return null;
    try { return JSON.parse(Buffer.concat(chunks).toString("utf8")) || null; }
    catch { return null; }
  }

  // Rebuild LOCALLY for a deterministic tx_id (the peer's timestamp/tx_id are
  // not covered by the sigs). Accept only with >= quorum valid prev-committee
  // sigs over a payload_hash that binds the committee.
  function _acceptRepairedTx(receivedTx, expectedRotation) {
    const d = receivedTx && receivedTx.data;
    if (!receivedTx || receivedTx.tx_type !== TX_TYPES.COMMITTEE_ROTATION || !d) return false;
    if (Number(d.rotation_number) !== Number(expectedRotation)) return false;

    const latest = (typeof dag.getLatestRotation === "function") ? dag.getLatestRotation() : null;
    const expectedNext = latest ? latest.rotation_number + 1 : 1;
    if (Number(d.rotation_number) !== expectedNext) return false;

    const recomputed = shake256(canonicalJson({
      rotation_number: d.rotation_number, effective_round: d.effective_round, committee: d.new_committee,
    }));
    if (recomputed !== d.payload_hash) return false;

    const prevCommittee = Array.isArray(latest?.committee) ? latest.committee : [];
    const prevPubkeys = new Map(prevCommittee.map(m => [m.node_id, m.public_key]));
    const required = computeQuorum(prevCommittee.length);
    const valid = new Map();
    for (const c of (Array.isArray(d.cosignatures) ? d.cosignatures : [])) {
      const signer = c.signer_ref;
      if (!signer || valid.has(signer) || !prevPubkeys.has(signer)) continue;
      let okSig = false;
      try { okSig = mldsaVerify(`rotation:${d.payload_hash}:${signer}`, c.signature, prevPubkeys.get(signer)); }
      catch { okSig = false; }   // malformed signature bytes from an untrusted peer
      if (okSig) valid.set(signer, c.signature);
    }
    if (valid.size < required) return false;

    const signer_node_ids = [...valid.keys()].sort();
    const signatures = signer_node_ids.map(id => valid.get(id));
    let tx;
    try {
      tx = buildRotationTx(dag, {
        rotation_number: d.rotation_number, effective_round: d.effective_round,
        new_committee: d.new_committee, payload_hash: d.payload_hash,
      }, signer_node_ids, signatures);
    } catch (err) {
      log.debug(`rotation-repair: rebuild failed: ${err.message}`);
      return false;
    }
    try {
      const r = submitTx(tx);
      if (r && typeof r.catch === "function") r.catch(() => { });
      // Suppress a redundant self-submit if our own aggregation later reaches
      // quorum: the injected tx is canonical and already in the mempool.
      const inflight = _inFlight.get(d.rotation_number);
      if (inflight && inflight.submittedAt == null) inflight.submittedAt = nowMs();
      return true;
    } catch (err) {
      log.debug(`rotation-repair: submit of fetched tx failed: ${err.message}`);
      return false;
    }
  }

  function stop() {
    _stopRebroadcast();
  }

  /**
   * Public dedup signal for upstream callers (bullshark.tryRotationProposal).
   * Returns true if a proposal for `rotation_number` is currently being
   * aggregated OR has been submitted recently (within deadlineMs). In
   * those cases the upstream caller should NOT force a fresh proposal
   * — the existing one is in flight.
   *
   * Returns false if there's no inflight at all OR if the existing
   * inflight is older than deadlineMs (likely stale/lost — re-proposal
   * is justified).
   */
  function hasOpenInflight(rotation_number) {
    const inflight = _inFlight.get(rotation_number);
    if (!inflight) return false;
    if (inflight.submittedAt == null) return true;          // still aggregating
    return nowMs() - inflight.submittedAt < deadlineMs;  // submitted, awaiting commit
  }

  return {
    proposeRotation,
    handleIncoming,
    registerProtocol,
    pruneExpired,
    resetInflight,
    hasOpenInflight,
    requestTxRepair,
    stop,
    // Test-only introspection.
    _state: () => _inFlight,
    _rebroadcastTick: () => _rebroadcastTick(),
    _handleRepairRequest: (args) => _handleRepairRequest(args),
    _acceptRepairedTx: (tx, rotation_number) => _acceptRepairedTx(tx, rotation_number),
    _mergePulledSig: (rn, ph, signer, sigHex) => _mergePulledSig(rn, ph, signer, sigHex),
  };
}

module.exports = { createRotationCoordinator, buildRotationTx };
