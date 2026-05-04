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

const { mldsaSign, mldsaVerify, computeTxId } = require("../../../shared/crypto");
const { TX_TYPES } = require("../../../shared/constants");
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
 * @param {object} dag      — needed for `getRecentPrev()`
 * @param {object} proposal — { rotation_number, effective_round, new_committee, payload_hash }
 * @param {string[]} signer_node_ids   — sorted ASC
 * @param {string[]} signatures        — parallel to signer_node_ids
 * @returns {object} tx with tx_id computed
 */
function buildRotationTx(dag, proposal, signer_node_ids, signatures) {
  const data = {
    rotation_number: proposal.rotation_number,
    effective_round: proposal.effective_round,
    new_committee: proposal.new_committee,
    payload_hash: proposal.payload_hash,
    signer_node_ids,
    signatures,
  };
  const tx = {
    tx_type: TX_TYPES.COMMITTEE_ROTATION,
    timestamp: new Date().toISOString(),
    prev: dag.getRecentPrev ? dag.getRecentPrev() : [],
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
function createRotationCoordinator({ dag, network, proto, identity, submitTx, deadlineMs = 30_000 }) {
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

  function _topic() { return network.TOPICS && network.TOPICS.ROTATION_COORDINATION; }

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
    if (_inFlight.has(rotation_number) && _inFlight.get(rotation_number).submittedAt != null) {
      // Already submitted — proposer hop reattempt is a no-op.
      return false;
    }
    const message = `rotation:${payload_hash}:${identity.nodeId}`;
    const proposerSig = mldsaSign(message, identity.privateKey);

    const sigs = new Map();
    sigs.set(identity.nodeId, proposerSig);

    _inFlight.set(rotation_number, {
      proposal: { rotation_number, effective_round, new_committee, payload_hash, proposer_node_id: identity.nodeId, proposer_signature: proposerSig },
      sigs,
      prevCommittee: new Set(prevCommitteeNodeIds),
      prevPubkeys: new Map(Object.entries(prevPubkeys || {})),
      submittedAt: null,
      deadline: Date.now() + deadlineMs,
    });

    const buf = proto.encode("RotationProposal", {
      rotationNumber: rotation_number,
      effectiveRound: effective_round,
      newCommittee: new_committee.map(m => ({ nodeId: m.node_id, publicKey: m.public_key })),
      payloadHash: payload_hash,
      proposerNodeId: identity.nodeId,
      proposerSignature: hexToBytes(proposerSig),
    });
    network.publish(_topic(), buf);
    log.info(`Rotation ${rotation_number} proposal broadcast (proposer=${identity.nodeId.slice(-12)}, prevCommitteeSize=${prevCommitteeNodeIds.length}, quorum=${computeQuorum(prevCommitteeNodeIds.length)})`);

    // Self-aggregate immediately — solo committees (n=1) reach quorum from
    // the proposer's own signature without any peer round-trip. Otherwise
    // this is a no-op until peer signatures arrive.
    _maybeSubmit(rotation_number);
    return true;
  }

  // ── Receiver side ──────────────────────────────────────────────────────────
  /**
   * Dispatched from network.js when a message lands on the
   * `tip/rotation-coordination` topic. Auto-detects whether the message is
   * a `RotationProposal` or `RotationSignature` by trying decode in order.
   * Failure on both = malformed; logged at debug + dropped.
   */
  function handleIncoming(buf, peerId) {
    let proposal = null;
    let signature = null;
    try { proposal = proto.decode("RotationProposal", buf); } catch { /* not a proposal */ }
    if (proposal && proposal.rotationNumber != null && proposal.payloadHash) {
      _onProposal(proposal);
      return;
    }
    try { signature = proto.decode("RotationSignature", buf); } catch { /* not a signature */ }
    if (signature && signature.rotationNumber != null && signature.payloadHash && signature.signerNodeId) {
      _onSignature(signature);
      return;
    }
    log.debug(`Unrecognized rotation-coordination message from ${peerId?.slice(0, 12)}`);
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

    // Seed in-flight if first sighting.
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
        deadline: Date.now() + deadlineMs,
      });
    }

    // Sign + broadcast our own RotationSignature if we're in the previous
    // committee. Otherwise observe-only.
    if (!prevPubkeys.has(identity.nodeId)) return;
    if (_inFlight.get(rotation_number).sigs.has(identity.nodeId)) return; // already signed

    const ourMsg = `rotation:${payload_hash}:${identity.nodeId}`;
    const ourSig = mldsaSign(ourMsg, identity.privateKey);
    _inFlight.get(rotation_number).sigs.set(identity.nodeId, ourSig);

    const sigBuf = proto.encode("RotationSignature", {
      rotationNumber: rotation_number,
      payloadHash: payload_hash,
      signerNodeId: identity.nodeId,
      signature: hexToBytes(ourSig),
    });
    network.publish(_topic(), sigBuf);
    log.debug(`Rotation ${rotation_number}: signed proposal as ${identity.nodeId.slice(-12)}`);

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

    // Only the proposer aggregates+submits. Other prev-committee members
    // store sigs locally for fallback (if proposer goes offline, deadline
    // expiry triggers retry from a different node on next anchor).
    if (inflight.proposal.proposer_node_id !== identity.nodeId) return;

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
    inflight.submittedAt = Date.now();

    try {
      const r = submitTx(tx);
      if (r && typeof r.catch === "function") {
        r.catch(err => log.warn(`Rotation ${rotation_number} submit rejected: ${(err && err.message) || err}`));
      }
      log.info(`Rotation ${rotation_number}: submitted with ${signer_node_ids.length}/${inflight.prevCommittee.size} sigs (quorum=${required})`);
    } catch (err) {
      log.warn(`Rotation ${rotation_number} submitTx threw: ${(err && err.message) || err}`);
    }
  }

  // ── Housekeeping ───────────────────────────────────────────────────────────
  /**
   * Drop in-flight aggregations past their deadline. Caller should invoke
   * this periodically (e.g., from bullshark anchor commit). Cheap: typically
   * 0–1 entries.
   */
  function pruneExpired() {
    const now = Date.now();
    for (const [rotation, inflight] of _inFlight) {
      if (inflight.submittedAt != null && now - inflight.submittedAt > deadlineMs * 2) {
        _inFlight.delete(rotation); // long-submitted; safe to forget
      } else if (inflight.submittedAt == null && now > inflight.deadline) {
        log.warn(`Rotation ${rotation}: aggregation timed out at ${inflight.sigs.size}/${inflight.prevCommittee.size} sigs (need ${computeQuorum(inflight.prevCommittee.size)}); dropping`);
        _inFlight.delete(rotation);
      }
    }
  }

  return {
    proposeRotation,
    handleIncoming,
    pruneExpired,
    // Test-only introspection.
    _state: () => _inFlight,
  };
}

module.exports = { createRotationCoordinator, buildRotationTx };
