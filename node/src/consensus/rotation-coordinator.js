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

const { mldsaSign, mldsaVerify, computeTxId } = require("../../../shared/crypto");
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
      signer_ref:  signer_node_ids[i],
      signature:   signatures[i],
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

    if (existing) {
      // Retry path — preserve accumulated sigs across bullshark's
      // per-anchor proposeRotation calls. Resetting inflight here would
      // throw away peer sigs that arrived between retries.
      _broadcast(_encodeProposal(existing.proposal));
      log.debug(`Rotation ${rotation_number}: re-broadcast proposal (sigs ${existing.sigs.size}/${existing.prevCommittee.size})`);
      _maybeSubmit(rotation_number);
      return true;
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
    return proto.encode("RotationProposal", {
      rotationNumber: p.rotation_number,
      effectiveRound: p.effective_round,
      newCommittee: p.new_committee.map(m => ({ nodeId: m.node_id, publicKey: m.public_key })),
      payloadHash: p.payload_hash,
      proposerNodeId: p.proposer_node_id,
      proposerSignature: hexToBytes(p.proposer_signature),
    });
  }

  function _encodeSignature(rotation_number, payload_hash, signer_node_id, signature) {
    return proto.encode("RotationSignature", {
      rotationNumber: rotation_number,
      payloadHash: payload_hash,
      signerNodeId: signer_node_id,
      signature: hexToBytes(signature),
    });
  }

  // ── Receiver side ──────────────────────────────────────────────────────────
  /**
   * Dispatched from network.js when a message lands on the
   * `tip/rotation-coordination` topic. Auto-detects whether the message is
   * a `RotationProposal` or `RotationSignature` by trying decode in order.
   * Failure on both = malformed; logged at debug + dropped.
   */
  function handleIncoming(buf, peerId) {
    let proposal = null, signature = null, propErr = null, sigErr = null;
    try { proposal = proto.decode("RotationProposal", buf); }
    catch (e) { propErr = e.message; }
    if (proposal && proposal.rotationNumber != null && proposal.payloadHash) {
      _onProposal(proposal);
      return;
    }
    try { signature = proto.decode("RotationSignature", buf); }
    catch (e) { sigErr = e.message; }
    if (signature && signature.rotationNumber != null && signature.payloadHash && signature.signerNodeId) {
      _onSignature(signature);
      return;
    }
    log.debug(
      `Unrecognized rotation-coordination message from ${peerId?.slice(0, 12)} ` +
      `(${buf.length} bytes; propThrew=${propErr ? propErr.slice(0, 60) : "no"}; ` +
      `sigThrew=${sigErr ? sigErr.slice(0, 60) : "no"}; ` +
      `propRn=${proposal?.rotationNumber}, propPh=${(proposal?.payloadHash || "").slice(0, 8)}, propPn=${(proposal?.proposerNodeId || "").slice(0, 12)}; ` +
      `sigRn=${signature?.rotationNumber}, sigPh=${(signature?.payloadHash || "").slice(0, 8)}, sigSn=${(signature?.signerNodeId || "").slice(0, 12)})`
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
    inflight.submittedAt = nowMs();

    try {
      const r = submitTx(tx);
      if (r && typeof r.catch === "function") {
        r.catch(err => log.warn(`Rotation ${rotation_number} submit rejected: ${(err && err.message) || err}`));
      }
      log.info(`Rotation ${rotation_number}: submitted with ${signer_node_ids.length}/${inflight.prevCommittee.size} sigs (quorum=${required})`);
    } catch (err) {
      log.warn(`Rotation ${rotation_number} submitTx threw: ${(err && err.message) || err}`);
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
    _rebroadcastTimer = setInterval(_rebroadcastTick, CONSENSUS.ROTATION_COORD_REBROADCAST_INTERVAL_MS);
  }

  function _stopRebroadcast() {
    if (_rebroadcastTimer) { clearInterval(_rebroadcastTimer); _rebroadcastTimer = null; }
  }

  function _rebroadcastTick() {
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
    _protocolRegistered = true;
    log.info(`rotation-coord protocol registered: ${network.ROTATION_COORD_PROTOCOL}`);
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
    stop,
    // Test-only introspection.
    _state: () => _inFlight,
    _rebroadcastTick: () => _rebroadcastTick(),
  };
}

module.exports = { createRotationCoordinator, buildRotationTx };
