/**
 * @file @tip-protocol/node/src/consensus/narwhal.js
 * @description Narwhal data availability layer for TIP consensus.
 *
 * Continuous-production design (reference Narwhal-faithful):
 *   - While running, every round produces a batch + cert (empty ok), no idle
 *   - Chain is always extended so late-arriving peer certs can self-heal
 *   - CertificateWaiter parks peer certs whose parents are missing in our DAG
 *     and reprocesses them once the parents land
 *
 * Each round:
 *   1. Drain txs from mempool → create Batch → broadcast on MEMPOOL topic
 *   2. Receive batches from peers → send BatchAck on CONSENSUS topic
 *   3. Collect 2/3+ BatchAcks → create Certificate → broadcast on CERTIFICATES topic
 *   4. Collect 2/3+ Certificates → advance to next round → notify Bullshark
 *   5. Immediately begin next round after a short inter-round delay
 *
 * Message routing:
 *   MEMPOOL topic     → Batch messages
 *   CONSENSUS topic   → BatchAck messages
 *   CERTIFICATES topic → Certificate messages
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");
const {
  createBatch, verifyBatch,
  createBatchAck, verifyBatchAck,
  createCertificate, verifyCertificate,
  computeQuorum, bftHaltThreshold,
} = require("./certificate");
const {
  serializeBatch, deserializeBatch,
  serializeCertificate, deserializeCertificate,
} = require("./certificate-codec");
const { encode, decode, bytesToHex, hexToBytes } = require("../network/proto");
const { epochOf } = require("./participants");
const { getLogger } = require("../logger");

const log = getLogger("tip.narwhal");

// #64: rate-limit the late-batch ack WARN. ~60 rounds ≈ 1 minute at the
// default 1s round budget — short enough that a sustained pathology
// (mis-sized horizon, persistently lagging peer) is still visible
// within a few minutes, long enough that warm-up doesn't flood.
const LATE_BATCH_LOG_INTERVAL_ROUNDS = 60;

/**
 * Create the Narwhal data availability layer.
 *
 * @param {Object} options
 * @param {Object} options.dag            DAG store (for persisting certificates)
 * @param {Object} options.mempool        Mempool instance
 * @param {Object} options.network        libp2p network node
 * @param {Object} options.config         Node config (nodeId, keys, etc.)
 * @param {Function} options.getNodeKey   (nodeId) => publicKey from node registry
 * @param {Function} options.getNodeCount () => total registered node count
 * @param {Function} options.onCommit     (certificates, round) => called when round commits
 * @returns {Object} Narwhal instance
 */
function createNarwhal({ dag, mempool, network, config, getNodeKey, getNodeCount, getCommittee, onCommit, onCertSaved, onProducerPaused, isPeerDivergent, peerJoinState, divergentPeers }) {
  const _getCommittee = typeof getCommittee === "function" ? getCommittee : () => [];
  const _onCertSaved = typeof onCertSaved === "function" ? onCertSaved : () => { };
  const _onProducerPaused = typeof onProducerPaused === "function" ? onProducerPaused : null;
  // Rate-limit the producer-pause notify. _beginRound retries every 50ms
  // while paused; the upstream consumer (bullshark rotation proposer)
  // doesn't need that frequency. 1.5s matches the rotation-coord
  // re-broadcast cadence so each cycle gets one fresh proposal attempt.
  let _lastProducerPausedAt = 0;
  let _currentRound;
  try { _currentRound = dag.getLatestRound() + 1; } catch { _currentRound = 1; }
  let _running = false;

  // Tri-state join FSM.
  //   syncing      — installing snapshot; no reception, no production.
  //   catching_up  — snapshot verified, pulling cert tail; receives + parks
  //                  consensus messages but does NOT produce certs.
  //   ready        — caught up + state-root matches 2f+1; cert production on.
  // External callers transition via markSnapshotInstalled / markCaughtUp.
  let _joinState = "ready";
  // Wall-clock when we entered syncing / catching_up. Sticky on repeat
  // entries; cleared on exit. The watchdog and halt detector both read
  // these to bound how long we can sit in a non-ready state.
  let _syncEnteredAt = 0;
  let _catchingUpEnteredAt = 0;
  // Peer's committed_round at snapshot-install time — the round the cert
  // tail must reach before catching_up can promote to ready. Anti-entropy
  // reads this to decide "is the tail closed?".
  let _catchUpTarget = 0;
  let _roundTimer = null;                           // per-round liveness timeout
  let _retryTimer = null;                           // retry while stuck below quorum
  // Counts every retry tick (round-timer expiry + each _scheduleRetry fire).
  // Drives two self-healing tiers: mesh re-graft at 3, direct-stream bypass at 6+.
  // Reset to 0 on every round advance so tiers are per-stuck-round, not cumulative.
  let _retryCount = 0;
  let _nextRoundTimer = null;                       // inter-round scheduler

  // Per-round state
  let _myBatch = null;
  const _peerBatches = new Map();                   // nodeId → batch
  const _batchAcks = new Map();                     // batchHash → [ack, ack, ...]
  const _roundCertificates = new Map();             // nodeId → certificate
  let _myCertificateCreated = false;

  // CertificateWaiter: peer certs whose parent hashes aren't in our DAG yet.
  // Parked on receive, reprocessed when the missing parent lands. Guarantees
  // no peer cert is silently dropped for arriving before its parents.
  const _pendingCerts = new Map();                  // certHash → { cert, missing: Set<parentHash> }
  const _pendingByParent = new Map();               // parentHash → Set<certHash>

  // #64: per-peer rate limiter for the late-batch ack WARN log. During
  // warm-up (quorum=1, no peers) every round advances faster than gossip
  // RTT, so every batch arrives "late" and the WARN floods one-per-round
  // per peer. We keep the metric per-batch but log only at first sighting
  // and every LATE_BATCH_LOG_INTERVAL_ROUNDS rounds thereafter, with a
  // running count of suppressed warns.
  const _lateBatchAckTracker = new Map();           // authorId → { count, lastLoggedRound }

  // Consensus counters — read by stats() for /v1/stats and periodic summary.
  // These are cumulative for the lifetime of the process; a supervisor can
  // compute deltas across snapshots for rate/throughput.
  const _metrics = {
    batches_created: 0,
    batches_received: 0,
    acks_received: 0,
    certs_created: 0,
    certs_received: 0,
    certs_parked: 0,
    certs_unblocked: 0,
    rounds_advanced: 0,
    fast_forwards: 0,
    retries: 0,
    equivocation_refused: 0,  // §1: count of refused double-attestations
    // #64: late-batch handling. Counts batches arriving after our round
    // has advanced past their batch.round but still within the bounded
    // look-back window (VOTES_RETENTION_ROUNDS). Pre-fix these were
    // silently dropped — losing peer txs whenever local round outran
    // gossip delivery by ≥1 round. Post-fix they're ack'd normally.
    batches_acked_late: 0,
    // #64: batches arriving from beyond the look-back horizon. These
    // ARE refused — equivocation defense table is pruned beyond the
    // horizon, so we can't safely ack. Sustained ticks mean either a
    // misbehaving peer is replaying very old batches or the horizon
    // is undersized for the deployment's jitter profile.
    batches_rejected_too_old: 0,
    // #64: count of rounds where _myBatch was discarded uncertified at
    // round advance. The txs are requeued to mempool by _resetRoundState
    // and re-attempted at the next round, so this is delay-not-loss —
    // but a sustained tick means this node is consistently failing to
    // get quorum on its own batches (lagging, partitioned, or under-
    // weighted in committee).
    my_batches_orphaned: 0,
  };

  // Wall-clock timestamp of the last successful round advance. Used by
  // the consensus-halt gate: if no rounds advance within the stuck-
  // threshold window (N × ROUND_TIMEOUT_MS) while we're supposed to be
  // running, the network is sub-quorum — writes get 503'd and /health
  // reports degraded status. Initialised to start() time so we don't
  // false-positive during the grace period before the first round lands.
  let _lastRoundAdvanceAt = 0;

  // Committee is derived deterministically from the DAG via getCommittee(),
  // not tracked locally. Every node reading the same DAG sees the same
  // committee, eliminating the handshake-history divergence class of bugs.

  const nodeId = config.nodeRegisteredId || config.nodeId;
  const privateKey = config.nodePrivateKey;

  // ── Lifecycle ────────────────────────────────────────────────────────────

  /**
   * Start the Narwhal consensus layer. Begins continuous round production
   * unless join state is "syncing" (in which case the first round will be
   * kicked off by exitSyncMode()).
   */
  function start() {
    if (_running) return;
    _running = true;
    // Grace period for the halt detector — without this, a freshly-booted
    // node would report "halted" for the first few seconds before any
    // round completes.
    _lastRoundAdvanceAt = Date.now();

    log.notice(`Narwhal started at round ${_currentRound} (committee: ${_getCommittee().length}, registered: ${getNodeCount()}, quorum: ${_getQuorum()})`);

    if (_joinState === "ready") _scheduleNextRound(0);
  }

  /**
   * Stop the Narwhal consensus layer.
   */
  function stop() {
    _running = false;
    _clearAllTimers();
    log.notice("Narwhal stopped");
  }

  /**
   * Get current round number.
   */
  function currentRound() {
    return _currentRound;
  }

  function _clearAllTimers() {
    if (_roundTimer) { clearTimeout(_roundTimer); _roundTimer = null; }
    if (_retryTimer) { clearTimeout(_retryTimer); _retryTimer = null; }
    if (_nextRoundTimer) { clearTimeout(_nextRoundTimer); _nextRoundTimer = null; }
    if (_watchdogTimer) { clearInterval(_watchdogTimer); _watchdogTimer = null; }
  }

  /**
   * Schedule the next _beginRound() call. Replaces any currently pending
   * next-round timer. Called from start, _tryAdvanceRound, and exitSyncMode.
   */
  function _scheduleNextRound(delayMs) {
    if (!_running) return;
    if (_nextRoundTimer) { clearTimeout(_nextRoundTimer); _nextRoundTimer = null; }
    _nextRoundTimer = setTimeout(() => {
      _nextRoundTimer = null;
      _beginRound();
    }, delayMs);
  }

  // ── Round lifecycle ──────────────────────────────────────────────────────

  // Byzantine-fork halt: anti-entropy detected persistent same-round
  // state_merkle_root divergence with ≥1 peer. Stay halted until operator
  // clears the flag manually (after forensic investigation + manual rejoin).
  // Auto-resolution would silently mask a real safety-violation event.
  let _byzantineForkHalt = null;  // { reason, atRound, peerNodeId, since }

  function haltDueToByzantineFork({ reason, atRound, peerNodeId } = {}) {
    if (_byzantineForkHalt) return; // already halted; first signal wins
    _byzantineForkHalt = {
      reason: reason || "unspecified byzantine-fork divergence",
      atRound: atRound != null ? atRound : _currentRound,
      peerNodeId: peerNodeId || "unknown",
      since: Date.now(),
    };
    log.error(`HALT (byzantine_fork): ${_byzantineForkHalt.reason}`);
  }

  function clearByzantineForkHalt() {
    if (!_byzantineForkHalt) return;
    log.notice(`Cleared byzantine_fork halt (was: ${_byzantineForkHalt.reason})`);
    _byzantineForkHalt = null;
  }

  function _canProduce() {
    return _running && _joinState === "ready" && !_byzantineForkHalt;
  }

  function _beginRound() {
    if (!_canProduce()) return;

    // #75 atomic boundary — producer-pause. Don't seal a cert at round R
    // until we have the rotation that R's epoch needs in our local
    // committee_history. Without this gate, a node whose commit-handler
    // hasn't yet applied the latest rotation tx would produce certs under
    // stale committee assumptions, causing peer-validation halts (the
    // 2026-05-03 round-202 halt). The rotation tx is being applied to
    // committee_history right now (or imminently); reschedule shortly.
    //
    // If the rotation isn't being produced (deadlock: no anchor commits
    // → bullshark never retries proposeRotation), the rate-limited
    // onProducerPaused callback nudges bullshark to attempt a proposal.
    // Three layers prevent over-firing: rate-limit here, DAG re-check on
    // bullshark's side, and rotation-coordinator's per-rotation inflight
    // dedup. Without the nudge the federation sits halted indefinitely.
    const targetRotation = epochOf(_currentRound);
    let _carveOutRotationTx = null;
    if (targetRotation > 0 && typeof dag.getCommitteeRotation === "function"
      && !dag.getCommitteeRotation(targetRotation)) {
      // Carve-out: if the missing rotation's tx is sitting in our local
      // mempool, drain ONLY that tx and produce a rotation-only batch.
      // Cert validation by peers at this boundary still uses the previous
      // committee (rotation N takes effect FOR FUTURE rounds; the cert at
      // round R = N×epoch_length is signed/ack'd by N-1's committee).
      // Acking peers don't need to leave producer-pause — only ONE node
      // needs to drain the rotation tx for the cert to form. Without this
      // carve-out the federation deadlocks when the rotation tx lands in
      // mempool but no node can drain it (everyone paused).
      _carveOutRotationTx = typeof mempool.peekRotationTx === "function"
        ? mempool.peekRotationTx(targetRotation) : null;
      if (!_carveOutRotationTx) {
        log.debug(`Round ${_currentRound}: pausing production — rotation ${targetRotation} not in local committee_history (atomic boundary)`);
        if (_onProducerPaused) {
          const now = Date.now();
          if (now - _lastProducerPausedAt > 1500) {
            _lastProducerPausedAt = now;
            try { _onProducerPaused(_currentRound, targetRotation); }
            catch (err) { log.warn(`onProducerPaused threw: ${err.message}`); }
          }
        }
        // Brief reschedule. The onProducerPaused callback nudges
        // bullshark to attempt a rotation proposal; once that lands a
        // tx in mempool, the carve-out above will fire on the next
        // _beginRound and unblock the federation.
        _scheduleNextRound(50);
        return;
      }
      log.notice(`Round ${_currentRound}: producer-pause carve-out — producing rotation-only batch for rotation ${targetRotation}`);
    }

    _resetRoundState();

    // Phase 1: Create batch from mempool and broadcast.
    // Carve-out path: only the rotation tx; normal path: drain everything.
    //
    // Carve-out does NOT drain the rotation tx from mempool. The rotation
    // tx must keep re-carving on every round until bullshark anchor-commit
    // applies it to committee_history through the normal pipeline (commit-
    // handler → transactions/committee_history/commits/mempool delete in
    // one transaction). Without this, each node carves exactly once and
    // then producer-pauses again with an empty mempool — federation halts
    // because anchor-commit at round R needs 2f+1 certs at R+2, but every
    // node has only one cert at the boundary epoch then nothing.
    // Live observed 2026-05-04 rotation-13 deadlock: 3 carve-outs at 2600,
    // 1 at 2601, 0 at 2602 → anchor-commit at 2600 impossible.
    // commit-handler dedups duplicate rotation txs ("rotation_number N
    // already exists") so re-carving across rounds is safe; the eventual
    // anchor commit removes the tx via deleteMempoolTxs and subsequent
    // rounds skip the carve branch entirely (rotation in CH).
    let txs;
    if (_carveOutRotationTx) {
      txs = [_carveOutRotationTx];
    } else {
      txs = mempool.drain(CONSENSUS.MAX_TXS_PER_CERTIFICATE);
    }

    _myBatch = createBatch(_currentRound, nodeId, txs, privateKey);
    _peerBatches.set(nodeId, _myBatch);

    // Broadcast batch on MEMPOOL topic (separate from certificates)
    try {
      const batchBuf = encode("Batch", serializeBatch(_myBatch));
      network.publish(network.TOPICS.MEMPOOL, batchBuf);
    } catch (err) {
      log.error(`Round ${_currentRound}: failed to broadcast batch: ${err.message}`);
    }

    if (txs.length > 0) {
      // Only this branch is operator-relevant (real txs hit a round).
      log.info(`Round ${_currentRound}: batch created with ${txs.length} txs`);
    } else {
      log.debug(`Round ${_currentRound}: empty batch (vote round)`);
    }
    _metrics.batches_created++;

    // Self-ack our own batch. signed_at is bound into the ack signature
    // (BFT Time) — every ack from every node carries the acker's wall-clock
    // at sign time. The cert author later derives cert.timestamp as the
    // median of all 2f+1 signed_at values.
    _recordAck(_myBatch.hash, createBatchAck(_myBatch.hash, nodeId, Date.now(), privateKey));

    // Try certificate immediately (works in single-node mode where quorum=1)
    // In single-node, this will create cert + advance round synchronously.
    const roundBeforeTry = _currentRound;
    _tryCreateCertificate();

    // Only set the timeout if the round hasn't already advanced.
    // In single-node, _tryCreateCertificate → _tryAdvanceRound fires synchronously,
    // so _currentRound is already incremented. Setting a timer here would fire on
    // stale state and cause spurious round advances.
    if (_currentRound === roundBeforeTry) {
      _roundTimer = setTimeout(() => {
        _roundTimer = null;
        if (!_running) return;

        if (!_myCertificateCreated) {
          log.debug(`Round ${_currentRound}: timeout — attempting certificate with ${(_batchAcks.get(_myBatch?.hash) || []).length} acks`);
          _tryCreateCertificate();
        }
        _tryAdvanceRound();

        // If still stuck, enter the retry loop.
        // We count the round-timer expiry as tick 1 so that _retryCount in
        // _scheduleRetry() stays aligned with wall-clock multiples of
        // ROUND_TIMEOUT_MS — Layer 1 fires at exactly 3× (~6s stuck),
        // Layer 2 at 6× (~12s stuck).
        if (_running && _roundCertificates.size < _getQuorum()) {
          _retryCount++;
          _scheduleRetry();
        }
      }, CONSENSUS.ROUND_TIMEOUT_MS);
    }
  }

  /**
   * Periodic retry when the round is stuck below quorum.
   *
   * Three escalating tiers, each separated by ROUND_TIMEOUT_MS (~2s):
   *   ticks 1-2  gossipsub re-broadcast only (existing behavior, best-effort)
   *   tick  3    Layer 1 — mesh re-graft: remove+re-add each non-acking peer
   *              from pubsub.direct so gossipsub heals the directed edge on its
   *              next heartbeat (~700ms). Root cause of the directed-delivery
   *              failure we saw in the field (stale mesh after reconnection).
   *   tick  6+   Layer 2 — direct libp2p stream: open /tip/consensus-ack/1.0.0
   *              to each non-acking peer and push the batch payload, bypassing
   *              gossipsub entirely. Fires only if mesh re-graft didn't recover
   *              quorum within 3 more cycles (~6s after Layer 1).
   */
  function _scheduleRetry() {
    if (_retryTimer || !_running) return;
    _retryTimer = setTimeout(() => {
      _retryTimer = null;
      if (!_running) return;

      _metrics.retries++;
      _retryCount++;

      // GossipSub is best-effort — a dropped batch or cert means this round
      // can never reach quorum. On each retry, re-broadcast whatever we
      // already have so peers that missed the original publish can still
      // collect it. Receivers dedup on message hash, so re-publishing to
      // peers that already got the message is a no-op.
      _rebroadcastOwnBatch();
      _rebroadcastOwnCertificate();

      // Layer 1 (retry 3): force-regraft gossipsub mesh edges for non-acking peers.
      // Removes + re-adds them from pubsub.direct; gossipsub re-grafts on next
      // heartbeat (~700ms). Clears directed delivery failures caused by stale mesh
      // edges after node reconnections.
      if (_retryCount === 3) _refreshMissingAckPeers();

      // Layer 2 (retry 6+): bypass gossipsub entirely via direct libp2p stream.
      // Fires if mesh refresh didn't recover quorum within 3 more retry cycles.
      if (_retryCount >= 6) _sendBatchToMissingAckPeers();

      _tryCreateCertificate();
      _tryAdvanceRound();
      // Keep retrying if still stuck
      if (_running && _roundCertificates.size < _getQuorum()) {
        _scheduleRetry();
      }
    }, CONSENSUS.ROUND_TIMEOUT_MS);
  }

  // Returns committee peers that have not yet acked _myBatch this round.
  // Excludes self — we never send ourselves an ack, so our own nodeId would
  // always appear "missing" and cause spurious self-dials in Layer 2.
  function _getMissingAckPeers() {
    if (!_myBatch) return [];
    const acks = _batchAcks.get(_myBatch.hash) || [];
    const ackSet = new Set(acks.map(a => a.acker_node_id));
    return _getCommittee(_currentRound).filter(nId => nId !== nodeId && !ackSet.has(nId));
  }

  // Layer 1: force-regraft gossipsub mesh edges for non-acking peers.
  // gossipsub only re-grafts when a peer is re-added to pubsub.direct —
  // the remove+add triggers the GRAFT control message on the next heartbeat.
  function _refreshMissingAckPeers() {
    if (typeof network.refreshDirectPeer !== "function") return;
    const missing = _getMissingAckPeers();
    if (missing.length === 0) return;
    log.info(`Round ${_currentRound}: mesh-refresh for ${missing.length} non-acking peers: [${missing.map(id => id.slice(-8)).join(",")}]`);
    for (const nId of missing) network.refreshDirectPeer(nId);
  }

  // Layer 2: push batch directly over a libp2p stream, bypassing gossipsub.
  // Receiver calls the same _handleBatch path as a normal MEMPOOL message —
  // no special handling needed on the other side.
  function _sendBatchToMissingAckPeers() {
    if (typeof network.sendBatchDirect !== "function") return;
    if (!_myBatch) return;
    const missing = _getMissingAckPeers();
    if (missing.length === 0) return;
    log.info(`Round ${_currentRound}: direct-stream batch to ${missing.length} non-acking peers: [${missing.map(id => id.slice(-8)).join(",")}]`);
    const buf = Buffer.from(encode("Batch", serializeBatch(_myBatch)));
    for (const nId of missing) network.sendBatchDirect(buf, nId);
  }

  function _rebroadcastOwnBatch() {
    if (!_myBatch) return;
    try {
      const buf = encode("Batch", serializeBatch(_myBatch));
      network.publish(network.TOPICS.MEMPOOL, buf);
      log.debug(`Round ${_currentRound}: re-broadcast own batch`);
    } catch (err) {
      log.warn(`Round ${_currentRound}: batch re-broadcast failed: ${err.message}`);
    }
  }

  function _rebroadcastOwnCertificate() {
    if (!_myCertificateCreated) return;
    const cert = _roundCertificates.get(nodeId);
    if (!cert) return;
    try {
      const buf = encode("Certificate", serializeCertificate(cert));
      if (buf.length <= CONSENSUS.CERTIFICATE_MAX_BYTES) {
        network.publish(network.TOPICS.CERTIFICATES, buf);
        log.debug(`Round ${_currentRound}: re-broadcast own certificate`);
      }
    } catch (err) {
      log.warn(`Round ${_currentRound}: cert re-broadcast failed: ${err.message}`);
    }
  }

  function _resetRoundState() {
    // #64: if our own batch never formed a cert at this round, return
    // its txs to the FRONT of the mempool so they get re-batched at
    // the next round, drained ahead of newer arrivals (the orphaned
    // txs were submitted earlier and deserve their original FIFO
    // position). Without this, txs we drained at T+0 but never got
    // 2f+1 acks for are silently lost when the round advances.
    //
    // The fast-forward path at handleIncomingBatch already requeues;
    // duplicating the logic here so it ALSO fires on natural advance
    // (via _tryAdvanceRound seeing 2f+1 certs from peers, even when
    // those certs don't include our own batch).
    if (_myBatch && !_myCertificateCreated) {
      const orphanedTxs = _myBatch.txs || [];
      if (orphanedTxs.length > 0) {
        let requeued = 0;
        // Re-insert in REVERSE order so the first tx of the original
        // batch ends up at the front of the queue (each addFront
        // prepends — last addFront becomes the new head).
        for (let i = orphanedTxs.length - 1; i >= 0; i--) {
          const r = mempool.addFront(orphanedTxs[i], Date.now());
          if (r && r.added) requeued++;
        }
        _metrics.my_batches_orphaned++;
        log.warn(`Round ${_myBatch.round} advanced without certifying my own batch — front-requeued ${requeued}/${orphanedTxs.length} txs to mempool`);
      }
      // Empty batches at vote rounds advancing without cert is normal
      // (peer certs arrive faster than ack quorum on our self-emitted
      // empty batch). Don't bump my_batches_orphaned for them — would
      // drown the signal we actually care about (orphaned tx-bearing
      // batches).
    }
    _myBatch = null;
    _peerBatches.clear();
    _batchAcks.clear();
    _roundCertificates.clear();
    _myCertificateCreated = false;
    if (_retryTimer) { clearTimeout(_retryTimer); _retryTimer = null; }
    _retryCount = 0;
  }

  // ── Batch handling ──────────────────────────────────────────────────────

  /**
   * Handle an incoming batch from a peer (via MEMPOOL topic).
   */
  function handleIncomingBatch(data) {
    if (!_running) return;

    // Byzantine-fork halt is comprehensive — no production (gated in
    // _canProduce), no counter advance (gated in _tryAdvanceRound), AND
    // no acks. Without this gate, a halted node keeps signing acks for
    // peer batches; those acks land in peer certs; anchor walks count
    // the halted node's participation; rotation_participation stays
    // above the eviction threshold. Result: the halted node never gets
    // dropped at the next committee rotation. Closing this gap lets RP
    // decay naturally to zero so eviction happens on schedule.
    if (_byzantineForkHalt) {
      _metrics.batches_dropped_byzantine_halt = (_metrics.batches_dropped_byzantine_halt || 0) + 1;
      return;
    }

    // Enforce size limit (batch is part of certificate, share the limit)
    if (data && data.length > CONSENSUS.CERTIFICATE_MAX_BYTES) {
      log.warn(`Rejected oversized batch: ${data.length} bytes`);
      return;
    }

    let batch;
    try {
      batch = deserializeBatch(decode("Batch", data));
    } catch (err) {
      log.warn(`Failed to decode incoming batch: ${err.message}`);
      return;
    }

    // Validate author
    const authorKey = getNodeKey(batch.author_node_id);
    if (!authorKey) {
      log.warn(`Round ${_currentRound}: rejected batch from unregistered node ${batch.author_node_id}`);
      return;
    }

    // Verify signature
    const result = verifyBatch(batch, authorKey);
    if (!result.valid) {
      log.warn(`Round ${_currentRound}: rejected invalid batch from ${batch.author_node_id}: ${result.error}`);
      return;
    }

    // During sync — ignore batches, our round is stale and will be resynced.
    if (_joinState === "syncing") {
      log.debug(`Ignoring batch from ${batch.author_node_id} — sync in progress`);
      return;
    }

    // Round-drift recovery: if a peer is producing at a higher round, the
    // cluster has moved on without us (we advanced slower, or missed a quorum
    // window). Fast-forward to catch up — abandon any in-flight round state,
    // join the peer's round, and immediately begin our own round so we can
    // contribute a batch + ack this peer's batch too.
    //
    // #64: orphan-tx requeue is centralised in `_resetRoundState` (which
    // we call below). When _myBatch was uncertified, _resetRoundState
    // front-loads its txs back into the mempool so they drain ahead of
    // newer arrivals at the next round. Don't duplicate the requeue
    // here.
    if (batch.round > _currentRound) {
      // Atomic-boundary fast-forward gate. A ready producer must NOT
      // advance _currentRound across a rotation boundary whose CH row
      // hasn't landed locally — otherwise the cluster ends up with
      // quorum-orphaned rounds (some nodes FF'd past the boundary while
      // others are still producing carve-outs at it), and no later anchor
      // can walk back to apply the rotation tx → permanent halt.
      //
      // Live evidence (2026-05-06): cluster halted at round 20003 with
      // certs scattered: round 20000=4, 20001=1 (only 1 author who hadn't
      // FF'd yet), 20002=2, 20003=0 — anchor at 20002 needs 3 vote certs
      // to commit, never gets them, rotation tx in 20000 carve-outs never
      // ordered, CH stays empty for rotation 100, federation stuck.
      //
      // Catching_up/syncing nodes are exempt: they don't produce certs
      // (_canProduce gates on joinState===ready), so _currentRound is
      // observation-only — let them track the cluster head freely; the
      // missing rotation row arrives via natural Bullshark commits as
      // cert-sync fills the DAG behind them.
      if (_joinState === "ready") {
        const fromEpoch = epochOf(_currentRound);
        const toEpoch = epochOf(batch.round);
        if (
          toEpoch > fromEpoch
          && typeof dag.getCommitteeRotation === "function"
          && !dag.getCommitteeRotation(toEpoch)
        ) {
          _metrics.fast_forwards_refused_boundary = (_metrics.fast_forwards_refused_boundary || 0) + 1;
          log.warn(
            `Refusing fast-forward to round ${batch.round} from ${batch.author_node_id}: ` +
            `rotation ${toEpoch} not in local committee_history. ` +
            `Peer is past the boundary, so they have rotation ${toEpoch} (or are misbehaving); ` +
            `staying at ${_currentRound} and continuing carve-out so all ready producers stay locked at the boundary ` +
            `until the rotation tx commits via natural anchor walk.`
          );
          return;
        }
      }
      _metrics.fast_forwards++;
      log.info(`Round ${_currentRound}: peer ${batch.author_node_id} is at round ${batch.round} — fast-forwarding`);
      _currentRound = batch.round;
      _resetRoundState();
      if (_roundTimer) { clearTimeout(_roundTimer); _roundTimer = null; }
      if (_nextRoundTimer) { clearTimeout(_nextRoundTimer); _nextRoundTimer = null; }
      // Kick off our own production at the new round, then fall through to
      // store + ack the peer batch below.
      _beginRound();
    }

    // Late-batch handling (#64). Two thresholds:
    //
    //   1. Beyond horizon (`< _currentRound - VOTES_RETENTION_ROUNDS`):
    //      refuse. The equivocation defense table (`votes_seen`) is
    //      pruned at exactly this window, so we don't have the prior-
    //      vote record to enforce "I've already attested to this
    //      (round, author)". Ack'ing here would risk double-signing
    //      under peer equivocation.
    //
    //   2. Within horizon (between `_currentRound - HORIZON` and
    //      `_currentRound`): ack normally. Reference Narwhal does this
    //      so a peer whose batch arrived a few hundred ms after we
    //      advanced doesn't have its txs orphaned. The cert can form
    //      retroactively; future Bullshark anchor walks pick it up via
    //      parent links. Sync-mode joiners are gated separately at
    //      line "_joinState === 'syncing'" above.
    //
    // Pre-fix: any `batch.round < _currentRound` was dropped silently.
    // Live impact: 2026-04-29 round 10244 — node 1's REGISTER_IDENTITY
    // batch arrived ~270ms late (one round boundary), got dropped on
    // both peers, never formed a cert, tx orphaned. User got 200 +
    // tip_id from API but GET 404'd forever.
    const horizon = CONSENSUS.VOTES_RETENTION_ROUNDS;
    if (batch.round < _currentRound - horizon) {
      log.debug(`Round ${_currentRound}: rejected batch from round ${batch.round} (beyond stale horizon ${horizon} rounds) author=${batch.author_node_id}`);
      _metrics.batches_rejected_too_old++;
      return;
    }
    if (batch.round < _currentRound) {
      _metrics.batches_acked_late++;
      // #64: rate-limit the WARN. First sighting from a peer logs immediately;
      // subsequent ones are summarised every LATE_BATCH_LOG_INTERVAL_ROUNDS
      // rounds with a running count. Otherwise warm-up (quorum=1, no peers)
      // floods the log one-per-round per peer because each round advances
      // before gossip RTT completes.
      const tracker = _lateBatchAckTracker.get(batch.author_node_id);
      if (!tracker) {
        log.warn(`Round ${_currentRound}: ack'ing late batch from round ${batch.round} (within horizon ${horizon}) author=${batch.author_node_id}`);
        _lateBatchAckTracker.set(batch.author_node_id, { count: 1, lastLoggedRound: _currentRound });
      } else {
        tracker.count++;
        if (_currentRound - tracker.lastLoggedRound >= LATE_BATCH_LOG_INTERVAL_ROUNDS) {
          log.warn(`Round ${_currentRound}: ack'ing late batch from round ${batch.round} (within horizon ${horizon}) author=${batch.author_node_id} — ${tracker.count} late batches from this peer since last log`);
          tracker.count = 0;
          tracker.lastLoggedRound = _currentRound;
        }
      }
      // fall through to equivocation guard + ack
    }

    // §1 Equivocation defense: refuse to sign a second attestation for the
    // same (round, author) with different content. Persistent across restarts
    // so a crash mid-round can't leave us attesting to two different batches.
    // Peer equivocation (same author broadcasting two batches at same round)
    // is also caught here — we endorse only the first one we saw.
    const priorVote = dag.getSeenVote(batch.round, batch.author_node_id);
    if (priorVote) {
      if (priorVote.batch_hash !== batch.hash) {
        log.error(`EQUIVOCATION detected from ${batch.author_node_id} at round ${batch.round}: ` +
          `already attested to ${priorVote.batch_hash.slice(0, 16)}, now seeing ${batch.hash.slice(0, 16)} — refusing`);
        _metrics.equivocation_refused = (_metrics.equivocation_refused || 0) + 1;
        return;
      }
      // Same (round, author, batch) arriving again — fall through to in-memory
      // dedup. Re-signing is safe (ML-DSA is randomized, same payload → valid
      // but non-identical signature; both are equally valid attestations).
    }

    // Deduplicate
    if (_peerBatches.has(batch.author_node_id)) return;

    _peerBatches.set(batch.author_node_id, batch);
    _metrics.batches_received++;

    // Persist the commitment BEFORE signing + broadcasting. If we crash
    // after persist but before broadcast, restart is safe: peer re-sends
    // the same batch, we see the prior-vote record, re-sign harmlessly.
    // If we crashed between sign+broadcast and persist, restart would allow
    // a fresh attestation to a potentially different batch — which is the
    // exact fork scenario we're closing.
    try {
      dag.recordSeenVote(batch.round, batch.author_node_id, batch.hash);
    } catch (err) {
      log.warn(`Round ${batch.round}: failed to persist vote commitment: ${err.message}`);
      // Proceed anyway — in-memory dedup is fallback for this message.
    }

    // Ack-filter: refuse to attest for a peer whose last AE-observed state
    // diverges from ours at the same committed_round. Symmetric — every
    // honest node applies the rule, so a divergent peer gets no acks and
    // their certs never reach quorum. Pairs with the threshold halt: halt
    // protects us when WE'RE wrong, filter protects us when THEY'RE wrong.
    // The seen-vote was already persisted above so we don't forget what we
    // saw — we just don't put our signature on it.
    //
    // Catch-up race guard: skip the refusal during the cache-lag race
    // where either side is mid-hydration. Two sub-cases:
    //
    //   • selfReady=false: our own state_root is briefly partial during
    //     snapshot install / cert-tail replay. Refusing peer's batch on
    //     a difference WE introduced would be wrong (the joiner would
    //     starve the cluster of its own ack-contribution).
    //
    //   • peerReady=false (cached): peer just transitioned catching_up →
    //     ready and is producing again, but our AE cache (≤
    //     ANTI_ENTROPY_INTERVAL_MS old) still says non-ready. Their
    //     state_root is fully hydrated by now (snapshot install is
    //     atomic via runInTransaction); the cache is stale, not the
    //     peer. Exempt to avoid a false-positive in the staleness window.
    //
    // Persistent malicious-non-ready peers are NOT handled here — they're
    // caught by anti-entropy._reconcileWithPeer's time-bounded halt
    // escalation, which forces byzantine_fork halt after
    // CONSENSUS.SYNC_DIVERGENCE_GRACE_MS of persistent divergence
    // regardless of joinState. Once that fires, the peer self-halts and
    // stops producing batches, so this code path never sees them again.
    const _selfReady = _joinState === "ready";
    const _peerReady = typeof peerJoinState === "function"
      ? peerJoinState(batch.author_node_id) === "ready"
      : true;
    if (
      _selfReady && _peerReady
      && typeof isPeerDivergent === "function"
      && isPeerDivergent(batch.author_node_id)
    ) {
      // Only refuse acks once the cluster has reached the BFT divergence threshold
      // (f+1 peers). A single divergent peer can be a lagging rejoiner — refusing
      // it depletes quorum margin and causes liveness failure when combined with
      // any other disconnection. Safety is preserved by _maybeHalt in anti-entropy,
      // which fires haltDueToByzantineFork at the same threshold.
      const dCount = typeof divergentPeers === "function" ? divergentPeers().length : 0;
      const threshold = bftHaltThreshold(_getCommittee().length);
      if (dCount >= threshold) {
        _metrics.acks_refused_divergent_peer = (_metrics.acks_refused_divergent_peer || 0) + 1;
        log.warn(`Round ${_currentRound}: refusing ack to ${batch.author_node_id} — ${dCount}/${threshold} divergent peers at last AE poll`);
        return;
      }
    }

    // Send ack — signed_at carries this node's wall-clock at sign time and
    // is bound into the signature scope (BFT Time).
    const ack = createBatchAck(batch.hash, nodeId, Date.now(), privateKey);
    _recordAck(batch.hash, ack);

    // Build ack buffer once — published via gossipsub AND returned so the
    // Layer 2 direct-stream handler can write it back on the same connection.
    // Gossipsub is the broken path that triggered Layer 2; the ack must not
    // depend on it reaching the batch sender.
    let ackBuf;
    try {
      ackBuf = encode("BatchAck", {
        batchHash: hexToBytes(batch.hash),
        ackerNodeId: nodeId,
        signature: hexToBytes(ack.signature),
        signedAt: ack.signed_at,
      });
      network.publish(network.TOPICS.CONSENSUS, ackBuf);
    } catch (err) {
      log.warn(`Failed to broadcast ack for batch ${batch.hash.slice(0, 16)}: ${err.message}`);
    }

    log.debug(`Round ${_currentRound}: received batch from ${batch.author_node_id} (${(batch.txs || []).length} txs)`);
    return ackBuf;
  }

  // ── Ack handling ─────────────────────────────────────────────────────────

  /**
   * Handle an incoming BatchAck from a peer (via CONSENSUS topic).
   */
  function handleIncomingAck(data) {
    if (!_running) return;

    let ack;
    try {
      const ackMsg = decode("BatchAck", data);
      // protobuf encodes int64 as Long when > 2^32; coerce to plain Number.
      // Safe up to 2^53 (year ~285K) — way past any realistic timestamp.
      const signedAtRaw = ackMsg.signedAt;
      const signedAt = typeof signedAtRaw === "object" && signedAtRaw !== null
        ? Number(signedAtRaw.toString())
        : Number(signedAtRaw || 0);
      ack = {
        batch_hash: bytesToHex(ackMsg.batchHash) || "",
        acker_node_id: ackMsg.ackerNodeId || "",
        signature: bytesToHex(ackMsg.signature) || "",
        signed_at: signedAt,
      };
    } catch (err) {
      log.warn(`Failed to decode incoming ack: ${err.message}`);
      return;
    }

    if (!ack.batch_hash || !ack.acker_node_id || !ack.signature) {
      log.warn("Rejected ack with missing fields");
      return;
    }
    if (!Number.isInteger(ack.signed_at) || ack.signed_at <= 0) {
      log.warn(`Rejected ack from ${ack.acker_node_id} — invalid signed_at: ${ack.signed_at}`);
      return;
    }

    // Verify ack signature
    const ackerKey = getNodeKey(ack.acker_node_id);
    if (!ackerKey) {
      log.warn(`Rejected ack from unregistered node ${ack.acker_node_id}`);
      return;
    }
    const result = verifyBatchAck(ack, ackerKey);
    if (!result.valid) {
      log.warn(`Rejected invalid ack from ${ack.acker_node_id}: ${result.error}`);
      return;
    }

    // Store and check
    _recordAck(ack.batch_hash, ack);
    _metrics.acks_received++;

    // If this ack is for our batch, try to create certificate
    if (ack.batch_hash === _myBatch?.hash) {
      _tryCreateCertificate();
    }
  }

  /**
   * Record an ack, deduplicating by acker node.
   */
  function _recordAck(batchHash, ack) {
    if (!batchHash || !ack || !ack.acker_node_id) return;
    if (!_batchAcks.has(batchHash)) _batchAcks.set(batchHash, []);
    const acks = _batchAcks.get(batchHash);
    if (!acks.find(a => a.acker_node_id === ack.acker_node_id)) {
      acks.push(ack);
    }
  }

  // ── Certificate creation ─────────────────────────────────────────────────

  function _tryCreateCertificate() {
    if (_myCertificateCreated || !_myBatch) return;

    // Filter to committee-member acks only. Non-committee peers (late-
    // joiners, recently-rotated-out nodes) may also send acks for
    // network responsiveness, but only committee members count toward
    // the BFT quorum. Without this filter, the cert author may seal a
    // cert with 2f+1 ack signatures that includes non-committee signers.
    // That cert verifies fine at runtime (peers do the same lenient
    // count), but FAILS snapshot-install verification in joiners
    // (snapshot-handler.js applies the strict committee-membership rule
    // at line 640: `if (!committeeSet.has(signer)) continue`). The two
    // layers using two different rules for "valid quorum ack" was the
    // 2026-05-05 incident where wiped-n5 couldn't re-sync because the
    // peer's snapshot anchor cert had a non-committee ack from n4.
    // Keeping rules consistent across cert-seal and snapshot-verify
    // closes that gap.
    const allAcks = _batchAcks.get(_myBatch.hash) || [];
    const committeeSet = new Set(_getCommittee(_currentRound));
    const acks = allAcks.filter(a => committeeSet.has(a.acker_node_id));
    const quorum = _getQuorum();

    if (acks.length < quorum) return;

    // §1 Own-cert equivocation defense (no new storage — reuses the
    // existing certs table). If a cert authored by us at this round
    // already exists (from a prior process instance that persisted it
    // before crashing), don't create a second one. Adopt the existing
    // one and re-broadcast to shake off any GossipSub loss.
    const existingOwn = dag.getCertificateByAuthorRound(nodeId, _currentRound);
    if (existingOwn) {
      log.info(`Round ${_currentRound}: own cert exists from prior session — reusing instead of re-signing`);
      _roundCertificates.set(nodeId, existingOwn);
      _myCertificateCreated = true;
      // Re-broadcast in case peers missed it
      try {
        const certBuf = encode("Certificate", serializeCertificate(existingOwn));
        if (certBuf.length <= CONSENSUS.CERTIFICATE_MAX_BYTES) {
          network.publish(network.TOPICS.CERTIFICATES, certBuf);
        }
      } catch (err) {
        log.warn(`Round ${_currentRound}: re-broadcast of existing own cert failed: ${err.message}`);
      }
      _tryAdvanceRound();
      return;
    }

    // Parent certificate hashes from previous round
    const parentHashes = _currentRound > 1
      ? dag.getCertificatesByRound(_currentRound - 1).map(c => c.hash)
      : [];

    const cert = createCertificate(
      _currentRound, nodeId, _myBatch, acks, parentHashes, privateKey
    );

    // Persist. If the SQLite connection is busy (snapshot serve in
    // flight on the same connection) the save is deferred — leave
    // _myCertificateCreated unset and skip broadcast so the next
    // round retries with a fresh cert. Cert is in memory only at
    // this point; nothing to clean up.
    const persisted = _saveCertAndNotify(cert);
    if (!persisted) {
      _scheduleNextRound(100);
      return;
    }
    _roundCertificates.set(nodeId, cert);
    _myCertificateCreated = true;

    // Broadcast on CERTIFICATES topic (enforce size limit)
    try {
      const certBuf = encode("Certificate", serializeCertificate(cert));
      if (certBuf.length > CONSENSUS.CERTIFICATE_MAX_BYTES) {
        log.error(`Round ${_currentRound}: certificate too large (${certBuf.length} bytes, max ${CONSENSUS.CERTIFICATE_MAX_BYTES}) — not broadcast`);
      } else {
        network.publish(network.TOPICS.CERTIFICATES, certBuf);
      }
    } catch (err) {
      log.error(`Failed to broadcast certificate: ${err.message}`);
    }

    _metrics.certs_created++;
    // INFO-level so this surfaces in info.log too — diff author's view
    // against the receiver's "Rejected certificate ... my committee at R"
    // line to spot gossip-lag asymmetry at sealing time.
    const committeeShort = _getCommittee(_currentRound).map(id => id.slice(-8)).join(",");
    const ackerShort = acks.map(a => (a.acker_node_id || "").slice(-8)).join(",");
    log.info(`Round ${_currentRound}: cert sealed (${acks.length} acks [${ackerShort}], ${(cert.batch.txs || []).length} txs) | author's committee view: [${committeeShort}] (size=${_getCommittee(_currentRound).length}, quorum=${_getQuorum()})`);

    _tryAdvanceRound();
  }

  // ── Certificate reception ────────────────────────────────────────────────

  /**
   * Handle an incoming certificate from a peer (via CERTIFICATES topic).
   */
  function handleIncomingCertificate(data) {
    if (!_running) return;

    // Don't wake on certificates — they're just data to store.
    // Only batches are an invitation to participate in a round.

    // Enforce size limit
    if (data && data.length > CONSENSUS.CERTIFICATE_MAX_BYTES) {
      log.warn(`Rejected oversized certificate: ${data.length} bytes (max ${CONSENSUS.CERTIFICATE_MAX_BYTES})`);
      return;
    }

    let cert;
    try {
      cert = deserializeCertificate(decode("Certificate", data));
    } catch (err) {
      log.warn(`Failed to decode incoming certificate: ${err.message}`);
      return;
    }

    // Skip if already persisted or already parked
    if (dag.getCertificate(cert.hash)) return;
    if (_pendingCerts.has(cert.hash)) return;

    // Full verification — use the committee AT this cert's wave, not current.
    // Committee is wave-stable, so cert.round maps to the cert's wave's
    // committee. Every node computes the same value from the same DAG, so
    // ack-count validation matches what the author used when signing.
    const committeeAtCertRound = _getCommittee(cert.round);
    const quorum = computeQuorum(committeeAtCertRound.length);
    const result = verifyCertificate(cert, getNodeKey, quorum);
    if (!result.valid) {
      // Extra context on rejection — surfaces gossip-lag asymmetry where
      // author and validator computed different committees from different
      // local DAG states at cert.round. Diff this line on author vs.
      // validator side to see exactly where they disagreed.
      const ackerIds = (cert.acknowledgments || []).map(a => (a.acker_node_id || "").slice(-8)).join(",");
      const committeeShort = committeeAtCertRound.map(id => id.slice(-8)).join(",");
      log.warn(`Rejected certificate from ${cert.author_node_id} round ${cert.round}: ${result.error} | my committee at R=${cert.round}: [${committeeShort}] (size=${committeeAtCertRound.length}, quorum=${quorum}) | cert ackers: [${ackerIds}]`);
      return;
    }

    // CertificateWaiter: if any parent is missing from the DAG, park the cert
    // and reprocess when the missing parent lands. Ensures no peer cert gets
    // dropped for arriving before its causal history has propagated.
    const missing = (cert.parent_hashes || []).filter(h => h && !dag.getCertificate(h));
    if (missing.length > 0) {
      _parkPendingCert(cert, missing);
      _metrics.certs_parked++;
      log.debug(`Round ${cert.round}: parked cert from ${cert.author_node_id} — waiting on ${missing.length} parent(s)`);
      return;
    }

    _metrics.certs_received++;
    _processVerifiedCertificate(cert);
  }

  /**
   * Persist, emit save events, and flush any pending certs whose last
   * missing parent is this one.
   *
   * better-sqlite3 throws "This database connection is busy executing
   * a query" if a write is attempted while a streaming iterator
   * (snapshot serving) is live on the same connection. This is a
   * transient condition — the iterator finishes within milliseconds.
   * Treat it as deferrable rather than fatal: log + skip this tick,
   * the cert is still in memory and will retry on the next round.
   * Letting it bubble crashes the node (crash observed 2026-05-05
   * round 800 during concurrent snapshot serve to two reconnecting
   * peers).
   *
   * For OWN cert: caller is `_tryCreateCertificate` from `_beginRound`.
   * Skipping the save without setting `_myCertificateCreated` lets the
   * next round retry naturally. Brief liveness hiccup, no state loss.
   *
   * For PEER cert: caller is `_processVerifiedCertificate`. Skipping
   * the save means we don't notify save-event listeners. Peer will
   * re-broadcast (or anti-entropy will pull) — idempotent via the
   * `dag.getCertificate()` dedup guard in handleIncomingCertificate.
   *
   * Returns true if persisted, false if deferred.
   */
  function _saveCertAndNotify(cert) {
    try {
      dag.saveCertificate(cert);
    } catch (err) {
      const msg = (err && err.message) || "";
      if (msg.includes("database connection is busy")) {
        log.warn(`Round ${cert.round}: cert save deferred — SQLite connection busy (snapshot serve in flight); will retry`);
        return false;
      }
      throw err;
    }
    _onCertSaved(cert);
    _flushPendingForParent(cert.hash);
    return true;
  }

  /**
   * Final step for a verified cert whose parents are all present. Runs after
   * the initial receive OR after a waiter unblock. Idempotent via the
   * dag.getCertificate() guard in handleIncomingCertificate.
   */
  function _processVerifiedCertificate(cert) {
    _saveCertAndNotify(cert);

    // Track if current round — peer is in sync and actively participating.
    // Committee membership is now a pure function of DAG state (saveCertificate
    // above is enough), so no local mutation here.
    if (cert.round === _currentRound) {
      _roundCertificates.set(cert.author_node_id, cert);
      _tryAdvanceRound();
    } else if (cert.round < _currentRound && cert.round > 0 && onCommit) {
      // Late-cert anchor re-trigger.
      //
      // Quorum for round-advance (2f+1 of committee) can be met before all
      // committee certs at the round have arrived. _tryAdvanceRound fires
      // onCommit with whatever's in _roundCertificates at that moment, and
      // Bullshark's _checkAnchorCommit reads dag.getCertificatesByRound —
      // also limited to certs that already landed. If support for the
      // anchor's leader is short by exactly the cert that hasn't arrived
      // yet, the anchor is permanently lost: subsequent gossip saves the
      // late cert to the DAG, but nothing re-runs the check for that
      // earlier round. Hits non-committee joiners hardest because they
      // never have their *own* cert in the round-advance snapshot.
      //
      // Fix: when a cert lands for an earlier round, re-invoke
      // bullshark.onRoundComplete for the relevant vote round (the cert's
      // own round if even, or the next round if this is a propose-round
      // cert that may be the missing leader). Bullshark idempotently
      // gates on _lastCommittedRound + even-round-only, so re-calls for
      // already-committed or odd rounds are safe no-ops.
      const voteRound = cert.round % 2 === 0 ? cert.round : cert.round + 1;
      try {
        const certs = dag.getCertificatesByRound(voteRound);
        onCommit(certs, voteRound);
      } catch (err) {
        log.debug(`Late-cert anchor re-check at round ${voteRound} failed: ${err.message}`);
      }
    }

    // Remove committed txs from our mempool
    const txIds = (cert.batch?.txs || []).map(t => t.tx_id).filter(Boolean);
    if (txIds.length > 0) mempool.remove(txIds);

    log.debug(`Round ${cert.round}: received certificate from ${cert.author_node_id} (${(cert.batch?.txs || []).length} txs)`);
  }

  /**
   * Park a verified cert whose parents aren't all in the DAG yet. Indexed
   * by each missing parent hash for O(1) flush on parent arrival.
   */
  function _parkPendingCert(cert, missingParents) {
    const missingSet = new Set(missingParents);
    _pendingCerts.set(cert.hash, { cert, missing: missingSet });
    for (const parentHash of missingSet) {
      if (!_pendingByParent.has(parentHash)) _pendingByParent.set(parentHash, new Set());
      _pendingByParent.get(parentHash).add(cert.hash);
    }
  }

  /**
   * §2 cert-waiter GC: drop parked certs whose round falls behind the
   * cert-GC horizon. Their parents are either pruned or will never arrive,
   * and consensus has already committed past their round — holding them
   * in memory is pointless and unbounded under adversarial conditions.
   * Also cleans up `_pendingByParent` entries that only referenced
   * now-dropped children so the parent-indexed map stays bounded.
   */
  function _prunePendingCertsBefore(cutoffRound) {
    if (_pendingCerts.size === 0) return 0;

    const toDrop = [];
    for (const [childHash, entry] of _pendingCerts) {
      if (entry.cert.round < cutoffRound) toDrop.push(childHash);
    }
    if (toDrop.length === 0) return 0;

    for (const childHash of toDrop) {
      const entry = _pendingCerts.get(childHash);
      _pendingCerts.delete(childHash);
      if (!entry) continue;
      for (const parentHash of entry.missing) {
        const siblings = _pendingByParent.get(parentHash);
        if (!siblings) continue;
        siblings.delete(childHash);
        if (siblings.size === 0) _pendingByParent.delete(parentHash);
      }
    }
    _metrics.pending_certs_pruned = (_metrics.pending_certs_pruned || 0) + toDrop.length;
    log.debug(`Pending-cert GC: dropped ${toDrop.length} stale waiters (round < ${cutoffRound})`);
    return toDrop.length;
  }

  /**
   * When a cert is saved, check whether it unblocks any parked children.
   * Recursive via _processVerifiedCertificate → _saveCertAndNotify.
   */
  function _flushPendingForParent(parentHash) {
    const waiters = _pendingByParent.get(parentHash);
    if (!waiters || waiters.size === 0) return;
    _pendingByParent.delete(parentHash);

    for (const childHash of waiters) {
      const entry = _pendingCerts.get(childHash);
      if (!entry) continue;
      entry.missing.delete(parentHash);
      if (entry.missing.size === 0) {
        _pendingCerts.delete(childHash);
        _metrics.certs_unblocked++;
        _processVerifiedCertificate(entry.cert);
      }
    }
  }

  // ── Round advancement ────────────────────────────────────────────────────

  function _tryAdvanceRound() {
    // Byzantine-fork halt freezes both production and round counter. Without
    // this gate, peer certs would still bump _currentRound while we're
    // halted — defeating "rounds don't grow on divergence" and making
    // post-halt forensics harder (the round at which divergence was first
    // detected drifts forward).
    if (_byzantineForkHalt) return;

    const quorum = _getQuorum();
    if (_roundCertificates.size < quorum) return;

    _metrics.rounds_advanced++;
    _lastRoundAdvanceAt = Date.now();
    log.debug(`Round ${_currentRound}: advancing (${_roundCertificates.size}/${_getCommittee().length} certificates)`);

    // Clear timers
    if (_roundTimer) { clearTimeout(_roundTimer); _roundTimer = null; }
    if (_retryTimer) { clearTimeout(_retryTimer); _retryTimer = null; }

    // Notify Bullshark
    if (onCommit) {
      const certs = Array.from(_roundCertificates.values());
      try {
        onCommit(certs, _currentRound);
      } catch (err) {
        log.error(`Bullshark commit failed at round ${_currentRound}: ${err.message}`);
      }
    }

    // Advance
    _currentRound++;

    // §1 votes_seen auto-prune. We only need the last few rounds' commitments
    // (old rounds can't be re-entered). Pruning here — tied to round advance
    // — means the table is bounded to ~VOTES_RETENTION_ROUNDS × committee_size
    // rows forever, with no separate timer or GC job.
    try {
      const cutoff = _currentRound - CONSENSUS.VOTES_RETENTION_ROUNDS;
      if (cutoff > 0 && dag.pruneVotesSeenBefore) dag.pruneVotesSeenBefore(cutoff);
    } catch (err) {
      log.debug(`votes_seen prune failed: ${err.message}`);
    }

    // §2 cert-waiter GC. `_pendingCerts` holds certs parked because their
    // parent hasn't arrived yet. If a parked cert's round falls behind the
    // cert-GC horizon (currentRound - GC_DEPTH), consensus has committed past
    // it and the cert can never unblock (its parent is pruned or never will
    // land). Drop it outright so the waiter maps stay bounded even under
    // adversarial or long-partition conditions.
    try {
      const gcDepth = CONSENSUS.GC_DEPTH;
      if (gcDepth && gcDepth > 0) {
        const cutoff = _currentRound - gcDepth;
        if (cutoff > 0) _prunePendingCertsBefore(cutoff);
      }
    } catch (err) {
      log.debug(`pending-cert prune failed: ${err.message}`);
    }

    // Continuous production: always schedule the next round. Short delay so
    // gossip has time to deliver peer certs for round-R before we freeze
    // parent_hashes for R+1. Chain extension is what lets late-arriving
    // tx-carrying certs get swept into a future anchor commit.
    _scheduleNextRound(CONSENSUS.BATCH_WAIT_MS);
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  function _getQuorum() {
    return computeQuorum(_getCommittee().length);
  }

  // Wire format ser/de for Batch/BatchAck/Certificate lives in
  // ./certificate-codec — single source of truth for both gossipsub
  // broadcast (this file) and framed sync (sync-handler.js).

  // Watchdog bounds non-ready states so a node never zombies. syncing's
  // observability is owned by halt-status (stuck_syncing reason); the
  // watchdog only acts on catching_up that drags past its threshold —
  // peer GC'd faster than we synced, current target is unreachable, flip
  // back to syncing so the next AE tick requests a fresher snapshot.
  const STUCK_CATCHING_UP_MS = CONSENSUS.ROUND_TIMEOUT_MS * 10;
  let _watchdogTimer = null;

  function enterSyncMode() {
    _joinState = "syncing";
    if (_syncEnteredAt === 0) _syncEnteredAt = Date.now();
    _catchingUpEnteredAt = 0;
    _catchUpTarget = 0;
    log.notice("Entering sync mode — suppressing round production");
    _startWatchdog();
  }

  // syncing → catching_up. Called by snapshot-handler after the install's
  // contract verification passes. peerCommittedRound is the cluster head
  // the cert tail must reach before catching_up can promote to ready.
  function markSnapshotInstalled(round, peerCommittedRound = 0) {
    if (_joinState !== "syncing") {
      log.debug(`markSnapshotInstalled ignored — joinState=${_joinState}`);
      return;
    }
    const target = Math.max(round, dag.getLatestRound()) + 1;
    if (target > _currentRound) {
      const oldRound = _currentRound;
      _currentRound = target;
      _resetRoundState();
      if (_roundTimer) { clearTimeout(_roundTimer); _roundTimer = null; }
      log.notice(`Round advanced after snapshot: ${oldRound} → ${_currentRound}`);
    }
    _joinState = "catching_up";
    _syncEnteredAt = 0;
    _catchingUpEnteredAt = Date.now();
    _catchUpTarget = Math.max(0, peerCommittedRound || round);
    log.notice(`Snapshot installed at round ${round}; catching up to peer head ${_catchUpTarget}`);
    _startWatchdog();
  }

  // catching_up → ready. Anti-entropy calls this after asserting the cert
  // tail reached _catchUpTarget AND our state_merkle_root matches 2f+1 of
  // authorized peers. peerLatestRound is the cluster's current head used
  // to floor _currentRound for the resumed production.
  function markCaughtUp(peerLatestRound = 0) {
    if (_joinState !== "catching_up") {
      log.debug(`markCaughtUp ignored — joinState=${_joinState}`);
      return;
    }
    _exitToReady(peerLatestRound);
    log.notice(`Caught up — ready at round ${_currentRound}`);
  }

  // Public override: forces a direct transition to ready from any state.
  // Retained for tests that drive _currentRound for setup, and for the
  // safety-floor branch in anti-entropy._runSnapshotFallback failure path.
  // Live happy-path callers should prefer markSnapshotInstalled +
  // markCaughtUp so the AE state-root assertion gates the transition.
  function exitSyncMode(peerLatestRound = 0) {
    _exitToReady(peerLatestRound);
    log.notice(`Exiting sync mode — ready at round ${_currentRound}`);
  }

  function _exitToReady(peerLatestRound) {
    const fromDag = dag.getLatestRound();
    const target = Math.max(peerLatestRound, fromDag) + 1;
    if (target > _currentRound) {
      const oldRound = _currentRound;
      _currentRound = target;
      _resetRoundState();
      if (_roundTimer) { clearTimeout(_roundTimer); _roundTimer = null; }
      log.notice(`Round resynced: ${oldRound} → ${_currentRound} (peer latest: ${peerLatestRound}, dag latest: ${fromDag})`);
    }
    _joinState = "ready";
    _syncEnteredAt = 0;
    _catchingUpEnteredAt = 0;
    _catchUpTarget = 0;
    _stopWatchdog();
    if (_running) _scheduleNextRound(0);
  }

  function _startWatchdog() {
    if (_watchdogTimer) return;
    const tick = Math.max(500, Math.floor(CONSENSUS.ROUND_TIMEOUT_MS / 2));
    _watchdogTimer = setInterval(_watchdogCheck, tick);
  }

  function _stopWatchdog() {
    if (_watchdogTimer) { clearInterval(_watchdogTimer); _watchdogTimer = null; }
  }

  function _watchdogCheck() {
    if (!_running || _joinState === "ready") { _stopWatchdog(); return; }
    if (_joinState !== "catching_up" || _catchingUpEnteredAt === 0) return;
    const elapsed = Date.now() - _catchingUpEnteredAt;
    if (elapsed <= STUCK_CATCHING_UP_MS) return;
    log.warn(`Watchdog: catching_up stalled ${Math.floor(elapsed / 1000)}s (target=${_catchUpTarget}, dag=${dag.getLatestRound()}) — reverting to syncing for fresh snapshot`);
    _joinState = "syncing";
    _catchingUpEnteredAt = 0;
    _catchUpTarget = 0;
    if (_syncEnteredAt === 0) _syncEnteredAt = Date.now();
  }

  function joinState() { return _joinState; }
  function catchUpTarget() { return _catchUpTarget; }
  function committeeSize() { return _getCommittee().length; }
  function byzantineForkHalt() { return _byzantineForkHalt ? { ..._byzantineForkHalt } : null; }

  return {
    start,
    stop,
    currentRound,
    enterSyncMode,
    exitSyncMode,
    markSnapshotInstalled,
    markCaughtUp,
    joinState,
    catchUpTarget,
    committeeSize,
    haltDueToByzantineFork,
    clearByzantineForkHalt,
    byzantineForkHalt,
    handleIncomingBatch,
    handleIncomingAck,
    handleIncomingCertificate,
    lastRoundAdvanceAt: () => _lastRoundAdvanceAt,

    /**
     * Force-prune parked cert waiters below `cutoffRound`. Normally fires
     * on every round advance (§2 GC). Exposed here for ops diagnostics
     * ("I see pendingCerts stuck, drop anything older than X") and to let
     * tests exercise the prune path without driving a full round cycle.
     * Returns the number of parked certs dropped.
     */
    prunePendingCertsBefore: (cutoff) => _prunePendingCertsBefore(cutoff),

    /**
     * Park an already-verified cert whose parents aren't in the DAG yet.
     * Mirrors the internal path used by handleIncomingCertificate when
     * parent hashes are missing. Exposed for ops recovery scenarios and
     * for tests that need to populate the waiter state without running
     * the full signature-verification pipeline.
     *
     * Caller is responsible for ensuring the cert is valid — this
     * bypasses the verification that handleIncomingCertificate performs.
     */
    parkPendingCert: (cert, missingParents) => _parkPendingCert(cert, missingParents),

    /** Count of currently-parked cert waiters (ops diagnostic). */
    pendingCertCount: () => _pendingCerts.size,
    stats: () => ({
      round: _currentRound,
      running: _running,
      joinState: _joinState,
      batchesThisRound: _peerBatches.size,
      certificatesThisRound: _roundCertificates.size,
      pendingCerts: _pendingCerts.size,
      quorum: _getQuorum(),
      activeParticipants: _getCommittee().length,
      registeredNodes: getNodeCount(),
      mempoolSize: mempool.size(),
      lastRoundAdvanceAt: _lastRoundAdvanceAt,
      syncEnteredAt: _syncEnteredAt,
      catchingUpEnteredAt: _catchingUpEnteredAt,
      catchUpTarget: _catchUpTarget,
      byzantineForkHalt: _byzantineForkHalt ? { ..._byzantineForkHalt } : null,
      metrics: { ..._metrics },
    }),
  };
}

module.exports = { createNarwhal };
