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
  computeQuorum,
} = require("./certificate");
const { encode, decode, bytesToHex, hexToBytes, bytesToUtf8 } = require("../network/proto");
const { getLogger } = require("../logger");

const log = getLogger("tip.narwhal");

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
function createNarwhal({ dag, mempool, network, config, getNodeKey, getNodeCount, getCommittee, onCommit, onCertSaved }) {
  const _getCommittee = typeof getCommittee === "function" ? getCommittee : () => [];
  const _onCertSaved = typeof onCertSaved === "function" ? onCertSaved : () => { };
  let _currentRound;
  try { _currentRound = dag.getLatestRound() + 1; } catch { _currentRound = 1; }
  let _running = false;

  // Join state: controls when a joining node can start producing.
  //   "ready"   — normal operation
  //   "syncing" — sync in progress, suppress round production
  // After sync, SyncResponse.latestRound gives the authoritative peer round,
  // so we transition "syncing" → "ready" directly and resume ticking.
  let _joinState = "ready";
  let _roundTimer = null;                           // per-round liveness timeout
  let _retryTimer = null;                           // retry while stuck below quorum
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
  };

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

  function _beginRound() {
    if (!_running || _joinState !== "ready") return;

    _resetRoundState();

    // Phase 1: Create batch from mempool and broadcast
    const txs = mempool.drain(CONSENSUS.MAX_TXS_PER_CERTIFICATE);

    _myBatch = createBatch(_currentRound, nodeId, txs, privateKey);
    _peerBatches.set(nodeId, _myBatch);

    // Broadcast batch on MEMPOOL topic (separate from certificates)
    try {
      const batchBuf = encode("Batch", _serializeBatch(_myBatch));
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

    // Self-ack our own batch
    _recordAck(_myBatch.hash, createBatchAck(_myBatch.hash, nodeId, privateKey));

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

        // If still stuck, schedule periodic retry
        if (_running && _roundCertificates.size < _getQuorum()) {
          _scheduleRetry();
        }
      }, CONSENSUS.ROUND_TIMEOUT_MS);
    }
  }

  /**
   * Periodic retry when round can't advance (e.g. waiting for peers).
   */
  function _scheduleRetry() {
    if (_retryTimer || !_running) return;
    _retryTimer = setTimeout(() => {
      _retryTimer = null;
      if (!_running) return;

      _metrics.retries++;
      // GossipSub is best-effort — a dropped batch or cert means this round
      // can never reach quorum. On each retry, re-broadcast whatever we
      // already have so peers that missed the original publish can still
      // collect it. Receivers dedup on message hash, so re-publishing to
      // peers that already got the message is a no-op.
      _rebroadcastOwnBatch();
      _rebroadcastOwnCertificate();

      _tryCreateCertificate();
      _tryAdvanceRound();
      // Keep retrying if still stuck
      if (_running && _roundCertificates.size < _getQuorum()) {
        _scheduleRetry();
      }
    }, CONSENSUS.ROUND_TIMEOUT_MS);
  }

  function _rebroadcastOwnBatch() {
    if (!_myBatch) return;
    try {
      const buf = encode("Batch", _serializeBatch(_myBatch));
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
      const buf = encode("Certificate", _serializeCertificate(cert));
      if (buf.length <= CONSENSUS.CERTIFICATE_MAX_BYTES) {
        network.publish(network.TOPICS.CERTIFICATES, buf);
        log.debug(`Round ${_currentRound}: re-broadcast own certificate`);
      }
    } catch (err) {
      log.warn(`Round ${_currentRound}: cert re-broadcast failed: ${err.message}`);
    }
  }

  function _resetRoundState() {
    _myBatch = null;
    _peerBatches.clear();
    _batchAcks.clear();
    _roundCertificates.clear();
    _myCertificateCreated = false;
    if (_retryTimer) { clearTimeout(_retryTimer); _retryTimer = null; }
  }

  // ── Batch handling ──────────────────────────────────────────────────────

  /**
   * Handle an incoming batch from a peer (via MEMPOOL topic).
   */
  function handleIncomingBatch(data) {
    if (!_running) return;

    // Enforce size limit (batch is part of certificate, share the limit)
    if (data && data.length > CONSENSUS.CERTIFICATE_MAX_BYTES) {
      log.warn(`Rejected oversized batch: ${data.length} bytes`);
      return;
    }

    let batch;
    try {
      batch = _deserializeBatch(decode("Batch", data));
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
    if (batch.round > _currentRound) {
      _metrics.fast_forwards++;
      log.info(`Round ${_currentRound}: peer ${batch.author_node_id} is at round ${batch.round} — fast-forwarding`);
      // Before discarding _myBatch, return its txs to the mempool so they're
      // drained again in the next _beginRound. Without this, txs we drained
      // but never got a cert for would be silently lost. Only needed when we
      // haven't already wrapped the batch in a cert — if _myCertificateCreated
      // is true, those txs live in the DAG permanently via our cert.
      if (_myBatch && !_myCertificateCreated) {
        const txs = _myBatch.txs || [];
        if (txs.length > 0) {
          let requeued = 0;
          for (const tx of txs) {
            const r = mempool.add(tx);
            if (r && r.added) requeued++;
          }
          log.info(`Fast-forward: returned ${requeued}/${txs.length} uncommitted txs to mempool`);
        }
      }
      _currentRound = batch.round;
      _resetRoundState();
      if (_roundTimer) { clearTimeout(_roundTimer); _roundTimer = null; }
      if (_nextRoundTimer) { clearTimeout(_nextRoundTimer); _nextRoundTimer = null; }
      // Kick off our own production at the new round, then fall through to
      // store + ack the peer batch below.
      _beginRound();
    }

    // Drop stale batches for older rounds (peer is behind; they'll catch up
    // via their own handleIncomingBatch when one of our batches reaches them).
    if (batch.round < _currentRound) {
      log.debug(`Round ${_currentRound}: ignoring stale batch for round ${batch.round} from ${batch.author_node_id}`);
      return;
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

    // Send ack
    const ack = createBatchAck(batch.hash, nodeId, privateKey);
    _recordAck(batch.hash, ack);

    // Broadcast ack on CONSENSUS topic
    try {
      const ackBuf = encode("BatchAck", {
        batchHash: hexToBytes(batch.hash),
        ackerNodeId: nodeId,
        signature: hexToBytes(ack.signature),
      });
      network.publish(network.TOPICS.CONSENSUS, ackBuf);
    } catch (err) {
      log.warn(`Failed to broadcast ack for batch ${batch.hash.slice(0, 16)}: ${err.message}`);
    }

    log.debug(`Round ${_currentRound}: received batch from ${batch.author_node_id} (${(batch.txs || []).length} txs)`);
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
      ack = {
        batch_hash: bytesToHex(ackMsg.batchHash) || "",
        acker_node_id: ackMsg.ackerNodeId || "",
        signature: bytesToHex(ackMsg.signature) || "",
      };
    } catch (err) {
      log.warn(`Failed to decode incoming ack: ${err.message}`);
      return;
    }

    if (!ack.batch_hash || !ack.acker_node_id || !ack.signature) {
      log.warn("Rejected ack with missing fields");
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

    const acks = _batchAcks.get(_myBatch.hash) || [];
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
        const certBuf = encode("Certificate", _serializeCertificate(existingOwn));
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

    // Persist
    _saveCertAndNotify(cert);
    _roundCertificates.set(nodeId, cert);
    _myCertificateCreated = true;

    // Broadcast on CERTIFICATES topic (enforce size limit)
    try {
      const certBuf = encode("Certificate", _serializeCertificate(cert));
      if (certBuf.length > CONSENSUS.CERTIFICATE_MAX_BYTES) {
        log.error(`Round ${_currentRound}: certificate too large (${certBuf.length} bytes, max ${CONSENSUS.CERTIFICATE_MAX_BYTES}) — not broadcast`);
      } else {
        network.publish(network.TOPICS.CERTIFICATES, certBuf);
      }
    } catch (err) {
      log.error(`Failed to broadcast certificate: ${err.message}`);
    }

    _metrics.certs_created++;
    log.debug(`Round ${_currentRound}: certificate created (${acks.length} acks, ${(cert.batch.txs || []).length} txs)`);

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
      cert = _deserializeCertificate(decode("Certificate", data));
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
    const quorum = computeQuorum(_getCommittee(cert.round).length);
    const result = verifyCertificate(cert, getNodeKey, quorum);
    if (!result.valid) {
      log.warn(`Rejected certificate from ${cert.author_node_id} round ${cert.round}: ${result.error}`);
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
   */
  function _saveCertAndNotify(cert) {
    dag.saveCertificate(cert);
    _onCertSaved(cert);
    _flushPendingForParent(cert.hash);
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
    const quorum = _getQuorum();
    if (_roundCertificates.size < quorum) return;

    _metrics.rounds_advanced++;
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

  function _serializeBatch(batch) {
    return {
      round: batch.round,
      authorNodeId: batch.author_node_id,
      txs: (batch.txs || []).map(tx => ({
        txId: tx.tx_id || "",
        txType: tx.tx_type || "",
        timestamp: tx.timestamp || "",
        prev: tx.prev || [],
        data: Buffer.from(JSON.stringify(tx.data || {})),
        signature: hexToBytes(tx.signature),
      })),
      signature: hexToBytes(batch.signature),
      hash: hexToBytes(batch.hash),
    };
  }

  function _deserializeBatch(msg) {
    if (!msg) return { round: 0, author_node_id: "", txs: [], signature: null, hash: null };
    return {
      round: msg.round || 0,
      author_node_id: msg.authorNodeId || "",
      txs: (msg.txs || []).map(tx => ({
        tx_id: tx.txId || "",
        tx_type: tx.txType || "",
        timestamp: tx.timestamp || "",
        prev: tx.prev || [],
        data: tx.data?.length ? (() => { try { return JSON.parse(bytesToUtf8(tx.data)); } catch { return {}; } })() : {},
        signature: bytesToHex(tx.signature),
      })),
      signature: bytesToHex(msg.signature),
      hash: bytesToHex(msg.hash),
    };
  }

  function _serializeCertificate(cert) {
    return {
      round: cert.round,
      authorNodeId: cert.author_node_id,
      batch: _serializeBatch(cert.batch),
      acknowledgments: (cert.acknowledgments || []).map(a => ({
        batchHash: hexToBytes(a.batch_hash),
        ackerNodeId: a.acker_node_id || "",
        signature: hexToBytes(a.signature),
      })),
      parentHashes: (cert.parent_hashes || []).map(h => hexToBytes(h)),
      signature: hexToBytes(cert.signature),
      hash: hexToBytes(cert.hash),
    };
  }

  function _deserializeCertificate(msg) {
    if (!msg) return { round: 0, author_node_id: "", batch: _deserializeBatch(null), acknowledgments: [], parent_hashes: [], signature: null, hash: null };
    return {
      round: msg.round || 0,
      author_node_id: msg.authorNodeId || "",
      batch: _deserializeBatch(msg.batch),
      acknowledgments: (msg.acknowledgments || []).map(a => ({
        batch_hash: bytesToHex(a.batchHash) || "",
        acker_node_id: a.ackerNodeId || "",
        signature: bytesToHex(a.signature) || "",
      })),
      parent_hashes: (msg.parentHashes || []).map(h => bytesToHex(h)).filter(Boolean),
      signature: bytesToHex(msg.signature),
      hash: bytesToHex(msg.hash),
    };
  }

  return {
    start,
    stop,
    currentRound,
    /** Enter sync mode — suppress all waking during sync */
    enterSyncMode() {
      _joinState = "syncing";
      log.notice("Entering sync mode — suppressing round production");
    },
    /**
     * Exit sync mode and resume normal operation. Uses peer's authoritative
     * latestRound (from SyncResponse) as the starting round; if not provided,
     * falls back to local DAG's latest round. Post-sync drift is handled by
     * handleIncomingBatch adopting higher rounds from incoming batches.
     * @param {number} [peerLatestRound]  Peer's current round from SyncResponse
     */
    exitSyncMode(peerLatestRound = 0) {
      const fromDag = dag.getLatestRound();
      const target = Math.max(peerLatestRound, fromDag) + 1;
      if (target > _currentRound) {
        const oldRound = _currentRound;
        _currentRound = target;
        // Any in-flight round state at the old round is now stale
        _resetRoundState();
        if (_roundTimer) { clearTimeout(_roundTimer); _roundTimer = null; }
        log.notice(`Round resynced: ${oldRound} → ${_currentRound} (peer latest: ${peerLatestRound}, dag latest: ${fromDag})`);
      }
      _joinState = "ready";
      log.notice(`Exiting sync mode — ready at round ${_currentRound}`);
      if (_running) _scheduleNextRound(0);
    },
    handleIncomingBatch,
    handleIncomingAck,
    handleIncomingCertificate,
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
      metrics: { ..._metrics },
    }),
  };
}

module.exports = { createNarwhal };
