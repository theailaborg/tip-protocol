/**
 * @file @tip-protocol/node/src/consensus/narwhal.js
 * @description Narwhal data availability layer for TIP consensus.
 *
 * Event-driven design:
 *   - IDLE when no work: zero certificates, zero DB writes, zero cost
 *   - Wakes on: local tx added to mempool, or peer batch received
 *   - Runs one complete wave (propose + vote) then returns to idle if no more work
 *
 * Each round (when active):
 *   1. Drain txs from mempool → create Batch → broadcast on MEMPOOL topic
 *   2. Receive batches from peers → send BatchAck on CONSENSUS topic
 *   3. Collect 2/3+ BatchAcks → create Certificate → broadcast on CERTIFICATES topic
 *   4. Collect 2/3+ Certificates → advance to next round → notify Bullshark
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
function createNarwhal({ dag, mempool, network, config, getNodeKey, getNodeCount, activeParticipants: _activeParticipants, onCommit, notePendingTxCert, hasPendingWork }) {
  const _notePending = typeof notePendingTxCert === "function" ? notePendingTxCert : () => { };
  const _hasPendingWork = typeof hasPendingWork === "function" ? hasPendingWork : () => false;
  let _currentRound;
  try { _currentRound = dag.getLatestRound() + 1; } catch { _currentRound = 1; }
  let _running = false;
  let _active = false;                              // false = idle, true = running rounds

  // Join state machine: controls when a joining node can start producing.
  //   "ready"               — normal operation, wake on txs and batches
  //   "syncing"             — sync in progress, suppress all waking
  //   "awaiting_peer_round" — sync done, wait for peer's batch to learn correct round
  let _joinState = "ready";
  let _roundTimer = null;
  let _retryTimer = null;
  let _batchWaitTimer = null;                       // batch accumulation timer

  // Per-round state
  let _myBatch = null;
  const _peerBatches = new Map();                   // nodeId → batch
  const _batchAcks = new Map();                     // batchHash → [ack, ack, ...]
  const _roundCertificates = new Map();             // nodeId → certificate
  let _myCertificateCreated = false;

  // _activeParticipants is shared with Bullshark via the orchestrator.
  // Nodes are added when we see their batches/certificates.
  // Quorum is based on this set, not the full registry.

  const nodeId = config.nodeRegisteredId || config.nodeId;
  const privateKey = config.nodePrivateKey;

  // ── Lifecycle ────────────────────────────────────────────────────────────

  /**
   * Start the Narwhal consensus layer.
   * Subscribes to mempool events but stays idle until work arrives.
   */
  function start() {
    if (_running) return;
    _running = true;

    // Subscribe to mempool — wake from idle when a tx arrives
    mempool.onTxAdded(() => {
      if (!_running) return;
      // Syncing or waiting for peer's round — don't wake yet.
      if (_joinState !== "ready") {
        log.debug(`Mempool tx added — suppressed wake (${_joinState})`);
        return;
      }
      _wake();
    });

    log.info(`Narwhal started at round ${_currentRound} (active: ${_activeParticipants.size}, registered: ${getNodeCount()}, quorum: ${_getQuorum()}) — idle, waiting for work`);

    // If mempool already has pending txs (restored from crash), wake immediately
    if (mempool.size() > 0) {
      _wake();
    }
  }

  /**
   * Stop the Narwhal consensus layer.
   */
  function stop() {
    _running = false;
    _active = false;
    if (_roundTimer) { clearTimeout(_roundTimer); _roundTimer = null; }
    if (_retryTimer) { clearTimeout(_retryTimer); _retryTimer = null; }
    if (_batchWaitTimer) { clearTimeout(_batchWaitTimer); _batchWaitTimer = null; }
    log.info("Narwhal stopped");
  }

  /**
   * Get current round number.
   */
  function currentRound() {
    return _currentRound;
  }

  // ── Wake / idle transitions ─────────────────────────────────────────────

  /**
   * Wake from idle state.
   * @param {boolean} [immediate=false]  Skip batch accumulation (e.g. peer sent a batch)
   */
  function _wake(immediate = false) {
    if (_active) return; // already running rounds
    _active = true;

    // If already waiting for batch accumulation, let it continue
    if (_batchWaitTimer) return;

    if (immediate) {
      // Peer is already running a round — start immediately to participate
      log.debug("Narwhal waking — immediate (peer activity)");
      _beginRound();
    } else {
      // Local tx — wait for more txs to accumulate (e.g. dispute = 9 txs together)
      _batchWaitTimer = setTimeout(() => {
        _batchWaitTimer = null;
        if (_running && _active) _beginRound();
      }, CONSENSUS.BATCH_WAIT_MS);
      log.debug(`Narwhal waking — accumulating batch (${CONSENSUS.BATCH_WAIT_MS}ms)`);
    }
  }

  /**
   * Check if we should go idle after a wave completes.
   * Safe for both single and multi-node: if a peer starts a round while
   * we're idle, their batch arrives via GossipSub → handleIncomingBatch
   * calls _wake() → we participate immediately.
   */
  function _checkIdle() {
    // Only check after even rounds (vote round done = wave complete)
    // _currentRound was already incremented, so it's now odd
    if (_currentRound % 2 !== 1) return;

    // Still have work in mempool
    if (mempool.size() > 0) return;

    // Drain-to-idle: a tx-carrying cert is in the DAG but Bullshark hasn't
    // ordered it yet. Keep producing rounds (empty batches ok) so a future
    // anchor commit can sweep its causal history into the ordered set.
    if (_hasPendingWork()) {
      log.debug(`Round ${_currentRound}: staying active — pending commit work`);
      return;
    }

    // No work → go idle (works for single and multi-node)
    _active = false;
    if (_roundTimer) { clearTimeout(_roundTimer); _roundTimer = null; }
    if (_retryTimer) { clearTimeout(_retryTimer); _retryTimer = null; }
    log.debug(`Round ${_currentRound}: idle — no pending work`);
  }

  // ── Round lifecycle ──────────────────────────────────────────────────────

  function _beginRound() {
    if (!_running || !_active) return;

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
      log.info(`Round ${_currentRound}: batch created with ${txs.length} txs`);
    } else {
      log.debug(`Round ${_currentRound}: empty batch (vote round)`);
    }

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
        if (_running && _active && _roundCertificates.size < _getQuorum()) {
          _scheduleRetry();
        }
      }, CONSENSUS.ROUND_TIMEOUT_MS);
    }
  }

  /**
   * Periodic retry when round can't advance (e.g. waiting for peers).
   */
  function _scheduleRetry() {
    if (_retryTimer || !_running || !_active) return;
    _retryTimer = setTimeout(() => {
      _retryTimer = null;
      if (!_running || !_active) return;
      _tryCreateCertificate();
      _tryAdvanceRound();
      // Keep retrying if still stuck
      if (_running && _active && _roundCertificates.size < _getQuorum()) {
        _scheduleRetry();
      }
    }, CONSENSUS.ROUND_TIMEOUT_MS);
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

    // After sync — adopt peer's round as truth and transition to ready.
    if (_joinState === "awaiting_peer_round") {
      if (batch.round !== _currentRound) {
        log.info(`Adopting peer round ${batch.round} (was ${_currentRound})`);
        _currentRound = batch.round;
      }
      _joinState = "ready";
      log.info(`Peer round received — ready to participate at round ${_currentRound}`);
    }

    // Normal operation — if idle and peer is ahead, adopt their round.
    if (_joinState === "ready" && !_active && batch.round > _currentRound) {
      log.info(`Adopting peer round ${batch.round} (was ${_currentRound})`);
      _currentRound = batch.round;
    }

    // Only accept batches for current round
    if (batch.round !== _currentRound) {
      log.debug(`Round ${_currentRound}: ignoring batch for round ${batch.round} from ${batch.author_node_id}`);
      return;
    }

    // Peer is active — wake up immediately to participate
    if (!_active) _wake(true);

    // Deduplicate
    if (_peerBatches.has(batch.author_node_id)) return;

    _peerBatches.set(batch.author_node_id, batch);

    // Track as active participant (affects quorum from next round)
    if (!_activeParticipants.has(batch.author_node_id)) {
      _activeParticipants.add(batch.author_node_id);
      log.info(`Active participant joined: ${batch.author_node_id} (active: ${_activeParticipants.size}, quorum: ${_getQuorum()})`);
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

    // Parent certificate hashes from previous round
    const parentHashes = _currentRound > 1
      ? dag.getCertificatesByRound(_currentRound - 1).map(c => c.hash)
      : [];

    const cert = createCertificate(
      _currentRound, nodeId, _myBatch, acks, parentHashes, privateKey
    );

    // Persist
    dag.saveCertificate(cert);
    _roundCertificates.set(nodeId, cert);
    _myCertificateCreated = true;

    // Drain-to-idle: register pending commit work if this cert carries txs.
    if ((cert.batch?.txs || []).length > 0) _notePending(cert);

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

    log.info(`Round ${_currentRound}: certificate created (${acks.length} acks, ${(cert.batch.txs || []).length} txs)`);

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

    // Skip if already persisted
    if (dag.getCertificate(cert.hash)) return;

    // Full verification
    const quorum = _getQuorum();
    const result = verifyCertificate(cert, getNodeKey, quorum);
    if (!result.valid) {
      log.warn(`Rejected certificate from ${cert.author_node_id} round ${cert.round}: ${result.error}`);
      return;
    }

    // Persist
    dag.saveCertificate(cert);

    // Drain-to-idle: register pending commit work if the peer's cert carries txs.
    if ((cert.batch?.txs || []).length > 0) _notePending(cert);

    // Track if current round — peer is in sync and actively participating
    if (cert.round === _currentRound) {
      _roundCertificates.set(cert.author_node_id, cert);

      // Add to active participants only when peer is producing current-round certs
      if (!_activeParticipants.has(cert.author_node_id)) {
        _activeParticipants.add(cert.author_node_id);
        log.info(`Active participant joined: ${cert.author_node_id} (active: ${_activeParticipants.size}, quorum: ${_getQuorum()})`);
      }

      _tryAdvanceRound();
    }

    // Remove committed txs from our mempool
    const txIds = (cert.batch?.txs || []).map(t => t.tx_id).filter(Boolean);
    if (txIds.length > 0) mempool.remove(txIds);

    log.debug(`Round ${cert.round}: received certificate from ${cert.author_node_id} (${(cert.batch?.txs || []).length} txs)`);
  }

  // ── Round advancement ────────────────────────────────────────────────────

  function _tryAdvanceRound() {
    const quorum = _getQuorum();
    if (_roundCertificates.size < quorum) return;

    log.info(`Round ${_currentRound}: advancing (${_roundCertificates.size}/${_activeParticipants.size} certificates)`);

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

    // Check if we should go idle (only after even rounds — wave complete)
    _checkIdle();

    // If still active, start next round
    if (_active && _running) {
      // Use batch_wait_ms if mempool has new txs, otherwise start immediately
      // (vote round shouldn't wait — it needs to happen promptly)
      const hasNewTxs = mempool.size() > 0;
      const delay = hasNewTxs ? CONSENSUS.BATCH_WAIT_MS : 0;
      setTimeout(() => _beginRound(), delay);
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  function _getQuorum() {
    return computeQuorum(_activeParticipants.size);
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
    /** Enter sync mode — suppress all waking until sync + first peer batch */
    enterSyncMode() {
      _joinState = "syncing";
      log.info("Entering sync mode — suppressing round production");
    },
    /** Exit sync mode — nothing to sync, go back to normal operation */
    exitSyncMode() {
      _joinState = "ready";
      log.info("Exiting sync mode — no certificates to sync, resuming normal operation");
    },
    /** Advance _currentRound after certificate sync, then wait for peer's batch */
    resyncRound() {
      const synced = dag.getLatestRound();
      if (synced >= _currentRound) {
        const oldRound = _currentRound;
        _currentRound = synced + 1;
        log.info(`Round resynced: ${oldRound} → ${_currentRound}`);
      }
      _joinState = "awaiting_peer_round";
      log.info(`Awaiting peer batch for exact round (current: ${_currentRound})`);
    },
    handleIncomingBatch,
    handleIncomingAck,
    handleIncomingCertificate,
    stats: () => ({
      round: _currentRound,
      running: _running,
      active: _active,
      batchesThisRound: _peerBatches.size,
      certificatesThisRound: _roundCertificates.size,
      quorum: _getQuorum(),
      activeParticipants: _activeParticipants.size,
      registeredNodes: getNodeCount(),
      mempoolSize: mempool.size(),
    }),
  };
}

module.exports = { createNarwhal };
