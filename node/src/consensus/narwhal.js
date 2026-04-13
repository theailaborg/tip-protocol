/**
 * @file @tip-protocol/node/src/consensus/narwhal.js
 * @description Narwhal data availability layer for TIP consensus.
 *
 * Each round:
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
const { encode, decode } = require("../network/proto");
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
function createNarwhal({ dag, mempool, network, config, getNodeKey, getNodeCount, onCommit }) {
  let _currentRound = dag.getLatestRound() + 1;
  let _running = false;
  let _roundTimer = null;
  let _retryTimer = null;

  // Per-round state
  let _myBatch = null;
  const _peerBatches = new Map();               // nodeId → batch
  const _batchAcks = new Map();                 // batchHash → [ack, ack, ...]
  const _roundCertificates = new Map();         // nodeId → certificate
  let _myCertificateCreated = false;

  const nodeId = config.nodeRegisteredId || config.nodeId;
  const privateKey = config.nodePrivateKey;

  // ── Lifecycle ────────────────────────────────────────────────────────────

  /**
   * Start the Narwhal round loop.
   */
  function start() {
    if (_running) return;
    _running = true;
    log.info(`Narwhal started at round ${_currentRound} (quorum: ${_getQuorum()}/${getNodeCount()})`);
    _beginRound();
  }

  /**
   * Stop the Narwhal round loop.
   */
  function stop() {
    _running = false;
    if (_roundTimer) { clearTimeout(_roundTimer); _roundTimer = null; }
    if (_retryTimer) { clearTimeout(_retryTimer); _retryTimer = null; }
    log.info("Narwhal stopped");
  }

  /**
   * Get current round number.
   */
  function currentRound() {
    return _currentRound;
  }

  // ── Round lifecycle ──────────────────────────────────────────────────────

  function _beginRound() {
    if (!_running) return;

    _resetRoundState();

    // Phase 1: Create batch from mempool and broadcast
    const txs = mempool.drain(CONSENSUS.MAX_TXS_PER_CERTIFICATE);

    // If no txs AND no connected peers, wait before retrying — avoids empty certificate spam
    if (txs.length === 0 && network.peerCount() === 0) {
      log.debug(`Round ${_currentRound}: idle — no txs, no peers`);
      _roundTimer = setTimeout(() => { _roundTimer = null; if (_running) _beginRound(); }, CONSENSUS.ROUND_TIMEOUT_MS);
      return;
    }

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
      log.debug(`Round ${_currentRound}: empty batch`);
    }

    // Self-ack our own batch
    _recordAck(_myBatch.hash, createBatchAck(_myBatch.hash, nodeId, privateKey));

    // Try certificate immediately (works in single-node mode where quorum=1)
    _tryCreateCertificate();

    // Round timeout — retry certificate creation + check advancement
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

  /**
   * Periodic retry when round can't advance (e.g. waiting for peers).
   */
  function _scheduleRetry() {
    if (_retryTimer || !_running) return;
    _retryTimer = setTimeout(() => {
      _retryTimer = null;
      if (!_running) return;
      _tryCreateCertificate();
      _tryAdvanceRound();
      // Keep retrying if still stuck
      if (_running && _roundCertificates.size < _getQuorum()) {
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

    // Only accept batches for current round
    if (batch.round !== _currentRound) {
      log.debug(`Round ${_currentRound}: ignoring batch for round ${batch.round} from ${batch.author_node_id}`);
      return;
    }

    // Deduplicate
    if (_peerBatches.has(batch.author_node_id)) return;

    _peerBatches.set(batch.author_node_id, batch);

    // Send ack
    const ack = createBatchAck(batch.hash, nodeId, privateKey);
    _recordAck(batch.hash, ack);

    // Broadcast ack on CONSENSUS topic
    try {
      const ackBuf = encode("BatchAck", {
        batchHash: Buffer.from(batch.hash, "hex"),
        ackerNodeId: nodeId,
        signature: Buffer.from(ack.signature, "hex"),
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
        batch_hash: ackMsg.batchHash?.toString("hex") || "",
        acker_node_id: ackMsg.ackerNodeId || "",
        signature: ackMsg.signature?.toString("hex") || "",
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

    // Broadcast on CERTIFICATES topic
    try {
      const certBuf = encode("Certificate", _serializeCertificate(cert));
      network.publish(network.TOPICS.CERTIFICATES, certBuf);
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

    // Track if current round
    if (cert.round === _currentRound) {
      _roundCertificates.set(cert.author_node_id, cert);
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

    log.info(`Round ${_currentRound}: advancing (${_roundCertificates.size}/${getNodeCount()} certificates)`);

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

    // Start next round after minimum interval (prevents spinning on empty rounds)
    if (_running) {
      setTimeout(() => _beginRound(), CONSENSUS.ROUND_TIMEOUT_MS);
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  function _getQuorum() {
    return computeQuorum(getNodeCount());
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
        signature: tx.signature ? Buffer.from(tx.signature, "hex") : Buffer.alloc(0),
      })),
      signature: batch.signature ? Buffer.from(batch.signature, "hex") : Buffer.alloc(0),
      hash: batch.hash ? Buffer.from(batch.hash, "hex") : Buffer.alloc(0),
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
        data: tx.data?.length ? JSON.parse(tx.data.toString()) : {},
        signature: tx.signature?.length ? tx.signature.toString("hex") : null,
      })),
      signature: msg.signature?.length ? msg.signature.toString("hex") : null,
      hash: msg.hash?.length ? msg.hash.toString("hex") : null,
    };
  }

  function _serializeCertificate(cert) {
    return {
      round: cert.round,
      authorNodeId: cert.author_node_id,
      batch: _serializeBatch(cert.batch),
      acknowledgments: (cert.acknowledgments || []).map(a => ({
        batchHash: Buffer.from(a.batch_hash || "", "hex"),
        ackerNodeId: a.acker_node_id || "",
        signature: Buffer.from(a.signature || "", "hex"),
      })),
      parentHashes: (cert.parent_hashes || []).map(h => Buffer.from(h, "hex")),
      signature: cert.signature ? Buffer.from(cert.signature, "hex") : Buffer.alloc(0),
      hash: cert.hash ? Buffer.from(cert.hash, "hex") : Buffer.alloc(0),
    };
  }

  function _deserializeCertificate(msg) {
    if (!msg) return { round: 0, author_node_id: "", batch: _deserializeBatch(null), acknowledgments: [], parent_hashes: [], signature: null, hash: null };
    return {
      round: msg.round || 0,
      author_node_id: msg.authorNodeId || "",
      batch: _deserializeBatch(msg.batch),
      acknowledgments: (msg.acknowledgments || []).map(a => ({
        batch_hash: a.batchHash?.toString("hex") || "",
        acker_node_id: a.ackerNodeId || "",
        signature: a.signature?.toString("hex") || "",
      })),
      parent_hashes: (msg.parentHashes || []).map(h => h.toString("hex")),
      signature: msg.signature?.length ? msg.signature.toString("hex") : null,
      hash: msg.hash?.length ? msg.hash.toString("hex") : null,
    };
  }

  return {
    start,
    stop,
    currentRound,
    handleIncomingBatch,
    handleIncomingAck,
    handleIncomingCertificate,
    stats: () => ({
      round: _currentRound,
      running: _running,
      batchesThisRound: _peerBatches.size,
      certificatesThisRound: _roundCertificates.size,
      quorum: _getQuorum(),
      nodeCount: getNodeCount(),
      mempoolSize: mempool.size(),
    }),
  };
}

module.exports = { createNarwhal };
