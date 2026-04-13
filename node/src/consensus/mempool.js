/**
 * @file @tip-protocol/node/src/consensus/mempool.js
 * @description Transaction mempool for Narwhal consensus.
 *
 * Holds validated transactions that have been accepted via the API
 * but not yet included in a certificate (and thus not yet ordered/committed).
 *
 * Features:
 *   - Dedup by tx_id (no duplicate txs)
 *   - Max size cap (reject when full)
 *   - Drain: returns and removes txs for certificate creation
 *   - Age-based eviction (txs older than TTL are dropped)
 *   - Thread-safe for single-threaded Node.js (no locking needed)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");
const { getLogger } = require("../logger");

const log = getLogger("tip.mempool");

/**
 * @param {Object} [options]  Override genesis defaults (mainly for testing)
 * @param {number} [options.maxSize]       Max pending txs
 * @param {number} [options.maxTxAgeSec]   Evict txs older than this
 */
function createMempool(options = {}) {
  const maxSize = options.maxSize || CONSENSUS.MEMPOOL_MAX_SIZE;
  const maxTxAgeSec = options.maxTxAgeSec || CONSENSUS.MEMPOOL_TX_TTL_SECONDS;
  /** @type {Map<string, { tx: Object, receivedAt: number }>} */
  const _pending = new Map();

  /**
   * Add a validated tx to the mempool.
   * @param {Object} tx  A validated transaction (must have tx_id)
   * @returns {{ added: boolean, reason?: string }}
   */
  function add(tx) {
    if (!tx || !tx.tx_id) {
      return { added: false, reason: "tx missing tx_id" };
    }

    if (_pending.has(tx.tx_id)) {
      return { added: false, reason: "duplicate" };
    }

    if (_pending.size >= maxSize) {
      log.warn(`Mempool full (${maxSize}), rejecting tx ${tx.tx_id}`);
      return { added: false, reason: "mempool_full" };
    }

    _pending.set(tx.tx_id, { tx, receivedAt: Date.now() });
    return { added: true };
  }

  /**
   * Drain up to `limit` txs from the mempool for certificate creation.
   * Removes drained txs from the pool. Evicts stale txs first.
   * @param {number} limit  Max txs to drain (default: 500)
   * @returns {Array<Object>}  The drained txs
   */
  function drain(limit = CONSENSUS.MAX_TXS_PER_CERTIFICATE) {
    _evictStale();

    const drained = [];
    for (const [txId, entry] of _pending) {
      if (drained.length >= limit) break;
      drained.push(entry.tx);
      _pending.delete(txId);
    }

    if (drained.length > 0) {
      log.debug(`Mempool drained ${drained.length} txs (${_pending.size} remaining)`);
    }

    return drained;
  }

  /**
   * Remove specific tx_ids from the mempool.
   * Used when txs are committed via a certificate from another node.
   * @param {Array<string>} txIds
   * @returns {number}  Count of removed txs
   */
  function remove(txIds) {
    let removed = 0;
    for (const id of txIds) {
      if (_pending.delete(id)) removed++;
    }
    return removed;
  }

  /**
   * Check if a tx_id is in the mempool.
   * @param {string} txId
   * @returns {boolean}
   */
  function has(txId) {
    return _pending.has(txId);
  }

  /**
   * Get all pending txs (without removing).
   * Used for mempool gossip — sharing pending txs with peers.
   * @returns {Array<Object>}
   */
  function getAll() {
    _evictStale();
    return Array.from(_pending.values()).map(e => e.tx);
  }

  /**
   * Current mempool size.
   * @returns {number}
   */
  function size() {
    return _pending.size;
  }

  /**
   * Clear all pending txs.
   */
  function clear() {
    _pending.clear();
  }

  /**
   * Remove txs that have been in the mempool too long.
   * Prevents stale txs from accumulating if they're never included in a certificate.
   */
  function _evictStale() {
    const cutoff = Date.now() - (maxTxAgeSec * 1000);
    let evicted = 0;
    for (const [txId, entry] of _pending) {
      if (entry.receivedAt < cutoff) {
        _pending.delete(txId);
        evicted++;
      }
    }
    if (evicted > 0) {
      log.info(`Mempool evicted ${evicted} stale txs (older than ${maxTxAgeSec}s)`);
    }
  }

  /**
   * Mempool stats for monitoring.
   * @returns {{ size: number, maxSize: number, oldestAgeSec: number | null }}
   */
  function stats() {
    let oldestAge = null;
    for (const entry of _pending.values()) {
      const age = (Date.now() - entry.receivedAt) / 1000;
      if (oldestAge === null || age > oldestAge) oldestAge = age;
    }
    return {
      size: _pending.size,
      maxSize,
      oldestAgeSec: oldestAge ? Math.round(oldestAge) : null,
    };
  }

  return { add, drain, remove, has, getAll, size, clear, stats };
}

module.exports = { createMempool };
