/**
 * @file @tip-protocol/node/src/consensus/mempool.js
 * @description Persistent transaction mempool for Narwhal consensus.
 *
 * Holds validated transactions that have been accepted via the API
 * but not yet included in a certificate (and thus not yet ordered/committed).
 *
 * Features:
 *   - Disk persistence: every tx written to SQLite via dag.saveMempoolTx()
 *   - Restored on restart: reloads pending txs from disk
 *   - Dedup by tx_id (no duplicate txs)
 *   - Max size cap (reject when full)
 *   - Drain: returns and removes txs for certificate creation
 *   - Age-based eviction (txs older than TTL are dropped)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");
const { TX_REJECTION_REASON } = require("../../../shared/constants");
const { getLogger } = require("../logger");

const log = getLogger("tip.mempool");

/**
 * @param {Object}  dag               DAG instance (for disk persistence)
 * @param {Object}  [options]         Override genesis defaults (mainly for testing)
 * @param {number}  [options.maxSize]
 * @param {number}  [options.maxTxAgeSec]
 * @param {string}  [options.nodeId]  Stamped onto tx_rejection rows as
 *                                    `dropper_node_id`. Falls back to
 *                                    "unknown" for tests that don't
 *                                    care about attribution.
 */
function createMempool(dag, options = {}) {
  const maxSize = options.maxSize || CONSENSUS.MEMPOOL_MAX_SIZE;
  const maxTxAgeSec = options.maxTxAgeSec || CONSENSUS.MEMPOOL_TX_TTL_SECONDS;
  const nodeId = options.nodeId || "unknown";

  // ── tx_rejections sink (#64 follow-up — no-loss invariant) ────────────
  // Single helper used by every mempool drop site so the rejection-row
  // shape is uniform. Skipped when dag.saveTxRejection is missing
  // (in-memory test stubs) and when tx has no tx_id (can't index the
  // PK; that case is a caller bug, not user-visible loss).
  function _persistRejection(tx, reason, detail) {
    if (!tx || !tx.tx_id) return;
    if (!dag || typeof dag.saveTxRejection !== "function") return;
    try {
      dag.saveTxRejection({
        tx_id:           tx.tx_id,
        reason,
        reason_detail:   detail || null,
        dropper_node_id: nodeId,
        tx_type:         tx.tx_type || null,
        tx_data:         tx,  // full body for replay / forensics
      });
    } catch (err) {
      log.warn(`tx_rejection persist failed for ${tx.tx_id}: ${err.message}`);
    }
  }

  /** @type {Map<string, { tx: Object, receivedAt: number }>} */
  const _pending = new Map();

  /** @type {Function|null} Callback when a tx is added (used by Narwhal to wake from idle) */
  let _onTxAdded = null;

  // Cumulative counters for observability — gauges miss fast tx flow because
  // a tx typically lives in the mempool for ~2-4s while Prometheus scrapes
  // at ~5s intervals. Counters never miss; rate(received_total[1m]) gives
  // submission rate, rate(drained_total[1m]) gives commit rate.
  const _counters = { received_total: 0, drained_total: 0, evicted_total: 0, rejected_total: 0 };

  // ── Restore from disk on startup ────────────────────────────────────────
  if (dag && typeof dag.getMempoolTxs === "function") {
    try {
      const persisted = dag.getMempoolTxs();
      for (const tx of persisted) {
        if (tx && tx.tx_id) {
          _pending.set(tx.tx_id, { tx, receivedAt: Date.now() });
        }
      }
      if (persisted.length > 0) {
        log.info(`Mempool restored ${persisted.length} pending txs from disk`);
      }
    } catch (err) {
      log.warn(`Mempool restore failed: ${err.message}`);
    }
  }

  /**
   * Add a validated tx to the mempool.
   * Persists to disk immediately for crash recovery.
   * @param {Object} tx  A validated transaction (must have tx_id)
   * @returns {{ added: boolean, reason?: string }}
   */
  function add(tx) {
    if (!tx || !tx.tx_id) {
      _counters.rejected_total++;
      return { added: false, reason: "tx missing tx_id" };
    }

    if (_pending.has(tx.tx_id)) {
      _counters.rejected_total++;
      return { added: false, reason: "duplicate" };
    }

    if (_pending.size >= maxSize) {
      _counters.rejected_total++;
      _persistRejection(tx, TX_REJECTION_REASON.MEMPOOL_FULL, `cap=${maxSize}`);
      log.warn(`Mempool full (${maxSize}), rejecting tx ${tx.tx_id}`);
      return { added: false, reason: "mempool_full" };
    }

    _pending.set(tx.tx_id, { tx, receivedAt: Date.now() });
    _counters.received_total++;

    // Persist to disk
    if (dag && typeof dag.saveMempoolTx === "function") {
      try { dag.saveMempoolTx(tx); } catch (err) {
        log.warn(`Mempool persist failed for ${tx.tx_id}: ${err.message}`);
      }
    }

    // Notify listener (Narwhal wakes from idle)
    if (_onTxAdded) _onTxAdded(tx);

    return { added: true };
  }

  /**
   * Drain up to `limit` txs from the mempool for certificate creation.
   * Removes drained txs from memory and disk. Evicts stale txs first.
   * @param {number} limit  Max txs to drain
   * @returns {Array<Object>}  The drained txs
   */
  function drain(limit = CONSENSUS.MAX_TXS_PER_CERTIFICATE) {
    _evictStale();

    const drained = [];
    const drainedIds = [];
    for (const [txId, entry] of _pending) {
      if (drained.length >= limit) break;
      drained.push(entry.tx);
      drainedIds.push(txId);
    }

    // Remove from memory
    for (const id of drainedIds) _pending.delete(id);
    _counters.drained_total += drained.length;

    // Remove from disk
    if (drainedIds.length > 0 && dag && typeof dag.deleteMempoolTxs === "function") {
      try { dag.deleteMempoolTxs(drainedIds); } catch (err) {
        log.warn(`Mempool disk cleanup failed: ${err.message}`);
      }
    }

    if (drained.length > 0) {
      log.debug(`Mempool drained ${drained.length} txs (${_pending.size} remaining)`);
    }

    return drained;
  }

  /**
   * Remove specific tx_ids from the mempool (memory + disk).
   * Used when txs are committed via a certificate from another node.
   * @param {Array<string>} txIds
   * @returns {number}  Count of removed txs
   */
  function remove(txIds) {
    let removed = 0;
    const toDelete = [];
    for (const id of txIds) {
      if (_pending.delete(id)) {
        removed++;
        toDelete.push(id);
      }
    }
    if (toDelete.length > 0 && dag && typeof dag.deleteMempoolTxs === "function") {
      try { dag.deleteMempoolTxs(toDelete); } catch (err) {
        log.warn(`Mempool disk remove failed: ${err.message}`);
      }
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
   * Clear all pending txs (memory + disk).
   */
  function clear() {
    const ids = Array.from(_pending.keys());
    _pending.clear();
    if (ids.length > 0 && dag && typeof dag.deleteMempoolTxs === "function") {
      try { dag.deleteMempoolTxs(ids); } catch (err) {
        log.warn(`Mempool disk clear failed: ${err.message}`);
      }
    }
  }

  /**
   * Remove txs that have been in the mempool too long.
   * Cleans both memory and disk.
   */
  function _evictStale() {
    const cutoff = Date.now() - (maxTxAgeSec * 1000);
    const evicted = [];
    for (const [txId, entry] of _pending) {
      if (entry.receivedAt < cutoff) {
        _pending.delete(txId);
        evicted.push(txId);
      }
    }
    if (evicted.length > 0) {
      _counters.evicted_total += evicted.length;
      log.info(`Mempool evicted ${evicted.length} stale txs (older than ${maxTxAgeSec}s)`);
      if (dag && typeof dag.deleteMempoolTxs === "function") {
        try { dag.deleteMempoolTxs(evicted); } catch (err) {
          log.warn(`Mempool disk eviction failed: ${err.message}`);
        }
      }
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
      // null only when mempool is empty. A just-added entry has age ~0;
      // truthy-checking `oldestAge` would round 0 to null and conflate
      // "no entries" with "entries present but fresh".
      oldestAgeSec: oldestAge === null ? null : Math.round(oldestAge),
      // Cumulative counters — never miss transient tx flow that the
      // gauge sees-only-at-scrape-time. rate(received_total[1m]) =
      // submission rate; rate(drained_total[1m]) = commit-into-batch
      // rate; ratio of drained:received over a window ≈ throughput.
      counters: { ..._counters },
    };
  }

  /**
   * Register a callback for when a tx is added.
   * @param {Function} fn  Called with (tx) when a new tx enters the mempool
   */
  function onTxAdded(fn) { _onTxAdded = fn; }

  /**
   * Re-insert an orphaned tx at the FRONT of the drain order — used by
   * narwhal._resetRoundState when our own batch advances uncertified
   * (#64). The tx was originally submitted earlier than every current
   * mempool entry; appending it would put it behind newer arrivals and
   * starve it indefinitely under load. Prepending preserves the
   * "older = drained first" semantics. The receivedAt is preserved
   * from the caller (the original submit time, not "now") so age-based
   * eviction also behaves correctly.
   *
   * Cost: O(n) Map rebuild. Only fires on natural orphan events, which
   * are rare in healthy operation; under load each occurrence
   * represents one tx-bearing round that didn't certify, not a
   * per-tx hot path.
   *
   * @param {Object} tx           A validated transaction (must have tx_id)
   * @param {number} receivedAt   Original submit timestamp (epoch ms)
   * @returns {{ added: boolean, reason?: string }}
   */
  function addFront(tx, receivedAt) {
    if (!tx || !tx.tx_id) {
      _counters.rejected_total++;
      return { added: false, reason: "tx missing tx_id" };
    }
    if (_pending.has(tx.tx_id)) {
      // Already in mempool — common after partial requeue or double-submit.
      // Not an error; just leave the existing entry in place.
      return { added: false, reason: "duplicate" };
    }
    if (_pending.size >= maxSize) {
      _counters.rejected_total++;
      _persistRejection(tx, TX_REJECTION_REASON.MEMPOOL_FULL, `cap=${maxSize} (front-load)`);
      log.warn(`Mempool full (${maxSize}), rejecting front-load tx ${tx.tx_id}`);
      return { added: false, reason: "mempool_full" };
    }

    // Rebuild the Map with this entry first to preserve insertion-order
    // semantics for `drain()`. JS Maps don't expose a prepend; pivoting
    // through a fresh Map is the standard pattern.
    const restored = new Map();
    restored.set(tx.tx_id, { tx, receivedAt: receivedAt || Date.now() });
    for (const [k, v] of _pending) restored.set(k, v);
    _pending.clear();
    for (const [k, v] of restored) _pending.set(k, v);

    _counters.received_total++;

    if (dag && typeof dag.saveMempoolTx === "function") {
      try { dag.saveMempoolTx(tx); } catch (err) {
        log.warn(`Mempool persist failed for ${tx.tx_id}: ${err.message}`);
      }
    }
    if (_onTxAdded) _onTxAdded(tx);
    return { added: true };
  }

  return { add, addFront, drain, remove, has, getAll, size, clear, stats, onTxAdded };
}

module.exports = { createMempool };
