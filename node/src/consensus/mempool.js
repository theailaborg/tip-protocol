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

const { nowMs } = require("../../../shared/time");

const { CONSENSUS } = require("../../../shared/protocol-constants");
const { TX_REJECTION_REASON } = require("../../../shared/constants");
const { createRejectionSink } = require("./tx-rejection-sink");
const { ownerOf: _defaultOwnerOf, ownerKey } = require("./tx-owner");
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
  // Injectable so unit tests can stub owner resolution without full signature
  // machinery; production uses the real signer-entity resolver.
  const _ownerOf = typeof options.ownerOf === "function" ? options.ownerOf : _defaultOwnerOf;

  // tx_rejections sink (#64) — shared with commit-handler so every
  // drop site in the codebase produces identically-shaped rows.
  const _persistRejection = createRejectionSink({ dag, nodeId: options.nodeId });

  /** @type {Map<string, { tx: Object, receivedAt: number }>} */
  const _pending = new Map();

  // Gossip has no drop memory: without tombstones peers re-add dead copies
  // forever (~3.2k foreign drops per peer per burst, 2026-07-12). Pruned
  // after maxTxAgeSec, once every live copy has aged out of peers' mempools.
  /** @type {Map<string, number>} */
  const _tombstones = new Map();

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
          _pending.set(tx.tx_id, { tx, receivedAt: nowMs() });
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

    if (_tombstones.has(tx.tx_id)) {
      _counters.rejected_total++;
      return { added: false, reason: "tombstoned" };
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

    // Over-budget tx can never ride a valid cert; admitting it would
    // head-of-line block drain forever (drain always takes the first tx).
    const txBytes = Buffer.byteLength(JSON.stringify(tx));
    if (txBytes > _batchByteBudget()) {
      _counters.rejected_total++;
      log.warn(`Rejecting oversized tx ${tx.tx_id} (${txBytes} bytes > batch budget)`);
      return { added: false, reason: "tx_too_large" };
    }

    _pending.set(tx.tx_id, { tx, receivedAt: nowMs() });
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
  // 85% of the cert cap: headroom for 2f+1 acks + parent refs + framing
  // (~3.4KB/ack covers committees to ~60). A full-count batch of large
  // post-quantum-signed txs can otherwise exceed CERTIFICATE_MAX_BYTES and
  // peers reject the cert, stalling consensus (live halt, 2026-07-04).
  const _batchByteBudget = () => Math.floor(CONSENSUS.CERTIFICATE_MAX_BYTES * 0.85);

  // Owner-lane resolution memoized on the entry: drain scans the whole
  // mempool each round and ownerOf parses signer fields, so recomputing per
  // scan is wasteful (owner is immutable per tx).
  function _laneOf(entry) {
    if (entry._laneComputed) return entry._lane;
    let lane = null;
    try { const o = _ownerOf(entry.tx); lane = o ? ownerKey(o) : null; }
    catch { lane = null; }
    entry._lane = lane;
    entry._laneComputed = true;
    return lane;
  }

  function drain(limit = CONSENSUS.MAX_TXS_PER_CERTIFICATE) {
    _evictStale();

    const byteBudget = _batchByteBudget();
    const drained = [];
    const drainedIds = [];
    let bytes = 0;

    // Emit each owner lane in prev-link DEPENDENCY order: insertion order lies
    // (requeue addFront reverses chains; ~11x stale churn per tx, 2026-07-12).
    // Siblings: first wins, rest held. Owner-less txs are never restricted.
    const laneMembers = new Map();   // lane -> Set<tx_id>
    const laneByPrev = new Map();    // lane -> Map<prev0, [txId, entry]>
    for (const [txId, entry] of _pending) {
      const lane = _laneOf(entry);
      if (lane === null) continue;
      if (!laneMembers.has(lane)) { laneMembers.set(lane, new Set()); laneByPrev.set(lane, new Map()); }
      laneMembers.get(lane).add(txId);
      const prev0 = (entry.tx.prev && entry.tx.prev[0]) || null;
      const byPrev = laneByPrev.get(lane);
      if (!byPrev.has(prev0)) byPrev.set(prev0, [txId, entry]);   // later siblings held
    }

    const _take = (txId, entry) => {
      if (drained.length >= limit) return false;
      const sz = entry.tx?._wireBytes || Buffer.byteLength(JSON.stringify(entry.tx));
      if (drained.length > 0 && bytes + sz > byteBudget) return false;
      drained.push(entry.tx);
      drainedIds.push(txId);
      bytes += sz;
      return true;
    };

    const laneDone = new Set();
    let stop = false;
    for (const [txId, entry] of _pending) {
      if (stop) break;
      const lane = _laneOf(entry);
      if (lane === null) { if (!_take(txId, entry)) stop = true; continue; }
      if (laneDone.has(lane)) continue;
      laneDone.add(lane);
      // Chain base: the member whose prev0 is NOT another member's tx_id ,
      // it hangs off already-committed (or in-flight) state, so it's the only
      // tx in the lane that can possibly commit this round.
      const members = laneMembers.get(lane);
      const byPrev = laneByPrev.get(lane);
      let cur = null;
      for (const [p0, pair] of byPrev) { if (!members.has(p0)) { cur = pair; break; } }
      // No base (members only reference each other): hold the lane this round.
      const seen = new Set();
      while (cur && !seen.has(cur[0])) {
        seen.add(cur[0]);
        if (!_take(cur[0], cur[1])) { stop = true; break; }
        cur = byPrev.get(cur[0]) || null;   // continuation chains onto the taken tx
      }
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
  /**
   * Mark a tx_id permanently dead (rebuilt away, foreign-signed stale, or
   * revalidation-failed); late copies from gossip/peer batches are rejected.
   * @param {string} txId
   */
  function tombstone(txId) {
    if (typeof txId !== "string" || txId.length === 0) return;
    _tombstones.set(txId, nowMs());
    if (_pending.delete(txId) && dag && typeof dag.deleteMempoolTxs === "function") {
      try { dag.deleteMempoolTxs([txId]); } catch (err) {
        log.warn(`Mempool tombstone disk cleanup failed: ${err.message}`);
      }
    }
  }

  function isTombstoned(txId) {
    return _tombstones.has(txId);
  }

  function _evictStale() {
    const cutoff = nowMs() - (maxTxAgeSec * 1000);
    for (const [txId, at] of _tombstones) {
      if (at < cutoff) _tombstones.delete(txId);
    }
    const evicted = [];  // [{ txId, tx }] — keep the body for tx_rejections
    for (const [txId, entry] of _pending) {
      if (entry.receivedAt < cutoff) {
        _pending.delete(txId);
        evicted.push({ txId, tx: entry.tx });
      }
    }
    if (evicted.length > 0) {
      _counters.evicted_total += evicted.length;
      log.info(`Mempool evicted ${evicted.length} stale txs (older than ${maxTxAgeSec}s)`);

      // Each TTL eviction is a canonical silent-loss event: the API
      // returned tip_id to a client, the tx aged out before being
      // batched, the client would otherwise GET 404 forever. Record
      // each so the outcome endpoint can answer "what happened".
      const detail = `ttl=${maxTxAgeSec}s`;
      for (const e of evicted) {
        _persistRejection(e.tx, TX_REJECTION_REASON.MEMPOOL_TTL_EXPIRED, detail);
      }

      const evictedIds = evicted.map(e => e.txId);
      if (dag && typeof dag.deleteMempoolTxs === "function") {
        try { dag.deleteMempoolTxs(evictedIds); } catch (err) {
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
      const age = (nowMs() - entry.receivedAt) / 1000;
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
    if (_tombstones.has(tx.tx_id)) {
      _counters.rejected_total++;
      return { added: false, reason: "tombstoned" };
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
    restored.set(tx.tx_id, { tx, receivedAt: receivedAt || nowMs() });
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

  /**
   * Find (without removing) a pending COMMITTEE_ROTATION tx whose
   * payload targets `rotation_number`. Used by rotation-coordinator's
   * tx repair to serve the assembled tx to peers whose aggregation
   * never reached quorum. Returns null if not found.
   */
  function peekRotationTx(rotation_number) {
    for (const entry of _pending.values()) {
      const tx = entry.tx;
      if (tx?.tx_type !== "COMMITTEE_ROTATION") continue;
      const rn = tx?.data?.rotation_number;
      if (Number(rn) === Number(rotation_number)) return tx;
    }
    return null;
  }

  return { add, addFront, drain, remove, has, getAll, size, clear, stats, onTxAdded, peekRotationTx, tombstone, isTombstoned };
}

module.exports = { createMempool };
