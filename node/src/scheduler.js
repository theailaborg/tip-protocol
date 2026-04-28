/**
 * @file @tip-protocol/node/src/scheduler.js
 * @description Production scheduler for TIP node background tasks.
 *
 * Features:
 *   - Named task registry with configurable intervals
 *   - Overlap guard (skips if previous run still in progress)
 *   - stop() for graceful shutdown (clears all intervals)
 *   - Protocol-level intervals from genesis, node-level from config
 *
 * Tasks:
 *   1. Merkle root publication     (genesis: merkle_publish_hours)
 *   2. Score recomputation sweep   (config: scoreRecomputeInterval)
 *   3. Peer health ping            (config: peerHealthInterval)
 *
 * NOTE: Both `verdict-check` and `clean-record` are NO LONGER scheduler-
 * driven. They moved to `consensus/verdict-trigger.js` and
 * `consensus/clean-record-trigger.js`, which commit-handler invokes per
 * Bullshark round commit using `cert.timestamp` as the deterministic
 * clock. Reactive (no polling), deterministic (cert.ts is the BFT
 * median), leader-gated (round-modulo for verdicts, day-modulo for
 * clean-record) so only one node fires per round/day.
 *
 * The remaining merkle-root task routes through `submitTx` so every node
 * sees the same MERKLE_ROOT_PUBLISHED via consensus.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { TX_TYPES } = require("../../shared/constants");
const { shake256Multi } = require("../../shared/crypto");
const { NETWORK } = require("../../shared/protocol-constants");
const { nodeSignedAuto } = require("./services/helpers");
const { getLogger } = require("./logger");

const log = getLogger("tip.scheduler");

/**
 * Create a scheduler with named tasks, overlap protection, and stop().
 *
 * @param {Object} dag
 * @param {Object} scoring
 * @param {Object} network
 * @param {Object} config
 * @param {Object} txSubmitter         { submitTx, submitBatch } — required.
 *                                     Routes scheduler-produced txs through
 *                                     consensus mempool. See `services/helpers.js`.
 */
function createScheduler(dag, scoring, network, config, { submitTx } = {}) {
  if (typeof submitTx !== "function") {
    throw new Error("createScheduler: requires { submitTx } — see services/helpers.createTxSubmitter");
  }

  const _tasks = new Map();

  /**
   * Register a named task with overlap guard.
   */
  function register(name, intervalMs, fn) {
    let running = false;

    const handle = setInterval(async () => {
      if (running) {
        log.debug(`[${name}] skipped — previous run still in progress`);
        return;
      }
      running = true;
      const start = Date.now();
      try {
        await fn();
        log.debug(`[${name}] completed in ${Date.now() - start}ms`);
      } catch (err) {
        log.error(`[${name}] failed: ${err.message}`);
      } finally {
        running = false;
      }
    }, intervalMs);

    _tasks.set(name, handle);
    log.info(`Task registered: ${name} (every ${formatInterval(intervalMs)})`);
  }

  // ── Task definitions ─────────────────────────────────────────────────────

  // 1. Merkle root publication (genesis: merkle_publish_hours)
  // Routed through `submitTx` so every node sees the same MERKLE_ROOT_PUBLISHED
  // tx via consensus instead of writing local-only rows.
  register("merkle-root", NETWORK.MERKLE_PUBLISH_HOURS * 3600000, () => {
    const count = dag.dedupCount();
    const idCount = dag.getTxsByType(TX_TYPES.REGISTER_IDENTITY).length;
    const root = shake256Multi(count.toString(), idCount.toString(), new Date().toISOString().slice(0, 13));

    const tx = nodeSignedAuto({
      tx_type: TX_TYPES.MERKLE_ROOT_PUBLISHED,
      timestamp: new Date().toISOString(),
      prev: dag.getRecentPrev(),
      data: {
        merkle_root: root,
        dedup_count: count,
        identity_count: idCount,
      },
    }, config);

    try {
      submitTx(tx);
      log.info(`Merkle root proposed: ${root.slice(0, 16)}... (dedup: ${count}, identities: ${idCount})`);
    } catch (err) {
      log.debug(`[merkle-root] submission deferred: ${err?.error || err?.message || err}`);
    }
  });

  // 2. Score recomputation sweep (node config)
  register("score-recompute", config.scoreRecomputeInterval, async () => {
    log.info("Starting score recomputation sweep...");
    await scoring.recomputeAll();
    log.info("Score recomputation complete");
  });

  // 3. Peer health ping (node config)
  register("peer-health", config.peerHealthInterval, () => {
    const pc = network ? network.peerCount() : 0;
    if (pc === 0 && config.peers.length > 0) {
      log.warn(`No active peers (${config.peers.length} configured). DAG sync paused.`);
    }
  });

  log.info(`Scheduler started: ${_tasks.size} tasks registered`);

  // ── Public API ───────────────────────────────────────────────────────────

  return {
    /** Stop all scheduled tasks (for graceful shutdown). */
    stop() {
      for (const [name, handle] of _tasks) {
        clearInterval(handle);
        log.info(`Task stopped: ${name}`);
      }
      _tasks.clear();
      log.info("Scheduler stopped");
    },

    /** Get status of all registered tasks. */
    status() {
      return Array.from(_tasks.keys());
    },
  };
}

/** Format ms interval to human-readable string. */
function formatInterval(ms) {
  if (ms >= 3600000) return `${ms / 3600000}h`;
  if (ms >= 60000) return `${ms / 60000}m`;
  return `${ms / 1000}s`;
}

module.exports = { createScheduler };
