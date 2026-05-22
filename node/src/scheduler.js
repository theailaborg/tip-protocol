/**
 * @file @tip-protocol/node/src/scheduler.js
 * @description Production scheduler for TIP node background tasks.
 *
 * Features:
 *   - Named task registry with configurable intervals
 *   - Overlap guard (skips if previous run still in progress)
 *   - stop() for graceful shutdown (clears all intervals)
 *   - Node-level intervals from config
 *
 * Tasks:
 *   1. Peer health ping            (config: peerHealthInterval)
 *
 * NOTE: `verdict-check` and `clean-record` are NOT scheduler-driven.
 * They live in `consensus/verdict-trigger.js` and
 * `consensus/clean-record-trigger.js`, invoked by commit-handler per
 * Bullshark round commit using `cert.timestamp` as the deterministic
 * clock — reactive (no polling), deterministic (cert.ts is the BFT
 * median), leader-gated (round-modulo for verdicts, day-modulo for
 * clean-record) so only one node fires per round/day.
 *
 * The historical 6-hour `merkle-root` task is gone — `commits.state_merkle_root`
 * (written by bullshark on every anchor commit, 2f+1 signed) is the
 * cryptographically sound replacement; expose via `/v1/state-root/latest`.
 *
 * The historical `score-recompute` task is also gone — commit-handler
 * is the sole writer to the scores table per #38. The recompute task
 * was a footgun that would overwrite consensus-correct scores with
 * replay-derived values that didn't match commit-handler's math; it
 * forked a live federation when its 12h timer fired on some nodes
 * before others.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { nowMs } = require("../../shared/time");

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
function createScheduler(network, config) {
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
      const start = nowMs();
      try {
        await fn();
        log.debug(`[${name}] completed in ${nowMs() - start}ms`);
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

  // Peer health ping (node config)
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
