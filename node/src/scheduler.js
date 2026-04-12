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
 *   3. Clean-record bonus          (genesis: clean_period_days — runs daily)
 *   4. Verdict auto-trigger        (config: verdictCheckInterval)
 *   5. Peer health ping            (config: peerHealthInterval)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { TX_TYPES } = require("../../shared/constants");
const { shake256Multi } = require("../../shared/crypto");
const { NETWORK, REPUTATION } = require("../../shared/protocol-constants");
const { tallyVerdictAndApply, applyAppealVerdict } = require("./jury");
const { getLogger } = require("./logger");

const log = getLogger("tip.scheduler");

/**
 * Create a scheduler with named tasks, overlap protection, and stop().
 */
function createScheduler(dag, scoring, gossip, config) {
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
  register("merkle-root", NETWORK.MERKLE_PUBLISH_HOURS * 3600000, () => {
    const count = dag.dedupCount();
    const idCount = dag.getTxsByType(TX_TYPES.REGISTER_IDENTITY).length;
    const root = shake256Multi(count.toString(), idCount.toString(), new Date().toISOString().slice(0, 13));

    dag.addTx({
      tx_type: TX_TYPES.MERKLE_ROOT_PUBLISHED,
      timestamp: new Date().toISOString(),
      data: {
        merkle_root: root,
        dedup_count: count,
        identity_count: idCount,
        node_id: config.nodeId,
      },
    });

    log.info(`Merkle root published: ${root.slice(0, 16)}... (dedup: ${count}, identities: ${idCount})`);
  });

  // 2. Score recomputation sweep (node config)
  register("score-recompute", config.scoreRecomputeInterval, async () => {
    log.info("Starting score recomputation sweep...");
    await scoring.recomputeAll();
    log.info("Score recomputation complete");
  });

  // 3. Clean-record bonus (genesis: clean_period_days — check runs daily)
  register("clean-record", config.cleanRecordInterval, () => {
    const cutoff = new Date(Date.now() - REPUTATION.CLEAN_PERIOD_DAYS * 24 * 3600000).toISOString();
    const eligible = dag.getCleanRecordEligible(cutoff)
      .filter(tipId => !dag.isRevoked(tipId));
    for (const tipId of eligible) {
      scoring.applyScoreEvent(tipId, REPUTATION.CLEAN_PERIOD_BONUS, "clean_record_bonus");
    }
    if (eligible.length > 0) {
      log.info(`Clean record bonus: ${eligible.length} identities awarded +${REPUTATION.CLEAN_PERIOD_BONUS}`);
    }
  });

  // 4. Verdict auto-trigger — jury + appeal in single pass (node config)
  register("verdict-check", config.verdictCheckInterval, () => {
    const disputedContent = dag.getContentByStatus("disputed");
    if (!disputedContent.length) return;

    const now = Date.now();
    for (const rec of disputedContent) {
      const ctid = rec.ctid;
      try {
        const allSummons = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid);
        if (!allSummons.length) continue;

        const jurySummons = allSummons.filter(t => !t.data?.is_appeal);
        const appealSummons = allSummons.filter(t => t.data?.is_appeal === true);

        // Check appeal first (if exists, it's the active stage)
        if (appealSummons.length) {
          const deadline = new Date(appealSummons[0].data?.reveal_deadline).getTime();
          if (!isNaN(deadline) && now >= deadline) {
            const hasResult = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_RESULT, ctid).length > 0;
            if (!hasResult) {
              const reveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid)
                .filter(t => t.data?.is_appeal === true);
              log.info(`Auto-appeal verdict: ${ctid} (${reveals.length}/${appealSummons.length} reveals)`);
              const r = applyAppealVerdict(ctid, reveals, appealSummons, dag, scoring, config);
              log.info(`Appeal result: ${ctid} → ${r.verdict} (overturned: ${r.overturned})`);
            }
          }
          continue; // appeal is active, skip jury check
        }

        // Check jury (no appeal exists)
        if (jurySummons.length) {
          const deadline = new Date(jurySummons[0].data?.reveal_deadline).getTime();
          if (!isNaN(deadline) && now >= deadline) {
            const hasVerdict = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid).length > 0;
            if (!hasVerdict) {
              const reveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid)
                .filter(t => !t.data?.is_appeal);
              log.info(`Auto-jury verdict: ${ctid} (${reveals.length}/${jurySummons.length} reveals)`);
              const r = tallyVerdictAndApply(ctid, reveals, jurySummons, dag, scoring, config);
              log.info(`Jury result: ${ctid} → ${r.verdict}`);
            }
          }
        }
      } catch (err) {
        log.error(`[verdict-check] Failed for ${ctid}: ${err.message}`);
      }
    }
  });

  // 5. Peer health ping (node config)
  register("peer-health", config.peerHealthInterval, () => {
    const pc = gossip.peerCount();
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
