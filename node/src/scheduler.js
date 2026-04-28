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
 * Issue #13 — every tx the scheduler produces flows through `submitTx` /
 * `submitBatch` (consensus mempool → Bullshark → commit-handler) instead
 * of being written directly to the local DAG. On multi-node, each node's
 * scheduler may produce overlapping batches; commit-handler enforces
 * first-wins per (tx_type, ctid) for verdicts and (tip_id, ctid, reason)
 * for SCORE_UPDATE so only one batch's effects land. Wasted bandwidth
 * (N submissions per verdict, mostly dropped at commit) is acceptable at
 * federation scale and the only correctness-meaningful exchange.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { TX_TYPES } = require("../../shared/constants");
const { shake256Multi } = require("../../shared/crypto");
const { NETWORK, REPUTATION } = require("../../shared/protocol-constants");
const { buildAdjudicationBatch, buildAppealBatch } = require("./jury");
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
function createScheduler(dag, scoring, network, config, { submitTx, submitBatch } = {}) {
  if (typeof submitTx !== "function" || typeof submitBatch !== "function") {
    throw new Error("createScheduler: requires { submitTx, submitBatch } — see services/helpers.createTxSubmitter");
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

  /**
   * Best-effort batch submission with consensus error tolerance.
   * Mempool may reject txs that already exist (idempotent dedup at the
   * consensus layer); we log and move on rather than throw.
   */
  function _submitBatchSafe(txs, tag) {
    if (!txs || txs.length === 0) return;
    try {
      submitBatch(txs);
      log.debug(`[${tag}] submitted batch of ${txs.length} txs to consensus`);
    } catch (err) {
      // Treat mempool-rejection as expected on multi-node (peer beat us to it).
      // Real consensus failures (consensus halted, etc.) surface as 503 — log
      // and let next tick retry.
      log.debug(`[${tag}] batch submission deferred: ${err?.error || err?.message || err}`);
    }
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

  // 3. Clean-record bonus (genesis: clean_period_days — check runs daily)
  // Routed through `submitBatch` so every clean-record SCORE_UPDATE tx flows
  // through consensus. commit-handler dedups by (tip_id, ctid, reason) — the
  // reason is "clean_record_bonus" with no ctid, so the dedup key collapses
  // to (tip_id, "clean_record_bonus") which is correctly idempotent across
  // all federation nodes' submissions in the same window.
  register("clean-record", config.cleanRecordInterval, () => {
    const cutoff = new Date(Date.now() - REPUTATION.CLEAN_PERIOD_DAYS * 24 * 3600000).toISOString();
    const eligible = dag.getCleanRecordEligible(cutoff)
      .filter(tipId => !dag.isRevoked(tipId));
    if (eligible.length === 0) return;

    const timestamp = new Date().toISOString();
    const getRecentPrev = () => dag.getRecentPrev();
    const txs = eligible.map(tipId => scoring.buildScoreUpdateTx({
      tipId,
      delta: REPUTATION.CLEAN_PERIOD_BONUS,
      reason: "clean_record_bonus",
      ctid: null,
      relatedTxId: null,
      timestamp,
      getRecentPrev,
      config,
    }));

    _submitBatchSafe(txs, "clean-record");
    log.info(`Clean record bonus: ${eligible.length} identities proposed +${REPUTATION.CLEAN_PERIOD_BONUS}`);
  });

  // 4. Verdict auto-trigger — jury + appeal in single pass (node config)
  // Reads consensus-ordered DAG state, builds the verdict batch via the
  // pure builders in jury.js, routes through submitBatch. On multi-node,
  // every node's scheduler may build a batch for the same dispute;
  // commit-handler first-wins guards drop the duplicates.
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
              const batch = buildAppealBatch(ctid, reveals, appealSummons, dag, scoring, config);
              _submitBatchSafe(batch.txs, "appeal-verdict");
              log.info(`Appeal verdict proposed: ${ctid} → ${batch.verdict} (overturned: ${batch.overturned})`);
            }
          }
          continue; // appeal is active, skip jury check
        }

        // Check jury (no appeal exists)
        if (jurySummons.length) {
          const deadline = new Date(jurySummons[0].data?.reveal_deadline).getTime();
          if (!isNaN(deadline) && now >= deadline) {
            const hasVerdict = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid).length > 0;
            // NO_QUORUM auto-escalation produces an APPEAL_FILED tx instead of an
            // ADJUDICATION_RESULT, so we also gate on whether an APPEAL_FILED has
            // already been produced for this ctid (commit-handler accepts the
            // first; later schedulers see it and skip).
            const hasAutoAppeal = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, ctid).length > 0;
            if (!hasVerdict && !hasAutoAppeal) {
              const reveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid)
                .filter(t => !t.data?.is_appeal);
              const batch = buildAdjudicationBatch(ctid, reveals, jurySummons, dag, scoring, config);
              _submitBatchSafe(batch.txs, "jury-verdict");
              log.info(`Jury verdict proposed: ${ctid} → ${batch.verdict}`);
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
