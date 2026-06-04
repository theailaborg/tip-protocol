/**
 * @file @tip-protocol/node/src/init-prescan-worker.js
 * @description Prescan worker boot for the API node. Mirrors the
 * init-network pattern — owns the startup orchestration for one
 * subsystem so index.js stays terse.
 *
 * Scaling options:
 *
 *   1. Concurrency within one worker (IO-bound parallelism):
 *      TIP_PRESCAN_CONCURRENCY=4    # one Worker, 4 in-flight classifier calls
 *      Cheap; recommended for typical loads.
 *
 *   2. Multiple workers in the same process:
 *      TIP_PRESCAN_WORKER_COUNT=3   # three Worker instances sharing the queue
 *      Each instance independently polls the queue and respects its own
 *      TIP_PRESCAN_CONCURRENCY. The atomic SQLite UPDATE…RETURNING claim
 *      prevents two workers from picking the same job. Useful when you
 *      want isolation between workers (one slow classifier call doesn't
 *      block the pool's free slots) without separate processes.
 *
 *   3. Multiple worker processes (true horizontal scale):
 *      Run a sibling Node process via docker-compose / pm2 that imports
 *      this file's initPrescanWorker. Each process picks TIP_PRESCAN_*
 *      env vars independently. The atomic claim at the DB layer makes
 *      this safe.
 *
 * Returns an array of worker instances (each with .stop()) or [] when
 * disabled:
 *   - TIP_PRESCAN_WORKER_DISABLE=1
 *   - TIP_CLASSIFIER_URL is unset
 *   - Worker construction throws (logged loudly, content will stall in
 *     PENDING_PRESCAN until the cross-node failover trigger fires)
 *
 * Caller is responsible for stop() on shutdown — `stopAll()` is the
 * convenience helper.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { createClassifierClient } = require("./services/classifier-client");
const { createPrescanWorker } = require("./workers/prescan-worker");
const { createTxSubmitter } = require("./services/helpers");
const { log } = require("./logger");

const DEFAULT_WORKER_COUNT = 1;

function _resolveWorkerCount() {
  const raw = parseInt(process.env.TIP_PRESCAN_WORKER_COUNT || "", 10);
  if (Number.isInteger(raw) && raw > 0) return raw;
  return DEFAULT_WORKER_COUNT;
}

/**
 * Boot N prescan workers (default 1) sharing the same prescan_jobs queue.
 *
 * @param {Object} deps
 * @param {Object} deps.dag           DAG facade
 * @param {Object} deps.prescanJobs   createPrescanJobs() instance
 * @param {Object} deps.consensusRef  { current: consensus } shared with createApp
 * @param {Object} deps.config        Node config (signing key + reg id)
 * @returns {Object}                  { workers: Worker[], stopAll(): void }
 */
function initPrescanWorker({ dag, prescanJobs, consensusRef, config, mediaService }) {
  const empty = { workers: [], stopAll() { /* no-op */ } };

  if (process.env.TIP_PRESCAN_WORKER_DISABLE === "1") {
    log.info("Prescan worker disabled via TIP_PRESCAN_WORKER_DISABLE=1");
    return empty;
  }
  if (!process.env.TIP_CLASSIFIER_URL) {
    log.warn("Prescan worker NOT started: TIP_CLASSIFIER_URL not set");
    return empty;
  }

  const count = _resolveWorkerCount();
  const concurrency = process.env.TIP_PRESCAN_CONCURRENCY || 1;
  const workers = [];
  // Track each worker's run() promise so stopAll() can await drain.
  // Without this, shutdown signals stop() but doesn't wait for in-flight
  // classifier calls to settle — the queue's claim-timeout safety net
  // catches orphans but adds latency for the affected jobs.
  const runPromises = [];

  for (let i = 0; i < count; i++) {
    try {
      const { worker, runPromise } = _spawnWorker({ dag, prescanJobs, consensusRef, config, mediaService, index: i });
      workers.push(worker);
      runPromises.push(runPromise);
    } catch (err) {
      log.error(
        `Prescan worker #${i} failed to start: ${err?.message || err} — ` +
        `content may stall in PENDING_PRESCAN until failover trigger fires`,
      );
    }
  }

  if (workers.length > 0) {
    log.notice(
      `Prescan workers started: count=${workers.length}/${count} ` +
      `concurrency_each=${concurrency} ` +
      `classifier=${process.env.TIP_CLASSIFIER_URL}`,
    );
  }

  async function stopAll() {
    for (const w of workers) {
      try { w.stop(); } catch { /* nothing we can do */ }
    }
    // Wait for each worker's run loop to exit AND drain its in-flight
    // pool. allSettled so one stuck worker doesn't block the others.
    await Promise.allSettled(runPromises);
  }

  return { workers, stopAll };
}

function _spawnWorker({ dag, prescanJobs, consensusRef, config, mediaService, index }) {
  const classifierClient = createClassifierClient({ config });
  const { submitTx } = createTxSubmitter(consensusRef);
  // Pass `config` unmodified — `nodeRegisteredId` flows into the on-chain
  // signed PRESCAN_COMPLETED tx; tagging it per-worker would make the
  // signer ID invalid in the registry. Per-worker claim tagging happens
  // via worker.tag (claim debugging only, no on-chain effect).
  const worker = createPrescanWorker({
    dag, jobs: prescanJobs, classifierClient,
    submitTx, config, log, mediaService,
    workerTag: `#${index}`,
  });
  const runPromise = worker.run().catch(err => {
    log.error(`prescan-worker #${index} exited: ${err?.stack || err}`);
  });
  return { worker, runPromise };
}

module.exports = { initPrescanWorker };
