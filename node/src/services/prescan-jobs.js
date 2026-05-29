/**
 * @file @tip-protocol/node/src/services/prescan-jobs.js
 * @description Service wrapper around the `prescan_jobs` table. Owns the
 * worker queue lifecycle: enqueue at register time, claim from the worker
 * loop, mark done/failed, release for retry.
 *
 * The queue is node-local (one table per node, not in state_merkle_root).
 * Result of each successfully-classified job is a PRESCAN_COMPLETED tx
 * that lands on chain via consensus and is read by every replay node.
 *
 * Atomicity: the SQLite claim primitive runs as a single
 * `UPDATE … RETURNING` so concurrent workers can't claim the same row.
 * The in-memory store path uses single-threaded JS semantics (no
 * inter-process races on a Memory backend).
 *
 * Stuck-claim recovery: any claim older than worker_claim_timeout_ms
 * (genesis: 60s) is eligible to be re-claimed. Handles worker crashes
 * mid-job — DB row survives, next worker tick picks it up.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const crypto = require("crypto");
const { PRESCAN_WORKER } = require("../../../shared/protocol-constants");

/**
 * Create the prescan-jobs service bound to a DAG facade.
 *
 * @param {Object} deps
 * @param {Object} deps.dag   DAG store exposing
 *   { enqueuePrescanJob, getPrescanJob, getPrescanJobByCtid,
 *     claimPrescanJob, markPrescanJobDone, markPrescanJobFailed,
 *     releasePrescanJobForRetry }
 * @param {() => number} [deps.now]  Time source. Default Date.now;
 *   tests can inject a deterministic clock.
 */
function createPrescanJobs({ dag, now: nowFn }) {
  if (!dag) throw new Error("prescan-jobs: dag required");
  const now = typeof nowFn === "function" ? nowFn : Date.now;

  /**
   * Enqueue a new prescan job for a freshly-registered ctid.
   *
   * @param {Object} args
   * @param {string} args.ctid                 The content being registered.
   * @param {Object|string} args.payload       Classifier input. Object will
   *   be JSON-stringified; string assumed canonical.
   * @returns {{ job_id: string, enqueued: boolean }}
   *   `enqueued=false` indicates a row with the same ctid already exists
   *   (idempotent re-register; caller can treat as success).
   */
  function enqueue({ ctid, payload }) {
    if (typeof ctid !== "string" || ctid.length === 0) {
      throw new Error("enqueue: ctid required");
    }
    if (payload === undefined || payload === null) {
      throw new Error("enqueue: payload required");
    }
    const existing = dag.getPrescanJobByCtid(ctid);
    if (existing) return { job_id: existing.job_id, enqueued: false };

    const jobId = `pj_${crypto.randomUUID()}`;
    const blob = typeof payload === "string" ? payload : JSON.stringify(payload);
    const enqueued = dag.enqueuePrescanJob({
      job_id: jobId,
      ctid,
      payload: Buffer.from(blob, "utf8"),
      created_at: now(),
    });
    return { job_id: jobId, enqueued };
  }

  /**
   * Atomically claim the next available job for a worker. Returns the
   * full row (with payload as a parsed object) or null when no work
   * is available.
   */
  function claim(workerId) {
    if (typeof workerId !== "string" || workerId.length === 0) {
      throw new Error("claim: workerId required");
    }
    const row = dag.claimPrescanJob({
      workerId,
      now: now(),
      claimTimeoutMs: PRESCAN_WORKER.CLAIM_TIMEOUT_MS,
    });
    if (!row) return null;
    return _decode(row);
  }

  function markDone(jobId) {
    return dag.markPrescanJobDone(jobId, { completedAt: now() });
  }

  function markFailed(jobId, error) {
    return dag.markPrescanJobFailed(jobId, {
      lastError: _errorMessage(error),
      completedAt: now(),
    });
  }

  /**
   * Release a claimed job back to the queue for retry. Increments the
   * retries counter; the worker checks this against the genesis max
   * before deciding whether to retry or fail-open.
   */
  function releaseForRetry(jobId, error) {
    return dag.releasePrescanJobForRetry(jobId, {
      lastError: _errorMessage(error),
    });
  }

  /**
   * Read job status for a given ctid (used by the
   * GET /v1/content/:ctid/prescan_status endpoint).
   */
  function getByCtid(ctid) {
    const row = dag.getPrescanJobByCtid(ctid);
    return row ? _decode(row) : null;
  }

  function get(jobId) {
    const row = dag.getPrescanJob(jobId);
    return row ? _decode(row) : null;
  }

  return { enqueue, claim, markDone, markFailed, releaseForRetry, getByCtid, get };
}

// ── helpers ────────────────────────────────────────────────────────────────

function _decode(row) {
  let payload = row.payload;
  // payload arrives as a Buffer (SQLite BLOB / MemoryStore Buffer) or
  // a string. Decode to UTF-8 + parse JSON so the worker gets the
  // structured input it enqueued.
  if (Buffer.isBuffer(payload)) {
    try { payload = JSON.parse(payload.toString("utf8")); }
    catch { payload = payload.toString("utf8"); }
  } else if (typeof payload === "string") {
    try { payload = JSON.parse(payload); }
    catch { /* leave as string */ }
  }
  return { ...row, payload };
}

function _errorMessage(err) {
  if (err == null) return null;
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  try { return JSON.stringify(err); }
  catch { return String(err); }
}

module.exports = { createPrescanJobs };
