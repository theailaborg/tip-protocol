/**
 * @file @tip-protocol/node/src/workers/prescan-worker.js
 * @description Async prescan worker loop. Polls the prescan_jobs table,
 * calls the classifier for each modality, aggregates the per-modality
 * results, builds + signs a PRESCAN_COMPLETED tx, and submits it through
 * consensus.
 *
 * Retry policy (per ASYNC_PRESCAN_ARCHITECTURE.md § Degraded handling):
 *
 *   1. Clean signal → emit PRESCAN_COMPLETED with verdict.
 *   2. Soft-degraded (e.g. disagreement_override — classifier returned a
 *      real probability but self-flagged as low-confidence) → emit
 *      PRESCAN_COMPLETED with overall_degraded=true and the real
 *      probability. No retry: retrying with the same input yields the
 *      same low-confidence answer.
 *   3. Hard-degraded (error / non-finite / forced 0.5 neutral) AND
 *      retries < max → release back to queue with backoff.
 *   4. Hard-degraded AND retries exhausted → fail-open with
 *      overall_degraded=true and failed=true (probability=0 is a
 *      placeholder; downstream sees the degraded flag and knows).
 *
 * Fan-out: classifier accepts ONE file per call. For posts with N media
 * items, the worker makes N calls (first one includes text, others
 * file-only) and aggregates the union of modality_results. The
 * aggregator collapses same-modality results by max.
 *
 * Factory function — caller wires in dag + classifierClient + jobs +
 * config. Tests can inject mocks.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES } = require("../../../shared/constants");
const { PRESCAN_WORKER } = require("../../../shared/protocol-constants");
const { nowMs } = require("../../../shared/time");
const { aggregate } = require("../services/prescan-aggregator");
const prescanCompletedSchema = require("../schemas/prescan-completed");
const { nodeSignedAuto } = require("../services/helpers");
const { isSkipped, isHeuristicOnly } = require("../services/classifier-client");

const POLL_IDLE_MS = 500;        // how long to sleep when queue is empty
const POLL_BUSY_MS = 50;         // brief breather between claim attempts when pool isn't full
const DEFAULT_CONCURRENCY = 1;   // sequential by default; bump via run({ concurrency }) or env
const STAGE_TEXT = "text";
const STAGE_IMAGE = "image";
const STAGE_AUDIO = "audio";

/**
 * Build the worker.
 *
 * @param {Object} deps
 * @param {Object} deps.dag                 DAG facade.
 * @param {Object} deps.jobs                createPrescanJobs() instance.
 * @param {Object} deps.classifierClient    createClassifierClient() instance.
 * @param {Function} deps.submitTx          Consensus submitter.
 * @param {Object} deps.config              Node config (private key + reg id).
 * @param {Object} [deps.log]               Logger (defaults to console).
 * @param {() => number} [deps.now]         Time source for tests.
 * @param {() => Promise<void>} [deps.sleep] Sleep impl for tests.
 */
function createPrescanWorker({ dag, jobs, classifierClient, submitTx, config, log, now: nowFn, sleep: sleepFn, workerTag = "" }) {
  if (!dag) throw new Error("prescan-worker: dag required");
  if (!jobs) throw new Error("prescan-worker: jobs required");
  if (!classifierClient) throw new Error("prescan-worker: classifierClient required");
  if (typeof submitTx !== "function") throw new Error("prescan-worker: submitTx required");
  if (!config?.nodePrivateKey) throw new Error("prescan-worker: config.nodePrivateKey required");

  const logger = log || console;
  // workerId identifies this worker in the queue's claimed_by column —
  // useful for debugging stuck claims when multiple workers run against
  // the same queue. Has NO effect on signed tx (config.nodeRegisteredId
  // flows separately into nodeSignedAuto for the on-chain signer field).
  const baseId = config.nodeRegisteredId || config.nodeId || `worker_${process.pid}`;
  const workerId = `${baseId}${workerTag}`;
  const now = typeof nowFn === "function" ? nowFn : nowMs;
  const sleep = typeof sleepFn === "function"
    ? sleepFn
    : (ms) => new Promise(r => setTimeout(r, ms));

  let _stopped = false;

  // ── Public loop ─────────────────────────────────────────────────────────

  async function tick() {
    const job = jobs.claim(workerId);
    if (!job) return { worked: false };
    try {
      await _processJob(job);
      return { worked: true, jobId: job.job_id, outcome: "completed" };
    } catch (err) {
      // _processJob handles its own retry/fail-open accounting; anything
      // that escapes here is a programmer bug. Emit a fail-open so the
      // chain reflects a terminal state instead of leaving the content
      // stuck in PENDING_PRESCAN until the cross-node trigger picks it
      // up at FAIL_OPEN_AFTER_MS.
      logger.error?.(`prescan-worker: unexpected error on ${job.job_id}: ${err?.message || err}`);
      _safeEmitFailOpen(job, `worker_crash: ${err?.message || err}`, err);
      return { worked: true, jobId: job.job_id, outcome: "crashed", error: err };
    }
  }

  /**
   * Run the worker loop. Maintains up to `concurrency` in-flight jobs at a
   * time. Each job's classifier call is IO-bound, so a single Node process
   * can comfortably run many concurrently — typical setting is 4-8.
   *
   * Race-safety: each claim is atomic at the queue layer (SQLite
   * UPDATE…RETURNING), so two concurrent _processJob() calls can't grab
   * the same job. The retry budget (`worker_claim_timeout_ms`) recovers
   * any job left orphaned by a crash mid-processing.
   *
   * @param {Object} [opts]
   * @param {number} [opts.concurrency]  Max in-flight jobs. Default 1
   *   (sequential — same as before). Reads `TIP_PRESCAN_CONCURRENCY` if
   *   not passed.
   */
  async function run(opts = {}) {
    const envConcurrency = parseInt(process.env.TIP_PRESCAN_CONCURRENCY || "", 10);
    const concurrency = Math.max(1, Number.isInteger(opts.concurrency)
      ? opts.concurrency
      : (Number.isInteger(envConcurrency) && envConcurrency > 0 ? envConcurrency : DEFAULT_CONCURRENCY));

    const inFlight = new Set();

    while (!_stopped) {
      // Top up to the concurrency limit: claim + dispatch jobs without
      // awaiting so the classifier calls actually overlap.
      let claimedThisRound = 0;
      while (inFlight.size < concurrency) {
        const task = _runOne();
        if (task === null) break;              // queue empty
        claimedThisRound += 1;
        task.finally(() => inFlight.delete(task));
        inFlight.add(task);
      }

      if (inFlight.size === 0) {
        await sleep(POLL_IDLE_MS);             // queue empty + nothing in flight
      } else if (inFlight.size >= concurrency || claimedThisRound === 0) {
        await Promise.race(inFlight);          // pool full or queue empty — wait for any to finish
      } else {
        await sleep(POLL_BUSY_MS);             // briefly yield, then try to claim more
      }
    }

    // Drain in-flight before returning so the caller can rely on stop()
    // meaning "everything settled."
    if (inFlight.size > 0) await Promise.all(inFlight);
  }

  /**
   * Claim + process one job in the background. Returns the in-flight
   * promise (so the pool can track it) or null when the queue is empty.
   * Mirrors tick()'s error handling but doesn't await — caller manages
   * the lifecycle.
   */
  function _runOne() {
    const job = jobs.claim(workerId);
    if (!job) return null;
    return _processJob(job).catch((err) => {
      logger.error?.(`prescan-worker: unexpected error on ${job.job_id}: ${err?.message || err}`);
      _safeEmitFailOpen(job, `worker_crash: ${err?.message || err}`, err);
    });
  }

  function stop() { _stopped = true; }

  // ── Private ─────────────────────────────────────────────────────────────

  async function _processJob(job) {
    const payload = job.payload;
    if (!payload || typeof payload !== "object") {
      // Can't classify a corrupt payload. Fail-open so the content
      // moves out of PENDING_PRESCAN — local marker alone would leave
      // the chain inconsistent with the queue until the cross-node
      // trigger catches it at FAIL_OPEN_AFTER_MS.
      _safeEmitFailOpen(job, "payload_not_parseable", null);
      return;
    }

    let modalityResults;
    let providersUsed;
    let classifierVersion;
    let skipped = false;
    try {
      const fanOut = await _fanOutClassifierCalls(payload);
      modalityResults = fanOut.modalityResults;
      providersUsed = fanOut.providersUsed;
      classifierVersion = fanOut.classifierVersion;
      skipped = !!fanOut.skipped;
    } catch (err) {
      _handleHardFailure(job, err);
      return;
    }

    const contentType = payload.content_type;

    // Locally-skipped (non-OH origin): emit clean verdict directly.
    // No real verdict to produce — classifier deliberately didn't run.
    // Content moves to REGISTERED with probability 0.
    if (skipped) {
      _submitPrescanCompleted({
        ctid: job.ctid,
        probability: 0,
        tier: "low",
        flagged: false,
        overall_degraded: false,
        content_type: contentType,
        content_type_meta: payload.content_type_meta || { hint_provided: null, resolution: "derived", reason: null },
        modality_results: [],
        classifier_version: classifierVersion || "n/a",
        classifier_providers_used: providersUsed || "skipped_locally",
        completed_at: now(),
        failed: false,
        failure_reason: null,
      });
      jobs.markDone(job.job_id);
      return;
    }

    // Aggregate using the primary-floor algorithm. content_type comes
    // off the enqueued payload (resolved at register time).
    const agg = aggregate(modalityResults, contentType);

    // Hard-degraded path: at least one modality produced no usable signal
    // (error / non-finite / forced 0.5). Retry if budget remains — these
    // are transient and a re-run may yield a real probability.
    if (agg.overall_hard_degraded) {
      if (job.retries < PRESCAN_WORKER.MAX_RETRIES_ON_DEGRADED) {
        jobs.releaseForRetry(job.job_id, "hard_degraded_signal");
        return;
      }
      // Exhausted — fail-open. Preserve whatever the aggregator produced
      // (a non-hard modality may have given a usable number); only fall
      // back to the no-signal neutral when the aggregator itself has no
      // probability to share.
      _emitFailOpen(job, contentType, "hard_degraded_after_retries", {
        probability: agg.probability,
        modalityResults: agg.modality_results,
      });
      return;
    }

    // Soft-degraded OR clean: ship the probability through. Soft cases
    // (e.g. disagreement_override) carry a real classifier number that
    // would just repeat on retry — record it with overall_degraded=true
    // so downstream consumers know it's low-confidence.
    const tier = prescanCompletedSchema.tierFromProbability(agg.probability);
    const flagged = tier === "high" || tier === "critical";

    const data = {
      ctid: job.ctid,
      probability: agg.probability,
      tier,
      flagged,
      overall_degraded: agg.overall_degraded,
      content_type: contentType,
      content_type_meta: payload.content_type_meta || { hint_provided: null, resolution: "derived", reason: null },
      modality_results: agg.modality_results,
      classifier_version: classifierVersion || "unknown",
      classifier_providers_used: providersUsed || "unknown",
      completed_at: now(),
      failed: false,
      failure_reason: null,
    };
    _submitPrescanCompleted(data);
    jobs.markDone(job.job_id);
  }

  function _handleHardFailure(job, err) {
    const msg = err?.message || String(err);
    if (job.retries < PRESCAN_WORKER.MAX_RETRIES_ON_ERROR) {
      logger.warn?.(`prescan-worker: classifier call failed on ${job.job_id} (retry ${job.retries + 1}): ${msg}`);
      jobs.releaseForRetry(job.job_id, msg);
      return;
    }
    logger.warn?.(`prescan-worker: classifier exhausted retries on ${job.job_id}; failing open: ${msg}`);
    _emitFailOpen(job, job.payload?.content_type, `error_after_retries: ${msg}`);
  }

  /**
   * Defensive wrapper around _emitFailOpen for use in catch handlers.
   * If _emitFailOpen itself throws (consensus submitter error, sign
   * failure), we fall back to the previous behaviour — markFailed
   * locally and let the cross-node prescan-completion-trigger emit
   * the fail-open after FAIL_OPEN_AFTER_MS. Never throws.
   */
  function _safeEmitFailOpen(job, reason, originalErr) {
    try {
      _emitFailOpen(job, job?.payload?.content_type, reason);
    } catch (emitErr) {
      logger.error?.(
        `prescan-worker: emit fail-open failed for ${job?.job_id}: ${emitErr?.message || emitErr}` +
        " — falling back to local mark; cross-node trigger will handle"
      );
      try { jobs.markFailed(job.job_id, originalErr || reason); }
      catch { /* nothing we can do */ }
    }
  }

  function _emitFailOpen(job, contentType, reason, opts = {}) {
    // Preserve the classifier's probability when we have one — fail-open
    // should not overwrite a real number from a modality that actually
    // worked. Fall back to 0.5 (the canonical "no signal" neutral, matching
    // the aggregator's _clamp01 fallback and the all-hard-degraded
    // short-circuit) when the classifier never produced a usable value
    // (network error, corrupt payload, worker crash). probability=0 is
    // never used here — that would imply "definitely human," a verdict
    // the classifier never produced.
    const probability = Number.isFinite(opts.probability) ? opts.probability : 0.5;
    const modalityResults = Array.isArray(opts.modalityResults) ? opts.modalityResults : [];
    const tier = prescanCompletedSchema.tierFromProbability(probability);
    const flagged = tier === "high" || tier === "critical";
    const data = {
      ctid: job.ctid,
      probability,
      tier,
      flagged,
      overall_degraded: true,
      content_type: contentType || "multi",
      content_type_meta: { hint_provided: null, resolution: "fail_open", reason: null },
      modality_results: modalityResults,
      classifier_version: "unknown",
      classifier_providers_used: "fail_open",
      completed_at: now(),
      failed: true,
      failure_reason: reason,
    };
    _submitPrescanCompleted(data);
    jobs.markFailed(job.job_id, reason);
  }

  function _submitPrescanCompleted(data) {
    const txBody = {
      tx_type: TX_TYPES.PRESCAN_COMPLETED,
      timestamp: now(),
      prev: dag.getRecentPrev(),
      data,
    };
    const signed = nodeSignedAuto(txBody, config);
    submitTx(signed);
  }

  /**
   * Fan out N classifier calls — text+media[0] in the first call, then
   * one call per remaining media item. Return the union of all
   * per-modality result entries, with provider + version strings drawn
   * from the responses (worker reports the most informative one).
   */
  async function _fanOutClassifierCalls(payload) {
    const text = typeof payload.text === "string" ? payload.text : "";
    const originCode = payload.origin_code;
    const media = Array.isArray(payload.media) ? payload.media : [];
    const cleared = Number.isInteger(payload.creator_cleared_count) ? payload.creator_cleared_count : 0;
    const authorTip = payload.author_tip_id || undefined;

    const calls = [];
    if (media.length === 0) {
      calls.push(classifierClient.prescan({ originCode, text, creatorClearedCount: cleared, authorTipId: authorTip }));
    } else {
      // First call carries the text alongside media[0].
      calls.push(classifierClient.prescan({
        originCode, text,
        file: { base64: media[0].base64, mime: media[0].mime },
        creatorClearedCount: cleared, authorTipId: authorTip,
      }));
      // Remaining media files alone (empty text).
      for (let i = 1; i < media.length; i++) {
        calls.push(classifierClient.prescan({
          originCode, text: "",
          file: { base64: media[i].base64, mime: media[i].mime },
          creatorClearedCount: cleared, authorTipId: authorTip,
        }));
      }
    }

    const responses = await Promise.all(calls);

    // Special-case: locally-skipped (non-OH origins) — emit a no-modality
    // verdict and skip the aggregator path. Downstream sees prob=0, low
    // tier, not flagged.
    if (responses.length === 1 && isSkipped(responses[0])) {
      return {
        modalityResults: [],
        providersUsed: responses[0].provider_used,
        classifierVersion: responses[0].classifier_version || "n/a",
        skipped: true,
      };
    }

    // Quality gate: heuristic-only responses shouldn't drive verdicts.
    // Surface as degraded so the aggregator handles them like other
    // unreliable signals.
    const modalityResults = [];
    const providers = new Set();
    let version;
    for (const r of responses) {
      if (!r) continue;
      providers.add(r.provider_used || "unknown");
      version = version || r.classifier_version;
      const heuristicOnly = isHeuristicOnly(r);
      for (const m of r.modality_results || []) {
        modalityResults.push({
          ...m,
          // Mark heuristic-only modality results as degraded — the
          // aggregator already treats degraded entries as unreliable.
          error: m.error || (heuristicOnly ? "heuristic_only_unreliable" : null),
        });
      }
    }

    return {
      modalityResults,
      providersUsed: Array.from(providers).join("|"),
      classifierVersion: version || "unknown",
    };
  }

  return { tick, run, stop };
}

module.exports = { createPrescanWorker };
