/**
 * @file @tip-protocol/node/src/services/classifier-local.js
 * @description Local fallback classifier — keeps the prescan pipeline
 * accepting registrations when the external AI classifier is not
 * running.
 *
 *   text   → the local heuristic (`preScanContent`) produces a real
 *            probability, same function the sync-prescan era used.
 *   image/audio → stub neutral 0.5 ("no signal") until a local media
 *            model exists. Tagged provider=local_fallback_stub so
 *            downstream can tell a stub from a scored verdict.
 *
 * Response shape mirrors the real classifier-client byte-for-byte
 * (modality_results, provider_used, locally_skipped …) so the worker
 * needs zero special-casing. provider_used is "local_fallback" — NOT
 * "heuristic" — deliberately: isHeuristicOnly() marks heuristic-only
 * responses degraded, but a fallback verdict is the best signal
 * available when the classifier is down and should commit cleanly.
 * Consumers see the provenance in classifier_providers_used.
 *
 * `createFallbackClassifierClient` wraps the real client: network-level
 * failures (refused / DNS / timeout) fall back to the local client with
 * a warning; application-level errors (4xx semantics) still throw.
 *
 * Enable/disable via TIP_CLASSIFIER_FALLBACK (default enabled; "0"
 * disables → strict mode, prescan stalls without a classifier exactly
 * as before).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs } = require("../../../shared/time");

const { ORIGIN } = require("../../../shared/constants");
const { preScanContent } = require("./helpers");

const LOCAL_VERSION = "local_fallback_v1";
// Neutral "no signal" — protocol convention shared with fail-open and
// the aggregator's clamp fallback. NOT 0 (would read "definitely human").
const MEDIA_STUB_PROBABILITY = 0.5;

function _skippedResponse(originCode) {
  return {
    flagged: false,
    probability: 0.0,
    modalities_analyzed: [],
    modality_results: [],
    provider_used: "skipped_locally",
    classifier_version: LOCAL_VERSION,
    processing_ms: 0,
    note: `Pre-scan only applies to OH declarations. origin_code=${originCode} skipped (local fallback).`,
    locally_skipped: true,
  };
}

function _modalityFromMime(mime) {
  const m = String(mime || "").toLowerCase();
  if (m.startsWith("image/")) return "image";
  if (m.startsWith("audio/")) return "audio";
  if (m.startsWith("video/")) return "video";
  return "image";
}

function createLocalClassifierClient() {
  async function prescan({ originCode, text, files, creatorClearedCount } = {}) {
    if (originCode !== ORIGIN.OH) {
      return _skippedResponse(originCode);
    }

    const modalityResults = [];

    const t = typeof text === "string" ? text : "";
    if (t.length > 0) {
      const ps = preScanContent(t, originCode, { clearedCount: creatorClearedCount || 0 });
      modalityResults.push({
        media_id: null,
        modality: "text",
        probability: ps.probability,
        weight: 1.0,
        provider: "local_fallback",
        features_used: ["heuristic"],
        reasoning: "classifier offline — local heuristic verdict",
        processing_ms: 0,
        error: null,
      });
    }

    for (const f of (Array.isArray(files) ? files : [])) {
      if (!f || !f.mime) continue;
      modalityResults.push({
        media_id: f.media_id ?? null,
        modality: _modalityFromMime(f.mime),
        probability: MEDIA_STUB_PROBABILITY,
        weight: 1.0,
        provider: "local_fallback_stub",
        features_used: [],
        reasoning: "classifier offline — stub neutral value, no media model locally",
        processing_ms: 0,
        error: null,
      });
    }

    const top = modalityResults.length
      ? Math.max(...modalityResults.map(m => m.probability))
      : 0;

    return {
      flagged: false,
      probability: top,
      modalities_analyzed: modalityResults.map(m => m.modality),
      modality_results: modalityResults,
      provider_used: "local_fallback",
      classifier_version: LOCAL_VERSION,
      processing_ms: 0,
      note: "External classifier unavailable — local fallback verdict.",
    };
  }

  async function stage1() { return { provider_used: "local_fallback" }; }
  async function providers() { return { providers: ["local_fallback"] }; }
  async function health() { return { status: "local_fallback" }; }

  return { prescan, stage1, providers, health, isLocalFallback: true };
}

// Network-level failure detection — these mean "classifier not
// reachable", which the fallback covers. Anything else (HTTP 4xx
// semantics surfaced as errors, validation failures) still throws so
// real API contract problems stay loud.
const NETWORK_ERROR_RE = /fetch failed|ECONNREFUSED|ECONNRESET|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ABORT_ERR|aborted|timeout/i;

function _isNetworkError(err) {
  if (!err) return false;
  if (NETWORK_ERROR_RE.test(err.message || "")) return true;
  if (err.cause && NETWORK_ERROR_RE.test(String(err.cause.code || err.cause.message || ""))) return true;
  return NETWORK_ERROR_RE.test(String(err.code || ""));
}

/**
 * Wrap the real classifier client with runtime fallback: when a prescan
 * call fails at the network level, warn once per call and serve the
 * local verdict instead. Keeps registrations flowing through classifier
 * outages without retry-loop latency.
 */
function createFallbackClassifierClient({ primary, local, log }) {
  if (!primary) throw new Error("classifier-fallback: primary client required");
  const logger = log || console;
  const localClient = local || createLocalClassifierClient();

  // Circuit breaker: after BREAK_AFTER consecutive network failures, skip the
  // primary entirely for COOLDOWN_MS , a dead classifier must not cost every
  // job a fetch round-trip (2026-07-04: per-job fetch failures against a dead
  // endpoint kept a node's CPU pegged for 40min draining its queue).
  const { CLASSIFIER_BREAK_AFTER: BREAK_AFTER, CLASSIFIER_COOLDOWN_MS: COOLDOWN_MS } =
    require("../../../shared/constants");
  let _consecutiveFailures = 0;
  let _openUntil = 0;

  async function prescan(args) {
    if (_openUntil > nowMs()) return localClient.prescan(args);
    try {
      const result = await primary.prescan(args);
      if (_consecutiveFailures >= BREAK_AFTER) logger.warn?.("classifier reachable again , circuit closed");
      _consecutiveFailures = 0;
      return result;
    } catch (err) {
      if (!_isNetworkError(err)) throw err;
      _consecutiveFailures++;
      if (_consecutiveFailures === BREAK_AFTER) {
        _openUntil = nowMs() + COOLDOWN_MS;
        logger.warn?.(
          `classifier unreachable ${BREAK_AFTER}x (${err.message || err}) , circuit OPEN, ` +
          `serving LOCAL FALLBACK verdicts without fetch attempts for ${COOLDOWN_MS / 1000}s`,
        );
      } else if (_consecutiveFailures < BREAK_AFTER) {
        logger.warn?.(
          `classifier unreachable (${err.message || err}); serving LOCAL FALLBACK verdict ` +
          "(heuristic text, stub media). Set TIP_CLASSIFIER_FALLBACK=0 to disable fallback.",
        );
      }
      return localClient.prescan(args);
    }
  }

  return {
    prescan,
    stage1: (...a) => primary.stage1(...a),
    providers: (...a) => primary.providers(...a),
    health: (...a) => primary.health(...a),
    isFallbackWrapped: true,
  };
}

module.exports = {
  createLocalClassifierClient,
  createFallbackClassifierClient,
  MEDIA_STUB_PROBABILITY,
};
