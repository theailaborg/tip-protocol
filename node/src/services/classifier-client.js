/**
 * @file @tip-protocol/node/src/services/classifier-client.js
 * @description Thin HTTP client for the TIP Protocol AI classifier
 * (CLASSIFIER_INTEGRATION.md). Used by the prescan worker to call
 * /v1/prescan + /v1/stage1 + /v1/providers + /health.
 *
 * Behaviour shaped by lessons in my-notes/CLASSIFIER_API_PROBES.md:
 *
 *   1. Always send `text` field (even empty string) — the API rejects
 *      requests with the field missing even when a file is present.
 *   2. Validate `origin_code` locally against {OH, AA, AG, MX} — the
 *      API silently accepts unknown codes as "skipped".
 *   3. Skip the round-trip entirely for non-OH origins (the API would
 *      respond with `provider_used: "skipped"` anyway). Saves latency
 *      and classifier load.
 *   4. Block video at the boundary in v1 (genesis: video_max_bytes=0).
 *      The classifier crashes 500 on video today; defer until v2
 *      ships file_url + content-storage.
 *   5. Per-modality timeouts: text 60 s, image/audio 180 s. Cold starts
 *      (ollama ~33 s, ONNX vision ~118 s) sometimes overshoot, but
 *      retry policy on the worker side picks up.
 *
 * Factory function with injected fetch — tests can pass a mock.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONTENT_LIMITS } = require("../../../shared/protocol-constants");
const { ORIGIN, CLASSIFIER_CLIENT } = require("../../../shared/constants");

const ORIGIN_CODES = Object.freeze(new Set(Object.values(ORIGIN)));

/**
 * Build a clean response that mirrors what the classifier returns for
 * non-OH origins, so callers downstream don't need to special-case the
 * locally-skipped path. Matches the actual API shape verified in the
 * probes.
 */
function _skippedResponse(originCode, providerUsed = "skipped_locally") {
  return {
    flagged: false,
    probability: 0.0,
    modalities_analyzed: [],
    modality_results: [],
    provider_used: providerUsed,
    processing_ms: 0,
    note: `Pre-scan only applies to OH declarations. origin_code=${originCode} skipped (client).`,
    locally_skipped: true,
  };
}

/**
 * Create a classifier client bound to a base URL + optional auth key.
 *
 * URL is deployment config — must come from env (TIP_CLASSIFIER_URL) or
 * an explicit opts.url. No default. If neither is set, the factory
 * throws so misconfigured deployments fail loud at boot, not silently
 * pointing at localhost in production.
 *
 * @param {Object} [opts]
 * @param {string} [opts.url]       Override env (used by tests).
 * @param {string} [opts.key]       Override env (used by tests). When
 *   unset and TIP_CLASSIFIER_KEY is empty, the X-TIP-Classifier-Key
 *   header is omitted — dev mode against an unauthenticated classifier.
 * @param {Object} [opts.timeouts]  Override the protocol-level
 *   { text, file } ceilings. Tests use this; production should not.
 * @param {Function} [opts.fetch]   Injectable fetch (tests pass a mock).
 */
function createClassifierClient(opts = {}) {
  const url = opts.url ?? process.env.TIP_CLASSIFIER_URL;
  if (typeof url !== "string" || url.length === 0) {
    throw new Error(
      "classifier-client: TIP_CLASSIFIER_URL env var is not set (and no opts.url provided)",
    );
  }
  const key = opts.key ?? process.env.TIP_CLASSIFIER_KEY ?? "";
  const timeouts = {
    text: opts.timeouts?.text ?? CLASSIFIER_CLIENT.TEXT_TIMEOUT_MS,
    file: opts.timeouts?.file ?? CLASSIFIER_CLIENT.FILE_TIMEOUT_MS,
  };
  const fetchImpl = opts.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("classifier-client: fetch implementation not available");
  }

  function _headers() {
    const h = { "Content-Type": "application/json", "Accept": "application/json" };
    if (key) h["X-TIP-Classifier-Key"] = key;
    return h;
  }

  async function _post(path, body, timeoutMs) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    const started = Date.now();
    try {
      const res = await fetchImpl(`${url}${path}`, {
        method: "POST",
        headers: _headers(),
        body: JSON.stringify(body),
        signal: ac.signal,
      });
      const elapsed = Date.now() - started;
      const text = await res.text();
      let parsed = null;
      try { parsed = text ? JSON.parse(text) : null; }
      catch { /* keep null */ }
      return { status: res.status, wall_ms: elapsed, body: parsed, raw: text };
    } finally {
      clearTimeout(timer);
    }
  }

  async function _get(path, timeoutMs = timeouts.text) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetchImpl(`${url}${path}`, {
        method: "GET",
        headers: _headers(),
        signal: ac.signal,
      });
      const text = await res.text();
      let parsed = null;
      try { parsed = text ? JSON.parse(text) : null; }
      catch { /* keep null */ }
      return { status: res.status, body: parsed, raw: text };
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Public methods ──────────────────────────────────────────────────────

  /**
   * Call POST /v1/prescan.
   *
   * @param {Object} args
   * @param {string} args.originCode             Required. {OH, AA, AG, MX}.
   * @param {string} [args.text=""]              Text body. Empty string for
   *   file-only submissions; the API requires the field to be present.
   * @param {Object} [args.file]                 { base64, mime }. Optional;
   *   classifier accepts one file per call. v1 rejects video mime types.
   * @param {number} [args.creatorClearedCount]  H for FIX-03 calibration.
   * @param {string} [args.authorTipId]
   * @returns {Promise<Object>} Classifier response or locally-skipped shim.
   * @throws {Object} { code, status, message } on validation / HTTP errors.
   */
  async function prescan(args = {}) {
    const originCode = args.originCode;
    if (!ORIGIN_CODES.has(originCode)) {
      throw {
        code: "invalid_origin_code",
        message: `origin_code must be one of: OH, AA, AG, MX (got "${originCode}")`,
      };
    }
    // Non-OH origins: classifier always returns "skipped". Short-circuit
    // locally to save latency + classifier load.
    if (originCode !== "OH") {
      return _skippedResponse(originCode);
    }

    const body = {
      text: typeof args.text === "string" ? args.text : "",
      origin_code: originCode,
      creator_cleared_count: Number.isInteger(args.creatorClearedCount) ? args.creatorClearedCount : 0,
      provider_preference: "ensemble",
    };
    if (args.authorTipId) body.author_tip_id = args.authorTipId;

    const hasFile = !!(args.file && args.file.base64);
    if (hasFile) {
      _assertFileAllowed(args.file);
      body.file_base64 = args.file.base64;
      if (args.file.mime) body.file_mime_type = args.file.mime;
    }

    const timeoutMs = hasFile ? timeouts.file : timeouts.text;
    const res = await _post("/v1/prescan", body, timeoutMs);
    if (res.status < 200 || res.status >= 300) {
      throw {
        code: "classifier_http_error",
        status: res.status,
        message: `classifier /v1/prescan returned ${res.status}`,
        body: res.body ?? res.raw,
      };
    }
    return res.body;
  }

  /**
   * Call POST /v1/stage1. Used (in v2 dispute flow) once the creator's
   * grace window expires without correction. Not wired into v1 worker.
   */
  async function stage1(args = {}) {
    if (!args.ctid) {
      throw { code: "ctid_required", message: "stage1: ctid is required" };
    }
    if (!ORIGIN_CODES.has(args.declaredOrigin)) {
      throw { code: "invalid_origin_code", message: "stage1: declared_origin invalid" };
    }
    const body = {
      ctid: args.ctid,
      declared_origin: args.declaredOrigin,
      text: typeof args.text === "string" ? args.text : "",
      dispute_reason: args.disputeReason || "pre_scan_flag",
    };
    if (args.authorTipId) body.author_tip_id = args.authorTipId;
    if (args.title) body.title = args.title;
    const hasFile = !!(args.file && args.file.base64);
    if (hasFile) {
      _assertFileAllowed(args.file);
      body.file_base64 = args.file.base64;
      if (args.file.mime) body.file_mime_type = args.file.mime;
    }

    const timeoutMs = hasFile ? timeouts.file : timeouts.text;
    const res = await _post("/v1/stage1", body, timeoutMs);
    if (res.status < 200 || res.status >= 300) {
      throw {
        code: "classifier_http_error",
        status: res.status,
        message: `classifier /v1/stage1 returned ${res.status}`,
        body: res.body ?? res.raw,
      };
    }
    return res.body;
  }

  async function providers() {
    const res = await _get("/v1/providers");
    return res.body;
  }

  async function health() {
    const res = await _get("/health");
    return res.body;
  }

  return { prescan, stage1, providers, health };
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function _assertFileAllowed(file) {
  const mime = String(file.mime || "").toLowerCase();
  if (mime.startsWith("video/")) {
    if (CONTENT_LIMITS.VIDEO_MAX_BYTES <= 0) {
      throw {
        code: "video_unsupported_v1",
        status: 415,
        message: "Video uploads are not supported in v1 — coming when the content-storage layer ships",
      };
    }
  }
  // Other mime sanity (text excluded) — defer to classifier-side limits.
}

/**
 * Treat a classifier response as "trustworthy" or not. Per
 * CLASSIFIER_INTEGRATION.md §6: if provider_used is heuristic-only
 * (the always-on fallback), the verdict is from the heuristic alone
 * and should NOT be acted on as a real signal. The aggregator treats
 * these as low-confidence; the worker may also force-fail-open.
 */
function isHeuristicOnly(response) {
  return !!(response && response.provider_used === "heuristic");
}

/**
 * Recognise the "non-OH skipped" / "locally skipped" response so
 * callers can treat it as a deliberate clean result, not degraded.
 */
function isSkipped(response) {
  if (!response) return false;
  if (response.locally_skipped) return true;
  if (response.provider_used === "skipped") return true;
  return false;
}

module.exports = {
  createClassifierClient,
  isHeuristicOnly,
  isSkipped,
};
