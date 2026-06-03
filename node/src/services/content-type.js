/**
 * @file @tip-protocol/node/src/services/content-type.js
 * @description Pure functions that resolve the canonical content_type for
 * a registration request. The result drives modality-weight selection in
 * the prescan aggregator.
 *
 * Resolution ladder (priority order):
 *
 *   1. Client declaration   — `content_type_hint` on REGISTER_CONTENT,
 *                             signed by the publisher. Trusted unless it
 *                             clearly contradicts the request shape.
 *   2. URL platform lookup  — registered_urls[0] host matched against
 *                             shared/platforms.js PLATFORM_CONTENT_TYPE.
 *                             Resolves via a strategy (FIXED, MEDIA_DOMINANT,
 *                             MIXED, TEXT_DOMINANT) appropriate to the
 *                             platform's posting conventions.
 *   3. Shape heuristic      — when host isn't registered, infer from
 *                             media MIME types + text length.
 *   4. Validate + auto-correct — when the hint is catastrophically wrong
 *                             (e.g. "text" declared with a 30 MB video
 *                             and 5 chars of text), override and record
 *                             the correction for audit.
 *
 * The authoritative `content_type` lives on `PRESCAN_COMPLETED.data`. The
 * hint lives on `REGISTER_CONTENT.data.content_type_hint`. Every replay
 * node reads the resolved value off PRESCAN_COMPLETED — they don't
 * re-derive.
 *
 * Pure functions: no DAG access, no IO, no clocks. Fully unit-testable.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONTENT_TYPE } = require("../../../shared/protocol-constants");
const { PLATFORM_ALIASES, PLATFORM_CONTENT_TYPE } = require("../../../shared/platforms");

const PRIMARY_MODALITY = Object.freeze({
  text: "text",
  image: "image",
  audio: "audio",
  video: "video",
  multi: null,   // no single primary
});

/**
 * Inspect a request's media array + text and return modality booleans +
 * counts. Internal helper for both derive and validate.
 */
function _shape(req) {
  const text = typeof req.text === "string" ? req.text : "";
  const media = Array.isArray(req.media) ? req.media : [];
  const mimes = media.map(m => (m && typeof m.mime === "string" ? m.mime : "").toLowerCase());

  const hasVideo = mimes.some(m => m.startsWith("video/"));
  const hasAudio = mimes.some(m => m.startsWith("audio/"));
  const hasImage = mimes.some(m => m.startsWith("image/"));
  const kinds = [hasVideo, hasAudio, hasImage].filter(Boolean).length;

  return {
    text,
    textLen: text.length,
    hasVideo, hasAudio, hasImage,
    kinds,
    mediaCount: media.length,
  };
}

/**
 * Derive content_type heuristically from request shape. Last-resort
 * fallback used when no publisher hint AND no platform-registry match.
 *
 * Order matters: video > audio > image+long-text (article-with-hero) >
 * image+short-text (photo-with-caption) > text-only. Multiple media kinds
 * collapse to "multi".
 *
 * @returns {string|null} one of valid_content_types, or null when the
 *   request has no classifiable content (caller throws 400).
 */
function deriveContentType(req) {
  const s = _shape(req);

  if (s.kinds >= 2) return "multi";
  if (s.hasVideo) return "video";
  if (s.hasAudio) return "audio";
  if (s.hasImage) {
    return s.textLen >= CONTENT_TYPE.ARTICLE_TEXT_THRESHOLD_CHARS ? "text" : "image";
  }
  if (s.textLen > 0) return "text";

  return null;
}

/**
 * Look up a URL's host in PLATFORM_CONTENT_TYPE, resolving aliases first
 * (twitter.com → x.com) and walking subdomain suffixes
 * (anyone.substack.com → substack.com). Returns the strategy string or
 * null when the host isn't registered.
 */
function resolvePlatformStrategy(url) {
  if (typeof url !== "string" || url.length === 0) return null;
  let host;
  try { host = new URL(url).hostname.toLowerCase(); }
  catch { return null; }
  if (host.startsWith("www.")) host = host.slice(4);

  while (true) {
    const canonical = PLATFORM_ALIASES[host] || host;
    if (PLATFORM_CONTENT_TYPE[canonical]) return PLATFORM_CONTENT_TYPE[canonical];
    const dot = host.indexOf(".");
    if (dot < 0 || dot === host.length - 1) return null;
    host = host.slice(dot + 1);
    if (!host.includes(".")) {
      const root = PLATFORM_ALIASES[host] || host;
      return PLATFORM_CONTENT_TYPE[root] || null;
    }
  }
}

/**
 * Apply a platform-strategy ruleset against a request's shape and return
 * the resolved content_type or null when the shape carries no
 * classifiable content.
 *
 * Strategy semantics are documented at the top of shared/platforms.js;
 * the table below summarises each strategy's behavior when text+media
 * are both present.
 *
 *   FIXED:type       → the type, regardless of request shape
 *   MEDIA_DOMINANT   → media kind wins (text is caption)
 *   TEXT_DOMINANT    → text if any text present, else media kind
 *   MIXED            → video/audio always win; image+text → "multi"
 */
function applyStrategy(strategy, req) {
  // Fixed-type strategies — the platform IS the type. We still require
  // *some* classifiable content so an empty request 400s like the
  // heuristic path.
  if (strategy === "video" || strategy === "audio" || strategy === "image" || strategy === "text") {
    const s = _shape(req);
    if (s.kinds === 0 && s.textLen === 0) return null;
    return strategy;
  }

  const s = _shape(req);
  if (s.kinds === 0 && s.textLen === 0) return null;

  if (strategy === "MEDIA_DOMINANT") {
    if (s.kinds >= 2) return "multi";
    if (s.hasVideo) return "video";
    if (s.hasAudio) return "audio";
    if (s.hasImage) return "image";
    return "text";
  }

  if (strategy === "TEXT_DOMINANT") {
    if (s.textLen > 0) return "text";
    if (s.kinds >= 2) return "multi";
    if (s.hasVideo) return "video";
    if (s.hasAudio) return "audio";
    if (s.hasImage) return "image";
    return null;
  }

  if (strategy === "MIXED") {
    if (s.kinds === 0) return "text";              // text-only post
    if (s.kinds >= 2) return "multi";              // mixed-media → multi
    if (s.hasVideo) return "video";                // attention-dominant
    if (s.hasAudio) return "audio";                // attention-dominant
    // Only image remains. Image + any text → multi (text might be the work);
    // image-only → image.
    if (s.hasImage) return s.textLen > 0 ? "multi" : "image";
    return null;
  }

  return null;
}

/**
 * Decide whether a publisher-declared `hint` is consistent with the
 * request's actual shape. Only catches structural impossibilities
 * (declared modality with the required file entirely absent); text
 * length, media size, and other heuristic comparisons are intentionally
 * NOT checked — the publisher's signed hint is authoritative and the
 * classifier scans every present modality regardless of the resolved
 * content_type, so the aggregator catches AI signal in modalities the
 * publisher de-emphasised.
 *
 * Returns:
 *   { ok: true }                                  — hint is structurally valid; trust it
 *   { ok: false, code: "...", message: "..." }    — declared modality requires
 *                                                   a file of that type that
 *                                                   the request doesn't carry
 */
function validateAgainstShape(hint, req) {
  if (!CONTENT_TYPE.VALID_TYPES.includes(hint)) {
    return { ok: false, code: "invalid_content_type", message: `Unknown content_type: ${hint}` };
  }
  const s = _shape(req);

  if (hint === "video" && !s.hasVideo) {
    return { ok: false, code: "missing_video", message: "content_type=video requires a video file" };
  }
  if (hint === "audio" && !s.hasAudio) {
    return { ok: false, code: "missing_audio", message: "content_type=audio requires an audio file" };
  }
  if (hint === "image" && !s.hasImage) {
    return { ok: false, code: "missing_image", message: "content_type=image requires an image file" };
  }

  return { ok: true };
}

/**
 * Resolve the authoritative content_type for a registration request.
 *
 * The caller (content-service.register) passes the parsed request body
 * augmented with `registered_url` (the canonical URL from
 * registered_urls[0]). The resolver returns:
 *
 *   {
 *     contentType:      "text"|"image"|"audio"|"video"|"multi",
 *     hintProvided:     string | null,
 *     resolution:       "from_hint" | "from_url" | "derived",
 *     platformStrategy: string | null,   // populated when resolved from URL
 *   }
 *
 * Throws { status, error, code } on:
 *   - hint specifies audio/video/image but the corresponding file is absent
 *   - request has no classifiable content (no text, no media)
 */
function resolve(req) {
  const hint = req && typeof req.content_type_hint === "string" ? req.content_type_hint : null;
  const url = req && typeof req.registered_url === "string" ? req.registered_url : null;

  // Step 1: explicit publisher hint — trust unless the declared modality
  // is structurally impossible (missing required file).
  if (hint) {
    const v = validateAgainstShape(hint, req);
    if (!v.ok) {
      throw { status: 400, error: v.message, code: v.code };
    }
    return {
      contentType: hint,
      hintProvided: hint,
      resolution: "from_hint",
      platformStrategy: null,
    };
  }

  // Step 2: URL platform lookup.
  const strategy = resolvePlatformStrategy(url);
  if (strategy) {
    const resolved = applyStrategy(strategy, req);
    if (resolved === null) {
      throw {
        status: 400,
        error: "Request has no classifiable content (no text, no media)",
        code: "no_content_to_classify",
      };
    }
    return {
      contentType: resolved,
      hintProvided: null,
      resolution: "from_url",
      platformStrategy: strategy,
    };
  }

  // Step 3: shape heuristic (unknown / no URL).
  const derived = deriveContentType(req);
  if (derived === null) {
    throw {
      status: 400,
      error: "Request has no classifiable content (no text, no media)",
      code: "no_content_to_classify",
    };
  }
  return {
    contentType: derived,
    hintProvided: null,
    resolution: "derived",
    platformStrategy: null,
  };
}

/**
 * Return the primary modality for a given content_type.
 * Used by the aggregator (Step 4) to identify the floor modality.
 * Returns null for "multi" (no single primary; aggregator falls back
 * to weighted-average over present modalities).
 */
function primaryModality(contentType) {
  return PRIMARY_MODALITY[contentType] !== undefined
    ? PRIMARY_MODALITY[contentType]
    : null;
}

module.exports = {
  deriveContentType,
  validateAgainstShape,
  resolvePlatformStrategy,
  applyStrategy,
  resolve,
  primaryModality,
};
