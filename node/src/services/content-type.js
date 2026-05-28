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
 *   2. Heuristic derivation — when no hint, infer from media MIME types +
 *                             text length.
 *   3. Validate + auto-correct — when the hint is catastrophically wrong
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
 * Derive content_type heuristically from request shape.
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
 * Decide whether a publisher-declared `hint` is consistent with the
 * request's actual shape.
 *
 * Returns:
 *   { ok: true }                                  — hint matches shape; trust it
 *   { ok: false, code: "...", message: "..." }    — major mismatch the caller
 *                                                   should reject (audio/video
 *                                                   declared without the file)
 *   { ok: true, correctedTo, reason }             — recoverable mismatch
 *                                                   (e.g. "text" with a huge
 *                                                   media file): caller should
 *                                                   use correctedTo instead.
 */
function validateAgainstShape(hint, req) {
  if (!CONTENT_TYPE.VALID_TYPES.includes(hint)) {
    return { ok: false, code: "invalid_content_type", message: `Unknown content_type: ${hint}` };
  }
  const s = _shape(req);

  // Catastrophic: declared modality requires a file of that type, none present.
  if (hint === "video" && !s.hasVideo) {
    return { ok: false, code: "missing_video", message: "content_type=video requires a video file" };
  }
  if (hint === "audio" && !s.hasAudio) {
    return { ok: false, code: "missing_audio", message: "content_type=audio requires an audio file" };
  }
  if (hint === "image" && !s.hasImage) {
    return { ok: false, code: "missing_image", message: "content_type=image requires an image file" };
  }

  // Recoverable: "text" with a substantial media file + trivial text.
  // The publisher likely mis-declared a photo/video post. Auto-correct
  // to the heuristic-derived type and record the override for audit.
  if (hint === "text" && s.kinds >= 1 && s.textLen < 100) {
    const derived = deriveContentType(req);
    if (derived && derived !== hint) {
      return {
        ok: true,
        correctedTo: derived,
        reason: `hint=text but request carries ${s.mediaCount} media file(s) with only ${s.textLen} chars of text`,
      };
    }
  }

  // Recoverable: "multi" with only one media kind. Not strictly wrong,
  // but the heuristic suggests a more specific type. Trust the hint for
  // "multi" since publishers may genuinely have heterogeneous content
  // they want classified neutrally — log only.
  // (No auto-correction; multi is always valid.)

  return { ok: true };
}

/**
 * Resolve the authoritative content_type for a registration request.
 *
 * The caller (content-service.register) passes the parsed request body;
 * the resolver returns:
 *
 *   {
 *     contentType:   "text"|"image"|"audio"|"video"|"multi",
 *     hintProvided:  string | null,
 *     resolution:    "from_hint" | "derived" | "auto_corrected_from_hint",
 *     reason:        string | null   // populated for auto-corrections
 *   }
 *
 * Throws { status, error, code } on:
 *   - hint specifies audio/video/image but the corresponding file is absent
 *   - request has no classifiable content (no text, no media)
 */
function resolve(req) {
  const hint = req && typeof req.content_type_hint === "string" ? req.content_type_hint : null;

  if (hint) {
    const v = validateAgainstShape(hint, req);
    if (!v.ok) {
      throw { status: 400, error: v.message, code: v.code };
    }
    if (v.correctedTo) {
      return {
        contentType: v.correctedTo,
        hintProvided: hint,
        resolution: "auto_corrected_from_hint",
        reason: v.reason,
      };
    }
    return {
      contentType: hint,
      hintProvided: hint,
      resolution: "from_hint",
      reason: null,
    };
  }

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
    reason: null,
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
  resolve,
  primaryModality,
};
