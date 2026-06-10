/**
 * @file @tip-protocol/node/src/schemas/media-upload.js
 * @description Request validation for POST /v1/media/upload.
 *
 * Owns ALL request-level validation per the project rule (validateRequest
 * lives in schemas/, never inline in services). Matches media-access:
 *
 *   schema (here):                          service (media-service.js):
 *     - shape (bytes, mime, signer, sig)      - signature verifies against
 *     - mime format (image/audio/video)         identity's public_key
 *     - mime family enabled (video gate)      - storage.put
 *     - per-mime size limit (genesis)
 *     - replay window (nowMs ± window)
 *     - DAG presence (signer exists,
 *       active, not revoked)
 *
 * Challenge format (signed by uploader's ML-DSA-65 key):
 *   MEDIA_UPLOAD:{content_hash_hex}:{mime}:{timestamp}:{signer_tip_id}
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError } = require("./_common");
const { isValidMs, nowMs } = require("../../../shared/time");
const { CONTENT_LIMITS } = require("../../../shared/protocol-constants");

const TIP_ID_RE = /^tip:\/\/id\/[A-Z]{2}-[0-9a-f]{16}$/;
const HEX_RE = /^[0-9a-f]+$/i;
const MIME_RE = /^(image|audio|video)\/[a-z0-9.+\-]+$/i;

// Replay window: signed timestamps from clients must fall within ±N ms of
// server clock. Tight enough to defeat replay; loose enough to forgive
// honest NTP-level clock skew.
const UPLOAD_TIMESTAMP_WINDOW_MS = 5 * 60 * 1000;

function _resolveSizeLimit(mime) {
  if (mime.startsWith("image/")) return CONTENT_LIMITS.IMAGE_MAX_BYTES;
  if (mime.startsWith("audio/")) return CONTENT_LIMITS.AUDIO_MAX_BYTES;
  if (mime.startsWith("video/")) return CONTENT_LIMITS.VIDEO_MAX_BYTES;
  return null;
}

/**
 * Look up the signer's identity on the DAG and reject if missing,
 * inactive, or revoked. Mirrors media-access.resolveRequester so the
 * "is this caller a valid TIP-ID?" predicate is identical across
 * media endpoints.
 */
function resolveSigner(tipId, dag) {
  const identity = dag.getIdentity(tipId);
  if (!identity) {
    throw schemaError(404, `Unknown signer: ${tipId}`, "signer_not_found");
  }
  if (identity.status !== "active") {
    throw schemaError(403, `Signer not active: ${tipId}`, "signer_inactive");
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(tipId)) {
    throw schemaError(403, `Signer revoked: ${tipId}`, "signer_revoked");
  }
  return identity;
}

/**
 * Validate a media upload request. Throws schemaError on the first problem.
 * Service keeps only the signature verification (needs canonical challenge
 * bytes + the identity's public key).
 *
 * @param {Object} input
 * @param {Buffer} input.bytes
 * @param {string} input.mime
 * @param {string} input.signer_tip_id
 * @param {string} input.signature
 * @param {number} input.timestamp
 * @param {Object} deps          { dag } — identity lookups
 */
function validateRequest(input, deps) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "request input is required", "input_invalid");
  }
  if (!Buffer.isBuffer(input.bytes) || input.bytes.length === 0) {
    throw schemaError(400, "bytes is required (non-empty buffer)", "bytes_required");
  }
  if (typeof input.mime !== "string" || input.mime.length === 0) {
    throw schemaError(400, "mime is required", "mime_required");
  }
  if (!MIME_RE.test(input.mime)) {
    throw schemaError(415, `mime must match image/*, audio/*, or video/* (got ${input.mime})`, "mime_invalid");
  }

  const sizeLimit = _resolveSizeLimit(input.mime);
  if (sizeLimit <= 0) {
    // Mime family hard-gated in genesis (today: video). Disabled at the
    // schema layer so callers see a 415 before any storage cost is paid.
    throw schemaError(415, `Mime family disabled in genesis: ${input.mime}`, "mime_disabled");
  }
  if (input.bytes.length > sizeLimit) {
    throw schemaError(413, `File too large: ${input.bytes.length} > ${sizeLimit}`, "file_too_large");
  }

  if (typeof input.signer_tip_id !== "string" || !TIP_ID_RE.test(input.signer_tip_id)) {
    throw schemaError(400, "signer_tip_id is required (tip://id/<REGION>-<16hex>)", "signer_tip_id_required");
  }
  if (typeof input.signature !== "string" || !HEX_RE.test(input.signature) || input.signature.length === 0) {
    throw schemaError(400, "signature is required (hex-encoded ML-DSA)", "signature_required");
  }
  if (!Number.isInteger(input.timestamp) || !isValidMs(input.timestamp)) {
    throw schemaError(400, "timestamp is required (integer ms epoch)", "timestamp_required");
  }

  // Replay defense. Tight ±5min window; client must NTP-sync within
  // reason. Past failures here are usually a client clock skew bug.
  const drift = Math.abs(nowMs() - input.timestamp);
  if (drift > UPLOAD_TIMESTAMP_WINDOW_MS) {
    throw schemaError(
      400,
      `Timestamp drift ${drift}ms exceeds ${UPLOAD_TIMESTAMP_WINDOW_MS}ms window`,
      "timestamp_drift",
    );
  }

  if (!deps || !deps.dag) {
    throw new Error("media-upload.validateRequest: deps.dag required");
  }
  resolveSigner(input.signer_tip_id, deps.dag);
}

/**
 * Build the canonical signed challenge for an upload. Single source of
 * truth so client and server compute identical bytes.
 *
 * @param {Object} input
 * @param {string} input.content_hash   shake256(bytes, 32) as 64-hex
 * @param {string} input.mime
 * @param {number} input.timestamp
 * @param {string} input.signer_tip_id
 * @returns {string} canonical challenge
 */
function buildChallenge({ content_hash, mime, timestamp, signer_tip_id }) {
  return `MEDIA_UPLOAD:${content_hash}:${mime}:${timestamp}:${signer_tip_id}`;
}

module.exports = {
  validateRequest,
  resolveSigner,
  buildChallenge,
  TIP_ID_RE,
  MIME_RE,
  UPLOAD_TIMESTAMP_WINDOW_MS,
};
