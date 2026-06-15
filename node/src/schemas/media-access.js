/**
 * @file @tip-protocol/node/src/schemas/media-access.js
 * @description Request validation for GET /v1/content/:ctid/media/:idx.
 *
 * Reviewers / jurors / authors fetch a piece of stored media for a
 * registered content by signing a per-request challenge. The signed
 * challenge binds the request to (ctid, idx, requester, timestamp) so a
 * captured signature can't be replayed against a different ctid or media
 * slot, and can't be replayed indefinitely.
 *
 * Validation split (matches the project-wide rule and content-register):
 *   schema (here):
 *     - shape (ctid, idx, requester_tip_id, signature, timestamp)
 *     - replay window
 *     - DAG presence: identity exists, active, not revoked
 *   service (media-service.fetchForReviewer):
 *     - signature verifies under DAG public key
 *     - access-policy check (author / reviewer / disputer / juror / expert)
 *
 * Challenge format (signed by requester's ML-DSA-65 key):
 *   MEDIA_ACCESS:{ctid}:{idx}:{timestamp}:{requester_tip_id}
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError } = require("./_common");
const { isValidMs, nowMs } = require("../../../shared/time");

const TIP_ID_RE = /^tip:\/\/id\/[A-Z]{2}-[0-9a-f]{16}$/;
const HEX_RE = /^[0-9a-f]+$/i;
const CTID_RE = /^tip:\/\/c\/[A-Z]+-[0-9a-f]{14}-[0-9a-f]{4}$/;

// ±5min — same as media-upload. Reviewer client must NTP-sync.
const ACCESS_TIMESTAMP_WINDOW_MS = 5 * 60 * 1000;

/**
 * Look up the requester's identity on the DAG and reject if missing,
 * inactive, or revoked. Mirrors content-register.resolveSigner so the
 * "is this caller a valid TIP-ID?" predicate is identical across
 * endpoints. Service refetches identity for the public_key during
 * signature verification — single source of truth for the policy.
 */
function resolveRequester(tipId, dag) {
  const identity = dag.getIdentity(tipId);
  if (!identity) {
    throw schemaError(404, `Unknown requester: ${tipId}`, "requester_not_found");
  }
  if (identity.status !== "active") {
    throw schemaError(403, `Requester not active: ${tipId}`, "requester_inactive");
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(tipId)) {
    throw schemaError(403, `Requester revoked: ${tipId}`, "requester_revoked");
  }
  return identity;
}

function validateRequest(input, deps) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "request input is required", "input_invalid");
  }
  if (typeof input.ctid !== "string" || !CTID_RE.test(input.ctid)) {
    throw schemaError(400, "ctid must match tip://c/<ORIGIN>-<14hex>-<4hex>", "ctid_invalid");
  }
  if (!Number.isInteger(input.idx) || input.idx < 0) {
    throw schemaError(400, "idx must be a non-negative integer", "idx_invalid");
  }
  if (typeof input.requester_tip_id !== "string" || !TIP_ID_RE.test(input.requester_tip_id)) {
    throw schemaError(400, "requester_tip_id is required (tip://id/<REGION>-<16hex>)", "requester_tip_id_required");
  }
  if (typeof input.signature !== "string" || input.signature.length === 0 || !HEX_RE.test(input.signature)) {
    throw schemaError(400, "signature is required (hex-encoded ML-DSA)", "signature_required");
  }
  if (!Number.isInteger(input.timestamp) || !isValidMs(input.timestamp)) {
    throw schemaError(400, "timestamp is required (integer ms epoch)", "timestamp_required");
  }

  const drift = Math.abs(nowMs() - input.timestamp);
  if (drift > ACCESS_TIMESTAMP_WINDOW_MS) {
    throw schemaError(
      400,
      `Timestamp drift ${drift}ms exceeds ${ACCESS_TIMESTAMP_WINDOW_MS}ms window`,
      "timestamp_drift",
    );
  }

  // DAG presence — must exist, be active, and not be revoked. Throws
  // 404/403 with structured codes. Identity is returned for callers that
  // want to skip a refetch (currently unused; service refetches for
  // the public_key during signature verification).
  if (!deps || !deps.dag) {
    throw new Error("media-access.validateRequest: deps.dag required");
  }
  resolveRequester(input.requester_tip_id, deps.dag);
}

function buildChallenge({ ctid, idx, timestamp, requester_tip_id }) {
  return `MEDIA_ACCESS:${ctid}:${idx}:${timestamp}:${requester_tip_id}`;
}

module.exports = {
  validateRequest,
  resolveRequester,
  buildChallenge,
  TIP_ID_RE,
  CTID_RE,
  ACCESS_TIMESTAMP_WINDOW_MS,
};
