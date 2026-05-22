/**
 * @file @tip-protocol/node/src/schemas/prescan-review-dismissed.js
 * @description Canonical schema for `PRESCAN_REVIEW_DISMISSED` —
 * reviewer's "AI's flag was wrong" decision. The review closes; content
 * status returns to REGISTERED; no public dispute is created.
 *
 * Signed by: the assigned reviewer's ML-DSA-65 key (user signature on
 * `tx.data.signature`).
 *
 * Canonical signed fields (alphabetical):
 *   decision_note      string|null,  optional reviewer-written notes
 *   review_id          string,       which review this decision closes
 *   reviewer_tip_id    string,       the signer (must match the review's
 *                                    assigned_reviewer to validate)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError } = require("./_common");
const { TX_TYPES, PRESCAN_REVIEW_STATES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS } = require("../../../shared/constants");

const TX_TYPE = TX_TYPES.PRESCAN_REVIEW_DISMISSED;
// GH #51 — unified signature storage. Reviewer signs the canonical
// dismissal payload.
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.REVIEWER_TIP_ID;

function resolveReviewer(reviewerTipId, dag) {
  const identity = dag.getIdentity(reviewerTipId);
  if (!identity) {
    throw schemaError(412, "Reviewer TIP-ID not registered on DAG", "reviewer_not_registered");
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(reviewerTipId)) {
    throw schemaError(403, "Reviewer TIP-ID is revoked", "reviewer_revoked");
  }
  return identity;
}

/**
 * Resolve the review row and check the reviewer is authorized + the
 * review is in a state that can accept a dismissal. Shared between
 * API time (validateRequest) and consensus replay (verifyTx).
 */
function resolveReview(reviewId, reviewerTipId, dag) {
  const review = dag.getPrescanReview(reviewId);
  if (!review) {
    throw schemaError(404, `Review not found: ${reviewId}`, "review_not_found");
  }
  if (review.assigned_reviewer !== reviewerTipId) {
    throw schemaError(403, "Only the assigned reviewer can dismiss this review", "reviewer_not_assigned");
  }
  if (review.state !== PRESCAN_REVIEW_STATES.TRIGGERED) {
    throw schemaError(
      409,
      `Review is not in a dismissable state (state=${review.state})`,
      "review_state_invalid",
    );
  }
  return review;
}

function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (typeof body.review_id !== "string" || body.review_id.length === 0) {
    throw schemaError(400, "review_id is required", "review_id_required");
  }
  if (typeof body.reviewer_tip_id !== "string" || !body.reviewer_tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "reviewer_tip_id is required (tip://id/...)", "reviewer_tip_id_required");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }
  if (body.decision_note != null && typeof body.decision_note !== "string") {
    throw schemaError(400, "decision_note must be a string when present", "decision_note_invalid");
  }
  resolveReviewer(body.reviewer_tip_id, deps.dag);
  resolveReview(body.review_id, body.reviewer_tip_id, deps.dag);
}

/**
 * Build the canonical signed payload. decision_note is always emitted
 * (as null when absent) so the canonical bytes are deterministic.
 */
function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (typeof input.review_id !== "string") {
    throw schemaError(400, "review_id is required", "review_id_required");
  }
  if (typeof input.reviewer_tip_id !== "string") {
    throw schemaError(400, "reviewer_tip_id is required", "reviewer_tip_id_required");
  }
  return {
    decision_note: typeof input.decision_note === "string" ? input.decision_note : null,
    review_id: input.review_id,
    reviewer_tip_id: input.reviewer_tip_id,
  };
}

function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * State-level verification at consensus replay. GH #51: the signature
 * itself is verified by the unified dispatcher
 * (`schemas/_common.verifyTxSignature`) — this function only enforces
 * the state-machine + reviewer-assignment invariants the dispatcher
 * doesn't know about.
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};
  if (!d.reviewer_tip_id) {
    return { ok: false, status: 400, error: "reviewer_tip_id missing", code: "reviewer_tip_id_missing" };
  }
  if (!d.review_id) {
    return { ok: false, status: 400, error: "review_id missing", code: "review_id_missing" };
  }
  try {
    resolveReviewer(d.reviewer_tip_id, dag);
    resolveReview(d.review_id, d.reviewer_tip_id, dag);
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }
  return { ok: true };
}

module.exports = {
  TX_TYPE,
  resolveReviewer,
  resolveReview,
  validateRequest,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
  // GH #51 — unified signature contract
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
};
