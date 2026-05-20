/**
 * @file @tip-protocol/node/src/schemas/prescan-review-recused.js
 * @description Canonical schema for `PRESCAN_REVIEW_RECUSED` — the
 * assigned reviewer bows out of an open review. The current review
 * row closes with state=RECUSED; commit-handler also flips
 * content.status back to REGISTERED so the prescan-review-trigger
 * naturally re-emits a fresh PRESCAN_REVIEW_TRIGGERED (with a new
 * assignment) on the next round. The recusing reviewer is excluded
 * from re-selection by selectReviewer's accuracy gate only — recusal
 * itself isn't a "wrong call", so it doesn't impact accuracy.
 *
 * Signed by: the assigned reviewer's ML-DSA-65 key (user signature on
 * `tx.data.signature`).
 *
 * Canonical signed fields (alphabetical):
 *   recusal_reason     string|null,  optional reviewer-written note
 *   review_id          string,       which review the reviewer is
 *                                    recusing from
 *   reviewer_tip_id    string,       the signer (must match the
 *                                    review's assigned_reviewer)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError } = require("./_common");
const { mldsaVerify, canonicalTx } = require("../../../shared/crypto");
const { TX_TYPES, PRESCAN_REVIEW_STATES } = require("../../../shared/constants");

const TX_TYPE = TX_TYPES.PRESCAN_REVIEW_RECUSED;

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
 * Gate: review exists and state is TRIGGERED (the only state from
 * which recusal makes sense — once a decision is made, there's
 * nothing left to recuse from). For user-initiated recusal (auto !=
 * true) the signer MUST be the assigned reviewer; the node-signed
 * auto path skips that check because the trigger module emits on
 * behalf of an inactive assignee. Shared between API time and
 * consensus replay.
 */
function resolveReview(reviewId, reviewerTipId, dag, { auto = false } = {}) {
  const review = dag.getPrescanReview(reviewId);
  if (!review) {
    throw schemaError(404, `Review not found: ${reviewId}`, "review_not_found");
  }
  if (!auto && review.assigned_reviewer !== reviewerTipId) {
    throw schemaError(403, "Only the assigned reviewer can recuse from this review", "reviewer_not_assigned");
  }
  if (review.state !== PRESCAN_REVIEW_STATES.TRIGGERED) {
    throw schemaError(
      409,
      `Review is not in a recusable state (state=${review.state})`,
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
  if (body.recusal_reason != null && typeof body.recusal_reason !== "string") {
    throw schemaError(400, "recusal_reason must be a string when present", "recusal_reason_invalid");
  }
  resolveReviewer(body.reviewer_tip_id, deps.dag);
  resolveReview(body.review_id, body.reviewer_tip_id, deps.dag);
}

/**
 * Canonical signed payload. recusal_reason is always emitted (as null
 * when absent) so the canonical bytes are deterministic.
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
    recusal_reason: typeof input.recusal_reason === "string" ? input.recusal_reason : null,
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

function verifyTx(tx, dag) {
  const d = tx.data || {};

  if (!d.review_id) {
    return { ok: false, status: 400, error: "review_id missing", code: "review_id_missing" };
  }

  // Node-signed auto-recuse — emitted by prescan-review-trigger when
  // the assigned reviewer's AUTO_RECUSE_AGE_MS elapses without a
  // decision. Same shape as CONTENT_DISPUTED auto-cascade (data.auto +
  // data.node_id, tx.signature at top level over canonicalTx).
  if (d.auto) {
    if (!d.node_id) {
      return { ok: false, status: 400, error: "node_id missing on auto-recuse", code: "node_id_missing" };
    }
    if (typeof tx.signature !== "string" || tx.signature.length === 0) {
      return { ok: false, status: 400, error: "tx.signature missing on auto-recuse", code: "signature_missing" };
    }
    const node = dag.getNode(d.node_id);
    if (!node) {
      return { ok: false, status: 412, error: `Node not registered: ${d.node_id}`, code: "node_not_registered" };
    }
    if (node.status !== "active") {
      return { ok: false, status: 403, error: `Node not active: ${d.node_id}`, code: "node_inactive" };
    }
    try {
      resolveReview(d.review_id, null, dag, { auto: true });
    } catch (err) {
      if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
      throw err;
    }
    if (!mldsaVerify(canonicalTx(tx), tx.signature, node.public_key)) {
      return { ok: false, status: 403, error: "Node signature verification failed", code: "signature_invalid" };
    }
    return { ok: true };
  }

  // Reviewer-signed manual recuse (the original path).
  if (typeof d.signature !== "string") {
    return { ok: false, status: 400, error: "signature missing on tx", code: "signature_missing" };
  }
  if (!d.reviewer_tip_id) {
    return { ok: false, status: 400, error: "reviewer_tip_id missing", code: "reviewer_tip_id_missing" };
  }

  let reviewer;
  let payload;
  try {
    reviewer = resolveReviewer(d.reviewer_tip_id, dag);
    resolveReview(d.review_id, d.reviewer_tip_id, dag);
    payload = buildSigningPayload(d);
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }

  if (!verifySignature(payload, d.signature, reviewer.public_key)) {
    return { ok: false, status: 403, error: "Reviewer signature verification failed", code: "signature_invalid" };
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
};
