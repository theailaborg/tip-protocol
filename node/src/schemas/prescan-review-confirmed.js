/**
 * @file @tip-protocol/node/src/schemas/prescan-review-confirmed.js
 * @description Canonical schema for `PRESCAN_REVIEW_CONFIRMED` —
 * reviewer's "AI's flag was right" decision. The review transitions to
 * state=confirmed and the creator's 24h accept-or-escalate window opens.
 *
 * Signed by: the assigned reviewer's ML-DSA-65 key at `tx.signature`
 * (GH #51 unified storage). Body scope over the canonical payload
 * `buildSigningPayload` produces. Dual-mode contract: reviewer confirm =
 * reviewer body sig; no-show auto-confirm (data.auto=true) = node
 * envelope sig. `getSignatureContract(tx)` branches.
 *
 * Canonical signed fields (alphabetical):
 *   decision_note      string|null,  optional reviewer-written notes
 *   review_id          string,       which review this decision applies to
 *   reviewer_tip_id    string,       the signer (must match review's
 *                                    assigned_reviewer)
 *   suggested_origin   string,       AA / AG / MX — reviewer's recommendation
 *                                    for the corrected origin code
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError } = require("./_common");
const { buildSignedPayload } = require("../../../shared/crypto");
const {
  TX_TYPES, ORIGIN, PRESCAN_REVIEW_STATES, RECUSAL_REASONS, PRESCAN_REVIEW_CAP, CONTENT_STATUS,
  SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS,
} = require("../../../shared/constants");

const TX_TYPE = TX_TYPES.PRESCAN_REVIEW_CONFIRMED;
// GH #51 — unified signature storage. Reviewer signs the canonical
// decision payload returned by buildSigningPayload.
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.REVIEWER_TIP_ID;
// Reviewer can only suggest "more AI" labels — OH is already what the
// creator declared, so confirming an AI flag must recommend something
// that discloses AI involvement.
const VALID_SUGGESTED_ORIGINS = Object.freeze([ORIGIN.AA, ORIGIN.AG, ORIGIN.MX]);

// Two signature paths under one tx_type, discriminated by `tx.data.auto`:
// node-emitted no-show auto-confirm (envelope sig by the node) vs the
// assigned reviewer's own decision (body sig).
function getSignatureContract(tx) {
  if (tx?.data?.auto) {
    return {
      SIGNATURE_SCOPE: SIGNATURE_SCOPE.ENVELOPE,
      SIGNED_BY: SIGNED_BY_KIND.NODE,
    };
  }
  return {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
    SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.REVIEWER_TIP_ID,
    buildSigningPayload,
  };
}

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

function resolveReview(reviewId, reviewerTipId, dag) {
  const review = dag.getPrescanReview(reviewId);
  if (!review) {
    throw schemaError(404, `Review not found: ${reviewId}`, "review_not_found");
  }
  if (review.assigned_reviewer !== reviewerTipId) {
    throw schemaError(403, "Only the assigned reviewer can confirm this review", "reviewer_not_assigned");
  }
  if (review.state !== PRESCAN_REVIEW_STATES.TRIGGERED) {
    throw schemaError(
      409,
      `Review is not in a confirmable state (state=${review.state})`,
      "review_state_invalid",
    );
  }
  return review;
}

/** SLA no-shows recorded for a post, across every review slot it has had. */
function countNoShows(dag, ctid) {
  const reviews = dag.getPrescanReviewsByCtid(ctid) || [];
  return reviews.filter(r => r.state === PRESCAN_REVIEW_STATES.RECUSED
    && r.decision_note === RECUSAL_REASONS.SLA_EXPIRED).length;
}

/**
 * Gate for the node-emitted auto-confirm: the post is still a review
 * candidate (registered, declared OH, flagged), has no open review and no
 * row under this review_id yet, and has reached the no-show cap. The
 * activation epoch is checked by the commit-handler, which holds the
 * round's cert timestamp.
 */
function resolveAutoConfirm(d, dag) {
  if (!d.node_id) {
    throw schemaError(400, "node_id missing on auto-confirm", "node_id_missing");
  }
  const node = dag.getNode(d.node_id);
  if (!node) {
    throw schemaError(412, `Node not registered: ${d.node_id}`, "node_not_registered");
  }
  if (node.status !== "active") {
    throw schemaError(403, `Node not active: ${d.node_id}`, "node_inactive");
  }
  if (!d.ctid) {
    throw schemaError(400, "ctid missing on auto-confirm", "ctid_missing");
  }
  const content = dag.getContent(d.ctid);
  if (!content) {
    throw schemaError(404, `Content not found: ${d.ctid}`, "content_not_found");
  }
  if (content.status !== CONTENT_STATUS.REGISTERED || content.origin_code !== ORIGIN.OH
    || (content.prescan_tier !== "high" && content.prescan_tier !== "critical")) {
    throw schemaError(409, `Content is not awaiting review: ${d.ctid}`, "content_not_reviewable");
  }
  if (dag.getPrescanReview(d.review_id)) {
    throw schemaError(409, `Review already exists: ${d.review_id}`, "review_exists");
  }
  if (dag.getOpenPrescanReviewByCtid(d.ctid)) {
    throw schemaError(409, `An open review already exists for ${d.ctid}`, "review_open");
  }
  const noShows = countNoShows(dag, d.ctid);
  if (noShows < PRESCAN_REVIEW_CAP.MAX_NO_SHOWS) {
    throw schemaError(409, `No-show cap not reached for ${d.ctid} (${noShows}/${PRESCAN_REVIEW_CAP.MAX_NO_SHOWS})`, "no_show_cap_not_reached");
  }
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
  if (!VALID_SUGGESTED_ORIGINS.includes(body.suggested_origin)) {
    throw schemaError(
      400,
      `suggested_origin must be one of: ${VALID_SUGGESTED_ORIGINS.join(", ")}`,
      "suggested_origin_invalid",
    );
  }
  if (body.decision_note != null && typeof body.decision_note !== "string") {
    throw schemaError(400, "decision_note must be a string when present", "decision_note_invalid");
  }
  resolveReviewer(body.reviewer_tip_id, deps.dag);
  resolveReview(body.review_id, body.reviewer_tip_id, deps.dag);
}

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
  if (!VALID_SUGGESTED_ORIGINS.includes(input.suggested_origin)) {
    throw schemaError(
      400,
      `suggested_origin must be one of: ${VALID_SUGGESTED_ORIGINS.join(", ")}`,
      "suggested_origin_invalid",
    );
  }
  return buildSignedPayload(input, {
    required: ["review_id", "reviewer_tip_id", "suggested_origin"],
    optional: ["decision_note"],
  });
}

function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * State-level verification at consensus replay. GH #51: the signature
 * (auto: node envelope; reviewer: body sig) is verified by the unified
 * dispatcher via `getSignatureContract(tx)` — this function only enforces
 * the state-machine + reviewer-assignment / node-registration invariants
 * the dispatcher doesn't know about.
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};
  if (!d.review_id) {
    return { ok: false, status: 400, error: "review_id missing", code: "review_id_missing" };
  }
  if (!VALID_SUGGESTED_ORIGINS.includes(d.suggested_origin)) {
    return { ok: false, status: 400, error: "suggested_origin invalid", code: "suggested_origin_invalid" };
  }

  if (d.auto) {
    try {
      resolveAutoConfirm(d, dag);
    } catch (err) {
      if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
      throw err;
    }
    return { ok: true };
  }

  if (!d.reviewer_tip_id) {
    return { ok: false, status: 400, error: "reviewer_tip_id missing", code: "reviewer_tip_id_missing" };
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
  VALID_SUGGESTED_ORIGINS,
  resolveReviewer,
  resolveReview,
  resolveAutoConfirm,
  countNoShows,
  validateRequest,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
  // GH #51 — unified signature contract (dual-mode via function; the static
  // fields describe the reviewer path for callers that read them directly)
  getSignatureContract,
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
};
