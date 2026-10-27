/**
 * @file @tip-protocol/node/src/schemas/prescan-review-claimed.js
 * @description Canonical schema for `PRESCAN_REVIEW_CLAIMED`: a review desk
 * member takes over an open review. The open slot closes as CLAIMED_OVER (no
 * no-show for the replaced reviewer) and commit-handler opens a new TRIGGERED
 * slot assigned to the claimer, its SLA clock starting at the cert time.
 *
 * The desk is the genesis organization's roster members holding
 * PRESCAN_REVIEW_DESK.ROLE. A claimer may never take a post they signed or
 * are listed on as an author.
 *
 * Signed by: the claimer's ML-DSA-65 key (body signature).
 *
 * Canonical signed fields (alphabetical):
 *   review_id          string, the open review being taken over
 *   reviewer_tip_id    string, the claimer
 * Unsigned context added by the API (checked against the review at commit):
 *   ctid, creator_tip_id, previous_reviewer_tip_id
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError } = require("./_common");
const { buildSignedPayload } = require("../../../shared/crypto");
const {
  TX_TYPES, PRESCAN_REVIEW_STATES, PRESCAN_REVIEW_DESK, SIGNATURE_SCOPE, SIGNED_BY_KIND,
  TIP_ID_FIELDS, TIP_ID_TYPES,
} = require("../../../shared/constants");
const { getGenesisOrg } = require("../genesis");
const roster = require("./_org-members");

const TX_TYPE = TX_TYPES.PRESCAN_REVIEW_CLAIMED;
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.REVIEWER_TIP_ID;

function resolveClaimer(claimerTipId, dag) {
  const identity = dag.getIdentity(claimerTipId);
  if (!identity) {
    throw schemaError(412, "Reviewer TIP-ID not registered on DAG", "reviewer_not_registered");
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(claimerTipId)) {
    throw schemaError(403, "Reviewer TIP-ID is revoked", "reviewer_revoked");
  }
  if (identity.tip_id_type && identity.tip_id_type !== TIP_ID_TYPES.PERSONAL) {
    throw schemaError(403, "Only a personal TIP-ID can review", "reviewer_not_personal");
  }
  const deskOrg = getGenesisOrg();
  const membership = deskOrg ? roster.activeMembership(dag, deskOrg, claimerTipId) : null;
  if (!membership || membership.role !== PRESCAN_REVIEW_DESK.ROLE) {
    throw schemaError(403, "Only a review desk member can claim a review", "not_desk_member");
  }
  return identity;
}

function _isOwnContent(content, claimerTipId) {
  if (content.author_tip_id === claimerTipId || content.signer_tip_id === claimerTipId) return true;
  return Array.isArray(content.authors) && content.authors.some(a => a && a.tip_id === claimerTipId);
}

function resolveReview(reviewId, claimerTipId, dag) {
  const review = dag.getPrescanReview(reviewId);
  if (!review) {
    throw schemaError(404, `Review not found: ${reviewId}`, "review_not_found");
  }
  if (review.state !== PRESCAN_REVIEW_STATES.TRIGGERED) {
    throw schemaError(409, `Review is not open for a claim (state=${review.state})`, "review_state_invalid");
  }
  if (review.assigned_reviewer === claimerTipId) {
    throw schemaError(409, "This review is already assigned to you", "already_assigned");
  }
  const content = dag.getContent(review.ctid);
  if (!content) {
    throw schemaError(404, `Content not found: ${review.ctid}`, "content_not_found");
  }
  if (_isOwnContent(content, claimerTipId)) {
    throw schemaError(403, "You cannot review content you signed or authored", "own_content");
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
  resolveClaimer(body.reviewer_tip_id, deps.dag);
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
  return buildSignedPayload(input, { required: ["review_id", "reviewer_tip_id"] });
}

function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/** State checks at consensus replay; the signature is verified by the unified dispatcher. */
function verifyTx(tx, dag) {
  const d = tx.data || {};
  if (!d.review_id) {
    return { ok: false, status: 400, error: "review_id missing", code: "review_id_missing" };
  }
  if (!d.reviewer_tip_id) {
    return { ok: false, status: 400, error: "reviewer_tip_id missing", code: "reviewer_tip_id_missing" };
  }
  try {
    resolveClaimer(d.reviewer_tip_id, dag);
    const review = resolveReview(d.review_id, d.reviewer_tip_id, dag);
    // Unsigned context fields drive attribution, so they must name this review.
    if ((d.ctid ?? review.ctid) !== review.ctid
      || (d.creator_tip_id ?? review.creator_tip_id) !== review.creator_tip_id
      || (d.previous_reviewer_tip_id ?? review.assigned_reviewer) !== review.assigned_reviewer) {
      return { ok: false, status: 400, error: "claim context does not match the review", code: "claim_context_mismatch" };
    }
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }
  return { ok: true };
}

module.exports = {
  TX_TYPE,
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
  resolveClaimer,
  resolveReview,
  validateRequest,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
};
