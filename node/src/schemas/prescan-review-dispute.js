/**
 * @file @tip-protocol/node/src/schemas/prescan-review-dispute.js
 * @description Request validation for the creator's Option 2 — manually
 * escalate a CONFIRMED prescan-review to a public dispute, before the
 * h=R+24 auto-escalation trigger would fire.
 *
 * Semantically the creator is fast-forwarding what the system would do
 * anyway: emit a CONTENT_DISPUTED with `auto: true` + `source_review_id`,
 * which puts the reviewer on the hook as the de-facto disputer at
 * Stage-2 verdict time (via the escalated_review linkage in
 * jury.buildAdjudicationBatch). Same tx shape, same economics — just
 * triggered by an explicit creator action instead of the timer.
 *
 * Body shape:
 *   author_tip_id  string,  must equal review.creator_tip_id (only the
 *                           content's creator can manually escalate)
 *   ctid           string,  must equal review.ctid (replay protection —
 *                           same pattern as retract / update-origin /
 *                           accept-correction)
 *   signature      string,  body signature over { author_tip_id, ctid,
 *                           review_id } verified against the creator's
 *                           ML-DSA-65 public key. This signature is
 *                           embedded on the resulting CONTENT_DISPUTED
 *                           tx as `escalation_signature` so consensus
 *                           replay can verify the creator authorised
 *                           the escalation (in addition to the node-
 *                           signed tx envelope).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError } = require("./_common");
const { verifyBodySignature } = require("../../../shared/crypto");
const { PRESCAN_REVIEW_STATES } = require("../../../shared/constants");

// Signed canonical payload binds the escalation to a specific creator,
// ctid, and review. Without ctid + review_id in the signature, a
// captured `author_tip_id`-only blob could be replayed against any
// other CONFIRMED review owned by the same creator.
const SIGNED_FIELDS = Object.freeze(["author_tip_id", "ctid", "review_id"]);

/**
 * Resolve the review and gate it to state=CONFIRMED. The CONFIRMED
 * state is the only one in which manual escalation is meaningful:
 * TRIGGERED is still in reviewer-evaluation; CLOSED_* states are
 * terminal; ESCALATED_TO_DISPUTE means it's already in the dispute
 * pipeline.
 */
function resolveReview(reviewId, dag) {
  const review = dag.getPrescanReview(reviewId);
  if (!review) throw schemaError(404, `Review not found: ${reviewId}`, "review_not_found");
  if (review.state !== PRESCAN_REVIEW_STATES.CONFIRMED) {
    throw schemaError(
      409,
      `Review is not in 'confirmed' state (state=${review.state}) — manual dispute escalation is only valid during the creator's 24h decision window`,
      "review_state_invalid",
    );
  }
  return review;
}

/**
 * Validate an escalate-to-dispute request end-to-end. Returns the
 * verified context the caller needs to build the CONTENT_DISPUTED tx:
 *   { review, content }
 *
 * All gates live here so review-service stays pure tx-building.
 */
function validateRequest(reviewId, body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (!reviewId || typeof reviewId !== "string") {
    throw schemaError(400, "review_id is required", "review_id_required");
  }

  const { dag } = deps;

  // Shape
  if (typeof body.author_tip_id !== "string" || !body.author_tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "author_tip_id is required (tip://id/...)", "author_tip_id_required");
  }
  if (typeof body.ctid !== "string" || !body.ctid.startsWith("tip://c/")) {
    throw schemaError(400, "ctid is required (tip://c/...)", "ctid_required");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }

  // State + identity
  const review = resolveReview(reviewId, dag);
  if (body.author_tip_id !== review.creator_tip_id) {
    throw schemaError(403, "Only the content's creator can escalate the review to a public dispute", "not_creator");
  }
  if (body.ctid !== review.ctid) {
    throw schemaError(400, "ctid in body does not match the review's ctid", "ctid_mismatch");
  }

  // Signature
  const author = dag.getIdentity(body.author_tip_id);
  if (!author) throw schemaError(404, "Author identity not found", "author_not_registered");
  const sigBody = { author_tip_id: body.author_tip_id, ctid: review.ctid, review_id: reviewId };
  if (!verifyBodySignature(sigBody, body.signature, author.public_key, SIGNED_FIELDS)) {
    throw schemaError(403, "Author signature verification failed", "signature_invalid");
  }

  // Content row should still exist (review can't exist without it, but
  // defensive — gives a clear error if state got out of sync).
  const content = dag.getContent(review.ctid);
  if (!content) {
    throw schemaError(404, `Content not found: ${review.ctid}`, "content_not_found");
  }

  return { review, content };
}

module.exports = {
  SIGNED_FIELDS,
  resolveReview,
  validateRequest,
};
