/**
 * @file @tip-protocol/node/src/schemas/prescan-review-accept-correction.js
 * @description Request validation for the creator's Option 1 — accept
 * the reviewer's correction privately inside the 24h decision window
 * after PRESCAN_REVIEW_CONFIRMED.
 *
 * This endpoint emits an existing UPDATE_ORIGIN tx (no new tx type).
 * The schema module exists to keep request validation co-located with
 * the canonical signed-body fields and the state-machine gating —
 * matching the structure of every other endpoint in the codebase.
 *
 * Body shape:
 *   author_tip_id     string,  must equal review.creator_tip_id
 *   new_origin_code   string?, defaults to review.suggested_origin;
 *                              must be one of AA / AG / MX (OH is
 *                              rejected — confirming an AI flag must
 *                              land on an AI-disclosing label)
 *   signature         string,  body signature over { author_tip_id,
 *                              new_origin_code } verified against the
 *                              creator's ML-DSA-65 public key
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs } = require("../../../shared/time");

const { schemaError } = require("./_common");
const { verifyBodySignature } = require("../../../shared/crypto");
const { ORIGIN, PRESCAN_REVIEW_STATES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS } = require("../../../shared/constants");
const rules = require("../validators/business-rules");

// GH #51 — unified signature storage. The content's author signs the
// canonical accept-correction payload.
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.AUTHOR_TIP_ID;

// Reviewer can only suggest an AI label; creator's accept-correction
// must therefore land on the same set. OH (human-only) is excluded.
const VALID_NEW_ORIGINS = Object.freeze([ORIGIN.AA, ORIGIN.AG, ORIGIN.MX]);

// Signed canonical payload binds the ack to a specific ctid (review.ctid
// here, since the URL carries review_id rather than the ctid directly).
// Without ctid in the signature, a captured `author_tip_id +
// new_origin_code` pair could be replayed against any other CONFIRMED
// review the same creator owns.
const SIGNED_FIELDS = Object.freeze(["author_tip_id", "ctid", "new_origin_code"]);

/**
 * Resolve the review and gate it to state=CONFIRMED (the only state in
 * which accept-correction is meaningful). Throws on miss / wrong state.
 */
function resolveReview(reviewId, dag) {
  const review = dag.getPrescanReview(reviewId);
  if (!review) throw schemaError(404, `Review not found: ${reviewId}`, "review_not_found");
  if (review.state !== PRESCAN_REVIEW_STATES.CONFIRMED) {
    throw schemaError(
      409,
      `Review is not in 'confirmed' state (state=${review.state}) — accept-correction is only valid during the creator's 24h decision window`,
      "review_state_invalid",
    );
  }
  return review;
}

/**
 * Validate an accept-correction request end-to-end. Returns the verified
 * context the caller needs to build the UPDATE_ORIGIN tx:
 *   { review, content, new_origin_code }
 *
 * All gates live here (declarative shape, state machine, creator
 * identity match, origin enum, canUpdateOrigin business rules, body
 * signature verification) so the service layer can stay pure
 * tx-building.
 */
function validateRequest(reviewId, body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (!reviewId || typeof reviewId !== "string") {
    throw schemaError(400, "review_id is required", "review_id_required");
  }

  const { dag } = deps;

  // Declarative shape
  if (typeof body.author_tip_id !== "string" || !body.author_tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "author_tip_id is required (tip://id/...)", "author_tip_id_required");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }
  if (body.new_origin_code !== undefined && typeof body.new_origin_code !== "string") {
    throw schemaError(400, "new_origin_code must be a string when present", "new_origin_code_invalid");
  }

  // State machine
  const review = resolveReview(reviewId, dag);
  if (body.author_tip_id !== review.creator_tip_id) {
    throw schemaError(403, "Only the content's creator can accept the reviewer's correction", "not_creator");
  }

  // Resolve effective new_origin_code (body wins; falls back to review.suggested_origin)
  const new_origin_code = body.new_origin_code ?? review.suggested_origin;
  if (!new_origin_code) {
    throw schemaError(400, "new_origin_code is required (and review has no suggested_origin)", "new_origin_code_required");
  }
  if (!VALID_NEW_ORIGINS.includes(new_origin_code)) {
    throw schemaError(
      400,
      `new_origin_code must be one of: ${VALID_NEW_ORIGINS.join(", ")} (an AI-disclosing label)`,
      "new_origin_code_invalid",
    );
  }

  // Business rule — canUpdateOrigin enforces the 24h window from
  // confirmed_at_ms when an open CONFIRMED review exists for the ctid.
  const r = rules.canUpdateOrigin(
    dag,
    { ctid: review.ctid, author_tip_id: body.author_tip_id, new_origin_code },
    { now: nowMs() },
  );
  if (!r.valid) throw schemaError(r.error.status, r.error.message, r.error.code);

  // Signature — creator signed { author_tip_id, ctid, new_origin_code }.
  // ctid comes from the resolved review, not the request body, so a
  // client can't trick the verifier by sending a different ctid in body.
  const author = dag.getIdentity(body.author_tip_id);
  if (!author) throw schemaError(404, "Author identity not found", "author_not_registered");
  const sigBody = { author_tip_id: body.author_tip_id, ctid: review.ctid, new_origin_code };
  if (!verifyBodySignature(sigBody, body.signature, author.public_key, SIGNED_FIELDS)) {
    throw schemaError(403, "Author signature verification failed", "signature_invalid");
  }

  const content = dag.getContent(review.ctid);
  if (!content) throw schemaError(404, `Content not found: ${review.ctid}`, "content_not_found");

  return { review, content, new_origin_code };
}

// GH #51 — canonical signed payload for the unified verifier. Picks
// the exact three fields the signature covers; canonicalJson sorts
// keys, so this is byte-identical to what the client signed.
function buildSigningPayload(input) {
  return {
    author_tip_id: input.author_tip_id,
    ctid: input.ctid,
    new_origin_code: input.new_origin_code,
  };
}

module.exports = {
  VALID_NEW_ORIGINS,
  SIGNED_FIELDS,
  resolveReview,
  validateRequest,
  buildSigningPayload,
  // GH #51 — unified signature contract
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
};
