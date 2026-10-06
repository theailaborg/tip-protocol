/**
 * @file @tip-protocol/node/src/schemas/org-member-invite-cancelled.js
 * @description Canonical schema for `ORG_MEMBER_INVITE_CANCELLED`: closes an
 * open ORG_MEMBER_INVITED before it is accepted. The organization cancels or
 * the invitee declines, so the signer is named in the body and must be one
 * of the two parties. A cancelled invite can never be accepted and no longer
 * counts as open.
 *
 * Signed canonical payload (5 fields, alphabetical):
 *   claimed_at     number  epoch ms, freshness window
 *   invite_tx_id   string  tx_id of the ORG_MEMBER_INVITED being closed
 *   member_tip_id  string  tip://id/... the invitee
 *   org_tip_id     string  tip://id/... the organization
 *   signer_tip_id  string  org_tip_id or member_tip_id, whoever signs
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError, canonicalJson } = require("./_common");
const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS, CLAIM_MAX_AGE_MS, ORG_MEMBER_STATUS,
} = require("../../../shared/constants");
const { isValidMs, nowMs } = require("../../../shared/time");
const roster = require("./_org-members");

const TX_TYPE = TX_TYPES.ORG_MEMBER_INVITE_CANCELLED;
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.SIGNER_TIP_ID;

/** State predicate shared by the API gate and consensus replay. */
function checkCancel(d, dag) {
  if (d.signer_tip_id !== d.org_tip_id && d.signer_tip_id !== d.member_tip_id) {
    return roster.fail(403, "Only the organization or the invitee can close an invite", "not_party");
  }
  const row = dag.getOrgMember(d.invite_tx_id);
  if (!row) return roster.fail(412, `Invite not found: ${d.invite_tx_id}`, "invite_not_found");
  if (row.org_tip_id !== d.org_tip_id || row.member_tip_id !== d.member_tip_id) {
    return roster.fail(400, "org_tip_id / member_tip_id do not match the invite", "invite_mismatch");
  }
  if (row.status !== ORG_MEMBER_STATUS.INVITED) {
    return roster.fail(409, `Invite is ${row.status}, not open`, "invite_not_open");
  }
  const signer = dag.getIdentity(d.signer_tip_id);
  if (!signer) return roster.fail(412, `signer_tip_id not registered on DAG: ${d.signer_tip_id}`, "signer_tip_id_not_found");
  if (typeof dag.isRevoked === "function" && dag.isRevoked(d.signer_tip_id)) {
    return roster.fail(403, `signer_tip_id is revoked: ${d.signer_tip_id}`, "signer_tip_id_revoked");
  }
  return { ok: true };
}

/**
 * Request-envelope validator for POST /v1/identity/:tipId/members/cancel-invite.
 *
 * Body shape (snake_case):
 *   org_tip_id, member_tip_id, invite_tx_id, claimed_at, signer_tip_id, signature   required
 *
 * deps: { dag, urlTipId?, now?, activationMs? }
 */
function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (deps && deps.urlTipId !== undefined && body.signer_tip_id !== deps.urlTipId) {
    throw schemaError(400, "URL tip_id does not match body.signer_tip_id", "tip_id_mismatch");
  }
  if (!body.org_tip_id || !body.member_tip_id || !body.invite_tx_id || !body.claimed_at
      || !body.signer_tip_id || !body.signature) {
    throw schemaError(
      400,
      "org_tip_id, member_tip_id, invite_tx_id, claimed_at, signer_tip_id, signature are required",
      "missing_fields",
    );
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }
  buildSigningPayload(body);

  const now = deps && typeof deps.now === "number" ? deps.now : nowMs();
  roster.throwIfFailed(roster.checkActive(now, deps));
  if (now - body.claimed_at > CLAIM_MAX_AGE_MS) {
    throw schemaError(400, "Claim has expired (max 15 minutes)", "claim_expired");
  }

  if (!deps || !deps.dag) return;
  const { dag } = deps;
  roster.throwIfFailed(checkCancel(body, dag));

  const identity = dag.getIdentity(body.signer_tip_id);
  if (!verifyPayload(buildSigningPayload(body), body.signature, identity.public_key)) {
    throw schemaError(403, "Signature verification failed", "signature_invalid");
  }
}

function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (!roster.isTipId(input.org_tip_id)) {
    throw schemaError(400, "org_tip_id is required (tip://id/...)", "org_tip_id_required");
  }
  if (!roster.isTipId(input.member_tip_id)) {
    throw schemaError(400, "member_tip_id is required (tip://id/...)", "member_tip_id_required");
  }
  if (!roster.isTipId(input.signer_tip_id)) {
    throw schemaError(400, "signer_tip_id is required (tip://id/...)", "signer_tip_id_required");
  }
  if (typeof input.invite_tx_id !== "string" || input.invite_tx_id.length === 0) {
    throw schemaError(400, "invite_tx_id is required", "invite_tx_id_required");
  }
  if (!isValidMs(input.claimed_at)) {
    throw schemaError(400, "claimed_at must be a valid epoch ms timestamp", "claimed_at_invalid");
  }
  return {
    claimed_at: input.claimed_at,
    invite_tx_id: input.invite_tx_id,
    member_tip_id: input.member_tip_id,
    org_tip_id: input.org_tip_id,
    signer_tip_id: input.signer_tip_id,
  };
}

function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

function verifyTx(tx, dag, opts) {
  const d = tx.data || {};
  const active = roster.checkActive(tx.timestamp, opts);
  if (!active.ok) return active;
  try {
    buildSigningPayload(d);
  } catch (err) {
    if (err && err.status) return roster.fail(err.status, err.error || err.message, err.code);
    throw err;
  }
  return checkCancel(d, dag);
}

module.exports = {
  TX_TYPE,
  validateRequest,
  buildSigningPayload,
  checkCancel,
  sign,
  verifySignature,
  verifyTx,
  canonicalJson,
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
};
