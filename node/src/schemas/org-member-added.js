/**
 * @file @tip-protocol/node/src/schemas/org-member-added.js
 * @description Canonical schema for `ORG_MEMBER_ADDED`: the invited person
 * accepts an open ORG_MEMBER_INVITED and joins the organization's roster.
 *
 * Trust model: SUBJECT-signed by the member. The organization's consent is
 * already on chain (the invite tx it signed), so no cosignature is needed;
 * invite_tx_id binds this acceptance to that exact invite. The seat limit
 * is enforced here, at acceptance, on committed rows: an invite sent while
 * a seat was free fails cleanly if the seat is gone by the time it is
 * accepted.
 *
 * Signed canonical payload (4 fields, alphabetical):
 *   accepted_at    number  epoch ms, freshness window (CLAIM_MAX_AGE_MS)
 *   invite_tx_id   string  tx_id of the ORG_MEMBER_INVITED being accepted
 *   member_tip_id  string  tip://id/... the accepting person (signer)
 *   org_tip_id     string  tip://id/... the organization
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError, canonicalJson } = require("./_common");
const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS, ORG_MEMBER_STATUS,
} = require("../../../shared/constants");
const { isValidMs, nowMs } = require("../../../shared/time");
const roster = require("./_org-members");

const TX_TYPE = TX_TYPES.ORG_MEMBER_ADDED;
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.MEMBER_TIP_ID;

/** State predicate shared by the API gate and consensus replay. */
function checkAccept(d, dag, atMs) {
  // A rejected acceptance's signature is public; without this a relayer could
  // re-wrap it once a seat frees, or backdate tx.timestamp past the TTL.
  const fresh = roster.checkClaimFresh(d.accepted_at, atMs, "Acceptance");
  if (!fresh.ok) return fresh;
  const row = dag.getOrgMember(d.invite_tx_id);
  if (!row) return roster.fail(412, `Invite not found: ${d.invite_tx_id}`, "invite_not_found");
  if (row.org_tip_id !== d.org_tip_id || row.member_tip_id !== d.member_tip_id) {
    return roster.fail(400, "org_tip_id / member_tip_id do not match the invite", "invite_mismatch");
  }
  if (row.status !== ORG_MEMBER_STATUS.INVITED) {
    return roster.fail(409, `Invite is ${row.status}, not open`, "invite_not_open");
  }
  if (roster.isInviteExpired(row, atMs)) {
    return roster.fail(410, "Invite has expired", "invite_expired");
  }
  const parties = roster.resolveParties(dag, d.org_tip_id, d.member_tip_id);
  if (!parties.ok) return parties;
  if (roster.activeMembership(dag, d.org_tip_id, d.member_tip_id)) {
    return roster.fail(409, `${d.member_tip_id} is already a member of ${d.org_tip_id}`, "already_member");
  }
  const limit = roster.memberLimit(dag, d.org_tip_id);
  if (roster.activeMembers(dag, d.org_tip_id).length >= limit) {
    return roster.fail(409, `Organization has no free seat (limit ${limit})`, "member_limit_reached");
  }
  return { ok: true };
}

/**
 * Request-envelope validator for POST /v1/identity/:tipId/members/accept.
 *
 * Body shape (snake_case):
 *   org_tip_id, member_tip_id, invite_tx_id, accepted_at, signature   required
 *
 * deps: { dag, urlTipId?, now?, activationMs? }
 */
function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (deps && deps.urlTipId !== undefined && body.member_tip_id !== deps.urlTipId) {
    throw schemaError(400, "URL tip_id does not match body.member_tip_id", "tip_id_mismatch");
  }
  if (!body.org_tip_id || !body.member_tip_id || !body.invite_tx_id || !body.accepted_at || !body.signature) {
    throw schemaError(400, "org_tip_id, member_tip_id, invite_tx_id, accepted_at, signature are required", "missing_fields");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }
  buildSigningPayload(body);

  const now = deps && typeof deps.now === "number" ? deps.now : nowMs();
  roster.throwIfFailed(roster.checkActive(now, deps));
  roster.throwIfFailed(roster.checkClaimFresh(body.accepted_at, now, "Acceptance"));

  if (!deps || !deps.dag) return;
  const { dag } = deps;
  roster.throwIfFailed(checkAccept(body, dag, now));

  if (typeof dag.getMempoolTxsByTipId === "function") {
    const pending = dag.getMempoolTxsByTipId(body.member_tip_id)
      .filter(t => t.tx_type === TX_TYPE && t.data?.org_tip_id === body.org_tip_id);
    if (pending.length > 0) {
      throw schemaError(409, `An acceptance for ${body.org_tip_id} is already pending`, "acceptance_pending");
    }
  }

  const identity = dag.getIdentity(body.member_tip_id);
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
  if (typeof input.invite_tx_id !== "string" || input.invite_tx_id.length === 0) {
    throw schemaError(400, "invite_tx_id is required", "invite_tx_id_required");
  }
  if (!isValidMs(input.accepted_at)) {
    throw schemaError(400, "accepted_at must be a valid epoch ms timestamp", "accepted_at_invalid");
  }
  return {
    accepted_at: input.accepted_at,
    invite_tx_id: input.invite_tx_id,
    member_tip_id: input.member_tip_id,
    org_tip_id: input.org_tip_id,
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
  return checkAccept(d, dag, tx.timestamp);
}

module.exports = {
  TX_TYPE,
  validateRequest,
  buildSigningPayload,
  checkAccept,
  sign,
  verifySignature,
  verifyTx,
  canonicalJson,
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
};
