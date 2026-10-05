/**
 * @file @tip-protocol/node/src/schemas/org-member-invited.js
 * @description Canonical schema for `ORG_MEMBER_INVITED`: an organization
 * invites a registered personal TIP-ID onto its roster.
 *
 * Trust model: SUBJECT-signed by the organization. The invite is public
 * state (any node can list it for the invitee, whichever VP issued either
 * identity) but binds nothing: the person is on the roster only once they
 * commit ORG_MEMBER_ADDED referencing this tx. The invite is usable for
 * ORG_MEMBERS.INVITE_TTL_MS after tx.timestamp and never consumes a seat.
 *
 * Signed canonical payload (4 fields, alphabetical):
 *   invited_at     number  epoch ms, freshness window (CLAIM_MAX_AGE_MS)
 *   member_tip_id  string  tip://id/... the invited person
 *   org_tip_id     string  tip://id/... the inviting organization (signer)
 *   role           string  roster role token (e.g. "author")
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError, canonicalJson } = require("./_common");
const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS, CLAIM_MAX_AGE_MS,
} = require("../../../shared/constants");
const { isValidMs, nowMs } = require("../../../shared/time");
const roster = require("./_org-members");

const TX_TYPE = TX_TYPES.ORG_MEMBER_INVITED;
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.ORG_TIP_ID;

/**
 * State predicate shared by the API gate and consensus replay. `atMs` is
 * the API clock at submit and the frozen tx.timestamp at commit.
 */
function checkInvite(d, dag, atMs) {
  const parties = roster.resolveParties(dag, d.org_tip_id, d.member_tip_id);
  if (!parties.ok) return parties;
  if (roster.activeMembership(dag, d.org_tip_id, d.member_tip_id)) {
    return roster.fail(409, `${d.member_tip_id} is already a member of ${d.org_tip_id}`, "already_member");
  }
  if (roster.openInviteFor(dag, d.org_tip_id, d.member_tip_id, atMs)) {
    return roster.fail(409, `An open invite already exists for ${d.member_tip_id}`, "invite_pending");
  }
  const limit = roster.memberLimit(dag, d.org_tip_id);
  if (roster.activeMembers(dag, d.org_tip_id).length >= limit) {
    return roster.fail(409, `Organization has no free seat (limit ${limit})`, "member_limit_reached");
  }
  const inviteLimit = roster.openInviteLimit(dag, d.org_tip_id);
  if (roster.openInvites(dag, d.org_tip_id, atMs).length >= inviteLimit) {
    return roster.fail(409, `Organization has too many open invites (limit ${inviteLimit})`, "invite_limit_reached");
  }
  return { ok: true };
}

/**
 * Request-envelope validator for POST /v1/identity/:tipId/members/invite.
 *
 * Body shape (snake_case):
 *   org_tip_id, member_tip_id, role, invited_at, signature   required
 *
 * deps: { dag, urlTipId?, now?, activationMs? }
 */
function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (deps && deps.urlTipId !== undefined && body.org_tip_id !== deps.urlTipId) {
    throw schemaError(400, "URL tip_id does not match body.org_tip_id", "tip_id_mismatch");
  }
  if (!body.org_tip_id || !body.member_tip_id || !body.role || !body.invited_at || !body.signature) {
    throw schemaError(400, "org_tip_id, member_tip_id, role, invited_at, signature are required", "missing_fields");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }
  buildSigningPayload(body);

  const now = deps && typeof deps.now === "number" ? deps.now : nowMs();
  roster.throwIfFailed(roster.checkActive(now, deps));
  if (now - body.invited_at > CLAIM_MAX_AGE_MS) {
    throw schemaError(400, "Invite signature has expired (max 15 minutes)", "claim_expired");
  }

  if (!deps || !deps.dag) return;
  const { dag } = deps;
  roster.throwIfFailed(checkInvite(body, dag, now));

  // Mempool guard: a second invite for the same pair while the first is
  // still pending would otherwise both pass the committed-state check.
  if (typeof dag.getMempoolTxsByTipId === "function") {
    const pending = dag.getMempoolTxsByTipId(body.org_tip_id)
      .filter(t => t.tx_type === TX_TYPE && t.data?.member_tip_id === body.member_tip_id);
    if (pending.length > 0) {
      throw schemaError(409, `An invite for ${body.member_tip_id} is already pending`, "invite_pending");
    }
  }

  const identity = dag.getIdentity(body.org_tip_id);
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
  roster.assertRole(input.role);
  if (!isValidMs(input.invited_at)) {
    throw schemaError(400, "invited_at must be a valid epoch ms timestamp", "invited_at_invalid");
  }
  return {
    invited_at: input.invited_at,
    member_tip_id: input.member_tip_id,
    org_tip_id: input.org_tip_id,
    role: input.role,
  };
}

function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * State-level verification at consensus replay. The org's body signature
 * is verified by the unified dispatcher; this enforces the activation gate
 * and the roster invariants on the frozen tx.timestamp.
 */
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
  return checkInvite(d, dag, tx.timestamp);
}

module.exports = {
  TX_TYPE,
  validateRequest,
  buildSigningPayload,
  checkInvite,
  sign,
  verifySignature,
  verifyTx,
  canonicalJson,
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
};
