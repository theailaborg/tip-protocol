/**
 * @file @tip-protocol/node/src/schemas/_org-members.js
 * @description State helpers shared by the three org roster schemas
 * (ORG_MEMBER_INVITED / ADDED / REMOVED). Every predicate reads committed
 * org_members rows and decides on a frozen `atMs` (tx.timestamp at commit,
 * the API clock at submit), never on wall-clock, so each node answers the
 * same way for the same tx.
 *
 * Roster row lifecycle (pk = invite_tx_id):
 *   invited  -- ORG_MEMBER_INVITED committed; usable for INVITE_TTL_MS
 *   active   -- ORG_MEMBER_ADDED committed; counts toward the seat limit
 *   removed  -- ORG_MEMBER_REMOVED committed; seat freed, row kept
 * An invite past its TTL stays "invited" on chain but is dead: it cannot be
 * accepted and no longer counts as open.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError, assertBounded } = require("./_common");
const {
  ORG_MEMBERS, ORG_MEMBER_STATUS, TIP_ID_TYPES,
} = require("../../../shared/constants");

const ROLE_SPEC = Object.freeze({
  field: "role",
  max: ORG_MEMBERS.ROLE_MAX_LENGTH,
  pattern: ORG_MEMBERS.ROLE_PATTERN,
  describe: "a lowercase token (a-z, 0-9, _ or -) starting with a letter",
  required: true,
});

function fail(status, error, code) {
  return { ok: false, status, error, code };
}

/** Throw the schemaError equivalent of a failed predicate result. */
function throwIfFailed(r) {
  if (r && r.ok === false) throw schemaError(r.status, r.error, r.code);
}

function assertRole(role) {
  assertBounded(role, ROLE_SPEC);
}

function isTipId(v) {
  return typeof v === "string" && v.startsWith("tip://id/");
}

/** Fleet-wide gate; `opts.activationMs` overrides the constant (config / tests). */
function activationMs(opts) {
  return opts && Number.isFinite(opts.activationMs) ? opts.activationMs : ORG_MEMBERS.ACTIVATION_MS;
}

function checkActive(atMs, opts) {
  if (!Number.isFinite(atMs) || atMs < activationMs(opts)) {
    return fail(403, "Organization roster is not active on this network yet", "org_members_not_active");
  }
  return { ok: true };
}

function isInviteExpired(row, atMs) {
  return atMs - row.invited_at > ORG_MEMBERS.INVITE_TTL_MS;
}

function isOpenInvite(row, atMs) {
  return row.status === ORG_MEMBER_STATUS.INVITED && !isInviteExpired(row, atMs);
}

function activeMembers(dag, orgTipId) {
  return (dag.getOrgMembersByOrg(orgTipId) || []).filter(r => r.status === ORG_MEMBER_STATUS.ACTIVE);
}

function activeMembership(dag, orgTipId, memberTipId) {
  return activeMembers(dag, orgTipId).find(r => r.member_tip_id === memberTipId) || null;
}

function openInvites(dag, orgTipId, atMs) {
  return (dag.getOrgMembersByOrg(orgTipId) || []).filter(r => isOpenInvite(r, atMs));
}

function openInviteFor(dag, orgTipId, memberTipId, atMs) {
  return openInvites(dag, orgTipId, atMs).find(r => r.member_tip_id === memberTipId) || null;
}

function activeMemberships(dag, memberTipId) {
  return (dag.getOrgMembersByMember(memberTipId) || []).filter(r => r.status === ORG_MEMBER_STATUS.ACTIVE);
}

function openInvitesFor(dag, memberTipId, atMs) {
  return (dag.getOrgMembersByMember(memberTipId) || []).filter(r => isOpenInvite(r, atMs));
}

// The only tier today. A paid plan becomes a per-org lookup here; every
// limit check in the roster schemas goes through this one function.
function memberLimit(_dag, _orgTipId) {
  return ORG_MEMBERS.FREE_MEMBER_LIMIT;
}

function openInviteLimit(dag, orgTipId) {
  return memberLimit(dag, orgTipId) * ORG_MEMBERS.OPEN_INVITE_MULTIPLIER;
}

/** Registered, unrevoked identity of the expected type, or a failed result. */
function resolveParty(dag, tipId, expectedType, label) {
  if (!isTipId(tipId)) return fail(400, `${label} must be a tip://id/... string`, `${label}_invalid`);
  const identity = dag.getIdentity(tipId);
  if (!identity) return fail(412, `${label} not registered on DAG: ${tipId}`, `${label}_not_found`);
  if (typeof dag.isRevoked === "function" && dag.isRevoked(tipId)) {
    return fail(403, `${label} is revoked: ${tipId}`, `${label}_revoked`);
  }
  const type = identity.tip_id_type || TIP_ID_TYPES.PERSONAL;
  if (type !== expectedType) {
    return fail(403, `${label} must be a ${expectedType} TIP-ID (got ${type}): ${tipId}`, `${label}_type_invalid`);
  }
  return { ok: true, identity };
}

/** Both roster parties: org is an organization, member is a person, and they differ. */
function resolveParties(dag, orgTipId, memberTipId) {
  const org = resolveParty(dag, orgTipId, TIP_ID_TYPES.ORGANIZATION, "org_tip_id");
  if (!org.ok) return org;
  const member = resolveParty(dag, memberTipId, TIP_ID_TYPES.PERSONAL, "member_tip_id");
  if (!member.ok) return member;
  if (orgTipId === memberTipId) return fail(400, "org_tip_id and member_tip_id must differ", "member_is_org");
  return { ok: true, org: org.identity, member: member.identity };
}

module.exports = {
  ROLE_SPEC,
  fail,
  throwIfFailed,
  assertRole,
  isTipId,
  activationMs,
  checkActive,
  isInviteExpired,
  isOpenInvite,
  activeMembers,
  activeMembership,
  openInvites,
  openInviteFor,
  activeMemberships,
  openInvitesFor,
  memberLimit,
  openInviteLimit,
  resolveParty,
  resolveParties,
};
