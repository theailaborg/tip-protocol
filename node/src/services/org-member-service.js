"use strict";

const { nowMs } = require("../../../shared/time");
const { TX_TYPES, ORG_MEMBERS, ORG_MEMBER_STATUS, ORG_MEMBER_ROLES } = require("../../../shared/constants");
const invitedSchema = require("../schemas/org-member-invited");
const cancelledSchema = require("../schemas/org-member-invite-cancelled");
const addedSchema = require("../schemas/org-member-added");
const removedSchema = require("../schemas/org-member-removed");
const roster = require("../schemas/_org-members");
const { schemaError } = require("../schemas/_common");
const { validateTransaction } = require("../validators/tx-validator");
const { withTxId } = require("./helpers");
const { log } = require("../logger");

// Public view of a roster row. Signatures stay on the three txs.
function _view(row) {
  return {
    invite_tx_id: row.invite_tx_id,
    org_tip_id: row.org_tip_id,
    member_tip_id: row.member_tip_id,
    role: row.role,
    status: row.status,
    invited_at: row.invited_at,
    accepted_at: row.accepted_at ?? null,
    add_tx_id: row.add_tx_id ?? null,
    removed_at: row.removed_at ?? null,
    remove_tx_id: row.remove_tx_id ?? null,
    removed_by: row.removed_by ?? null,
  };
}

function createOrgMemberService({ dag, config, submitTx, seatAllowance }) {
  const deps = () => ({ dag, activationMs: config && config.orgMembersActivationMs });

  // Seats the org may fill right now: the operator's allowance (free limit
  // without a plan or a billing service), never above the consensus ceiling.
  async function _seats(orgTipId) {
    const allowance = seatAllowance
      ? await seatAllowance.allowanceFor(orgTipId)
      : { limit: ORG_MEMBERS.FREE_MEMBER_LIMIT, plan: "free", upgrade_url: null };
    const limit = Math.min(allowance.limit, roster.memberLimit(dag, orgTipId, nowMs()));
    return { ...allowance, limit };
  }

  // Operator policy at the API: consensus would accept up to its ceiling, so
  // the plan limit is checked here, before the tx is relayed.
  async function _admit(orgTipId, { opening }) {
    const seats = await _seats(orgTipId);
    const details = { limit: seats.limit, plan: seats.plan, upgrade_url: seats.upgrade_url };
    if (roster.activeMembers(dag, orgTipId).length >= seats.limit) {
      throw schemaError(409, `Organization has no free seat (limit ${seats.limit})`, "member_limit_reached", details);
    }
    if (opening) {
      const openCap = seats.limit * ORG_MEMBERS.OPEN_INVITE_MULTIPLIER;
      if (roster.openInvites(dag, orgTipId, nowMs()).length >= openCap) {
        throw schemaError(409, `Organization has too many open invites (limit ${openCap})`, "invite_limit_reached", details);
      }
    }
  }

  // All three flows are SUBJECT-signed relays: the client signed the
  // canonical body, the signature becomes tx.signature, the node adds
  // only the envelope (same shape as UNLINK_PLATFORM).
  function _submit(txType, data, signature) {
    const tx = withTxId({ tx_type: txType, timestamp: nowMs(), data, signature }, dag);
    const validation = validateTransaction(tx, dag, { skipPrevCheck: true });
    if (!validation.valid) {
      throw schemaError(400, validation.errors.join("; "), "tx_validation_failed");
    }
    submitTx(tx);
    return tx;
  }

  async function invite({ urlTipId, body }) {
    invitedSchema.validateRequest(body, { ...deps(), urlTipId });
    await _admit(body.org_tip_id, { opening: true });
    const tx = _submit(TX_TYPES.ORG_MEMBER_INVITED, {
      org_tip_id: body.org_tip_id,
      member_tip_id: body.member_tip_id,
      role: body.role,
      invited_at: body.invited_at,
    }, body.signature);
    log.info(`Org member invited: ${body.org_tip_id} -> ${body.member_tip_id} (${body.role})`);
    return {
      org_tip_id: body.org_tip_id, member_tip_id: body.member_tip_id, role: body.role,
      invite_tx_id: tx.tx_id, invited_at: body.invited_at, proposed_at: tx.timestamp, confirmation: "proposed",
    };
  }

  function cancelInvite({ urlTipId, body }) {
    cancelledSchema.validateRequest(body, { ...deps(), urlTipId });
    const tx = _submit(TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, {
      org_tip_id: body.org_tip_id,
      member_tip_id: body.member_tip_id,
      invite_tx_id: body.invite_tx_id,
      claimed_at: body.claimed_at,
      signer_tip_id: body.signer_tip_id,
    }, body.signature);
    log.info(`Org member invite cancelled: ${body.org_tip_id} -> ${body.member_tip_id} by ${body.signer_tip_id}`);
    return {
      org_tip_id: body.org_tip_id, member_tip_id: body.member_tip_id,
      invite_tx_id: body.invite_tx_id, cancel_tx_id: tx.tx_id, claimed_at: body.claimed_at, proposed_at: tx.timestamp,
      confirmation: "proposed",
    };
  }

  async function accept({ urlTipId, body }) {
    addedSchema.validateRequest(body, { ...deps(), urlTipId });
    await _admit(body.org_tip_id, { opening: false });
    const tx = _submit(TX_TYPES.ORG_MEMBER_ADDED, {
      org_tip_id: body.org_tip_id,
      member_tip_id: body.member_tip_id,
      invite_tx_id: body.invite_tx_id,
      accepted_at: body.accepted_at,
    }, body.signature);
    log.info(`Org member accepted: ${body.member_tip_id} joined ${body.org_tip_id}`);
    return {
      org_tip_id: body.org_tip_id, member_tip_id: body.member_tip_id,
      invite_tx_id: body.invite_tx_id, add_tx_id: tx.tx_id, accepted_at: body.accepted_at, proposed_at: tx.timestamp,
      confirmation: "proposed",
    };
  }

  function remove({ urlTipId, body }) {
    removedSchema.validateRequest(body, { ...deps(), urlTipId });
    const tx = _submit(TX_TYPES.ORG_MEMBER_REMOVED, {
      org_tip_id: body.org_tip_id,
      member_tip_id: body.member_tip_id,
      add_tx_id: body.add_tx_id,
      claimed_at: body.claimed_at,
      signer_tip_id: body.signer_tip_id,
    }, body.signature);
    log.info(`Org member removed: ${body.member_tip_id} from ${body.org_tip_id} by ${body.signer_tip_id}`);
    return {
      org_tip_id: body.org_tip_id, member_tip_id: body.member_tip_id,
      add_tx_id: body.add_tx_id, remove_tx_id: tx.tx_id, claimed_at: body.claimed_at, proposed_at: tx.timestamp,
      confirmation: "proposed",
    };
  }

  // GET /identity/:org/members: active roster plus open invites; ?include=removed adds history.
  async function listMembers(orgTipId, query = {}) {
    if (!dag.getIdentity(orgTipId)) throw schemaError(404, "TIP-ID not found", "tip_id_not_found");
    const now = nowMs();
    const rows = dag.getOrgMembersByOrg(orgTipId) || [];
    const includeRemoved = String(query.include || "").split(",").includes("removed");
    return {
      org_tip_id: orgTipId,
      ...(await _seatsView(orgTipId)),
      roles: ORG_MEMBER_ROLES,
      members: rows.filter(r => r.status === ORG_MEMBER_STATUS.ACTIVE).map(_view),
      pending_invites: rows.filter(r => roster.isOpenInvite(r, now)).map(_view),
      ...(includeRemoved ? {
        removed: rows.filter(r => r.status === ORG_MEMBER_STATUS.REMOVED).map(_view),
        cancelled: rows.filter(r => r.status === ORG_MEMBER_STATUS.CANCELLED).map(_view),
      } : {}),
    };
  }

  async function _seatsView(orgTipId) {
    const seats = await _seats(orgTipId);
    return { limit: seats.limit, plan: seats.plan, upgrade_url: seats.upgrade_url };
  }

  // GET /identity/:member/invites: open invites addressed to a person.
  function listInvites(memberTipId) {
    if (!dag.getIdentity(memberTipId)) throw schemaError(404, "TIP-ID not found", "tip_id_not_found");
    return {
      member_tip_id: memberTipId,
      invites: roster.openInvitesFor(dag, memberTipId, nowMs()).map(_view),
    };
  }

  // GET /identity/:member/memberships: organizations a person is active in.
  function listMemberships(memberTipId) {
    if (!dag.getIdentity(memberTipId)) throw schemaError(404, "TIP-ID not found", "tip_id_not_found");
    return {
      member_tip_id: memberTipId,
      memberships: roster.activeMemberships(dag, memberTipId).map(_view),
    };
  }

  return { invite, cancelInvite, accept, remove, listMembers, listInvites, listMemberships };
}

module.exports = { createOrgMemberService };
