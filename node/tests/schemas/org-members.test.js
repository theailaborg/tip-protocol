/**
 * @file tests/schemas/org-members.test.js
 * @description Unit contract for the three org roster schemas
 * (ORG_MEMBER_INVITED / ADDED / REMOVED) against a fake DAG: canonical
 * payload shape, request gate, and the state machine every node replays.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { ORG_MEMBERS, ORG_MEMBER_ROLES, ORG_MEMBER_STATUS, CLAIM_MAX_AGE_MS } = require(path.join(SHARED, "constants"));
const invited = require(path.join(SRC, "schemas", "org-member-invited"));
const added = require(path.join(SRC, "schemas", "org-member-added"));
const removed = require(path.join(SRC, "schemas", "org-member-removed"));
const roster = require(path.join(SRC, "schemas", "_org-members"));

beforeAll(async () => { await initCrypto(); });

const ORG = "tip://id/GB-400d3636845c06f2";
const MEMBER = "tip://id/IN-cbcd2ea94f1f1d49";
const OTHER = "tip://id/US-ed1c6dbddac62443";
const T = 1767225600000;
const ACTIVE = { activationMs: 0 };

// Minimal DAG: identities by id, roster rows by invite_tx_id.
function fakeDag({ identities = {}, rows = [], revoked = [] } = {}) {
  return {
    getIdentity: (id) => identities[id] || null,
    isRevoked: (id) => revoked.includes(id),
    getOrgMembersByOrg: (org) => rows.filter(r => r.org_tip_id === org),
    getOrgMembersByMember: (m) => rows.filter(r => r.member_tip_id === m),
    getOrgMember: (id) => rows.find(r => r.invite_tx_id === id) || null,
    getOrgMemberByAddTxId: (id) => rows.find(r => r.add_tx_id === id) || null,
    getMempoolTxsByTipId: () => [],
  };
}

function identities(orgKp, memberKp) {
  return {
    [ORG]: { tip_id: ORG, tip_id_type: "organization", public_key: orgKp.publicKey },
    [MEMBER]: { tip_id: MEMBER, tip_id_type: "personal", public_key: memberKp.publicKey },
    [OTHER]: { tip_id: OTHER, tip_id_type: "personal", public_key: memberKp.publicKey },
  };
}

function inviteRow(over = {}) {
  return {
    invite_tx_id: "inv-1", org_tip_id: ORG, member_tip_id: MEMBER, role: "author",
    status: ORG_MEMBER_STATUS.INVITED, invited_at: T, accepted_at: null, add_tx_id: null,
    removed_at: null, remove_tx_id: null, removed_by: null, ...over,
  };
}

function activeRow(over = {}) {
  return inviteRow({ status: ORG_MEMBER_STATUS.ACTIVE, accepted_at: T + 10, add_tx_id: "add-1", ...over });
}

describe("canonical payloads", () => {
  test("INVITED signs exactly {invited_at, member_tip_id, org_tip_id, role}", () => {
    const p = invited.buildSigningPayload({ org_tip_id: ORG, member_tip_id: MEMBER, role: "author", invited_at: T, extra: 1 });
    expect(Object.keys(p)).toEqual(["invited_at", "member_tip_id", "org_tip_id", "role"]);
  });

  test("ADDED signs exactly {accepted_at, invite_tx_id, member_tip_id, org_tip_id}", () => {
    const p = added.buildSigningPayload({ org_tip_id: ORG, member_tip_id: MEMBER, invite_tx_id: "inv-1", accepted_at: T });
    expect(Object.keys(p)).toEqual(["accepted_at", "invite_tx_id", "member_tip_id", "org_tip_id"]);
  });

  test("REMOVED signs exactly {add_tx_id, claimed_at, member_tip_id, org_tip_id, signer_tip_id}", () => {
    const p = removed.buildSigningPayload({ org_tip_id: ORG, member_tip_id: MEMBER, add_tx_id: "add-1", claimed_at: T, signer_tip_id: MEMBER });
    expect(Object.keys(p)).toEqual(["add_tx_id", "claimed_at", "member_tip_id", "org_tip_id", "signer_tip_id"]);
  });

  test("role is one of the locked roster roles", () => {
    const base = { org_tip_id: ORG, member_tip_id: MEMBER, invited_at: T };
    expect(() => invited.buildSigningPayload({ ...base, role: "Editor" })).toThrow(expect.objectContaining({ code: "role_invalid" }));
    expect(() => invited.buildSigningPayload({ ...base, role: "a".repeat(ORG_MEMBERS.ROLE_MAX_LENGTH + 1) })).toThrow(expect.objectContaining({ code: "role_too_long" }));
    expect(() => invited.buildSigningPayload({ ...base })).toThrow(expect.objectContaining({ code: "role_required" }));
    expect(() => invited.buildSigningPayload({ ...base, role: "senior-editor_2" })).toThrow(expect.objectContaining({ code: "role_invalid" }));
    expect(() => invited.buildSigningPayload({ ...base, role: "autor" })).toThrow(expect.objectContaining({ code: "role_invalid" }));
    for (const r of ORG_MEMBER_ROLES) expect(invited.buildSigningPayload({ ...base, role: r }).role).toBe(r);
  });
});

describe("ORG_MEMBER_INVITED state machine", () => {
  let orgKp, memberKp;
  beforeAll(() => { orgKp = generateMLDSAKeypair(); memberKp = generateMLDSAKeypair(); });

  const data = () => ({ org_tip_id: ORG, member_tip_id: MEMBER, role: "author", invited_at: T });
  const tx = (d = data(), timestamp = T) => ({ tx_type: invited.TX_TYPE, timestamp, data: d });

  test("org must be an organization, member must be personal, both registered and unrevoked", () => {
    const ids = identities(orgKp, memberKp);
    expect(invited.verifyTx(tx(), fakeDag({ identities: ids }), ACTIVE)).toEqual({ ok: true });

    expect(invited.verifyTx(tx({ ...data(), org_tip_id: OTHER }), fakeDag({ identities: ids }), ACTIVE).code).toBe("org_tip_id_type_invalid");
    expect(invited.verifyTx(tx({ ...data(), member_tip_id: ORG }), fakeDag({ identities: ids }), ACTIVE).code).toBe("member_tip_id_type_invalid");
    expect(invited.verifyTx(tx({ ...data(), member_tip_id: "tip://id/XX-0" }), fakeDag({ identities: ids }), ACTIVE).code).toBe("member_tip_id_not_found");
    expect(invited.verifyTx(tx(), fakeDag({ identities: ids, revoked: [ORG] }), ACTIVE).code).toBe("org_tip_id_revoked");
    expect(invited.verifyTx(tx(), fakeDag({ identities: ids, revoked: [MEMBER] }), ACTIVE).code).toBe("member_tip_id_revoked");
  });

  test("rejects before the activation epoch, on the frozen tx.timestamp", () => {
    const dag = fakeDag({ identities: identities(orgKp, memberKp) });
    expect(invited.verifyTx(tx(data(), T), dag, { activationMs: T + 1 }).code).toBe("org_members_not_active");
    expect(invited.verifyTx(tx(data(), T + 1), dag, { activationMs: T + 1 })).toEqual({ ok: true });
    // The constant is the default gate when no override is given.
    expect(invited.verifyTx(tx(data(), ORG_MEMBERS.ACTIVATION_MS - 1), dag).code).toBe("org_members_not_active");
  });

  test("already a member, an open invite, a full roster and too many open invites each reject", () => {
    const ids = identities(orgKp, memberKp);
    expect(invited.verifyTx(tx(), fakeDag({ identities: ids, rows: [activeRow()] }), ACTIVE).code).toBe("already_member");
    expect(invited.verifyTx(tx(), fakeDag({ identities: ids, rows: [inviteRow()] }), ACTIVE).code).toBe("invite_pending");
    // Seat held by someone else.
    expect(invited.verifyTx(tx(), fakeDag({ identities: ids, rows: [activeRow({ member_tip_id: OTHER })] }), ACTIVE).code).toBe("member_limit_reached");
    // Open invites to other people fill the invite cap (limit x multiplier).
    const cap = ORG_MEMBERS.FREE_MEMBER_LIMIT * ORG_MEMBERS.OPEN_INVITE_MULTIPLIER;
    const others = Array.from({ length: cap }, (_, i) => inviteRow({ invite_tx_id: `inv-o${i}`, member_tip_id: `tip://id/US-${i}` }));
    expect(invited.verifyTx(tx(), fakeDag({ identities: ids, rows: others }), ACTIVE).code).toBe("invite_limit_reached");
  });

  test("an expired invite is neither pending nor counted against the invite cap", () => {
    const ids = identities(orgKp, memberKp);
    const stale = inviteRow({ invited_at: T - ORG_MEMBERS.INVITE_TTL_MS - 1 });
    expect(invited.verifyTx(tx(), fakeDag({ identities: ids, rows: [stale] }), ACTIVE)).toEqual({ ok: true });
    expect(roster.openInvites(fakeDag({ rows: [stale] }), ORG, T)).toEqual([]);
    expect(roster.openInvites(fakeDag({ rows: [stale] }), ORG, T - ORG_MEMBERS.INVITE_TTL_MS - 1)).toHaveLength(1);
  });

  test("validateRequest: URL must be the org, signature must be the org's, invite must be fresh", () => {
    const dag = fakeDag({ identities: identities(orgKp, memberKp) });
    const body = { ...data(), signature: invited.sign(invited.buildSigningPayload(data()), orgKp.privateKey) };
    expect(() => invited.validateRequest(body, { dag, urlTipId: ORG, now: T, ...ACTIVE })).not.toThrow();
    expect(() => invited.validateRequest(body, { dag, urlTipId: MEMBER, now: T, ...ACTIVE })).toThrow(expect.objectContaining({ code: "tip_id_mismatch" }));
    expect(() => invited.validateRequest(body, { dag, urlTipId: ORG, now: T + CLAIM_MAX_AGE_MS + 1, ...ACTIVE })).toThrow(expect.objectContaining({ code: "claim_expired" }));
    expect(() => invited.validateRequest(body, { dag, urlTipId: ORG, now: T, activationMs: T + 1 })).toThrow(expect.objectContaining({ code: "org_members_not_active" }));
    const forged = { ...body, signature: invited.sign(invited.buildSigningPayload(data()), memberKp.privateKey) };
    expect(() => invited.validateRequest(forged, { dag, urlTipId: ORG, now: T, ...ACTIVE })).toThrow(expect.objectContaining({ code: "signature_invalid" }));
  });
});

describe("ORG_MEMBER_ADDED state machine", () => {
  let orgKp, memberKp;
  beforeAll(() => { orgKp = generateMLDSAKeypair(); memberKp = generateMLDSAKeypair(); });

  const data = () => ({ org_tip_id: ORG, member_tip_id: MEMBER, invite_tx_id: "inv-1", accepted_at: T + 10 });
  const tx = (d = data(), timestamp = T + 10) => ({ tx_type: added.TX_TYPE, timestamp, data: d });

  test("accepts an open invite addressed to the signer while a seat is free", () => {
    const dag = fakeDag({ identities: identities(orgKp, memberKp), rows: [inviteRow()] });
    expect(added.verifyTx(tx(), dag, ACTIVE)).toEqual({ ok: true });
  });

  test("unknown, mismatched, closed and expired invites reject", () => {
    const ids = identities(orgKp, memberKp);
    expect(added.verifyTx(tx(), fakeDag({ identities: ids }), ACTIVE).code).toBe("invite_not_found");
    expect(added.verifyTx(tx({ ...data(), member_tip_id: OTHER }), fakeDag({ identities: ids, rows: [inviteRow()] }), ACTIVE).code).toBe("invite_mismatch");
    expect(added.verifyTx(tx(), fakeDag({ identities: ids, rows: [activeRow()] }), ACTIVE).code).toBe("invite_not_open");
    expect(added.verifyTx(tx(), fakeDag({ identities: ids, rows: [inviteRow({ status: "removed" })] }), ACTIVE).code).toBe("invite_not_open");
    // accepted_at must track the tx timestamp (claim freshness runs first).
    const lateTs = T + ORG_MEMBERS.INVITE_TTL_MS + 1;
    const late = tx({ ...data(), accepted_at: lateTs }, lateTs);
    expect(added.verifyTx(late, fakeDag({ identities: ids, rows: [inviteRow()] }), ACTIVE).code).toBe("invite_expired");
    const edgeTs = T + ORG_MEMBERS.INVITE_TTL_MS;
    expect(added.verifyTx(tx({ ...data(), accepted_at: edgeTs }, edgeTs), fakeDag({ identities: ids, rows: [inviteRow()] }), ACTIVE)).toEqual({ ok: true });
  });

  test("the seat limit is enforced at acceptance: an invite sent while free fails once the seat is gone", () => {
    const ids = identities(orgKp, memberKp);
    const rows = [inviteRow(), activeRow({ invite_tx_id: "inv-2", add_tx_id: "add-2", member_tip_id: OTHER })];
    expect(added.verifyTx(tx(), fakeDag({ identities: ids, rows }), ACTIVE).code).toBe("member_limit_reached");
    // A removed member frees the seat again.
    rows[1] = { ...rows[1], status: ORG_MEMBER_STATUS.REMOVED };
    expect(added.verifyTx(tx(), fakeDag({ identities: ids, rows }), ACTIVE)).toEqual({ ok: true });
  });

  test("parties are re-checked at acceptance (revocation between invite and accept)", () => {
    const ids = identities(orgKp, memberKp);
    expect(added.verifyTx(tx(), fakeDag({ identities: ids, rows: [inviteRow()], revoked: [ORG] }), ACTIVE).code).toBe("org_tip_id_revoked");
    expect(added.verifyTx(tx(), fakeDag({ identities: ids, rows: [inviteRow()], revoked: [MEMBER] }), ACTIVE).code).toBe("member_tip_id_revoked");
  });

  test("validateRequest: URL must be the member and the signature the member's", () => {
    const dag = fakeDag({ identities: identities(orgKp, memberKp), rows: [inviteRow()] });
    const body = { ...data(), signature: added.sign(added.buildSigningPayload(data()), memberKp.privateKey) };
    expect(() => added.validateRequest(body, { dag, urlTipId: MEMBER, now: T + 10, ...ACTIVE })).not.toThrow();
    expect(() => added.validateRequest(body, { dag, urlTipId: ORG, now: T + 10, ...ACTIVE })).toThrow(expect.objectContaining({ code: "tip_id_mismatch" }));
    const forged = { ...body, signature: added.sign(added.buildSigningPayload(data()), orgKp.privateKey) };
    expect(() => added.validateRequest(forged, { dag, urlTipId: MEMBER, now: T + 10, ...ACTIVE })).toThrow(expect.objectContaining({ code: "signature_invalid" }));
  });
});

describe("ORG_MEMBER_REMOVED state machine", () => {
  let orgKp, memberKp;
  beforeAll(() => { orgKp = generateMLDSAKeypair(); memberKp = generateMLDSAKeypair(); });

  const data = (signer = ORG) => ({ org_tip_id: ORG, member_tip_id: MEMBER, add_tx_id: "add-1", claimed_at: T + 20, signer_tip_id: signer });
  const tx = (d = data()) => ({ tx_type: removed.TX_TYPE, timestamp: T + 20, data: d });

  test("either the org or the member may end an active membership, nobody else", () => {
    const ids = identities(orgKp, memberKp);
    const dag = () => fakeDag({ identities: ids, rows: [activeRow()] });
    expect(removed.verifyTx(tx(data(ORG)), dag(), ACTIVE)).toEqual({ ok: true });
    expect(removed.verifyTx(tx(data(MEMBER)), dag(), ACTIVE)).toEqual({ ok: true });
    expect(removed.verifyTx(tx(data(OTHER)), dag(), ACTIVE).code).toBe("not_party");
  });

  test("binds to one membership instance and requires it to be active", () => {
    const ids = identities(orgKp, memberKp);
    expect(removed.verifyTx(tx(), fakeDag({ identities: ids }), ACTIVE).code).toBe("membership_not_found");
    expect(removed.verifyTx(tx(), fakeDag({ identities: ids, rows: [activeRow({ status: "removed" })] }), ACTIVE).code).toBe("membership_not_active");
    expect(removed.verifyTx(tx({ ...data(), member_tip_id: OTHER, signer_tip_id: OTHER }), fakeDag({ identities: ids, rows: [activeRow()] }), ACTIVE).code).toBe("membership_mismatch");
  });

  test("only the signer must be unrevoked: a member can leave a revoked org and an org can drop a revoked member", () => {
    const ids = identities(orgKp, memberKp);
    expect(removed.verifyTx(tx(data(MEMBER)), fakeDag({ identities: ids, rows: [activeRow()], revoked: [ORG] }), ACTIVE)).toEqual({ ok: true });
    expect(removed.verifyTx(tx(data(ORG)), fakeDag({ identities: ids, rows: [activeRow()], revoked: [MEMBER] }), ACTIVE)).toEqual({ ok: true });
    expect(removed.verifyTx(tx(data(ORG)), fakeDag({ identities: ids, rows: [activeRow()], revoked: [ORG] }), ACTIVE).code).toBe("signer_tip_id_revoked");
  });

  test("validateRequest: URL is the signer and the signature must be theirs", () => {
    const dag = fakeDag({ identities: identities(orgKp, memberKp), rows: [activeRow()] });
    const d = data(MEMBER);
    const body = { ...d, signature: removed.sign(removed.buildSigningPayload(d), memberKp.privateKey) };
    expect(() => removed.validateRequest(body, { dag, urlTipId: MEMBER, now: T + 20, ...ACTIVE })).not.toThrow();
    expect(() => removed.validateRequest(body, { dag, urlTipId: ORG, now: T + 20, ...ACTIVE })).toThrow(expect.objectContaining({ code: "tip_id_mismatch" }));
    const forged = { ...body, signature: removed.sign(removed.buildSigningPayload(d), orgKp.privateKey) };
    expect(() => removed.validateRequest(forged, { dag, urlTipId: MEMBER, now: T + 20, ...ACTIVE })).toThrow(expect.objectContaining({ code: "signature_invalid" }));
  });
});
