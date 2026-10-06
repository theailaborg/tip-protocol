/**
 * @file tests/consensus/org-members-edge-cases.test.js
 * @description Every roster rule asserted at BOTH layers on one real DAG:
 * the API gate (schema validateRequest, what the HTTP route runs) and the
 * consensus gate (commitOrderedTxs, what a gossiped tx meets). A rule that
 * only one layer enforced would be bypassable through the other.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, computeTxId, shake256, tipNormalize } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { TX_TYPES, ORG_MEMBERS, ORG_MEMBER_STATUS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createOrgMemberService } = require(path.join(SRC, "services", "org-member-service"));
const contentSchema = require(path.join(SRC, "schemas", "content-register"));
const invitedSchema = require(path.join(SRC, "schemas", "org-member-invited"));
const cancelledSchema = require(path.join(SRC, "schemas", "org-member-invite-cancelled"));
const addedSchema = require(path.join(SRC, "schemas", "org-member-added"));
const removedSchema = require(path.join(SRC, "schemas", "org-member-removed"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/test-org-edges";
const ORG = "tip://id/GB-400d3636845c06f2";
const ORG2 = "tip://id/US-0e7db4040667073a";
const ALICE = "tip://id/IN-cbcd2ea94f1f1d49";
const BOB = "tip://id/US-ed1c6dbddac62443";
const BASE_TS = 1767225600000;
const ACTIVE = { activationMs: 0 };

let round = 0;
// Scenario clock: recent past, so the service's wall-clock view of "open invite" matches the frozen tx timestamps.
let ts = nowMs() - 120_000;
const next = () => (ts += 1000);

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const keys = {};
  for (const id of [ORG, ORG2, ALICE, BOB]) keys[id] = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey, status: "active", registered_at: BASE_TS });
  const saveId = (tipId, type) => dag.saveIdentity({
    tip_id: tipId, region: tipId.slice(9, 11), public_key: keys[tipId].publicKey, root_public_key: "00",
    vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active",
    tip_id_type: type, registered_at: BASE_TS,
    tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  saveId(ORG, "organization"); saveId(ORG2, "organization"); saveId(ALICE, "personal"); saveId(BOB, "personal");
  for (const id of Object.keys(keys)) dag.setScore(id, 500, 0, BASE_TS);
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, orgMembersActivationMs: 0 };
  const handler = createCommitHandler({ dag, scoring: initScoring(dag, config), config });
  const service = createOrgMemberService({ dag, config, submitTx: () => ({}) });
  return { dag, keys, handler, service };
}

// ── signed bodies (API shape) and the tx built from them (DAG shape) ────────
function signed(schema, data, key) {
  return { ...data, signature: schema.sign(schema.buildSigningPayload(data), key.privateKey) };
}
function txOf(ctx, txType, body, at) {
  const { signature, ...data } = body;
  const tx = { tx_type: txType, timestamp: at, signature, prev: [], data };
  tx.prev = ctx.dag.prevFor(tx.tx_type, tx.data);
  tx.tx_id = computeTxId(tx);
  return tx;
}
const inviteBody = (ctx, org, member, at, role = "author") =>
  signed(invitedSchema, { org_tip_id: org, member_tip_id: member, role, invited_at: at }, ctx.keys[org]);
const cancelBody = (ctx, org, member, inviteTxId, by, at) =>
  signed(cancelledSchema, { org_tip_id: org, member_tip_id: member, invite_tx_id: inviteTxId, claimed_at: at, signer_tip_id: by }, ctx.keys[by]);
const acceptBody = (ctx, org, member, inviteTxId, at) =>
  signed(addedSchema, { org_tip_id: org, member_tip_id: member, invite_tx_id: inviteTxId, accepted_at: at }, ctx.keys[member]);
const removeBody = (ctx, org, member, addTxId, by, at) =>
  signed(removedSchema, { org_tip_id: org, member_tip_id: member, add_tx_id: addTxId, claimed_at: at, signer_tip_id: by }, ctx.keys[by]);

let seq = 0;
function contentBody(ctx, signer, authors, mode = "employed", authorExtra = {}) {
  const text = `edge ${++seq}`;
  const hash = shake256(tipNormalize(text));
  const b = {
    signer_tip_id: signer, origin_code: "OH", content: text, media_canonical_hash: null, content_type_hint: null,
    cna_version: contentSchema.CURRENT_CNA_VERSION, attribution_mode: mode, extras: {}, registered_urls: [],
    authors: authors.map(a => ({ tip_id: a, tip_id_type: [ORG, ORG2].includes(a) ? "organization" : "personal", role: "byline", ...authorExtra })),
  };
  b.signature = contentSchema.sign(contentSchema.buildSigningPayload(b, hash), ctx.keys[signer].privateKey);
  return { body: b, hash };
}
function contentTx(ctx, { body, hash }, at) {
  const { content, media_canonical_hash, content_type_hint, ...rest } = body;
  const data = { ...rest, content_hash: hash, ctid: `tip://c/OH-${hash.slice(0, 14)}-${hash.slice(14, 18)}` };
  const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: at, signature: body.signature, prev: [], data };
  tx.prev = ctx.dag.prevFor(tx.tx_type, tx.data);
  tx.tx_id = computeTxId(tx);
  return tx;
}

// ── the two layers ───────────────────────────────────────────────────────────
const commit = (ctx, tx) => ctx.handler.commitOrderedTxs([tx], ++round);
function api(schema, body, ctx, urlTipId, at) {
  try {
    schema.validateRequest(body, { dag: ctx.dag, urlTipId, now: at, mediaLimits: {}, ...ACTIVE });
    return { ok: true };
  } catch (e) { return { ok: false, code: e.code, status: e.status }; }
}
// Assert the API refuses with `code` and the DAG drops the same signed action.
function rejectedEverywhere(ctx, schema, txType, body, urlTipId, at, code) {
  expect(api(schema, body, ctx, urlTipId, at)).toMatchObject({ ok: false, code });
  expect(commit(ctx, txOf(ctx, txType, body, at))).toMatchObject({ committed: 0, dropped: 1 });
}
function acceptedEverywhere(ctx, schema, txType, body, urlTipId, at) {
  expect(api(schema, body, ctx, urlTipId, at)).toEqual({ ok: true });
  const tx = txOf(ctx, txType, body, at);
  expect(commit(ctx, tx)).toMatchObject({ committed: 1, dropped: 0 });
  return tx;
}
function contentRejected(ctx, signer, authors, code, mode, authorExtra) {
  const c = contentBody(ctx, signer, authors, mode, authorExtra);
  expect(api(contentSchema, c.body, ctx, undefined, next())).toMatchObject({ ok: false, code });
  expect(commit(ctx, contentTx(ctx, c, next()))).toMatchObject({ committed: 0, dropped: 1 });
}
function contentAccepted(ctx, signer, authors, mode) {
  const c = contentBody(ctx, signer, authors, mode);
  expect(api(contentSchema, c.body, ctx, undefined, next())).toEqual({ ok: true });
  expect(commit(ctx, contentTx(ctx, c, next()))).toMatchObject({ committed: 1, dropped: 0 });
}
function joined(ctx, org, member) {
  const inv = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, org, member, next()), org, ts);
  const acc = acceptedEverywhere(ctx, addedSchema, TX_TYPES.ORG_MEMBER_ADDED, acceptBody(ctx, org, member, inv.tx_id, next()), member, ts);
  return { inv, acc };
}

describe("1. only an organization can send invites", () => {
  test("a person signing an invite as the org is refused at API and DAG", () => {
    const ctx = setup();
    const at = next();
    rejectedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ALICE, BOB, at), ALICE, at, "org_tip_id_type_invalid");
    expect(ctx.dag.getOrgMembersByOrg(ALICE)).toHaveLength(0);
  });
  test("an invite signed with someone else's key never passes", () => {
    const ctx = setup();
    const at = next();
    const body = inviteBody(ctx, ORG, ALICE, at);
    body.signature = invitedSchema.sign(invitedSchema.buildSigningPayload(body), ctx.keys[ALICE].privateKey);
    rejectedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, body, ORG, at, "signature_invalid");
  });
});

describe("2. an invite is pending until accepted; membership exists only after acceptance", () => {
  test("pending invite: listed as pending, not a member, cannot be an author; after accept all three flip", () => {
    const ctx = setup();
    const inv = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, next()), ORG, ts);
    expect(ctx.service.listMembers(ORG)).toMatchObject({ members: [], pending_invites: [expect.objectContaining({ invite_tx_id: inv.tx_id, status: ORG_MEMBER_STATUS.INVITED })] });
    expect(ctx.service.listMemberships(ALICE).memberships).toEqual([]);
    contentRejected(ctx, ORG, [ALICE], "invalid_author");

    acceptedEverywhere(ctx, addedSchema, TX_TYPES.ORG_MEMBER_ADDED, acceptBody(ctx, ORG, ALICE, inv.tx_id, next()), ALICE, ts);
    expect(ctx.service.listMembers(ORG).members).toHaveLength(1);
    expect(ctx.service.listMembers(ORG).pending_invites).toHaveLength(0);
    expect(ctx.service.listMemberships(ALICE).memberships.map(m => m.org_tip_id)).toEqual([ORG]);
    contentAccepted(ctx, ORG, [ALICE]);
  });
  test("accepting a pending invite that was never sent to you is refused at both layers", () => {
    const ctx = setup();
    const inv = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, next()), ORG, ts);
    const at = next();
    rejectedEverywhere(ctx, addedSchema, TX_TYPES.ORG_MEMBER_ADDED, acceptBody(ctx, ORG, BOB, inv.tx_id, at), BOB, at, "invite_mismatch");
  });
});

describe("3. only an active member can be an author on org-signed content", () => {
  test("non-member, pending invitee and removed member are all refused; the org itself and active members pass", () => {
    const ctx = setup();
    contentRejected(ctx, ORG, [BOB], "invalid_author");
    contentAccepted(ctx, ORG, [ORG], "self");
    const { acc } = joined(ctx, ORG, ALICE);
    contentAccepted(ctx, ORG, [ALICE]);
    contentAccepted(ctx, ORG, [ORG, ALICE]);
    contentRejected(ctx, ORG, [ALICE, BOB], "invalid_author");
    acceptedEverywhere(ctx, removedSchema, TX_TYPES.ORG_MEMBER_REMOVED, removeBody(ctx, ORG, ALICE, acc.tx_id, ORG, next()), ORG, ts);
    contentRejected(ctx, ORG, [ALICE], "invalid_author");
  });
});

describe("4. the free plan has one seat, enforced at API and DAG", () => {
  test("second acceptance refused while the seat is taken; a second invite is refused up front; at most one member can be an author", () => {
    const ctx = setup();
    expect(ORG_MEMBERS.FREE_MEMBER_LIMIT).toBe(1);
    const invA = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, next()), ORG, ts);
    const invB = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, BOB, next()), ORG, ts);
    acceptedEverywhere(ctx, addedSchema, TX_TYPES.ORG_MEMBER_ADDED, acceptBody(ctx, ORG, ALICE, invA.tx_id, next()), ALICE, ts);

    let at = next();
    rejectedEverywhere(ctx, addedSchema, TX_TYPES.ORG_MEMBER_ADDED, acceptBody(ctx, ORG, BOB, invB.tx_id, at), BOB, at, "member_limit_reached");
    expect(ctx.dag.getOrgMember(invB.tx_id).status).toBe(ORG_MEMBER_STATUS.INVITED);
    at = next();
    // Bob's invite is still open, so a fresh one is "invite_pending"; a third person hits the seat limit.
    rejectedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, BOB, at, "editor"), ORG, at, "invite_pending");
    expect(ctx.service.listMembers(ORG)).toMatchObject({ limit: 1, members: [expect.objectContaining({ member_tip_id: ALICE })] });
    contentAccepted(ctx, ORG, [ALICE]);
    contentRejected(ctx, ORG, [ALICE, BOB], "invalid_author");
  });
  test("with the seat taken, the org cannot invite anyone new", () => {
    const ctx = setup();
    joined(ctx, ORG, ALICE);
    const at = next();
    rejectedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, BOB, at), ORG, at, "member_limit_reached");
  });
});

describe("5. an invite can only go to a person, never to an organization", () => {
  test("inviting another org is refused at API and DAG; inviting itself too", () => {
    const ctx = setup();
    let at = next();
    rejectedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ORG2, at), ORG, at, "member_tip_id_type_invalid");
    at = next();
    rejectedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ORG, at), ORG, at, "member_tip_id_type_invalid");
    expect(ctx.dag.getOrgMembersByOrg(ORG)).toHaveLength(0);
  });
});

describe("6. no other organization can be an author on registered content", () => {
  test("an org listing another org, and a person listing an org, are refused at both layers", () => {
    const ctx = setup();
    contentRejected(ctx, ORG, [ORG2], "invalid_author");
    contentRejected(ctx, ORG, [ORG, ORG2], "invalid_author");
    contentRejected(ctx, ALICE, [ORG], "invalid_author");
    contentRejected(ctx, ALICE, [ALICE, ORG], "invalid_author");
    // Each org may still sign its own institutional content.
    contentAccepted(ctx, ORG, [ORG], "self");
    contentAccepted(ctx, ORG2, [ORG2], "self");
    contentAccepted(ctx, ALICE, [ALICE], "self");
  });
});

describe("7. an open invite can be cancelled by the org or declined by the invitee", () => {
  test("cancelled invite leaves pending, cannot be accepted, frees the invite cap; a third party cannot cancel", () => {
    const ctx = setup();
    const inv = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, next()), ORG, ts);
    let at = next();
    rejectedEverywhere(ctx, cancelledSchema, TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, cancelBody(ctx, ORG, ALICE, inv.tx_id, BOB, at), BOB, at, "not_party");

    acceptedEverywhere(ctx, cancelledSchema, TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, cancelBody(ctx, ORG, ALICE, inv.tx_id, ORG, next()), ORG, ts);
    expect(ctx.dag.getOrgMember(inv.tx_id)).toMatchObject({ status: ORG_MEMBER_STATUS.CANCELLED, removed_by: ORG });
    expect(ctx.service.listMembers(ORG).pending_invites).toHaveLength(0);
    expect(ctx.service.listMembers(ORG, { include: "removed" }).cancelled).toHaveLength(1);
    expect(ctx.service.listInvites(ALICE).invites).toHaveLength(0);

    at = next();
    rejectedEverywhere(ctx, addedSchema, TX_TYPES.ORG_MEMBER_ADDED, acceptBody(ctx, ORG, ALICE, inv.tx_id, at), ALICE, at, "invite_not_open");
    at = next();
    rejectedEverywhere(ctx, cancelledSchema, TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, cancelBody(ctx, ORG, ALICE, inv.tx_id, ORG, at), ORG, at, "invite_not_open");

    // The invitee declines the next one herself; the org may invite again afterwards.
    const inv2 = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, next()), ORG, ts);
    acceptedEverywhere(ctx, cancelledSchema, TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, cancelBody(ctx, ORG, ALICE, inv2.tx_id, ALICE, next()), ALICE, ts);
    expect(ctx.dag.getOrgMember(inv2.tx_id)).toMatchObject({ status: ORG_MEMBER_STATUS.CANCELLED, removed_by: ALICE });
    acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, next()), ORG, ts);
  });
  test("cancelled invites do not count toward the open-invite cap", () => {
    const ctx = setup();
    const cap = ORG_MEMBERS.FREE_MEMBER_LIMIT * ORG_MEMBERS.OPEN_INVITE_MULTIPLIER;
    const people = [ALICE, BOB];
    // Fill the cap with real invitees, cancelling each so the slot frees again.
    for (let i = 0; i < cap + 1; i++) {
      const who = people[i % people.length];
      const inv = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, who, next()), ORG, ts);
      acceptedEverywhere(ctx, cancelledSchema, TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, cancelBody(ctx, ORG, who, inv.tx_id, ORG, next()), ORG, ts);
    }
    expect(ctx.dag.getOrgMembersByOrg(ORG).filter(r => r.status === ORG_MEMBER_STATUS.CANCELLED)).toHaveLength(cap + 1);
  });
  test("an accept and a cancel of the same invite in one batch: only the first lands", () => {
    const ctx = setup();
    const inv = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, next()), ORG, ts);
    const acc = txOf(ctx, TX_TYPES.ORG_MEMBER_ADDED, acceptBody(ctx, ORG, ALICE, inv.tx_id, next()), ts);
    const can = txOf(ctx, TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, cancelBody(ctx, ORG, ALICE, inv.tx_id, ORG, next()), ts);
    expect(ctx.handler.commitOrderedTxs([acc, can], ++round)).toMatchObject({ committed: 1, dropped: 1 });
    expect(ctx.dag.getOrgMember(inv.tx_id).status).toBe(ORG_MEMBER_STATUS.ACTIVE);
  });
});

describe("8. a committed invite signature cannot be replayed; invites per day are capped", () => {
  test("after cancellation the identical signed invite is refused at API and DAG", () => {
    const ctx = setup();
    const body = inviteBody(ctx, ORG, ALICE, next());
    const inv = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, body, ORG, ts);
    acceptedEverywhere(ctx, cancelledSchema, TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, cancelBody(ctx, ORG, ALICE, inv.tx_id, ORG, next()), ORG, ts);
    // Same body, same signature, new envelope: the attacker's replay.
    const at = next();
    rejectedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, body, ORG, at, "invite_replayed");
    expect(ctx.service.listInvites(ALICE).invites).toHaveLength(0);
    // A genuinely new invite (fresh signed time) still works.
    acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, next()), ORG, ts);
  });
  test("a signed invite older than the claim window is dropped at commit even without a prior row", () => {
    const ctx = setup();
    const at = next();
    // Signed 16 minutes before the tx is built: outside CLAIM_MAX_AGE_MS.
    const body = inviteBody(ctx, ORG, ALICE, at - 16 * 60 * 1000);
    expect(api(invitedSchema, body, ctx, ORG, at)).toMatchObject({ ok: false, code: "claim_expired" });
    expect(commit(ctx, txOf(ctx, TX_TYPES.ORG_MEMBER_INVITED, body, at))).toMatchObject({ committed: 0, dropped: 1 });
  });
  test("the per-day invite cap counts cancelled invites too", () => {
    const ctx = setup();
    const dayCap = ORG_MEMBERS.FREE_MEMBER_LIMIT * ORG_MEMBERS.INVITES_PER_DAY_MULTIPLIER;
    for (let i = 0; i < dayCap; i++) {
      const who = i % 2 ? BOB : ALICE;
      const inv = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, who, next()), ORG, ts);
      acceptedEverywhere(ctx, cancelledSchema, TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, cancelBody(ctx, ORG, who, inv.tx_id, ORG, next()), ORG, ts);
    }
    const at = next();
    rejectedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, at), ORG, at, "invite_rate_limited");
    expect(ctx.dag.getOrgMembersByOrg(ORG)).toHaveLength(dayCap);
  });
});

describe("9. review follow-ups: batch ordering, claim freshness at commit, in-batch invite caps, revoked members", () => {
  test("cancel then accept of the same invite in one batch: the cancel wins", () => {
    const ctx = setup();
    const inv = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, next()), ORG, ts);
    const can = txOf(ctx, TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, cancelBody(ctx, ORG, ALICE, inv.tx_id, ORG, next()), ts);
    const acc = txOf(ctx, TX_TYPES.ORG_MEMBER_ADDED, acceptBody(ctx, ORG, ALICE, inv.tx_id, next()), ts);
    expect(ctx.handler.commitOrderedTxs([can, acc], ++round)).toMatchObject({ committed: 1, dropped: 1 });
    expect(ctx.dag.getOrgMember(inv.tx_id)).toMatchObject({ status: ORG_MEMBER_STATUS.CANCELLED, removed_by: ORG, add_tx_id: null });
  });

  test("a stale signed acceptance, removal or cancellation is dropped at commit (relayer cannot re-wrap or backdate)", () => {
    const ctx = setup();
    const inv = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, ALICE, next()), ORG, ts);
    // Bob's invite is created while the seat is still free; it stays open for the cancel probe below.
    const inv2 = acceptedEverywhere(ctx, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, BOB, next()), ORG, ts);
    let at = next();
    const oldAccept = acceptBody(ctx, ORG, ALICE, inv.tx_id, at - 16 * 60 * 1000);
    expect(api(addedSchema, oldAccept, ctx, ALICE, at)).toMatchObject({ ok: false, code: "claim_expired" });
    expect(commit(ctx, txOf(ctx, TX_TYPES.ORG_MEMBER_ADDED, oldAccept, at))).toMatchObject({ committed: 0, dropped: 1 });
    // Backdating tx.timestamp to the claim does not help: the relayed envelope must still be inside the window of the claim.
    const futureClaim = acceptBody(ctx, ORG, ALICE, inv.tx_id, at + 2 * 60 * 1000);
    expect(commit(ctx, txOf(ctx, TX_TYPES.ORG_MEMBER_ADDED, futureClaim, at))).toMatchObject({ committed: 0, dropped: 1 });
    const acc = acceptedEverywhere(ctx, addedSchema, TX_TYPES.ORG_MEMBER_ADDED, acceptBody(ctx, ORG, ALICE, inv.tx_id, next()), ALICE, ts);
    at = next();
    const oldRemove = removeBody(ctx, ORG, ALICE, acc.tx_id, ORG, at - 16 * 60 * 1000);
    rejectedEverywhere(ctx, removedSchema, TX_TYPES.ORG_MEMBER_REMOVED, oldRemove, ORG, at, "claim_expired");
    expect(ctx.dag.getOrgMember(inv.tx_id).status).toBe(ORG_MEMBER_STATUS.ACTIVE);
    at = next();
    const oldCancel = cancelBody(ctx, ORG, BOB, inv2.tx_id, ORG, at - 16 * 60 * 1000);
    rejectedEverywhere(ctx, cancelledSchema, TX_TYPES.ORG_MEMBER_INVITE_CANCELLED, oldCancel, ORG, at, "claim_expired");
    expect(ctx.dag.getOrgMember(inv2.tx_id).status).toBe(ORG_MEMBER_STATUS.INVITED);
  });

  test("the open-invite cap holds inside one batch", () => {
    const ctx = setup();
    const extra = ["tip://id/CA-acbdbe5b9f09edb7", "tip://id/US-9350d182f5f8e573"];
    for (const id of extra) {
      ctx.keys[id] = generateMLDSAKeypair();
      ctx.dag.saveIdentity({
        tip_id: id, region: id.slice(9, 11), public_key: ctx.keys[id].publicKey, root_public_key: "00",
        vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active",
        tip_id_type: "personal", registered_at: BASE_TS, tx_id: seedAnchorTx(ctx.dag, "REGISTER_IDENTITY", { tip_id: id }),
      });
    }
    const cap = ORG_MEMBERS.FREE_MEMBER_LIMIT * ORG_MEMBERS.OPEN_INVITE_MULTIPLIER;
    const people = [ALICE, BOB, ...extra];
    expect(people.length).toBe(cap + 1);
    const txs = people.map(p => txOf(ctx, TX_TYPES.ORG_MEMBER_INVITED, inviteBody(ctx, ORG, p, next()), ts));
    expect(ctx.handler.commitOrderedTxs(txs, ++round)).toMatchObject({ committed: cap, dropped: 1 });
    expect(ctx.service.listMembers(ORG).pending_invites).toHaveLength(cap);
  });

  test("a revoked member cannot be an author at API or DAG", () => {
    const ctx = setup();
    joined(ctx, ORG, ALICE);
    contentAccepted(ctx, ORG, [ALICE]);
    ctx.dag.addRevocation(ALICE, "REVOKE_VOLUNTARY", next(), "rev-1");
    contentRejected(ctx, ORG, [ALICE], "invalid_author");
    contentRejected(ctx, BOB, [BOB, ALICE], "invalid_author");
  });
});

describe("10. an author cannot claim a co-signature that is not in the envelope", () => {
  test("signed:true or key_mode:co_signed is refused at API and DAG for every signer type", () => {
    const ctx = setup();
    contentRejected(ctx, ALICE, [ALICE], "author_cosignature_missing", "self", { signed: true });
    contentRejected(ctx, ALICE, [ALICE], "author_cosignature_missing", "self", { key_mode: "co_signed" });
    contentRejected(ctx, ORG, [ORG], "author_cosignature_missing", "self", { signed: true });
    joined(ctx, ORG, ALICE);
    contentRejected(ctx, ORG, [ALICE], "author_cosignature_missing", "employed", { signed: true });
    contentAccepted(ctx, ORG, [ALICE]);
    contentAccepted(ctx, ALICE, [ALICE], "self");
  });
  test("before the activation epoch the claim is still recorded as before", () => {
    const ctxGate = (() => { const c = setup(); c.handler = createCommitHandler({ dag: c.dag, scoring: initScoring(c.dag, { nodeId: NODE_ID, nodeRegisteredId: NODE_ID }), config: { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, orgMembersActivationMs: Number.MAX_SAFE_INTEGER } }); return c; })();
    const c = contentBody(ctxGate, ALICE, [ALICE], "self", { signed: true });
    expect(commit(ctxGate, contentTx(ctxGate, c, next()))).toMatchObject({ committed: 1, dropped: 0 });
  });
});
