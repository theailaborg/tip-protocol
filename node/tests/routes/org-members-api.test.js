/**
 * @file tests/routes/org-members-api.test.js
 * @description The roster HTTP surface end to end: a client signs the
 * canonical bodies, POSTs them through the real router + service, the
 * proposed txs are committed through the real commit handler, and the
 * GET endpoints plus GET /identity/:id reflect the roster.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const express = require("express");
const request = require("supertest");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { ORG_MEMBERS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createOrgMemberService } = require(path.join(SRC, "services", "org-member-service"));
const { createIdentityService } = require(path.join(SRC, "services", "identity-service"));
const { createRouter } = require(path.join(SRC, "routes", "identity"));
const { errorHandler } = require(path.join(SRC, "middleware", "error-handler"));
const invitedSchema = require(path.join(SRC, "schemas", "org-member-invited"));
const cancelledSchema = require(path.join(SRC, "schemas", "org-member-invite-cancelled"));
const addedSchema = require(path.join(SRC, "schemas", "org-member-added"));
const removedSchema = require(path.join(SRC, "schemas", "org-member-removed"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/test-org-api";
const ORG = "tip://id/GB-400d3636845c06f2";
const ALICE = "tip://id/IN-cbcd2ea94f1f1d49";
const BOB = "tip://id/US-ed1c6dbddac62443";
const BASE_TS = 1767225600000;
const enc = (id) => encodeURIComponent(id);

function harness() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const keys = { [ORG]: generateMLDSAKeypair(), [ALICE]: generateMLDSAKeypair(), [BOB]: generateMLDSAKeypair() };
  dag.saveNode({ node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey, status: "active", registered_at: BASE_TS });
  const saveId = (tipId, type) => dag.saveIdentity({
    tip_id: tipId, region: tipId.slice(9, 11), public_key: keys[tipId].publicKey, root_public_key: "00",
    vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active",
    tip_id_type: type, registered_at: BASE_TS,
    tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  saveId(ORG, "organization"); saveId(ALICE, "personal"); saveId(BOB, "personal");
  for (const id of [ORG, ALICE, BOB]) dag.setScore(id, 500, 0, BASE_TS);

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, orgMembersActivationMs: 0 };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });

  // The API proposes; this test commits each proposed tx at once so the
  // GET endpoints read committed state, as on a live node a round later.
  let round = 0;
  const proposed = [];
  const submitTx = (tx) => { proposed.push(tx); return { tx_id: tx.tx_id }; };
  const commitProposed = () => {
    const txs = proposed.splice(0);
    return handler.commitOrderedTxs(txs, ++round);
  };

  const orgMemberService = createOrgMemberService({ dag, config, submitTx });
  const identityService = createIdentityService({ dag, scoring, config, submitTx, consensus: { current: null } });
  const app = express();
  app.use(express.json());
  app.use("/v1", createRouter({ identityService, profileService: {}, keyService: {}, orgMemberService }));
  app.use(errorHandler);
  return { dag, keys, app, commitProposed };
}

function signedInvite(h, member, role = "author") {
  const body = { org_tip_id: ORG, member_tip_id: member, role, invited_at: nowMs() };
  body.signature = invitedSchema.sign(invitedSchema.buildSigningPayload(body), h.keys[ORG].privateKey);
  return body;
}
function signedAccept(h, member, inviteTxId) {
  const body = { org_tip_id: ORG, member_tip_id: member, invite_tx_id: inviteTxId, accepted_at: nowMs() };
  body.signature = addedSchema.sign(addedSchema.buildSigningPayload(body), h.keys[member].privateKey);
  return body;
}
function signedRemove(h, member, addTxId, signer) {
  const body = { org_tip_id: ORG, member_tip_id: member, add_tx_id: addTxId, claimed_at: nowMs(), signer_tip_id: signer };
  body.signature = removedSchema.sign(removedSchema.buildSigningPayload(body), h.keys[signer].privateKey);
  return body;
}

describe("org roster API", () => {
  test("invite, accept, list, remove; GET /identity reflects seats and member_of", async () => {
    const h = harness();

    const inv = await request(h.app).post(`/v1/identity/${enc(ORG)}/members/invite`).send(signedInvite(h, ALICE));
    expect(inv.status).toBe(202);
    expect(inv.body).toMatchObject({ org_tip_id: ORG, member_tip_id: ALICE, role: "author", confirmation: "proposed" });
    expect(h.commitProposed()).toMatchObject({ committed: 1 });

    // Alice discovers the invite from any node, without a link.
    const invites = await request(h.app).get(`/v1/identity/${enc(ALICE)}/invites`);
    expect(invites.status).toBe(200);
    expect(invites.body.invites).toHaveLength(1);
    expect(invites.body.invites[0]).toMatchObject({ invite_tx_id: inv.body.invite_tx_id, org_tip_id: ORG, status: "invited" });

    let members = await request(h.app).get(`/v1/identity/${enc(ORG)}/members`);
    expect(members.body).toMatchObject({ org_tip_id: ORG, limit: ORG_MEMBERS.FREE_MEMBER_LIMIT, members: [] });
    expect(members.body.pending_invites).toHaveLength(1);

    const acc = await request(h.app).post(`/v1/identity/${enc(ALICE)}/members/accept`).send(signedAccept(h, ALICE, inv.body.invite_tx_id));
    expect(acc.status).toBe(202);
    expect(h.commitProposed()).toMatchObject({ committed: 1 });

    members = await request(h.app).get(`/v1/identity/${enc(ORG)}/members`);
    expect(members.body.members).toHaveLength(1);
    expect(members.body.members[0]).toMatchObject({ member_tip_id: ALICE, status: "active", add_tx_id: acc.body.add_tx_id });
    expect(members.body.pending_invites).toHaveLength(0);

    const org = await request(h.app).get(`/v1/identity/${enc(ORG)}`);
    expect(org.body.members).toEqual({ active: 1, limit: ORG_MEMBERS.FREE_MEMBER_LIMIT });
    const alice = await request(h.app).get(`/v1/identity/${enc(ALICE)}`);
    expect(alice.body.member_of).toEqual([ORG]);
    const memberships = await request(h.app).get(`/v1/identity/${enc(ALICE)}/memberships`);
    expect(memberships.body.memberships.map(m => m.org_tip_id)).toEqual([ORG]);

    // Alice leaves, signing herself.
    const rem = await request(h.app).post(`/v1/identity/${enc(ALICE)}/members/remove`).send(signedRemove(h, ALICE, acc.body.add_tx_id, ALICE));
    expect(rem.status).toBe(202);
    expect(h.commitProposed()).toMatchObject({ committed: 1 });

    members = await request(h.app).get(`/v1/identity/${enc(ORG)}/members?include=removed`);
    expect(members.body.members).toHaveLength(0);
    expect(members.body.removed).toHaveLength(1);
    expect(members.body.removed[0]).toMatchObject({ status: "removed", removed_by: ALICE });
    expect((await request(h.app).get(`/v1/identity/${enc(ALICE)}`)).body.member_of).toEqual([]);
  });

  test("seat limit at acceptance: 409 member_limit_reached, invite stays open; a third party cannot remove", async () => {
    const h = harness();
    const invA = await request(h.app).post(`/v1/identity/${enc(ORG)}/members/invite`).send(signedInvite(h, ALICE));
    const invB = await request(h.app).post(`/v1/identity/${enc(ORG)}/members/invite`).send(signedInvite(h, BOB));
    expect([invA.status, invB.status]).toEqual([202, 202]);
    expect(h.commitProposed()).toMatchObject({ committed: 2 });

    const accA = await request(h.app).post(`/v1/identity/${enc(ALICE)}/members/accept`).send(signedAccept(h, ALICE, invA.body.invite_tx_id));
    expect(accA.status).toBe(202);
    h.commitProposed();

    const accB = await request(h.app).post(`/v1/identity/${enc(BOB)}/members/accept`).send(signedAccept(h, BOB, invB.body.invite_tx_id));
    expect(accB.status).toBe(409);
    expect(accB.body.error.code).toBe("member_limit_reached");
    expect((await request(h.app).get(`/v1/identity/${enc(BOB)}/invites`)).body.invites).toHaveLength(1);

    // A full roster also refuses new invites up front.
    const invC = await request(h.app).post(`/v1/identity/${enc(ORG)}/members/invite`).send(signedInvite(h, BOB, "editor"));
    expect(invC.status).toBe(409);

    const byBob = await request(h.app).post(`/v1/identity/${enc(BOB)}/members/remove`).send(signedRemove(h, ALICE, accA.body.add_tx_id, BOB));
    expect(byBob.status).toBe(403);
    expect(byBob.body.error.code).toBe("not_party");
  });

  test("request gate: URL/body mismatch, wrong signer and unknown invite are rejected before anything is proposed", async () => {
    const h = harness();
    const mismatch = await request(h.app).post(`/v1/identity/${enc(ALICE)}/members/invite`).send(signedInvite(h, ALICE));
    expect(mismatch.status).toBe(400);
    expect(mismatch.body.error.code).toBe("tip_id_mismatch");

    const forged = signedInvite(h, ALICE);
    forged.signature = invitedSchema.sign(invitedSchema.buildSigningPayload(forged), h.keys[ALICE].privateKey);
    const bad = await request(h.app).post(`/v1/identity/${enc(ORG)}/members/invite`).send(forged);
    expect(bad.status).toBe(403);
    expect(bad.body.error.code).toBe("signature_invalid");

    const ghost = await request(h.app).post(`/v1/identity/${enc(ALICE)}/members/accept`).send(signedAccept(h, ALICE, "no-such-invite"));
    expect(ghost.status).toBe(412);
    expect(ghost.body.error.code).toBe("invite_not_found");
    expect(h.commitProposed()).toMatchObject({ committed: 0 });
  });
});

describe("org roster API: cancel-invite", () => {
  function signedCancel(h, member, inviteTxId, signer) {
    const body = { org_tip_id: ORG, member_tip_id: member, invite_tx_id: inviteTxId, claimed_at: nowMs(), signer_tip_id: signer };
    body.signature = cancelledSchema.sign(cancelledSchema.buildSigningPayload(body), h.keys[signer].privateKey);
    return body;
  }

  test("the org cancels, the invitee declines, a third party cannot; a cancelled invite cannot be accepted", async () => {
    const h = harness();
    const inv = await request(h.app).post(`/v1/identity/${enc(ORG)}/members/invite`).send(signedInvite(h, ALICE));
    expect(inv.status).toBe(202);
    h.commitProposed();

    const byBob = await request(h.app).post(`/v1/identity/${enc(BOB)}/members/cancel-invite`).send(signedCancel(h, ALICE, inv.body.invite_tx_id, BOB));
    expect(byBob.status).toBe(403);
    expect(byBob.body.error.code).toBe("not_party");

    const cancel = await request(h.app).post(`/v1/identity/${enc(ORG)}/members/cancel-invite`).send(signedCancel(h, ALICE, inv.body.invite_tx_id, ORG));
    expect(cancel.status).toBe(202);
    expect(cancel.body).toMatchObject({ invite_tx_id: inv.body.invite_tx_id, confirmation: "proposed" });
    expect(h.commitProposed()).toMatchObject({ committed: 1 });

    expect((await request(h.app).get(`/v1/identity/${enc(ALICE)}/invites`)).body.invites).toHaveLength(0);
    const members = await request(h.app).get(`/v1/identity/${enc(ORG)}/members?include=removed`);
    expect(members.body.pending_invites).toHaveLength(0);
    expect(members.body.cancelled).toHaveLength(1);
    expect(members.body.cancelled[0]).toMatchObject({ status: "cancelled", removed_by: ORG });

    const late = await request(h.app).post(`/v1/identity/${enc(ALICE)}/members/accept`).send(signedAccept(h, ALICE, inv.body.invite_tx_id));
    expect(late.status).toBe(409);
    expect(late.body.error.code).toBe("invite_not_open");

    // Invitee declines the next one herself.
    const inv2 = await request(h.app).post(`/v1/identity/${enc(ORG)}/members/invite`).send(signedInvite(h, ALICE, "editor"));
    expect(inv2.status).toBe(202);
    h.commitProposed();
    const decline = await request(h.app).post(`/v1/identity/${enc(ALICE)}/members/cancel-invite`).send(signedCancel(h, ALICE, inv2.body.invite_tx_id, ALICE));
    expect(decline.status).toBe(202);
    expect(h.commitProposed()).toMatchObject({ committed: 1 });
    expect((await request(h.app).get(`/v1/identity/${enc(ORG)}/members?include=removed`)).body.cancelled).toHaveLength(2);
  });
});

describe("GET /v1/identity/search (invite box type-ahead)", () => {
  test("matches TIP-ID prefix or name, personal and active only, bounded", async () => {
    const h = harness();
    const named = "tip://id/US-9350d182f5f8e573";
    h.keys[named] = generateMLDSAKeypair();
    h.dag.saveIdentity({
      tip_id: named, region: "US", public_key: h.keys[named].publicKey, root_public_key: "00",
      vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active",
      tip_id_type: "personal", creator_name: "Alice Example", registered_at: BASE_TS,
      tx_id: seedAnchorTx(h.dag, "REGISTER_IDENTITY", { tip_id: named }),
    });
    h.dag.setScore(named, 500, 0, BASE_TS);

    const byName = await request(h.app).get("/v1/identity/search?q=alice");
    expect(byName.status).toBe(200);
    expect(byName.body.results.map(r => r.tip_id)).toEqual([named]);
    expect(byName.body.results[0]).toMatchObject({ creator_name: "Alice Example", tip_id_type: "personal", region: "US" });

    const byId = await request(h.app).get(`/v1/identity/search?q=${encodeURIComponent("IN-cbcd")}`);
    expect(byId.body.results.map(r => r.tip_id)).toEqual([ALICE]);
    const byFullId = await request(h.app).get(`/v1/identity/search?q=${encodeURIComponent(ALICE)}`);
    expect(byFullId.body.results.map(r => r.tip_id)).toEqual([ALICE]);

    // Organizations are not offered by default; type=any includes them.
    const orgDefault = await request(h.app).get(`/v1/identity/search?q=${encodeURIComponent("GB-400d")}`);
    expect(orgDefault.body.results).toEqual([]);
    const orgAny = await request(h.app).get(`/v1/identity/search?q=${encodeURIComponent("GB-400d")}&type=any`);
    expect(orgAny.body.results.map(r => r.tip_id)).toEqual([ORG]);

    const short = await request(h.app).get("/v1/identity/search?q=a");
    expect(short.status).toBe(400);
    expect(short.body.error.code).toBe("query_too_short");
    const tooMany = await request(h.app).get("/v1/identity/search?q=al&limit=50");
    expect(tooMany.status).toBe(400);

    h.dag.addRevocation(named, "REVOKE_VOLUNTARY", BASE_TS + 1, "rev-1");
    expect((await request(h.app).get("/v1/identity/search?q=alice")).body.results).toEqual([]);
  });
});

describe("GET /v1/identity/:tipId/members on a person", () => {
  test("answers 200 with the limit, the roles and empty lists instead of an error", async () => {
    const h = harness();
    const r = await request(h.app).get(`/v1/identity/${enc(ALICE)}/members`);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ org_tip_id: ALICE, limit: ORG_MEMBERS.FREE_MEMBER_LIMIT, members: [], pending_invites: [] });
    expect(Array.isArray(r.body.roles)).toBe(true);
    const missing = await request(h.app).get(`/v1/identity/${enc("tip://id/US-0000000000000000")}/members`);
    expect(missing.status).toBe(404);
  });
});
