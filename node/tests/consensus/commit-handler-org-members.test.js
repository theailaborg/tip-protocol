/**
 * @file tests/consensus/commit-handler-org-members.test.js
 * @description The org roster through the REAL commit handler: signed
 * ORG_MEMBER_INVITED / ADDED / REMOVED txs committed via commitOrderedTxs,
 * the org_members rows they leave behind, the seat limit at acceptance,
 * the activation gate, in-batch dedup and the state root moving with
 * every row change.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, computeTxId } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, ORG_MEMBERS, ORG_MEMBER_STATUS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { computeStateMerkleRoot } = require(path.join(SRC, "consensus", "state-root"));
const contentRegisterSchema = require(path.join(SRC, "schemas", "content-register"));
const { shake256 } = require(path.join(SHARED, "crypto"));
const invitedSchema = require(path.join(SRC, "schemas", "org-member-invited"));
const addedSchema = require(path.join(SRC, "schemas", "org-member-added"));
const removedSchema = require(path.join(SRC, "schemas", "org-member-removed"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/test-org-members";
const ORG = "tip://id/GB-400d3636845c06f2";
const ALICE = "tip://id/IN-cbcd2ea94f1f1d49";
const BOB = "tip://id/US-ed1c6dbddac62443";
const BASE_TS = 1767225600000;

function _setup({ activationMs = 0 } = {}) {
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
  saveId(ORG, "organization");
  saveId(ALICE, "personal");
  saveId(BOB, "personal");
  for (const id of [ORG, ALICE, BOB]) dag.setScore(id, 500, 0, BASE_TS);

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, orgMembersActivationMs: activationMs };
  const handler = createCommitHandler({ dag, scoring: initScoring(dag, config), config });
  return { dag, keys, handler };
}

// SUBJECT-signed body: the signer's key signs the schema payload and the
// signature rides on the envelope, exactly as the API relays it.
function _tx(dag, schema, txType, data, signerKey, ts) {
  const body = {
    tx_type: txType, timestamp: ts,
    signature: schema.sign(schema.buildSigningPayload(data), signerKey.privateKey),
    prev: [], data,
  };
  body.prev = dag.prevFor(body.tx_type, body.data);
  body.tx_id = computeTxId(body);
  return body;
}

function inviteTx(ctx, member, ts, role = "author") {
  return _tx(ctx.dag, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED,
    { org_tip_id: ORG, member_tip_id: member, role, invited_at: ts }, ctx.keys[ORG], ts);
}
function acceptTx(ctx, member, inviteTxId, ts) {
  return _tx(ctx.dag, addedSchema, TX_TYPES.ORG_MEMBER_ADDED,
    { org_tip_id: ORG, member_tip_id: member, invite_tx_id: inviteTxId, accepted_at: ts }, ctx.keys[member], ts);
}
function removeTx(ctx, member, addTxId, signer, ts) {
  return _tx(ctx.dag, removedSchema, TX_TYPES.ORG_MEMBER_REMOVED,
    { org_tip_id: ORG, member_tip_id: member, add_tx_id: addTxId, claimed_at: ts, signer_tip_id: signer }, ctx.keys[signer], ts);
}

let round = 0;
function commit(ctx, txs) { return ctx.handler.commitOrderedTxs(txs, ++round); }

// REGISTER_CONTENT signed by `signer`, attributing the post to `authors`.
let seq = 0;
function contentTx(ctx, signer, authors, ts, mode = "employed") {
  const hash = shake256(`post-${++seq}`);
  const data = {
    signer_tip_id: signer, origin_code: "OH", content_hash: hash,
    ctid: `tip://c/OH-${hash.slice(0, 14)}-${hash.slice(14, 18)}`,
    attribution_mode: mode, extras: {}, registered_urls: [],
    cna_version: contentRegisterSchema.CURRENT_CNA_VERSION,
    authors: authors.map(a => ({
      key_mode: "attribution", role: "byline", signed: false, tip_id: a,
      tip_id_type: a === ORG ? "organization" : "personal",
    })),
  };
  data.signature = contentRegisterSchema.sign(contentRegisterSchema.buildSigningPayload(data, hash), ctx.keys[signer].privateKey);
  const body = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: ts, signature: data.signature, prev: [], data };
  body.prev = ctx.dag.prevFor(body.tx_type, body.data);
  body.tx_id = computeTxId(body);
  return body;
}

describe("org-signed content is attributed only to the org itself or its active members", () => {
  test("non-member author is dropped; after invite + accept it commits; after removal it is dropped again", () => {
    const ctx = _setup();
    expect(commit(ctx, [contentTx(ctx, ORG, [ALICE], BASE_TS + 100)])).toMatchObject({ committed: 0, dropped: 1 });
    // Institutional speech: the org is its own author.
    expect(commit(ctx, [contentTx(ctx, ORG, [ORG], BASE_TS + 200, "self")])).toMatchObject({ committed: 1 });

    const inv = inviteTx(ctx, ALICE, BASE_TS + 1000);
    commit(ctx, [inv]);
    const acc = acceptTx(ctx, ALICE, inv.tx_id, BASE_TS + 2000);
    commit(ctx, [acc]);
    expect(commit(ctx, [contentTx(ctx, ORG, [ALICE], BASE_TS + 2100)])).toMatchObject({ committed: 1 });
    expect(commit(ctx, [contentTx(ctx, ORG, [ORG, ALICE], BASE_TS + 2200)])).toMatchObject({ committed: 1 });
    // Bob never joined.
    expect(commit(ctx, [contentTx(ctx, ORG, [ALICE, BOB], BASE_TS + 2300)])).toMatchObject({ committed: 0, dropped: 1 });

    commit(ctx, [removeTx(ctx, ALICE, acc.tx_id, ORG, BASE_TS + 3000)]);
    expect(commit(ctx, [contentTx(ctx, ORG, [ALICE], BASE_TS + 3100)])).toMatchObject({ committed: 0, dropped: 1 });
    // Already-committed content is untouched by the removal (author_tip_id is authors[0]).
    expect(ctx.dag.getContentByAuthor(ALICE)).toHaveLength(1);
    expect(ctx.dag.getContentByAuthor(ORG)).toHaveLength(2);
  });

  test("personal signers are not gated by the roster; the author count cap applies to everyone", () => {
    const ctx = _setup();
    expect(commit(ctx, [contentTx(ctx, ALICE, [ALICE], BASE_TS + 100, "self")])).toMatchObject({ committed: 1 });
    expect(commit(ctx, [contentTx(ctx, ALICE, [ALICE, BOB], BASE_TS + 200)])).toMatchObject({ committed: 1 });
    const eleven = Array.from({ length: 11 }, () => ALICE);
    expect(commit(ctx, [contentTx(ctx, ALICE, eleven, BASE_TS + 300)])).toMatchObject({ committed: 0, dropped: 1 });
    const ten = Array.from({ length: 10 }, () => ALICE);
    expect(commit(ctx, [contentTx(ctx, ALICE, ten, BASE_TS + 400)])).toMatchObject({ committed: 1 });
  });

  test("before the activation epoch the old rules apply: an org may list anyone", () => {
    const ctx = _setup({ activationMs: BASE_TS + 5000 });
    expect(commit(ctx, [contentTx(ctx, ORG, [ALICE], BASE_TS + 100)])).toMatchObject({ committed: 1 });
    expect(commit(ctx, [contentTx(ctx, ORG, [ALICE], BASE_TS + 5000)])).toMatchObject({ committed: 0, dropped: 1 });
  });
});

describe("org roster lifecycle through the commit handler", () => {
  test("invite -> accept -> remove writes one row through invited, active, removed; each step moves the state root", () => {
    const ctx = _setup();
    const { dag } = ctx;
    const root0 = computeStateMerkleRoot(dag);

    const inv = inviteTx(ctx, ALICE, BASE_TS + 1000);
    expect(commit(ctx, [inv])).toMatchObject({ committed: 1, dropped: 0 });
    const row1 = dag.getOrgMember(inv.tx_id);
    expect(row1).toMatchObject({ org_tip_id: ORG, member_tip_id: ALICE, role: "author", status: ORG_MEMBER_STATUS.INVITED });
    expect(Number(row1.invited_at)).toBe(BASE_TS + 1000);
    const root1 = computeStateMerkleRoot(dag);
    expect(root1).not.toBe(root0);

    const acc = acceptTx(ctx, ALICE, inv.tx_id, BASE_TS + 2000);
    expect(commit(ctx, [acc])).toMatchObject({ committed: 1, dropped: 0 });
    const row2 = dag.getOrgMember(inv.tx_id);
    expect(row2).toMatchObject({ status: ORG_MEMBER_STATUS.ACTIVE, add_tx_id: acc.tx_id });
    expect(Number(row2.accepted_at)).toBe(BASE_TS + 2000);
    expect(dag.getOrgMemberByAddTxId(acc.tx_id).invite_tx_id).toBe(inv.tx_id);
    const root2 = computeStateMerkleRoot(dag);
    expect(root2).not.toBe(root1);

    const rem = removeTx(ctx, ALICE, acc.tx_id, ALICE, BASE_TS + 3000);
    expect(commit(ctx, [rem])).toMatchObject({ committed: 1, dropped: 0 });
    const row3 = dag.getOrgMember(inv.tx_id);
    expect(row3).toMatchObject({ status: ORG_MEMBER_STATUS.REMOVED, remove_tx_id: rem.tx_id, removed_by: ALICE });
    expect(Number(row3.removed_at)).toBe(BASE_TS + 3000);
    expect(computeStateMerkleRoot(dag)).not.toBe(root2);

    // The seat is free again: a fresh invite + accept makes a second row.
    const inv2 = inviteTx(ctx, ALICE, BASE_TS + 4000, "editor");
    expect(commit(ctx, [inv2])).toMatchObject({ committed: 1 });
    const acc2 = acceptTx(ctx, ALICE, inv2.tx_id, BASE_TS + 5000);
    expect(commit(ctx, [acc2])).toMatchObject({ committed: 1 });
    expect(dag.getOrgMembersByOrg(ORG)).toHaveLength(2);
    expect(dag.getOrgMembersByOrg(ORG).filter(r => r.status === ORG_MEMBER_STATUS.ACTIVE).map(r => r.role)).toEqual(["editor"]);
  });

  test("seat limit: the second person's acceptance is dropped once the only seat is taken, and commits after a removal", () => {
    const ctx = _setup();
    expect(ORG_MEMBERS.FREE_MEMBER_LIMIT).toBe(1);

    const invA = inviteTx(ctx, ALICE, BASE_TS + 1000);
    const invB = inviteTx(ctx, BOB, BASE_TS + 1001);
    expect(commit(ctx, [invA, invB])).toMatchObject({ committed: 2, dropped: 0 });

    const accA = acceptTx(ctx, ALICE, invA.tx_id, BASE_TS + 2000);
    expect(commit(ctx, [accA])).toMatchObject({ committed: 1 });

    const accB = acceptTx(ctx, BOB, invB.tx_id, BASE_TS + 3000);
    expect(commit(ctx, [accB])).toMatchObject({ committed: 0, dropped: 1 });
    expect(ctx.dag.getOrgMember(invB.tx_id).status).toBe(ORG_MEMBER_STATUS.INVITED);

    // Org removes Alice; Bob's still-fresh invite now goes through.
    const rem = removeTx(ctx, ALICE, accA.tx_id, ORG, BASE_TS + 4000);
    expect(commit(ctx, [rem])).toMatchObject({ committed: 1 });
    const accB2 = acceptTx(ctx, BOB, invB.tx_id, BASE_TS + 5000);
    expect(commit(ctx, [accB2])).toMatchObject({ committed: 1 });
    expect(ctx.dag.getOrgMember(invB.tx_id).status).toBe(ORG_MEMBER_STATUS.ACTIVE);
  });

  test("two acceptances for one org in the same batch: only the first takes the seat", () => {
    const ctx = _setup();
    const invA = inviteTx(ctx, ALICE, BASE_TS + 1000);
    const invB = inviteTx(ctx, BOB, BASE_TS + 1001);
    commit(ctx, [invA, invB]);
    const accA = acceptTx(ctx, ALICE, invA.tx_id, BASE_TS + 2000);
    const accB = acceptTx(ctx, BOB, invB.tx_id, BASE_TS + 2001);
    expect(commit(ctx, [accA, accB])).toMatchObject({ committed: 1, dropped: 1 });
    const active = ctx.dag.getOrgMembersByOrg(ORG).filter(r => r.status === ORG_MEMBER_STATUS.ACTIVE);
    expect(active).toHaveLength(1);
  });

  test("duplicate invites for one pair in a batch and an invite while one is open are dropped", () => {
    const ctx = _setup();
    const inv1 = inviteTx(ctx, ALICE, BASE_TS + 1000);
    const inv2 = inviteTx(ctx, ALICE, BASE_TS + 1001);
    expect(commit(ctx, [inv1, inv2])).toMatchObject({ committed: 1, dropped: 1 });
    const inv3 = inviteTx(ctx, ALICE, BASE_TS + 2000);
    expect(commit(ctx, [inv3])).toMatchObject({ committed: 0, dropped: 1 });
  });

  test("an expired invite cannot be accepted", () => {
    const ctx = _setup();
    const inv = inviteTx(ctx, ALICE, BASE_TS + 1000);
    commit(ctx, [inv]);
    const late = acceptTx(ctx, ALICE, inv.tx_id, BASE_TS + 1000 + ORG_MEMBERS.INVITE_TTL_MS + 1);
    expect(commit(ctx, [late])).toMatchObject({ committed: 0, dropped: 1 });
  });

  test("removal: a third party is rejected, a stale add_tx_id is rejected, the org can remove", () => {
    const ctx = _setup();
    const inv = inviteTx(ctx, ALICE, BASE_TS + 1000);
    commit(ctx, [inv]);
    const acc = acceptTx(ctx, ALICE, inv.tx_id, BASE_TS + 2000);
    commit(ctx, [acc]);

    const byBob = removeTx(ctx, ALICE, acc.tx_id, BOB, BASE_TS + 3000);
    expect(commit(ctx, [byBob])).toMatchObject({ committed: 0, dropped: 1 });
    const wrongInstance = removeTx(ctx, ALICE, inv.tx_id, ORG, BASE_TS + 3001);
    expect(commit(ctx, [wrongInstance])).toMatchObject({ committed: 0, dropped: 1 });
    const byOrg = removeTx(ctx, ALICE, acc.tx_id, ORG, BASE_TS + 3002);
    expect(commit(ctx, [byOrg])).toMatchObject({ committed: 1 });
    expect(ctx.dag.getOrgMember(inv.tx_id)).toMatchObject({ status: ORG_MEMBER_STATUS.REMOVED, removed_by: ORG });
    // Removing twice replays against a closed instance.
    const again = removeTx(ctx, ALICE, acc.tx_id, ORG, BASE_TS + 3003);
    expect(commit(ctx, [again])).toMatchObject({ committed: 0, dropped: 1 });
  });

  test("a signature by the wrong key never commits", () => {
    const ctx = _setup();
    const forged = _tx(ctx.dag, invitedSchema, TX_TYPES.ORG_MEMBER_INVITED,
      { org_tip_id: ORG, member_tip_id: ALICE, role: "author", invited_at: BASE_TS + 1000 }, ctx.keys[ALICE], BASE_TS + 1000);
    expect(commit(ctx, [forged])).toMatchObject({ committed: 0, dropped: 1 });
  });

  test("before the activation epoch every roster tx is dropped; from it on they commit", () => {
    const gate = BASE_TS + 5000;
    const ctx = _setup({ activationMs: gate });
    const early = inviteTx(ctx, ALICE, gate - 1);
    expect(commit(ctx, [early])).toMatchObject({ committed: 0, dropped: 1 });
    expect(ctx.dag.getOrgMember(early.tx_id)).toBeNull();
    const onTime = inviteTx(ctx, ALICE, gate);
    expect(commit(ctx, [onTime])).toMatchObject({ committed: 1 });
  });
});
