/**
 * @file tests/services/content-byline.test.js
 * @description Read model for org posts with member bylines: publisher and
 * authors_resolved on the content detail, the bylined list filter, and
 * bylined_count on the identity. Content is committed through the real
 * commit handler so the rows look exactly like production rows.
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
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createIdentityService } = require(path.join(SRC, "services", "identity-service"));
const contentSchema = require(path.join(SRC, "schemas", "content-register"));
const invitedSchema = require(path.join(SRC, "schemas", "org-member-invited"));
const addedSchema = require(path.join(SRC, "schemas", "org-member-added"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/test-byline";
const ORG = "tip://id/GB-400d3636845c06f2";
const ALICE = "tip://id/IND-1aeb5ec0aa16cb20";
const BOB = "tip://id/US-ed1c6dbddac62443";
const BASE_TS = 1767225600000;
let round = 0;
let ts = nowMs() - 120_000;
const next = () => (ts += 1000);
let seq = 0;

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const keys = {};
  for (const id of [ORG, ALICE, BOB]) keys[id] = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey, status: "active", registered_at: BASE_TS });
  const saveId = (tipId, type, name) => dag.saveIdentity({
    tip_id: tipId, region: tipId.slice(9, 11), public_key: keys[tipId].publicKey, root_public_key: "00",
    vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active",
    tip_id_type: type, creator_name: name, registered_at: BASE_TS,
    tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  saveId(ORG, "organization", "The AI Lab"); saveId(ALICE, "personal", "Alice Example"); saveId(BOB, "personal", "Bob Example");
  for (const id of Object.keys(keys)) dag.setScore(id, 500, 0, BASE_TS);
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, orgMembersActivationMs: 0, mediaLimits: {} };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });
  const submitTx = () => ({});
  const contentService = createContentService({ dag, scoring, config, submitTx, submitBatch: submitTx, consensus: { current: null }, mediaService: null });
  const identityService = createIdentityService({ dag, scoring, config, submitTx, consensus: { current: null } });
  return { dag, keys, handler, contentService, identityService };
}

function txOf(ctx, txType, data, signature, at) {
  const tx = { tx_type: txType, timestamp: at, signature, prev: [], data };
  tx.prev = ctx.dag.prevFor(tx.tx_type, tx.data);
  tx.tx_id = computeTxId(tx);
  return tx;
}
function commit(ctx, tx) { return ctx.handler.commitOrderedTxs([tx], ++round); }

function joined(ctx, org, member) {
  const inv = { org_tip_id: org, member_tip_id: member, role: "author", invited_at: next() };
  const invTx = txOf(ctx, TX_TYPES.ORG_MEMBER_INVITED, inv, invitedSchema.sign(invitedSchema.buildSigningPayload(inv), ctx.keys[org].privateKey), ts);
  expect(commit(ctx, invTx)).toMatchObject({ committed: 1 });
  const acc = { org_tip_id: org, member_tip_id: member, invite_tx_id: invTx.tx_id, accepted_at: next() };
  const accTx = txOf(ctx, TX_TYPES.ORG_MEMBER_ADDED, acc, addedSchema.sign(addedSchema.buildSigningPayload(acc), ctx.keys[member].privateKey), ts);
  expect(commit(ctx, accTx)).toMatchObject({ committed: 1 });
}

function post(ctx, signer, authors, mode) {
  const text = `byline ${++seq}`;
  const hash = shake256(tipNormalize(text));
  const data = {
    signer_tip_id: signer, origin_code: "OH", content_hash: hash,
    ctid: `tip://c/OH-${hash.slice(0, 14)}-${hash.slice(14, 18)}`,
    attribution_mode: mode, extras: {}, registered_urls: [], cna_version: contentSchema.CURRENT_CNA_VERSION,
    authors: authors.map(a => ({ key_mode: "attribution", role: a === signer ? "byline" : "author", signed: false, tip_id: a, tip_id_type: a === ORG ? "organization" : "personal" })),
  };
  data.signature = contentSchema.sign(contentSchema.buildSigningPayload(data, hash), ctx.keys[signer].privateKey);
  const tx = txOf(ctx, TX_TYPES.REGISTER_CONTENT, data, data.signature, next());
  expect(commit(ctx, tx)).toMatchObject({ committed: 1, dropped: 0 });
  return data.ctid;
}

describe("org posts with a member byline: read model", () => {
  test("content detail carries publisher and authors_resolved with relationships", async () => {
    const ctx = setup();
    joined(ctx, ORG, ALICE);
    const orgPost = post(ctx, ORG, [ORG, ALICE], "employed");
    const d = await ctx.contentService.resolve(orgPost);
    expect(d.author_tip_id).toBe(ORG);
    expect(d.publisher).toEqual({ tip_id: ORG, name: "The AI Lab", tip_id_type: "organization" });
    expect(d.authors_resolved).toEqual([
      expect.objectContaining({ tip_id: ORG, name: "The AI Lab", tip_id_type: "organization", relationship: "signer", revoked: false }),
      expect.objectContaining({ tip_id: ALICE, name: "Alice Example", tip_id_type: "personal", relationship: "member", role: "author", member_role: "author", revoked: false }),
    ]);
    expect(typeof d.authors_resolved[1].tier).toBe("string");

    const soloPost = post(ctx, ALICE, [ALICE, BOB], "self");
    const s = await ctx.contentService.resolve(soloPost);
    expect(s.publisher.tip_id).toBe(ALICE);
    expect(s.authors_resolved.map(a => a.relationship)).toEqual(["signer", "listed"]);
    expect(s.authors_resolved.map(a => a.member_role)).toEqual([null, null]);
    expect(d.authors_resolved[0].member_role).toBeNull();
  });

  test("list?bylined= returns org posts crediting the person, never their own; list rows carry the publisher", () => {
    const ctx = setup();
    joined(ctx, ORG, ALICE);
    const orgPost = post(ctx, ORG, [ORG, ALICE], "employed");
    const own = post(ctx, ALICE, [ALICE], "self");
    post(ctx, ORG, [ORG], "self");

    const bylined = ctx.contentService.list({ bylined: ALICE });
    expect(bylined.items.map(i => i.ctid)).toEqual([orgPost]);
    expect(bylined.items[0]).toMatchObject({ author_tip_id: ORG, signer_tip_id: ORG, attribution_mode: "employed", publisher_name: "The AI Lab" });

    const mine = ctx.contentService.list({ author: ALICE });
    expect(mine.items.map(i => i.ctid)).toEqual([own]);
    expect(mine.items[0]).toMatchObject({ attribution_mode: "self", publisher_name: null });

    expect(ctx.contentService.list({ bylined: ORG }).items).toEqual([]);
    expect(() => ctx.contentService.list({ author: ALICE, bylined: ALICE })).toThrow(expect.objectContaining({ code: "bylined_invalid" }));
    expect(() => ctx.contentService.list({ bylined: "not-an-id" })).toThrow(expect.objectContaining({ code: "bylined_invalid" }));
  });

  test("identity resolve reports bylined_count next to content_count", () => {
    const ctx = setup();
    joined(ctx, ORG, ALICE);
    post(ctx, ORG, [ORG, ALICE], "employed");
    post(ctx, ORG, [ORG, ALICE], "employed");
    post(ctx, ALICE, [ALICE], "self");
    const alice = ctx.identityService.resolve(ALICE);
    expect(alice).toMatchObject({ content_count: 1, bylined_count: 2, member_of: [ORG] });
    const org = ctx.identityService.resolve(ORG);
    expect(org).toMatchObject({ content_count: 2, bylined_count: 0 });
  });
});
