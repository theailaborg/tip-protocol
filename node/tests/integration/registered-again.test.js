/**
 * @file tests/integration/registered-again.test.js
 * @description Registered again: when someone else registers the very same
 * content (same normalized content_hash) after you, you (the first author)
 * get an Inbox item, and both record pages say who came first.
 *
 *   1. Inbox: one item per record, high for a fresh exact copy of
 *      substantial content, normal for short text; the copier gets nothing.
 *   2. Never a copy: same TIP-ID, an org and its active members, a shared
 *      byline author, replies.
 *   3. Retraction takes effect at once; three copies make one item.
 *   4. The index: built from history, kept current by the commit handler,
 *      rebuilt after a reset.
 *   5. Record pages (registered_first / registered_again) and the
 *      before-signing lookup by content hash.
 *   6. The receiving node counts the text (text_chars); copies from before
 *      the activation instant never count.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const _envBefore = process.env.TIP_REGISTERED_AGAIN_ACTIVATION_MS;
process.env.TIP_REGISTERED_AGAIN_ACTIVATION_MS = "1";
afterAll(() => {
  if (_envBefore === undefined) delete process.env.TIP_REGISTERED_AGAIN_ACTIVATION_MS;
  else process.env.TIP_REGISTERED_AGAIN_ACTIVATION_MS = _envBefore;
});

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256, tipNormalize, computeTxId } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { TIP_ID_TYPES, ORG_MEMBER_STATUS, TX_TYPES, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createRegisteredAgain, resetRegisteredAgain } = require(path.join(SRC, "services", "registered-again"));
const { createDisputeService } = require(path.join(SRC, "services", "dispute-service"));
const contentSchema = require(path.join(SRC, "schemas", "content-register"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";
const ANA = "tip://id/US-aaaaaaaaaaaaaaaa";     // the first author
const BEN = "tip://id/US-bbbbbbbbbbbbbbbb";     // registers it again
const ORG = "tip://id/US-cccccccccccccccc";
const MEMBER = "tip://id/US-dddddddddddddddd";
const CARL = "tip://id/US-eeeeeeeeeeeeeeee";
const NAMES = { [ANA]: "Ana Author", [BEN]: "Ben Copy", [ORG]: "Acme News", [MEMBER]: "Mo Member", [CARL]: "Carl Third" };

const LONG = "The quiet harbour at dawn is the best part of my day, and this is the story of how I learned to love it.";

function seed(dag, tipId, kp, type = TIP_ID_TYPES.PERSONAL) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", tip_id_type: type, founding: false, status: "active",
    registered_at: 1767225600000, creator_name: NAMES[tipId],
    tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  dag.setScore(tipId, 750, 0, 1767225600000);
}

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
    mediaLimits: { max_text_bytes: 1_000_000, max_image_bytes: 0, max_video_bytes: 0, max_audio_bytes: 0 } };
  const keys = {};
  for (const [t, type] of [[ANA], [BEN], [ORG, TIP_ID_TYPES.ORGANIZATION], [MEMBER], [CARL]]) {
    keys[t] = generateMLDSAKeypair();
    seed(dag, t, keys[t], type);
  }
  const scoring = initScoring(dag, config);
  const submitted = [];
  const contentService = createContentService({ dag, scoring, config, submitTx: (tx) => { submitted.push(tx); } });
  const handler = createCommitHandler({ dag, scoring, config });
  let round = 100;
  const commit = (txs) => handler.commitOrderedTxs(txs, round++, { certTimestamp: nowMs() });
  const disputes = createDisputeService({ dag, scoring: initScoring(dag, {}), config: {}, submitTx: () => {}, submitBatch: () => {} });
  const inbox = (t) => disputes.getUserDashboard(t).items.filter(i => i.type === "content_registered_again");
  return { dag, contentService, submitted, commit, keys, inbox };
}

// A signed REGISTER_CONTENT tx for `text` by `signer`, as a node would build it.
function reg(fx, { signer, text = LONG, origin = "OH", ts = nowMs(), parentUrl, byline, title, chars }) {
  const hash = shake256(tipNormalize(text));
  const authors = [{ key_mode: "attribution", role: "byline", signed: false, tip_id: byline || signer,
    tip_id_type: fx.dag.getIdentity(byline || signer).tip_id_type }];
  const data = {
    ctid: `tip://c/${origin}-${hash.slice(0, 14)}-${signer.slice(-4)}`, origin_code: origin, content_hash: hash,
    signer_tip_id: signer, registered_urls: [], attribution_mode: byline ? "attributed" : "self",
    extras: title ? { title } : {}, authors, cna_version: contentSchema.CURRENT_CNA_VERSION,
    ...(parentUrl ? { parent_url: parentUrl } : {}),
  };
  data.signature = contentSchema.sign(contentSchema.buildSigningPayload(data, hash), fx.keys[signer].privateKey);
  data.text_chars = chars !== undefined ? chars : tipNormalize(text).length;
  const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: ts, prev: fx.dag.getRecentPrev(), data, signature: data.signature };
  tx.tx_id = computeTxId(tx);
  return tx;
}

function both(fx, opts = {}) {
  const a = reg(fx, { signer: ANA, ts: nowMs() - 5000, ...(opts.first || {}) });
  expect(fx.commit([a]).committed).toBe(1);
  const b = reg(fx, { signer: BEN, ...(opts.copy || {}) });
  expect(fx.commit([b]).committed).toBe(1);
  return { first: a.data.ctid, copy: b.data.ctid };
}

describe("the first author's Inbox", () => {
  test("a fresh exact copy by someone else is one high item; the copier gets nothing", () => {
    const fx = setup();
    const { first, copy } = both(fx);
    const items = fx.inbox(ANA);
    expect(items).toHaveLength(1);
    const it = items[0];
    expect(it).toMatchObject({
      id: `content_registered_again:${first}`, priority: "high", role: "author", ctid: first,
      title: "Your content was registered again by someone else",
      action: { kind: "compare_records", label: "Compare records",
        href: `/compare?first=${encodeURIComponent(first)}&copy=${encodeURIComponent(copy)}` },
    });
    expect(it.summary).toMatch(/^Ben Copy registered content that matches your record .+\. Your record came first and keeps its original date\.$/);
    expect(it.metadata).toMatchObject({ first_ctid: first, match_type: "exact", count: 1 });
    expect(it.metadata.copies[0]).toMatchObject({ ctid: copy, author_tip_id: BEN, author_name: "Ben Copy", origin_code: "OH" });
    expect(fx.inbox(BEN)).toEqual([]);
    expect(createDisputeService({ dag: fx.dag, scoring: initScoring(fx.dag, {}), config: {}, submitTx() {}, submitBatch() {} })
      .getUserDashboard(ANA).attention_count).toBeGreaterThanOrEqual(1);
  });

  test("short text never alerts: an exact copy of 'gm' or 'Thank you so much!' is a normal item", () => {
    const fx = setup();
    both(fx, { first: { text: "gm" }, copy: { text: "gm" } });
    expect(fx.inbox(ANA).map(i => i.priority)).toEqual(["normal"]);
    const fx2 = setup();
    both(fx2, { first: { text: "Thank you so much!" }, copy: { text: "Thank you so much!" } });
    expect(fx2.inbox(ANA).map(i => i.priority)).toEqual(["normal"]);
  });

  test("short text with a title or media still alerts; unknown length counts as substantial", () => {
    const fx = setup();
    both(fx, { first: { text: "gm", title: "Morning" }, copy: { text: "gm", title: "Morning" } });
    expect(fx.inbox(ANA)[0].priority).toBe("high");
    const fx2 = setup();
    both(fx2, { first: { text: "hello there", chars: null }, copy: { text: "hello there", chars: null } });
    expect(fx2.inbox(ANA)[0].priority).toBe("high");
  });
});

describe("never a copy", () => {
  test("the same TIP-ID registering the same content again", () => {
    const fx = setup();
    expect(fx.commit([reg(fx, { signer: ANA, ts: nowMs() - 5000 })]).committed).toBe(1);
    expect(fx.commit([reg(fx, { signer: ANA, origin: "AA" })]).committed).toBe(1);
    expect(fx.inbox(ANA)).toEqual([]);
  });

  test("an organization and its active team member, either way round", () => {
    const fx = setup();
    fx.dag.saveOrgMember({ invite_tx_id: "inv", org_tip_id: ORG, member_tip_id: MEMBER, role: "author", invited_at: 1767225600000, accepted_at: 1767225600001, status: ORG_MEMBER_STATUS.ACTIVE });
    expect(fx.commit([reg(fx, { signer: ORG, ts: nowMs() - 5000 })]).committed).toBe(1);
    expect(fx.commit([reg(fx, { signer: MEMBER })]).committed).toBe(1);
    expect(fx.inbox(ORG)).toEqual([]);
    expect(fx.inbox(MEMBER)).toEqual([]);
  });

  test("a record that shares a byline author with the first one", () => {
    const fx = setup();
    const { copy } = both(fx);
    // Byline sharing is a read-side rule; set it on the committed row.
    const row = fx.dag.getContent(copy);
    fx.dag.saveContent({ ...row, authors: [...row.authors, { key_mode: "attribution", role: "byline", signed: false, tip_id: ANA, tip_id_type: "personal" }] });
    expect(fx.inbox(ANA)).toEqual([]);
  });

  test("replies: identical replies under one post", () => {
    const fx = setup();
    const p = "https://x.com/someone/status/1";
    both(fx, { first: { parentUrl: p }, copy: { parentUrl: p } });
    expect(fx.inbox(ANA)).toEqual([]);
  });
});

describe("retraction and many copies", () => {
  test("a retracted copy drops the item at once; a retracted first makes no new first author", () => {
    const fx = setup();
    const { first, copy } = both(fx);
    expect(fx.inbox(ANA)).toHaveLength(1);
    fx.dag.updateContentStatus(copy, CONTENT_STATUS.RETRACTED);
    expect(fx.inbox(ANA)).toEqual([]);
    const fx2 = setup();
    const r2 = both(fx2);
    fx2.dag.updateContentStatus(r2.first, CONTENT_STATUS.RETRACTED);
    expect(fx2.inbox(ANA)).toEqual([]);
    expect(fx2.inbox(BEN)).toEqual([]);
    expect(first).not.toBe(r2.copy);
  });

  test("two later copies by two people make one item, newest first", () => {
    const fx = setup();
    expect(fx.commit([reg(fx, { signer: ANA, ts: nowMs() - 9000 })]).committed).toBe(1);
    expect(fx.commit([reg(fx, { signer: BEN, ts: nowMs() - 5000 })]).committed).toBe(1);
    const c = reg(fx, { signer: CARL });
    expect(fx.commit([c]).committed).toBe(1);
    const items = fx.inbox(ANA);
    expect(items).toHaveLength(1);
    expect(items[0].title).toBe("Your content was registered again by 2 others");
    expect(items[0].summary).toMatch(/^Carl Third and 1 other registered content/);
    expect(items[0].metadata.copies.map(x => x.author_tip_id)).toEqual([CARL, BEN]);
    expect(fx.inbox(BEN)).toEqual([]);   // only the first author hears
  });
});

describe("the index", () => {
  test("a copy committed after the index was built shows up (commit handler keeps it current)", () => {
    const fx = setup();
    expect(fx.commit([reg(fx, { signer: ANA, ts: nowMs() - 5000 })]).committed).toBe(1);
    expect(fx.inbox(ANA)).toEqual([]);   // builds the index
    expect(fx.commit([reg(fx, { signer: BEN })]).committed).toBe(1);
    expect(fx.inbox(ANA)).toHaveLength(1);
  });

  test("after a reset the index is rebuilt from history", () => {
    const fx = setup();
    both(fx);
    resetRegisteredAgain(fx.dag);
    const again = createRegisteredAgain({ dag: fx.dag }).againFor(ANA, nowMs());
    expect(again).toHaveLength(1);
    expect(again[0].copies.map(c => c.author_tip_id)).toEqual([BEN]);
  });
});

describe("record pages and the before-signing lookup", () => {
  test("the first record lists later copies; the copy names the earlier record", async () => {
    const fx = setup();
    const { first, copy } = both(fx);
    const a = await fx.contentService.resolve(first);
    expect(a.registered_again).toEqual([expect.objectContaining({ ctid: copy, author_tip_id: BEN, author_name: "Ben Copy" })]);
    expect("registered_first" in a).toBe(false);
    const b = await fx.contentService.resolve(copy);
    expect(b.registered_first).toEqual(expect.objectContaining({ ctid: first, author_tip_id: ANA, author_name: "Ana Author" }));
    expect("registered_again" in b).toBe(false);
  });

  test("a record with no match carries neither key", async () => {
    const fx = setup();
    const t = reg(fx, { signer: ANA });
    fx.commit([t]);
    const r = await fx.contentService.resolve(t.data.ctid);
    expect("registered_again" in r || "registered_first" in r).toBe(false);
  });

  test("matchesByHash: live records oldest first, replies left out, bad hash refused", () => {
    const fx = setup();
    const { first, copy } = both(fx);
    const hash = shake256(tipNormalize(LONG));
    const m = fx.contentService.matchesByHash(hash);
    expect(m.total).toBe(2);
    expect(m.matches.map(x => x.ctid)).toEqual([first, copy]);
    expect(m.matches[0]).toMatchObject({ author_tip_id: ANA, author_name: "Ana Author", origin_code: "OH" });
    expect(fx.contentService.matchesByHash("0".repeat(64))).toEqual({ content_hash: "0".repeat(64), total: 0, matches: [] });
    let err = null;
    try { fx.contentService.matchesByHash("nope"); } catch (e) { err = e; }
    expect(err).toMatchObject({ status: 400, code: "invalid_hash" });
  });
});

describe("text length and activation", () => {
  test("the receiving node counts the normalized text on the tx (not signed)", async () => {
    const fx = setup();
    const fields = {
      origin_code: "OH", registered_urls: [], extras: {}, signer_tip_id: ANA, attribution_mode: "self",
      authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: ANA, tip_id_type: "personal" }],
    };
    const payload = contentSchema.buildSigningPayload(fields, shake256(tipNormalize(LONG)));
    await fx.contentService.register({ ...fields, cna_version: contentSchema.CURRENT_CNA_VERSION, content: LONG,
      content_type: "text", signature: contentSchema.sign(payload, fx.keys[ANA].privateKey) });
    const tx = fx.submitted.find(t => t.tx_type === TX_TYPES.REGISTER_CONTENT);
    expect(tx.data.text_chars).toBe(tipNormalize(LONG).length);
  });

  test("copies registered before the activation instant never count", () => {
    const fx = setup();
    both(fx);
    jest.isolateModules(() => {
      process.env.TIP_REGISTERED_AGAIN_ACTIVATION_MS = String(nowMs() + 86_400_000);
      const { createRegisteredAgain: later } = require(path.join(SRC, "services", "registered-again"));
      expect(later({ dag: fx.dag }).againFor(ANA, nowMs())).toEqual([]);
      process.env.TIP_REGISTERED_AGAIN_ACTIVATION_MS = "1";
    });
  });
});
