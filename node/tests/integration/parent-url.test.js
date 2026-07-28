/**
 * @file tests/integration/parent-url.test.js
 * @description Optional `parent_url` on REGISTER_CONTENT: where a response-type
 * content lives (a comment's parent post, a reply's parent comment). Registers
 * comments on platforms with no per-comment permalink without letting the
 * comment claim the parent's URL.
 *
 * Coverage:
 *   1. Round-trip: signed, mirrored onto tx.data, persisted by the real
 *      commit-handler replay path, returned by resolve()
 *   2. Strip rule: absent parent_url signs byte-identical to a pre-field payload
 *   3. NOT exclusivity-checked: two authors share one parent_url
 *   4. Empty registered_urls + parent_url (the Instagram / TikTok case)
 *   5. Canonical-form rejection at API time (non-canonical, #fragment)
 *   6. GET /v1/content?parent_url= gating: status, tier, one-per-author
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256, tipNormalize, canonicalJson,
} = require(path.join(SHARED, "crypto"));
const { CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const schema = require(path.join(SRC, "schemas", "content-register"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";
const PARENT = "https://instagram.com/p/abc123/";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
    mediaLimits: { max_text_bytes: 1_000_000, max_image_bytes: 0, max_video_bytes: 0, max_audio_bytes: 0 },
  };
  const scoring = initScoring(dag, config);
  // Record only: commitOrderedTxs skips a tx already in the DAG, so the
  // harness must leave the write to the commit-handler.
  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  const contentService = createContentService({ dag, scoring, config, submitTx });
  const handler = createCommitHandler({ dag, scoring, config });
  return { dag, scoring, contentService, handler, submitted };
}

function _seedIdentity(dag, tipId, kp, score = 750) {
  dag.saveIdentity({
    tip_id: tipId, region: "US",
    public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  dag.setScore(tipId, score, 0, 1767225600000);
}

function _newAuthor(dag, label, score = 750) {
  const kp = generateMLDSAKeypair();
  const tipId = `tip://id/US-${shake256(label).slice(0, 16)}`;
  _seedIdentity(dag, tipId, kp, score);
  return { kp, tipId };
}

function _buildRegisterBody({ tipId, privKey, content, registered_urls = ["https://example.com/post/"], parent_url = null }) {
  const contentHashFull = shake256(tipNormalize(content));
  const fields = {
    origin_code: "OH",
    registered_urls,
    extras: {},
    authors: [{ key_mode: "attribution", role: "byline", signed: false,
                 tip_id: tipId, tip_id_type: "personal" }],
    signer_tip_id: tipId,
    attribution_mode: "self",
  };
  if (parent_url) fields.parent_url = parent_url;
  const payload = schema.buildSigningPayload(fields, contentHashFull);
  const signature = schema.sign(payload, privKey);
  return {
    ...fields,
    cna_version: schema.CURRENT_CNA_VERSION,
    content,
    content_type: "text",
    signature,
  };
}

// Register through the API service, then commit the resulting tx through the
// REAL commit-handler so the content row is written by the replay path every
// node runs, not by a test-local stand-in.
let _round = 100;
async function _registerAndCommit(fx, author, opts) {
  const before = fx.submitted.length;
  const out = await fx.contentService.register(_buildRegisterBody({
    tipId: author.tipId, privKey: author.kp.privateKey, ...opts,
  }));
  const tx = fx.submitted.slice(before).find(t => t.tx_type === "REGISTER_CONTENT");
  fx.handler.commitOrderedTxs([tx], _round++);
  return { out, tx };
}

// ─── 1. Round-trip through sign -> tx.data -> commit replay -> resolve ─────

describe("parent_url: round-trip", () => {
  test("signed, mirrored onto tx.data, persisted by commit replay, returned by resolve", async () => {
    const fx = _setup();
    const author = _newAuthor(fx.dag, "pu-roundtrip");

    const { out, tx } = await _registerAndCommit(fx, author, {
      content: "a comment under a post", parent_url: PARENT,
    });
    expect(out.parent_url).toBe(PARENT);
    expect(tx.data.parent_url).toBe(PARENT);

    // Commit-handler wrote the row: the consensus-replay path stores it too,
    // so a node that only replays agrees with the node that received the API call.
    expect(fx.dag.getContent(tx.data.ctid).parent_url).toBe(PARENT);

    const detail = await fx.contentService.resolve(tx.data.ctid);
    expect(detail.parent_url).toBe(PARENT);
  });

  test("without parent_url the row is null and tx.data omits the field", async () => {
    const fx = _setup();
    const author = _newAuthor(fx.dag, "pu-absent");

    const { out, tx } = await _registerAndCommit(fx, author, { content: "a plain post" });
    expect(out.parent_url).toBeNull();
    expect(tx.data.parent_url).toBeUndefined();
    expect(fx.dag.getContent(tx.data.ctid).parent_url).toBeNull();
    expect((await fx.contentService.resolve(tx.data.ctid)).parent_url).toBeNull();
  });
});

// ─── 2. Strip rule ─────────────────────────────────────────────────────────

describe("parent_url: strip rule", () => {
  const base = {
    signer_tip_id: "tip://id/US-strip",
    origin_code: "OH",
    attribution_mode: "self",
    extras: {},
    registered_urls: ["https://example.com/post/"],
    authors: [{ key_mode: "attribution", role: "byline", signed: false,
                tip_id: "tip://id/US-strip", tip_id_type: "personal" }],
  };
  const hash = "a".repeat(64);

  test("absent parent_url signs byte-identical to a payload built without the field", () => {
    const withNull = canonicalJson(schema.buildSigningPayload({ ...base, parent_url: null }, hash));
    const withUndef = canonicalJson(schema.buildSigningPayload({ ...base, parent_url: undefined }, hash));
    const without = canonicalJson(schema.buildSigningPayload(base, hash));
    expect(withNull).toBe(without);
    expect(withUndef).toBe(without);
    expect(without.includes("parent_url")).toBe(false);
  });

  test("present parent_url is bound into the signed bytes", () => {
    const withParent = canonicalJson(schema.buildSigningPayload({ ...base, parent_url: PARENT }, hash));
    expect(withParent.includes(`"parent_url":"${PARENT}"`)).toBe(true);
  });

  test("a signature made without parent_url does not verify once one is attached", async () => {
    const fx = _setup();
    const author = _newAuthor(fx.dag, "pu-tamper");
    const body = _buildRegisterBody({
      tipId: author.tipId, privKey: author.kp.privateKey, content: "tamper parent",
    });
    body.parent_url = PARENT;
    await expect(fx.contentService.register(body))
      .rejects.toMatchObject({ status: 403, code: "signature_invalid" });
  });
});

// ─── 3. NOT exclusivity-checked ────────────────────────────────────────────

describe("parent_url: many contents may share one parent (no exclusivity)", () => {
  test("two different authors register against the SAME parent_url", async () => {
    const fx = _setup();
    const a = _newAuthor(fx.dag, "pu-share-a");
    const b = _newAuthor(fx.dag, "pu-share-b");

    const first = await _registerAndCommit(fx, a, {
      content: "first commenter", registered_urls: [], parent_url: PARENT,
    });
    const second = await _registerAndCommit(fx, b, {
      content: "second commenter", registered_urls: [], parent_url: PARENT,
    });

    expect(first.out.confirmation).toBe("proposed");
    expect(second.out.confirmation).toBe("proposed");
    expect(first.tx.data.ctid).not.toBe(second.tx.data.ctid);
    expect(fx.dag.getContent(first.tx.data.ctid).parent_url).toBe(PARENT);
    expect(fx.dag.getContent(second.tx.data.ctid).parent_url).toBe(PARENT);
  });

  test("the same author may point several contents at one parent", async () => {
    const fx = _setup();
    const a = _newAuthor(fx.dag, "pu-share-self");
    const one = await _registerAndCommit(fx, a, { content: "reply one", registered_urls: [], parent_url: PARENT });
    const two = await _registerAndCommit(fx, a, { content: "reply two", registered_urls: [], parent_url: PARENT });
    expect(fx.dag.getContent(one.tx.data.ctid).parent_url).toBe(PARENT);
    expect(fx.dag.getContent(two.tx.data.ctid).parent_url).toBe(PARENT);
  });

  test("a registered_urls collision still rejects, proving only that field is exclusive", async () => {
    const fx = _setup();
    const a = _newAuthor(fx.dag, "pu-excl-a");
    const b = _newAuthor(fx.dag, "pu-excl-b");
    const url = "https://example.com/claimed/";
    await _registerAndCommit(fx, a, { content: "claims the url", registered_urls: [url] });
    await expect(fx.contentService.register(_buildRegisterBody({
      tipId: b.tipId, privKey: b.kp.privateKey, content: "wants the same url", registered_urls: [url],
    }))).rejects.toMatchObject({ status: 409, code: "url_already_registered" });
  });
});

// ─── 4. The no-permalink case ──────────────────────────────────────────────

describe("parent_url: content with no published URL of its own", () => {
  test("empty registered_urls + parent_url registers fine", async () => {
    const fx = _setup();
    const author = _newAuthor(fx.dag, "pu-no-permalink");
    const { tx } = await _registerAndCommit(fx, author, {
      content: "an instagram comment", registered_urls: [], parent_url: PARENT,
    });
    const rec = fx.dag.getContent(tx.data.ctid);
    expect(rec.registered_urls).toEqual([]);
    expect(rec.parent_url).toBe(PARENT);
  });
});

// ─── 5. Canonical-form validation (API time only) ──────────────────────────

describe("parent_url: canonical-form rejection", () => {
  async function _expectReject(badUrl) {
    const fx = _setup();
    const author = _newAuthor(fx.dag, `pu-bad-${shake256(badUrl).slice(0, 8)}`);
    const body = _buildRegisterBody({
      tipId: author.tipId, privKey: author.kp.privateKey, content: "bad parent", parent_url: PARENT,
    });
    body.parent_url = badUrl;
    await expect(fx.contentService.register(body))
      .rejects.toMatchObject({ status: 400, code: "parent_url_invalid" });
  }

  test("non-canonical host casing → 400", () => _expectReject("https://X.COM/a"));
  test("#fragment → 400", () => _expectReject("https://example.com/a#comment-1"));
  test("non-http(s) scheme → 400", () => _expectReject("ftp://example.com/a"));
  test("registered_urls keeps its own error code", async () => {
    const fx = _setup();
    const author = _newAuthor(fx.dag, "pu-code-parity");
    await expect(fx.contentService.register(_buildRegisterBody({
      tipId: author.tipId, privKey: author.kp.privateKey, content: "bad url", registered_urls: ["https://X.COM/a"],
    }))).rejects.toMatchObject({ status: 400, code: "registered_urls_invalid" });
  });
});

// ─── 6. Gated lookup ───────────────────────────────────────────────────────

describe("parent_url: GET /v1/content?parent_url= gating", () => {
  test("returns the referencing content, one entry per author, score-ordered", async () => {
    const fx = _setup();
    const high = _newAuthor(fx.dag, "pu-list-high", 900);
    const mid = _newAuthor(fx.dag, "pu-list-mid", 500);
    await _registerAndCommit(fx, mid, { content: "mid reply", registered_urls: [], parent_url: PARENT });
    await _registerAndCommit(fx, mid, { content: "mid second reply", registered_urls: [], parent_url: PARENT });
    await _registerAndCommit(fx, high, { content: "high reply", registered_urls: [], parent_url: PARENT });
    // Unrelated content must not leak into the parent's thread.
    await _registerAndCommit(fx, high, { content: "unrelated post" });

    const { items, next_cursor } = fx.contentService.list({ parent_url: PARENT });
    expect(next_cursor).toBeNull();
    expect(items.map(i => i.author_tip_id)).toEqual([high.tipId, mid.tipId]);
    expect(items.every(i => i.parent_url === PARENT)).toBe(true);
  });

  test("retracted and disputed rows are excluded", async () => {
    const fx = _setup();
    const a = _newAuthor(fx.dag, "pu-list-retracted");
    const b = _newAuthor(fx.dag, "pu-list-disputed");
    const c = _newAuthor(fx.dag, "pu-list-live");
    const ra = await _registerAndCommit(fx, a, { content: "will retract", registered_urls: [], parent_url: PARENT });
    const rb = await _registerAndCommit(fx, b, { content: "will dispute", registered_urls: [], parent_url: PARENT });
    await _registerAndCommit(fx, c, { content: "stays live", registered_urls: [], parent_url: PARENT });
    fx.dag.updateContentStatus(ra.tx.data.ctid, CONTENT_STATUS.RETRACTED);
    fx.dag.updateContentStatus(rb.tx.data.ctid, CONTENT_STATUS.DISPUTED);

    const { items } = fx.contentService.list({ parent_url: PARENT });
    expect(items.map(i => i.author_tip_id)).toEqual([c.tipId]);
  });

  test("authors below the VERIFIED tier are excluded", async () => {
    const fx = _setup();
    const low = _newAuthor(fx.dag, "pu-list-low", 300);
    const ok = _newAuthor(fx.dag, "pu-list-ok", 400);
    await _registerAndCommit(fx, low, { content: "low-score reply", registered_urls: [], parent_url: PARENT });
    await _registerAndCommit(fx, ok, { content: "verified reply", registered_urls: [], parent_url: PARENT });

    const { items } = fx.contentService.list({ parent_url: PARENT });
    expect(items.map(i => i.author_tip_id)).toEqual([ok.tipId]);
  });

  test("an unknown parent_url returns nothing; a malformed one is a 400", () => {
    const fx = _setup();
    expect(fx.contentService.list({ parent_url: "https://example.com/nobody/" }).items).toEqual([]);
    expect(() => fx.contentService.list({ parent_url: "not-a-url" }))
      .toThrow(expect.objectContaining({ code: "parent_url_invalid" }));
  });
});

// ─── State-root strip rule ───────────────────────────────────────────────────
// parent_url joins the state root under the strip rule: emitted only when set,
// so rows predating the column hash byte-identically and a rolling upgrade
// cannot fork. A naive `parent_url: x || null` would add a null key to EVERY
// row and change the root for all of them, which is what this pins against.

describe("parent_url state-root strip rule", () => {
  const _row = (extra) => ({
    ctid: "tip://c/OH-canon-0001", origin_code: "OH", content_hash: "aa",
    author_tip_id: "tip://id/US-a", signer_tip_id: "tip://id/US-a",
    status: CONTENT_STATUS.REGISTERED, registered_at: 1767225600000,
    registered_urls: [], cna_version: "CNA-2.2", tx_id: "tx1", ...extra,
  });

  test("a row with parent_url absent and one with parent_url null hash the same", () => {
    const a = initDAG({ dbPath: ":memory:" });
    const b = initDAG({ dbPath: ":memory:" });
    a.saveContent(_row({}));
    b.saveContent(_row({ parent_url: null }));
    expect(b.stateRoot()).toBe(a.stateRoot());
  });

  test("setting parent_url does change the root (it is genuinely covered)", () => {
    const a = initDAG({ dbPath: ":memory:" });
    const b = initDAG({ dbPath: ":memory:" });
    a.saveContent(_row({}));
    b.saveContent(_row({ parent_url: "https://example.com/post/" }));
    expect(b.stateRoot()).not.toBe(a.stateRoot());
  });
});
