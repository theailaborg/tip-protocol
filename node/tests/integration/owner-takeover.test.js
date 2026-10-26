/**
 * @file tests/integration/owner-takeover.test.js
 * @description Owner takeover: a protected site's owner (or an active member
 * of an owning org) wins a page address back from a record by anyone else.
 *
 *   1. The plan: who can win what, and what stays first-wins.
 *   2. The declared url_takeovers must match the plan exactly (no invented
 *      or omitted takeovers), at the API and at commit.
 *   3. End to end: register and update-urls take the address over; the old
 *      record keeps its CTID without it; lookups by address find the owner.
 *   4. Read side: released_urls on the old record, an Inbox item for its
 *      author.
 *   5. Before the activation instant nothing changes.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// Saved and restored: --runInBand shares process.env with every later test file.
const _envBefore = {TIP_WEBSITE_PROTECTION_ACTIVATION_MS: process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS, TIP_URL_TAKEOVER_ACTIVATION_MS: process.env.TIP_URL_TAKEOVER_ACTIVATION_MS};
process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS = "1";
process.env.TIP_URL_TAKEOVER_ACTIVATION_MS = "1";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256, tipNormalize, computeTxId, signBody } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { TIP_ID_TYPES, DOMAIN_HEALTHY_EXPIRY_MS, ORG_MEMBER_STATUS, TX_TYPES, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const rules = require(path.join(SRC, "validators", "business-rules"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createUrlTakeovers, resetTakeovers } = require(path.join(SRC, "services", "url-takeovers"));
const { createDisputeService } = require(path.join(SRC, "services", "dispute-service"));
const contentSchema = require(path.join(SRC, "schemas", "content-register"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";
const OWNER = "tip://id/US-aaaaaaaaaaaaaaaa";
const SQUAT = "tip://id/US-bbbbbbbbbbbbbbbb";
const ORG = "tip://id/US-cccccccccccccccc";
const MEMBER = "tip://id/US-dddddddddddddddd";
const PAGE = "https://myblog.example/my-best-recipe";

function seed(dag, tipId, kp, type = TIP_ID_TYPES.PERSONAL) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", tip_id_type: type, founding: false, status: "active",
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  dag.setScore(tipId, 750, 0, 1767225600000);
}

// TAKEOVER_STORE=sqlite runs the whole suite on a real SQLite file per setup
// (production Postgres reads through an in-memory mirror, the default here).
const fs = require("fs"); const os = require("os");
const _tmpDirs = [];
afterAll(() => { for (const d of _tmpDirs) fs.rmSync(d, { recursive: true, force: true }); });
function _dbPath() {
  if (process.env.TAKEOVER_STORE !== "sqlite") return ":memory:";
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "tip-takeover-"));
  _tmpDirs.push(d);
  return path.join(d, "dag.db");
}

function setup() {
  const dag = initDAG({ dbPath: _dbPath() });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
    mediaLimits: { max_text_bytes: 1_000_000, max_image_bytes: 0, max_video_bytes: 0, max_audio_bytes: 0 } };
  const keys = { owner: generateMLDSAKeypair(), squat: generateMLDSAKeypair(), org: generateMLDSAKeypair(), member: generateMLDSAKeypair() };
  seed(dag, OWNER, keys.owner);
  seed(dag, SQUAT, keys.squat);
  seed(dag, ORG, keys.org, TIP_ID_TYPES.ORGANIZATION);
  seed(dag, MEMBER, keys.member);
  const scoring = initScoring(dag, config);
  const submitted = [];
  const contentService = createContentService({ dag, scoring, config, submitTx: (tx) => { submitted.push(tx); } });
  const handler = createCommitHandler({ dag, scoring, config });
  let round = 100;
  const commit = (txs) => handler.commitOrderedTxs(txs, round++, { certTimestamp: nowMs() });
  return { dag, contentService, submitted, commit, keys };
}

function bind(dag, domain, tipId) {
  const v = nowMs();
  dag.saveDomainBinding({ domain, tip_id: tipId, binding_state: "verified", method: "dns", claimed_at: v - 1000,
    verified_at: v, expires_at: v + DOMAIN_HEALTHY_EXPIRY_MS, consecutive_failures: 0, node_id: NODE_ID,
    claim_signature: "00", binding_signature: "00", tx_id: `tx-${domain}` });
}

// A committed record holding `urls`, registered by `signer`.
function signedTx(fx, { signer, kp, urls, tag, ts = nowMs(), takeovers }) {
  const data = {
    ctid: `tip://c/OH-${shake256(tag).slice(0, 14)}-0001`, origin_code: "OH", content_hash: shake256(tag),
    signer_tip_id: signer, registered_urls: urls, attribution_mode: "self", extras: {},
    authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: signer, tip_id_type: "personal" }],
    cna_version: contentSchema.CURRENT_CNA_VERSION,
  };
  data.signature = contentSchema.sign(contentSchema.buildSigningPayload(data, data.content_hash), kp.privateKey);
  if (takeovers !== undefined) data.url_takeovers = takeovers;
  const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: ts, prev: fx.dag.getRecentPrev(), data, signature: data.signature };
  tx.tx_id = computeTxId(tx);
  return tx;
}

function body({ tipId, privKey, content, urls }) {
  const fields = {
    origin_code: "OH", registered_urls: urls, extras: {}, signer_tip_id: tipId, attribution_mode: "self",
    authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: tipId, tip_id_type: "personal" }],
  };
  const payload = contentSchema.buildSigningPayload(fields, shake256(tipNormalize(content)));
  return { ...fields, cna_version: contentSchema.CURRENT_CNA_VERSION, content, content_type: "text", signature: contentSchema.sign(payload, privKey) };
}

// The squatter registers the page before the owner verifies the site.
function squatted(fx) {
  const tx = signedTx(fx, { signer: SQUAT, kp: fx.keys.squat, urls: [PAGE, "https://x.com/s/status/1"], tag: "squat" });
  expect(fx.commit([tx]).committed).toBe(1);
  bind(fx.dag, "myblog.example", OWNER);
  return tx.data.ctid;
}

describe("the takeover plan", () => {
  test("the verified owner wins the page back from someone else", () => {
    const fx = setup();
    const old = squatted(fx);
    const plan = rules.urlTakeoverPlan(fx.dag, { signer_tip_id: OWNER, ctid: "tip://c/OH-00000000000000-0001", urls: [PAGE], at_ms: nowMs() });
    expect(plan).toEqual({ takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] });
  });

  test("anyone else still gets first-wins 409, owner or not", () => {
    const fx = setup();
    squatted(fx);
    const third = "tip://id/US-eeeeeeeeeeeeeeee";
    seed(fx.dag, third, generateMLDSAKeypair());
    const r = rules.urlTakeoverPlan(fx.dag, { signer_tip_id: third, ctid: null, urls: [PAGE], at_ms: nowMs() });
    expect(r.fail.error).toEqual(expect.objectContaining({ status: 409, code: "url_already_registered" }));
  });

  test("an org's member keeps a page against the org's own owner side; the org wins it from an outsider", () => {
    const fx = setup();
    const mtx = signedTx(fx, { signer: MEMBER, kp: fx.keys.member, urls: ["https://acmenews.example/story"], tag: "m1" });
    const stx = signedTx(fx, { signer: SQUAT, kp: fx.keys.squat, urls: ["https://acmenews.example/other"], tag: "s1" });
    expect(fx.commit([mtx, stx]).committed).toBe(2);
    bind(fx.dag, "acmenews.example", ORG);
    fx.dag.saveOrgMember({ invite_tx_id: "inv", org_tip_id: ORG, member_tip_id: MEMBER, role: "member", invited_at: 1767225600000, accepted_at: 1767225600001, status: ORG_MEMBER_STATUS.ACTIVE });
    expect(rules.urlTakeoverPlan(fx.dag, { signer_tip_id: ORG, ctid: null, urls: ["https://acmenews.example/story"], at_ms: nowMs() }).fail)
      .toBeTruthy();
    expect(rules.urlTakeoverPlan(fx.dag, { signer_tip_id: ORG, ctid: null, urls: ["https://acmenews.example/other"], at_ms: nowMs() }).takeovers)
      .toEqual([{ url: "https://acmenews.example/other", ctid: stx.data.ctid, tip_id: SQUAT }]);
  });

  test("shared platforms and retracted records are never taken over", () => {
    const fx = setup();
    const t = signedTx(fx, { signer: SQUAT, kp: fx.keys.squat, urls: ["https://medium.com/@a/post"], tag: "md" });
    fx.commit([t]);
    bind(fx.dag, "medium.com", OWNER);
    expect(rules.urlTakeoverPlan(fx.dag, { signer_tip_id: OWNER, ctid: null, urls: ["https://medium.com/@a/post"], at_ms: nowMs() }).fail).toBeTruthy();
    const fx2 = setup();
    const c = squatted(fx2);
    fx2.dag.updateContentStatus(c, CONTENT_STATUS.RETRACTED);
    expect(rules.urlTakeoverPlan(fx2.dag, { signer_tip_id: OWNER, ctid: null, urls: [PAGE], at_ms: nowMs() })).toEqual({ takeovers: [] });
  });
});

describe("the declared list must match exactly", () => {
  const reg = (fx, url_takeovers) => rules.canRegisterContent(fx.dag, {
    signer_tip_id: OWNER, ctid: "tip://c/OH-11111111111111-0001", origin_code: "OH", registered_urls: [PAGE], at_ms: nowMs(), url_takeovers });

  test("right list passes; missing, invented or altered lists are refused", () => {
    const fx = setup();
    const old = squatted(fx);
    expect(reg(fx, [{ url: PAGE, ctid: old, tip_id: SQUAT }]).valid).toBe(true);
    for (const bad of [undefined, [], [{ url: PAGE, ctid: old, tip_id: OWNER }], [{ url: PAGE, ctid: "tip://c/OH-99999999999999-0001", tip_id: SQUAT }],
      [{ url: PAGE, ctid: old, tip_id: SQUAT }, { url: "https://myblog.example/x", ctid: old, tip_id: SQUAT }]]) {
      expect(reg(fx, bad).error.code).toBe("url_takeovers_mismatch");
    }
  });

  test("a takeover list on a registration that takes nothing is refused", () => {
    const fx = setup();
    bind(fx.dag, "myblog.example", OWNER);
    expect(reg(fx, [{ url: PAGE, ctid: "tip://c/OH-22222222222222-0001", tip_id: SQUAT }]).error.code).toBe("url_takeovers_mismatch");
  });
});

describe("review hardening", () => {
  test("the declared list may be in any order: stores list claimants differently, nodes must agree", () => {
    const fx = setup();
    const a = signedTx(fx, { signer: SQUAT, kp: fx.keys.squat, urls: [PAGE], tag: "ra" });
    const third = "tip://id/US-eeeeeeeeeeeeeeee"; const kp3 = generateMLDSAKeypair(); seed(fx.dag, third, kp3);
    const b = signedTx(fx, { signer: third, kp: kp3, urls: ["https://myblog.example/second"], tag: "rb" });
    expect(fx.commit([a, b]).committed).toBe(2);
    bind(fx.dag, "myblog.example", OWNER);
    const urls = [PAGE, "https://myblog.example/second"];
    const plan = rules.urlTakeoverPlan(fx.dag, { signer_tip_id: OWNER, ctid: null, urls, at_ms: nowMs() });
    expect(plan.takeovers).toHaveLength(2);
    const reg = (list) => rules.canRegisterContent(fx.dag, { signer_tip_id: OWNER, ctid: "tip://c/OH-33333333333333-0001",
      origin_code: "OH", registered_urls: urls, at_ms: nowMs(), url_takeovers: list });
    expect(reg(plan.takeovers).valid).toBe(true);
    expect(reg(plan.takeovers.slice().reverse()).valid).toBe(true);
    expect(reg([plan.takeovers[0]]).error.code).toBe("url_takeovers_mismatch");
    // One registration takes pages back from two different people.
    const win = signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls, tag: "rw", takeovers: plan.takeovers.slice().reverse() });
    expect(fx.commit([win]).committed).toBe(1);
    expect(fx.dag.getContent(a.data.ctid).registered_urls).toEqual([]);
    expect(fx.dag.getContent(b.data.ctid).registered_urls).toEqual([]);
    expect(createUrlTakeovers({ dag: fx.dag }).takenFrom(third).map(r => r.url)).toEqual(["https://myblog.example/second"]);
  });

  test("record views and Inboxes never rescan history: built once, then kept current by commits", () => {
    const fx = setup();
    const old = squatted(fx);
    const spy = jest.spyOn(fx.dag, "getTxsByType");
    const t = createUrlTakeovers({ dag: fx.dag });
    expect(t.releasedBy(old)).toEqual([]);
    const scans = spy.mock.calls.length;
    for (let i = 0; i < 20; i++) { t.releasedBy(old); t.takenFrom(SQUAT); }
    expect(spy.mock.calls.length).toBe(scans);
    fx.commit([signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "rv", takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] })]);
    const before = spy.mock.calls.filter(c => c[0] === TX_TYPES.REGISTER_CONTENT).length;
    expect(createUrlTakeovers({ dag: fx.dag }).releasedBy(old).map(r => r.url)).toEqual([PAGE]);
    expect(spy.mock.calls.filter(c => c[0] === TX_TYPES.REGISTER_CONTENT).length).toBe(before);
    spy.mockRestore();
  });

  test("a takeover tx that never took effect (dropped) shows nothing", () => {
    const fx = setup();
    const old = squatted(fx);
    const bad = signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "rd", takeovers: [{ url: PAGE, ctid: old, tip_id: OWNER }] });
    expect(fx.commit([bad]).committed).toBe(0);
    expect(createUrlTakeovers({ dag: fx.dag }).releasedBy(old)).toEqual([]);
  });

  test("before activation the refusal is byte-identical to the old first-wins rule", () => {
    jest.isolateModules(() => {
      process.env.TIP_URL_TAKEOVER_ACTIVATION_MS = String(nowMs() + 86_400_000);
      const r = require(path.join(SRC, "validators", "business-rules"));
      const fx = setup();
      const old = squatted(fx);
      const res = r.canRegisterContent(fx.dag, { signer_tip_id: OWNER, ctid: null, origin_code: "OH", registered_urls: [PAGE], at_ms: nowMs() });
      expect(res).toEqual({ valid: false, error: { status: 409, message: `URL already registered to existing content (CTID: ${old}): ${PAGE}`,
        code: "url_already_registered", details: { url: PAGE, conflict_ctid: old } } });
      // A tx carrying url_takeovers before activation is refused too.
      const res2 = r.canRegisterContent(fx.dag, { signer_tip_id: OWNER, ctid: null, origin_code: "OH", registered_urls: [PAGE], at_ms: nowMs(),
        url_takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] });
      expect(res2.valid).toBe(false);
    });
    process.env.TIP_URL_TAKEOVER_ACTIVATION_MS = "1";
  });
});

describe("second review: batch clashes, pre-activation, index", () => {
  function updateTx(fx, { ctid, urls, kp, author, ts = nowMs() }) {
    const signature = signBody({ author_tip_id: author, ctid, registered_urls: urls }, kp.privateKey);
    const tx = { tx_type: TX_TYPES.UPDATE_REGISTERED_URLS, timestamp: ts, prev: fx.dag.getRecentPrev(),
      data: { ctid, registered_urls: urls, author_tip_id: author }, signature };
    tx.tx_id = computeTxId(tx);
    return tx;
  }
  const holdersOf = (fx) => fx.dag.listContent({ url: PAGE, limit: 10 }).map(c => c.ctid);

  test("takeover then the squatter's own URL update in one batch: never two records on one address", () => {
    const fx = setup();
    const old = squatted(fx);
    const win = signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "c1", takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] });
    const upd = updateTx(fx, { ctid: old, urls: ["https://x.com/s/status/1", PAGE], kp: fx.keys.squat, author: SQUAT });
    const res = fx.commit([win, upd]);
    expect(res.committed).toBe(1);
    expect(holdersOf(fx)).toEqual([win.data.ctid]);
  });

  test("the squatter's URL update first, then the takeover, in one batch: the takeover waits", () => {
    const fx = setup();
    const old = squatted(fx);
    const upd = updateTx(fx, { ctid: old, urls: ["https://x.com/s/status/1", PAGE], kp: fx.keys.squat, author: SQUAT });
    const win = signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "c2", takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] });
    expect(fx.commit([upd, win]).committed).toBe(1);
    expect(holdersOf(fx)).toEqual([old]);
    // Resubmitted in a later batch, the takeover lands.
    const again = signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "c3", takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] });
    expect(fx.commit([again]).committed).toBe(1);
    expect(holdersOf(fx)).toEqual([again.data.ctid]);
  });

  test("before activation a bogus url_takeovers on an ordinary registration is ignored, as an old node would", () => {
    const fx = setup();
    const old = squatted(fx);
    // at_ms 0 is before every activation: protection and takeover are both off.
    const r = rules.canRegisterContent(fx.dag, { signer_tip_id: OWNER, ctid: "tip://c/OH-44444444444444-0001", origin_code: "OH",
      registered_urls: ["https://x.com/o/status/9"], at_ms: 0, url_takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] });
    expect(r.valid).toBe(true);
    // ...and the same list on a real conflict is not honoured either: first-wins.
    const r2 = rules.canRegisterContent(fx.dag, { signer_tip_id: OWNER, ctid: "tip://c/OH-44444444444444-0002", origin_code: "OH",
      registered_urls: [PAGE], at_ms: 0, url_takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] });
    expect(r2.error.code).toBe("url_already_registered");
  });

  test("the index is marked built only after a successful scan, and rebuilds after a reset", () => {
    const fx = setup();
    const old = squatted(fx);
    fx.commit([signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "i1", takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] })]);
    resetTakeovers(fx.dag);
    const real = fx.dag.getTxsByType;
    let fail = true;
    fx.dag.getTxsByType = (...a) => { if (fail) throw new Error("db busy"); return real.apply(fx.dag, a); };
    const t = createUrlTakeovers({ dag: fx.dag });
    expect(() => t.releasedBy(old)).toThrow("db busy");
    fail = false;
    expect(t.releasedBy(old).map(r => r.url)).toEqual([PAGE]);
    fx.dag.getTxsByType = real;
  });

  test("the byline author of an employed record gets the notice too", () => {
    const fx = setup();
    const ctid = `tip://c/OH-${shake256("emp").slice(0, 14)}-0001`;
    fx.dag.saveContent({ ctid, origin_code: "OH", content_hash: shake256("emp"), author_tip_id: MEMBER, signer_tip_id: ORG,
      authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: MEMBER, tip_id_type: "personal" }],
      attribution_mode: "employed", extras: {}, cna_version: contentSchema.CURRENT_CNA_VERSION, status: "registered",
      registered_at: nowMs() - 5000, registered_urls: [PAGE], media: [] });
    bind(fx.dag, "myblog.example", OWNER);
    const win = signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "e2", takeovers: [{ url: PAGE, ctid, tip_id: ORG }] });
    expect(fx.commit([win]).committed).toBe(1);
    const t = createUrlTakeovers({ dag: fx.dag });
    expect(t.takenFrom(ORG).map(r => r.ctid)).toEqual([ctid]);
    expect(t.takenFrom(MEMBER).map(r => r.ctid)).toEqual([ctid]);
  });
});

describe("end to end", () => {
  test("register: the owner's record takes the address; the old record keeps its CTID without it", async () => {
    const fx = setup();
    const old = squatted(fx);
    await fx.contentService.register(body({ tipId: OWNER, privKey: fx.keys.owner.privateKey, content: "My best recipe, the real one.", urls: [PAGE] }));
    const tx = fx.submitted.find(t => t.tx_type === TX_TYPES.REGISTER_CONTENT);
    expect(tx.data.url_takeovers).toEqual([{ url: PAGE, ctid: old, tip_id: SQUAT }]);
    expect(fx.commit([tx]).committed).toBeGreaterThanOrEqual(1);
    expect(fx.dag.getContent(old).registered_urls).toEqual(["https://x.com/s/status/1"]);
    expect(fx.dag.getContent(tx.data.ctid).registered_urls).toEqual([PAGE]);
    expect(fx.dag.listContent({ url: PAGE, limit: 10 }).map(c => c.ctid)).toEqual([tx.data.ctid]);
  });

  test("a registration with no takeover carries no url_takeovers key at all", async () => {
    const fx = setup();
    await fx.contentService.register(body({ tipId: OWNER, privKey: fx.keys.owner.privateKey, content: "A normal post.", urls: ["https://x.com/o/status/2"] }));
    expect("url_takeovers" in fx.submitted[0].data).toBe(false);
  });

  test("commit drops a forged takeover: missing list, or naming a record that does not hold the page", () => {
    const fx = setup();
    const old = squatted(fx);
    expect(fx.commit([signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "o1" })]).committed).toBe(0);
    expect(fx.commit([signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "o2",
      takeovers: [{ url: PAGE, ctid: "tip://c/OH-99999999999999-0001", tip_id: SQUAT }] })]).committed).toBe(0);
    expect(fx.dag.getContent(old).registered_urls).toContain(PAGE);
    expect(fx.commit([signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "o3",
      takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] })]).committed).toBe(1);
    expect(fx.dag.getContent(old).registered_urls).not.toContain(PAGE);
  });

  test("the squatter cannot add the page back afterwards", async () => {
    const fx = setup();
    const old = squatted(fx);
    fx.commit([signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "o4", takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] })]);
    const urls = ["https://x.com/s/status/1", PAGE];
    const b = { author_tip_id: SQUAT, registered_urls: urls, signature: signBody({ author_tip_id: SQUAT, ctid: old, registered_urls: urls }, fx.keys.squat.privateKey) };
    expect(() => fx.contentService.updateRegisteredUrls(old, b)).toThrow(expect.objectContaining({ status: 409 }));
  });

  test("update-urls: the owner adds a squatted page to an existing record", () => {
    const fx = setup();
    const old = squatted(fx);
    const mine = signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: ["https://x.com/o/status/3"], tag: "o5" });
    fx.commit([mine]);
    const urls = ["https://x.com/o/status/3", PAGE];
    const out = fx.contentService.updateRegisteredUrls(mine.data.ctid, { author_tip_id: OWNER, registered_urls: urls,
      signature: signBody({ author_tip_id: OWNER, ctid: mine.data.ctid, registered_urls: urls }, fx.keys.owner.privateKey) });
    expect(out.success).toBe(true);
    const tx = fx.submitted.find(t => t.tx_type === TX_TYPES.UPDATE_REGISTERED_URLS);
    expect(tx.data.url_takeovers).toEqual([{ url: PAGE, ctid: old, tip_id: SQUAT }]);
    expect(fx.commit([tx]).committed).toBe(1);
    expect(fx.dag.getContent(old).registered_urls).not.toContain(PAGE);
    expect(fx.dag.getContent(mine.data.ctid).registered_urls).toEqual(urls);
  });
});

describe("read side", () => {
  test("the old record lists what it released; its author's takeovers are listed newest first", () => {
    const fx = setup();
    const old = squatted(fx);
    const win = signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "o6", takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] });
    fx.commit([win]);
    const t = createUrlTakeovers({ dag: fx.dag });
    expect(t.releasedBy(old)).toEqual([expect.objectContaining({ url: PAGE, ctid: old, tip_id: SQUAT, domain: "myblog.example",
      to_ctid: win.data.ctid, to_tip_id: OWNER })]);
    expect(t.takenFrom(SQUAT).map(r => r.url)).toEqual([PAGE]);
    expect(t.takenFrom(OWNER)).toEqual([]);
    expect(t.releasedBy(win.data.ctid)).toEqual([]);
  });

  test("resolve() shows released_urls only on a record that released one", async () => {
    const fx = setup();
    const old = squatted(fx);
    const win = signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "o7", takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] });
    fx.commit([win]);
    const rec = await fx.contentService.resolve(old);
    expect(rec.released_urls).toEqual([expect.objectContaining({ url: PAGE, to_tip_id: OWNER })]);
    expect("released_urls" in (await fx.contentService.resolve(win.data.ctid))).toBe(false);
  });
});

describe("Inbox", () => {
  test("the old record's author gets a plain notice with the page, the site and a link to their record", () => {
    const fx = setup();
    const old = squatted(fx);
    fx.commit([signedTx(fx, { signer: OWNER, kp: fx.keys.owner, urls: [PAGE], tag: "o8", takeovers: [{ url: PAGE, ctid: old, tip_id: SQUAT }] })]);
    const svc = createDisputeService({ dag: fx.dag, scoring: initScoring(fx.dag, {}), config: {}, submitTx: () => {}, submitBatch: () => {} });
    const item = svc.getUserDashboard(SQUAT).items.find(i => i.type === "url_taken_over");
    expect(item).toEqual(expect.objectContaining({ priority: "info", ctid: old,
      action: expect.objectContaining({ href: "/content/" + encodeURIComponent(old) }),
      metadata: expect.objectContaining({ url: PAGE, domain: "myblog.example", owner_tip_id: OWNER }) }));
    expect(item.summary).toContain("myblog.example");
    expect(svc.getUserDashboard(OWNER).items.some(i => i.type === "url_taken_over")).toBe(false);
  });
});

describe("before the takeover activation", () => {
  test("first-wins exactly as before", () => {
    jest.isolateModules(() => {
      process.env.TIP_URL_TAKEOVER_ACTIVATION_MS = String(nowMs() + 86_400_000);
      const r = require(path.join(SRC, "validators", "business-rules"));
      const fx = setup();
      squatted(fx);
      const res = r.canRegisterContent(fx.dag, { signer_tip_id: OWNER, ctid: null, origin_code: "OH", registered_urls: [PAGE], at_ms: nowMs() });
      expect(res.error).toEqual(expect.objectContaining({ status: 409, code: "url_already_registered" }));
    });
    process.env.TIP_URL_TAKEOVER_ACTIVATION_MS = "1";
  });
});

afterAll(() => { for (const [k, v] of Object.entries(_envBefore)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });
