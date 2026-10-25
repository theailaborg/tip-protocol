/**
 * @file tests/integration/website-protection.test.js
 * @description Per-site website protection, end to end:
 *
 *   1. A live domain binding stops every other signer registering, or later
 *      adding, a URL on that site (www. and the apex are one site); the owner
 *      and active members of an owning org may.
 *   2. Bindings on shared platforms never protect, subdomains are their own
 *      site, and a binding past expires_at stops protecting.
 *   3. canBindDomain: a live binding to someone else blocks (either
 *      spelling), a lapsed one releases the site.
 *   4. Personal TIP-IDs bind domains from the activation; not before.
 *   5. Renewal re-proves control and re-commits the original claim.
 *   6. Pages of the signer's own protected site are counted with the billing
 *      service; a refusal is 429 and nothing is submitted.
 *   7. The verifier never fetches a non-public address.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// The gate is read once at module load; "1" means on for every real time.
// Saved and restored: --runInBand shares process.env with every later test file.
const _envBefore = {TIP_WEBSITE_PROTECTION_ACTIVATION_MS: process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS};
process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS = "1";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256, tipNormalize, computeTxId } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const {
  TIP_ID_TYPES, DOMAIN_BINDING_STATUS, DOMAIN_HEALTHY_EXPIRY_MS, ORG_MEMBER_STATUS, TX_TYPES,
} = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const rules = require(path.join(SRC, "validators", "business-rules"));
const { createDomainService } = require(path.join(SRC, "services", "domain-service"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createWebsitePagesClient } = require(path.join(SRC, "services", "website-pages-client"));
const registerDomainSchema = require(path.join(SRC, "schemas", "register-domain"));
const contentSchema = require(path.join(SRC, "schemas", "content-register"));
const { isNonPublicAddress, _publicOnlyLookup, _fetchJson } = require(path.join(SRC, "domain", "verifier"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";
const OWNER = "tip://id/US-aaaaaaaaaaaaaaaa";
const OTHER = "tip://id/US-bbbbbbbbbbbbbbbb";
const ORG = "tip://id/US-cccccccccccccccc";

function stubVerifier(outcome = "ok") {
  return {
    verify: jest.fn(async (method, domain, tipId) => (outcome === "ok"
      ? { verified: true, method: method === "auto" ? "dns" : method, verified_at: nowMs(),
        evidence: { url: null, body: null, txt: [`tip-id=${tipId}`] }, error: null }
      : { verified: false, method, verified_at: null, evidence: { url: null, body: null, txt: [] },
        error: { code: "dns_no_record", message: "no TXT record" } })),
  };
}

function seedIdentity(dag, tipId, kp, type = TIP_ID_TYPES.PERSONAL) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", tip_id_type: type, founding: false, status: "active",
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  dag.setScore(tipId, 750, 0, 1767225600000);
}

function setup({ verifier, websitePages, sitesPlan } = {}) {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
    mediaLimits: { max_text_bytes: 1_000_000, max_image_bytes: 0, max_video_bytes: 0, max_audio_bytes: 0 },
  };
  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  const scoring = initScoring(dag, config);
  const domainService = createDomainService({ dag, config, submitTx, verifier: verifier || stubVerifier("ok"), websitePages: sitesPlan });
  const contentService = createContentService({ dag, scoring, config, submitTx: (tx) => { submitTx(tx); dag.addTx(tx); }, websitePages });
  const commitHandler = createCommitHandler({ dag, nodeId: NODE_ID });
  const commitSubmitted = () => commitHandler.commitOrderedTxs(submitted.splice(0, submitted.length), 1, { certTimestamp: nowMs() });
  const keys = { owner: generateMLDSAKeypair(), other: generateMLDSAKeypair(), org: generateMLDSAKeypair() };
  seedIdentity(dag, OWNER, keys.owner);
  seedIdentity(dag, OTHER, keys.other);
  seedIdentity(dag, ORG, keys.org, TIP_ID_TYPES.ORGANIZATION);
  return { dag, domainService, contentService, submitted, commitSubmitted, keys };
}

function bind(dag, domain, tipId, { verifiedAt = nowMs(), state = "verified" } = {}) {
  dag.saveDomainBinding({
    domain, tip_id: tipId, binding_state: state, method: "dns",
    claimed_at: verifiedAt - 1000, verified_at: verifiedAt,
    expires_at: verifiedAt + DOMAIN_HEALTHY_EXPIRY_MS, consecutive_failures: 0,
    node_id: NODE_ID, claim_signature: "00", binding_signature: "00", tx_id: `tx-${domain}`,
  });
}

function claimFor({ tipId, privKey, domain, method = "auto" }) {
  const claimed_at = nowMs() - 60_000;
  const payload = registerDomainSchema.buildSigningPayload({ claimed_at, domain, method, tip_id: tipId });
  return { tip_id: tipId, domain, method, claimed_at, signature: registerDomainSchema.sign(payload, privKey) };
}

function registerBody({ tipId, privKey, content, urls }) {
  const fields = {
    origin_code: "OH", registered_urls: urls, extras: {},
    authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: tipId, tip_id_type: "personal" }],
    signer_tip_id: tipId, attribution_mode: "self",
  };
  const payload = contentSchema.buildSigningPayload(fields, shake256(tipNormalize(content)));
  return { ...fields, cna_version: contentSchema.CURRENT_CNA_VERSION, content, content_type: "text",
    signature: contentSchema.sign(payload, privKey) };
}

const reg = (dag, signer, urls, at = nowMs()) =>
  rules.canRegisterContent(dag, { signer_tip_id: signer, ctid: null, origin_code: "OH", registered_urls: urls, at_ms: at });

function signedRegisterTxFor(fx, { signer, kp, url, tag, ts }) {
  const data = {
    ctid: `tip://c/OH-${shake256(tag).slice(0, 14)}-0009`, origin_code: "OH", content_hash: shake256(tag),
    signer_tip_id: signer, registered_urls: [url], attribution_mode: "self", extras: {},
    authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: signer, tip_id_type: "personal" }],
    cna_version: contentSchema.CURRENT_CNA_VERSION,
  };
  data.signature = contentSchema.sign(contentSchema.buildSigningPayload(data, data.content_hash), kp.privateKey);
  const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: ts, prev: fx.dag.getRecentPrev(), data, signature: data.signature };
  tx.tx_id = computeTxId(tx);
  return tx;
}

// ─── 1. The protection rule ──────────────────────────────────────────────────

describe("a protected site's pages belong to its owner", () => {
  test("another signer is refused with 403 domain_protected; the owner is not", () => {
    const { dag } = setup();
    bind(dag, "myblog.example", OWNER);
    const r = reg(dag, OTHER, ["https://myblog.example/2026/10/post"]);
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(403);
    expect(r.error.code).toBe("domain_protected");
    expect(r.error.details).toEqual({ url: "https://myblog.example/2026/10/post", domain: "myblog.example" });
    expect(reg(dag, OWNER, ["https://myblog.example/2026/10/post"]).valid).toBe(true);
  });

  test("www. and the apex are one site, in both directions, any case, trailing dot", () => {
    const { dag } = setup();
    bind(dag, "myblog.example", OWNER);
    bind(dag, "www.other.example", OWNER);
    for (const u of ["https://WWW.MyBlog.Example/a", "https://myblog.example./b", "http://myblog.example/c",
      "https://other.example/d", "https://www.other.example/e"]) {
      expect(reg(dag, OTHER, [u]).error?.code).toBe("domain_protected");
    }
  });

  test("any number of trailing dots is still the same site", () => {
    const { dag } = setup();
    bind(dag, "myblog.example", OWNER);
    for (const u of ["https://myblog.example../a", "https://www.myblog.example.../b"]) {
      expect(reg(dag, OTHER, [u]).error?.code).toBe("domain_protected");
    }
  });

  test("a subdomain is its own site and is not covered", () => {
    const { dag } = setup();
    bind(dag, "myblog.example", OWNER);
    expect(reg(dag, OTHER, ["https://shop.myblog.example/item"]).valid).toBe(true);
  });

  test("one protected URL among several refuses the whole registration", () => {
    const { dag } = setup();
    bind(dag, "myblog.example", OWNER);
    const r = reg(dag, OTHER, ["https://x.com/someone/status/1", "https://myblog.example/p"]);
    expect(r.error.code).toBe("domain_protected");
  });

  test("a binding on a shared platform never protects anyone's posts there", () => {
    const { dag } = setup();
    for (const d of ["substack.com", "www.medium.com", "github.io", "x.com"]) bind(dag, d, OWNER);
    for (const u of ["https://substack.com/@writer/p/1", "https://medium.com/@a/b", "https://github.io/x", "https://x.com/a/status/2"]) {
      expect(reg(dag, OTHER, [u]).valid).toBe(true);
    }
  });

  test("a lapsed, revoked or other-state binding does not protect", () => {
    const { dag } = setup();
    bind(dag, "old.example", OWNER, { verifiedAt: nowMs() - DOMAIN_HEALTHY_EXPIRY_MS - 1000 });
    bind(dag, "gone.example", OWNER, { state: "revoked" });
    expect(reg(dag, OTHER, ["https://old.example/a"]).valid).toBe(true);
    expect(reg(dag, OTHER, ["https://gone.example/a"]).valid).toBe(true);
  });

  test("protection decides on the time it is given (frozen tx.timestamp)", () => {
    const { dag } = setup();
    const t0 = nowMs();
    bind(dag, "dated.example", OWNER, { verifiedAt: t0 });
    expect(reg(dag, OTHER, ["https://dated.example/a"], t0 + 1000).valid).toBe(false);
    expect(reg(dag, OTHER, ["https://dated.example/a"], t0 + DOMAIN_HEALTHY_EXPIRY_MS + 1).valid).toBe(true);
  });

  test("active members of an owning organization may register; removed members may not", () => {
    const { dag } = setup();
    bind(dag, "acmenews.example", ORG);
    dag.saveOrgMember({ invite_tx_id: "inv-1", org_tip_id: ORG, member_tip_id: OTHER, status: ORG_MEMBER_STATUS.ACTIVE });
    expect(reg(dag, OTHER, ["https://acmenews.example/story"]).valid).toBe(true);
    dag.saveOrgMember({ invite_tx_id: "inv-1", org_tip_id: ORG, member_tip_id: OTHER, status: ORG_MEMBER_STATUS.REMOVED });
    expect(reg(dag, OTHER, ["https://acmenews.example/story"]).error.code).toBe("domain_protected");
  });

  test("adding a protected page to existing content later is refused the same way", () => {
    const { dag } = setup();
    bind(dag, "myblog.example", OWNER);
    dag.saveContent({ ctid: "tip://c/OH-0123456789abcd-zz01", author_tip_id: OTHER, origin_code: "OH",
      status: "registered", registered_urls: ["https://x.com/o/status/9"], content_hash: shake256("c") });
    const r = rules.canUpdateRegisteredUrls(dag, {
      ctid: "tip://c/OH-0123456789abcd-zz01", author_tip_id: OTHER, at_ms: nowMs(),
      registered_urls: ["https://x.com/o/status/9", "https://myblog.example/p"],
    });
    expect(r.error.code).toBe("domain_protected");
  });

  test("a URL the record already had is not re-judged when the site is bound later", () => {
    const { dag } = setup();
    dag.saveContent({ ctid: "tip://c/OH-0123456789abcd-zz02", author_tip_id: OTHER, origin_code: "OH",
      status: "registered", registered_urls: ["https://myblog.example/early"], content_hash: shake256("d") });
    bind(dag, "myblog.example", OWNER);
    const r = rules.canUpdateRegisteredUrls(dag, {
      ctid: "tip://c/OH-0123456789abcd-zz02", author_tip_id: OTHER, at_ms: nowMs(),
      registered_urls: ["https://myblog.example/early", "https://x.com/o/status/1"],
    });
    expect(r.valid).toBe(true);
  });
});

describe("consensus drops a protected page sent straight to a peer", () => {
  test("a tx.timestamp backdated before the activation is still judged at the certificate's time", () => {
    jest.isolateModules(() => {
      const gate = nowMs() - 60_000;
      process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS = String(gate);
      const { createCommitHandler: mk } = require(path.join(SRC, "consensus", "commit-handler"));
      const fx = setup();
      bind(fx.dag, "myblog.example", OWNER, { verifiedAt: gate - 1000 });
      const handler = mk({ dag: fx.dag, scoring: initScoring(fx.dag, {}), config: {} });
      const old = signedRegisterTxFor(fx, { signer: OTHER, kp: fx.keys.other, url: "https://myblog.example/p", tag: "bd1", ts: gate - 86_400_000 });
      expect(handler.commitOrderedTxs([old], 30, { certTimestamp: nowMs() }).committed).toBe(0);
    });
    process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS = "1";
  });

  const signedRegisterTx = (...a) => signedRegisterTxFor(...a);

  test("another signer's tx is dropped at commit; the owner's commits", () => {
    const fx = setup();
    const handler = createCommitHandler({ dag: fx.dag, scoring: initScoring(fx.dag, {}), config: {} });
    const ts = nowMs();
    bind(fx.dag, "myblog.example", OWNER, { verifiedAt: ts - 1000 });
    const theirs = signedRegisterTx(fx, { signer: OTHER, kp: fx.keys.other, url: "https://myblog.example/p", tag: "t1", ts });
    expect(handler.commitOrderedTxs([theirs], 20).committed).toBe(0);
    // Control: the same signer, same shape, on a site nobody protects.
    const control = signedRegisterTx(fx, { signer: OTHER, kp: fx.keys.other, url: "https://open.example/p", tag: "t0", ts });
    expect(handler.commitOrderedTxs([control], 19).committed).toBe(1);
    const mine = signedRegisterTx(fx, { signer: OWNER, kp: fx.keys.owner, url: "https://myblog.example/p", tag: "t2", ts });
    expect(handler.commitOrderedTxs([mine], 21).committed).toBe(1);
  });

  test("the frozen tx.timestamp decides, not the commit time: a tx stamped after expiry commits", () => {
    const fx = setup();
    const handler = createCommitHandler({ dag: fx.dag, scoring: initScoring(fx.dag, {}), config: {} });
    const t0 = nowMs() - DOMAIN_HEALTHY_EXPIRY_MS - 5000;
    bind(fx.dag, "lapsed.example", OWNER, { verifiedAt: t0 });
    const tx = signedRegisterTx(fx, { signer: OTHER, kp: fx.keys.other, url: "https://lapsed.example/p", tag: "t3", ts: nowMs() });
    expect(handler.commitOrderedTxs([tx], 22).committed).toBe(1);
  });
});

// ─── 2. Binding conflicts ────────────────────────────────────────────────────

describe("canBindDomain with website protection on", () => {
  test("a live binding to someone else blocks, in either spelling", () => {
    const { dag } = setup();
    bind(dag, "myblog.example", OWNER);
    for (const d of ["myblog.example", "www.myblog.example"]) {
      const r = rules.canBindDomain(dag, { tip_id: OTHER, domain: d, at_ms: nowMs() });
      expect(r.valid).toBe(false);
      expect(r.error.status).toBe(409);
    }
    expect(rules.canBindDomain(dag, { tip_id: OWNER, domain: "www.myblog.example", at_ms: nowMs() }).valid).toBe(true);
  });

  test("a binding past its expiry releases the site to whoever proves control now", () => {
    const { dag } = setup();
    bind(dag, "sold.example", OWNER, { verifiedAt: nowMs() - DOMAIN_HEALTHY_EXPIRY_MS - 1000 });
    expect(rules.canBindDomain(dag, { tip_id: OTHER, domain: "sold.example", at_ms: nowMs() }).valid).toBe(true);
  });
});

// ─── 3. Who may bind ─────────────────────────────────────────────────────────

describe("personal TIP-IDs bind domains from the activation", () => {
  test("register + verify + commit for a person", async () => {
    const fx = setup();
    fx.domainService.register(claimFor({ tipId: OWNER, privKey: fx.keys.owner.privateKey, domain: "myblog.example" }));
    const out = await fx.domainService.verify({ domain: "myblog.example" });
    expect(out.verified).toBe(true);
    expect(fx.commitSubmitted().committed).toBe(1);
    expect(fx.dag.getDomainBinding("myblog.example").tip_id).toBe(OWNER);
  });

  test("before the activation a person is still refused (API and commit time)", () => {
    jest.isolateModules(() => {
      process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS = String(nowMs() + 365 * 86400000);
      const gate = require(path.join(SRC, "validators", "website-gate"));
      expect(gate.mayBindDomain(TIP_ID_TYPES.PERSONAL, nowMs())).toBe(false);
      expect(gate.mayBindDomain(TIP_ID_TYPES.ORGANIZATION, nowMs())).toBe(true);
      const r = require(path.join(SRC, "validators", "business-rules"));
      const { dag } = setup();
      bind(dag, "myblog.example", OWNER);
      expect(r.canRegisterContent(dag, { signer_tip_id: OTHER, ctid: null, origin_code: "OH",
        registered_urls: ["https://myblog.example/a"], at_ms: nowMs() }).valid).toBe(true);
    });
    process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS = "1";
  });
});

// ─── 4. Renewal ──────────────────────────────────────────────────────────────

describe("renewal re-proves control and keeps the owner's original claim", () => {
  async function bound(fx, domain = "myblog.example") {
    const claim = claimFor({ tipId: OWNER, privKey: fx.keys.owner.privateKey, domain });
    fx.domainService.register(claim);
    await fx.domainService.verify({ domain });
    fx.commitSubmitted();
    return claim;
  }

  test("not due: nothing is proposed", async () => {
    const fx = setup();
    await bound(fx);
    const out = await fx.domainService.renew({ domain: "myblog.example" });
    expect(out).toEqual(expect.objectContaining({ renewed: false, reason: "not_due" }));
    expect(fx.submitted).toHaveLength(0);
  });

  test("due: a fresh BIND_DOMAIN with the original claim signature commits and extends expiry", async () => {
    const fx = setup();
    const claim = await bound(fx);
    const b = fx.dag.getDomainBinding("myblog.example");
    fx.dag.saveDomainBinding({ ...b, verified_at: b.verified_at - 25 * 86400000, expires_at: b.expires_at - 25 * 86400000 });
    const before = fx.dag.getDomainBinding("myblog.example").expires_at;
    const out = await fx.domainService.renew({ domain: "myblog.example" });
    expect(out.renewed).toBe(true);
    const tx = fx.submitted[0];
    expect(tx.data.claimed_at).toBe(claim.claimed_at);
    expect(tx.data.claimed_method).toBe("auto");
    expect(tx.data.cosignatures[0].signature).toBe(claim.signature);
    expect(fx.commitSubmitted().committed).toBe(1);
    expect(fx.dag.getDomainBinding("myblog.example").expires_at).toBeGreaterThan(before);
    await expect(fx.domainService.renew({ domain: "myblog.example" })).resolves.toEqual(expect.objectContaining({ renewed: false }));
  });

  test("a second attempt within the hour is 429; a failed proof is 422", async () => {
    const verifier = stubVerifier("ok");
    const fx = setup({ verifier });
    await bound(fx);
    const b = fx.dag.getDomainBinding("myblog.example");
    fx.dag.saveDomainBinding({ ...b, expires_at: nowMs() + 1000 });
    verifier.verify.mockImplementationOnce(async () => ({ verified: false, method: "auto", verified_at: null,
      evidence: {}, error: { code: "dns_no_record", message: "gone" } }));
    await expect(fx.domainService.renew({ domain: "myblog.example" })).rejects.toMatchObject({ status: 422 });
    await expect(fx.domainService.renew({ domain: "myblog.example" })).rejects.toMatchObject({ status: 429, code: "renew_too_soon" });
  });

  test("an owner whose key changed must add the site again (409)", async () => {
    const fx = setup();
    await bound(fx);
    const b = fx.dag.getDomainBinding("myblog.example");
    fx.dag.saveDomainBinding({ ...b, expires_at: nowMs() + 1000 });
    const id = fx.dag.getIdentity(OWNER);
    fx.dag.saveIdentity({ ...id, public_key: generateMLDSAKeypair().publicKey });
    await expect(fx.domainService.renew({ domain: "myblog.example" })).rejects.toMatchObject({ status: 409, code: "renewal_needs_new_claim" });
  });

  test("unknown domain is 404; listByTip returns the owner's sites only", async () => {
    const fx = setup();
    await bound(fx, "myblog.example");
    bind(fx.dag, "someone-else.example", OTHER);
    await expect(fx.domainService.renew({ domain: "never.example" })).rejects.toMatchObject({ status: 404 });
    const list = fx.domainService.listByTip(OWNER);
    expect(list.domains.map(d => d.domain)).toEqual(["myblog.example"]);
    expect(list.domains[0].status).toBe(DOMAIN_BINDING_STATUS.VERIFIED);
    expect(list.domains[0].binding_signature).toBeUndefined();
    expect(() => fx.domainService.listByTip("not-a-tip-id")).toThrow(expect.objectContaining({ status: 400 }));
  });
});

// ─── 5. Page allowance ───────────────────────────────────────────────────────

describe("pages of your own protected site count against your plan", () => {
  function pages(answer) {
    const calls = [];
    return { calls, enabled: true, reserve: jest.fn(async (q) => { calls.push(q); return typeof answer === "function" ? answer(q) : answer; }) };
  }

  test("allowed: one reservation per site, then the page registers", async () => {
    const websitePages = pages({ allowed: true, used: 1, limit: 100 });
    const fx = setup({ websitePages });
    bind(fx.dag, "myblog.example", OWNER);
    await fx.contentService.register(registerBody({ tipId: OWNER, privKey: fx.keys.owner.privateKey,
      content: "First protected page", urls: ["https://myblog.example/one", "https://x.com/me/status/5"] }));
    expect(websitePages.calls).toEqual([expect.objectContaining({
      owner_tip_id: OWNER, signer_tip_id: OWNER, domain: "myblog.example", urls: ["https://myblog.example/one"],
    })]);
    expect(fx.submitted.some(t => t.tx_type === "REGISTER_CONTENT")).toBe(true);
  });

  test("refused: 429 website_page_limit with the numbers, and nothing is submitted", async () => {
    const websitePages = pages({ allowed: false, reason: "page_limit", used: 100, limit: 100, resets_at: 1798761600, upgrade_url: "/plans#websites" });
    const fx = setup({ websitePages });
    bind(fx.dag, "myblog.example", OWNER);
    await expect(fx.contentService.register(registerBody({ tipId: OWNER, privKey: fx.keys.owner.privateKey,
      content: "One page too many", urls: ["https://myblog.example/101"] })))
      .rejects.toMatchObject({ status: 429, code: "website_page_limit", details: expect.objectContaining({ used: 100, limit: 100 }) });
    expect(fx.submitted.some(t => t.tx_type === "REGISTER_CONTENT")).toBe(false);
  });

  test("a site beyond the plan's number of sites is 429 website_site_limit", async () => {
    const fx = setup({ websitePages: pages({ allowed: false, reason: "site_limit", sites_used: 1, sites_limit: 1 }) });
    bind(fx.dag, "second.example", OWNER);
    await expect(fx.contentService.register(registerBody({ tipId: OWNER, privKey: fx.keys.owner.privateKey,
      content: "Second site", urls: ["https://second.example/a"] })))
      .rejects.toMatchObject({ status: 429, code: "website_site_limit" });
  });

  test("a page on no protected site is never counted", async () => {
    const websitePages = pages({ allowed: false });
    const fx = setup({ websitePages });
    await fx.contentService.register(registerBody({ tipId: OWNER, privKey: fx.keys.owner.privateKey,
      content: "A normal post", urls: ["https://x.com/me/status/7"] }));
    expect(websitePages.reserve).not.toHaveBeenCalled();
  });

  test("a member's page on the org's site counts against the org", async () => {
    const websitePages = pages({ allowed: true });
    const fx = setup({ websitePages });
    bind(fx.dag, "acmenews.example", ORG);
    fx.dag.saveOrgMember({ invite_tx_id: "inv-2", org_tip_id: ORG, member_tip_id: OWNER, status: ORG_MEMBER_STATUS.ACTIVE });
    await fx.contentService.register(registerBody({ tipId: OWNER, privKey: fx.keys.owner.privateKey,
      content: "Newsroom story", urls: ["https://acmenews.example/story"] }));
    expect(websitePages.calls[0]).toEqual(expect.objectContaining({ owner_tip_id: ORG, signer_tip_id: OWNER }));
  });
});

describe("more than one website needs a paid plan", () => {
  const plan = (limit) => ({ enabled: true, reserve: jest.fn(), sitesLimit: jest.fn(async () => ({ sites_limit: limit, plan: limit > 1 ? "Creator Premium" : "Free", upgrade_url: "/plans#websites" })) });
  async function add(fx, domain, kp = fx.keys.owner, tip = OWNER) {
    fx.domainService.register(claimFor({ tipId: tip, privKey: kp.privateKey, domain }));
    const out = await fx.domainService.verify({ domain });
    fx.commitSubmitted();
    return out;
  }

  test("Free verifies a first website and refuses a second with 402 website_site_limit", async () => {
    const verifier = stubVerifier("ok");
    const fx = setup({ sitesPlan: plan(1), verifier });
    await add(fx, "first.example");
    verifier.verify.mockClear();
    await expect(add(fx, "second.example")).rejects.toMatchObject({ status: 402, code: "website_site_limit",
      details: expect.objectContaining({ sites_used: 1, sites_limit: 1, upgrade_url: "/plans#websites" }) });
    expect(verifier.verify).not.toHaveBeenCalled();
    expect(fx.dag.getDomainBinding("second.example")).toBeNull();
  });

  test("re-verifying your own site, or its www. spelling, never takes a second place", async () => {
    const fx = setup({ sitesPlan: plan(1) });
    await add(fx, "first.example");
    await expect(add(fx, "first.example")).resolves.toMatchObject({ verified: true });
    await expect(add(fx, "www.first.example")).resolves.toMatchObject({ verified: true });
  });

  test("a paid plan with 3 websites verifies three and refuses a fourth", async () => {
    const fx = setup({ sitesPlan: plan(3) });
    for (const d of ["a.example", "b.example", "c.example"]) await add(fx, d);
    await expect(add(fx, "d.example")).rejects.toMatchObject({ code: "website_site_limit" });
  });

  test("a lapsed site frees its place", async () => {
    const fx = setup({ sitesPlan: plan(1) });
    bind(fx.dag, "old.example", OWNER, { verifiedAt: nowMs() - DOMAIN_HEALTHY_EXPIRY_MS - 1000 });
    await expect(add(fx, "new.example")).resolves.toMatchObject({ verified: true });
  });

  test("after a downgrade only the oldest sites renew", async () => {
    const fx = setup({ sitesPlan: plan(3) });
    for (const d of ["a.example", "b.example"]) await add(fx, d);
    for (const d of ["a.example", "b.example"]) {
      const b = fx.dag.getDomainBinding(d);
      fx.dag.saveDomainBinding({ ...b, expires_at: nowMs() + 1000 });
    }
    // Same sites, now on Free: the oldest keeps renewing, the other lapses.
    const svc = createDomainService({ dag: fx.dag, config: { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: generateMLDSAKeypair().privateKey },
      submitTx: () => {}, verifier: stubVerifier("ok"), websitePages: plan(1) });
    await expect(svc.renew({ domain: "b.example" })).rejects.toMatchObject({ code: "website_site_limit" });
    await expect(svc.renew({ domain: "a.example" })).resolves.toMatchObject({ renewed: true });
  });

  test("an unreachable billing service lets the site through", async () => {
    const fx = setup({ sitesPlan: { enabled: true, reserve: jest.fn(), sitesLimit: jest.fn(async () => null) } });
    await add(fx, "first.example");
    await expect(add(fx, "second.example")).resolves.toMatchObject({ verified: true });
  });
});

describe("website-pages client", () => {
  const ok = (body) => ({ ok: true, status: 200, text: async () => JSON.stringify(body) });

  test("disabled without url and key", async () => {
    expect(await createWebsitePagesClient({}).reserve({ owner_tip_id: OWNER })).toBeNull();
  });

  test("sends the quota key and returns the answer", async () => {
    const fetch = jest.fn(async () => ok({ allowed: true, used: 3, limit: 100 }));
    const c = createWebsitePagesClient({ url: "https://vp.test/", key: "k1", fetch });
    const a = await c.reserve({ owner_tip_id: OWNER, signer_tip_id: OWNER, domain: "d.example", urls: ["https://d.example/a"] });
    expect(a.allowed).toBe(true);
    expect(fetch.mock.calls[0][0]).toBe("https://vp.test/api/websites/reserve");
    expect(fetch.mock.calls[0][1].headers["X-TIP-Quota-Key"]).toBe("k1");
  });

  test("an outage lets pages through, except a site already known full this month", async () => {
    let up = true;
    const fetch = jest.fn(async () => { if (!up) throw new Error("down"); return ok({ allowed: false, reason: "page_limit", resets_at: Math.floor(nowMs() / 1000) + 3600 }); });
    const c = createWebsitePagesClient({ url: "https://vp.test", key: "k", fetch, log: { warn() {} } });
    expect((await c.reserve({ owner_tip_id: OWNER })).allowed).toBe(false);
    up = false;
    expect(await c.reserve({ owner_tip_id: OWNER })).toEqual(expect.objectContaining({ allowed: false, stale: true }));
    expect(await c.reserve({ owner_tip_id: OTHER })).toBeNull();
  });

  test("a malformed answer counts as unreachable", async () => {
    const c = createWebsitePagesClient({ url: "https://vp.test", key: "k", fetch: async () => ok({ nope: 1 }), log: { warn() {} } });
    expect(await c.reserve({ owner_tip_id: OWNER })).toBeNull();
  });
});

// ─── 6. Verifier never fetches the node's own network ────────────────────────

describe("the verifier's lookup on a real Node connect path", () => {
  test("refuses loopback in both shapes Node asks for", async () => {
    for (const opts of [{ all: true }, {}, 0]) {
      const err = await new Promise((res) => _publicOnlyLookup("localhost", opts, (e) => res(e)));
      expect(err && err.code).toBe("ENONPUBLIC");
    }
  });

  test("returns an array when asked for all addresses, one address otherwise", async () => {
    const dns = require("dns");
    const spy = jest.spyOn(dns, "lookup").mockImplementation((h, o, cb) => cb(null, [{ address: "93.184.216.34", family: 4 }]));
    try {
      const all = await new Promise((res) => _publicOnlyLookup("ok.example", { all: true }, (e, a) => res([e, a])));
      expect(all).toEqual([null, [{ address: "93.184.216.34", family: 4 }]]);
      const one = await new Promise((res) => _publicOnlyLookup("ok.example", {}, (e, a, f) => res([e, a, f])));
      expect(one).toEqual([null, "93.184.216.34", 4]);
    } finally { spy.mockRestore(); }
  });

  test("a real https fetch to a loopback name fails as non-public, not as a broken lookup", async () => {
    await expect(_fetchJson("https://localhost:9/.well-known/tip-protocol.json", { timeoutMs: 2000 }))
      .rejects.toMatchObject({ code: "well_known_unreachable", message: expect.stringMatching(/non-public/) });
    await expect(_fetchJson("https://127.0.0.1:9/x", { timeoutMs: 2000 }))
      .rejects.toMatchObject({ message: expect.stringMatching(/non-public/) });
  });
});

describe("isNonPublicAddress", () => {
  test.each([
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "224.0.0.1", "198.18.0.1", "::1", "::", "fd00::1", "fe80::1", "::ffff:10.0.0.1",
  ])("%s is refused", (a) => expect(isNonPublicAddress(a)).toBe(true));

  test.each(["8.8.8.8", "1.1.1.1", "172.32.0.1", "52.87.175.253", "2606:4700:4700::1111"])(
    "%s is public", (a) => expect(isNonPublicAddress(a)).toBe(false));
});

afterAll(() => { for (const [k, v] of Object.entries(_envBefore)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });
