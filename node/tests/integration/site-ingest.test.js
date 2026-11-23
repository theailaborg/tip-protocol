/**
 * @file tests/integration/site-ingest.test.js
 * @description Off-DAG ingest of committed site snapshots, with the pack that
 * tip-site-archiver builds from Website Archive Test 1 and library 2.8.0:
 * the pack is checked against the signed record (hash, header, root, page
 * count), indexed, served page by page with a Merkle proof, compared with the
 * previous snapshot (changed / kept), and found by similar search.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const GATE = 1790000000000; // 2026-09-21: before every real now in these tests
const _envBefore = {
  TIP_WEBSITE_PROTECTION_ACTIVATION_MS: process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS,
  TIP_SITE_SNAPSHOT_ACTIVATION_MS: process.env.TIP_SITE_SNAPSHOT_ACTIVATION_MS,
};
process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS = "1";
process.env.TIP_SITE_SNAPSHOT_ACTIVATION_MS = String(GATE);

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const web = require("tip-content-fingerprint/src/web");
const { initCrypto, generateMLDSAKeypair, shake256, tipNormalize } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { TIP_ID_TYPES, DOMAIN_HEALTHY_EXPIRY_MS, TX_TYPES, SITE_INGEST } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { withTxId } = require(path.join(SRC, "services", "helpers"));
const { createSiteService } = require(path.join(SRC, "services", "site-service"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createSiteIngest, pageKeyFor, checkPack } = require(path.join(SRC, "perceptual", "site-ingest"));
const { pageProofs, decodeProof } = require(path.join(SRC, "perceptual", "site-pack"));
const { matchSitePassages } = require(path.join(SRC, "perceptual", "similar"));
const snapshotSchema = require(path.join(SRC, "schemas", "site-snapshot"));
const contentSchema = require(path.join(SRC, "schemas", "content-register"));

const PACK = new Uint8Array(fs.readFileSync(path.join(__dirname, "..", "fixtures", "site", "theailab-test-1.pack.json.gz")));
const TEST1 = {
  root: "15bb6f0d2d36256e0250b92e318c00f6098538002974be2ee62abafe68d01f8c",
  template_hash: "b833d6114baaedd115ae77ea80b81032a3d67e2d34ece8549a720aa174ade8d4",
  pack_hash: "a7bef976a68370a697800bf94da3ab8ba0669edc28b235201f4e101c5b0a3a79",
  page_count: 30,
};
const SOURCE = "https://archive.test";
const VP_ID = "tip://vp/US-0e7db4040667073a";
const NODE_ID = "tip://node/n1";
const OWNER = "tip://id/US-aaaaaaaaaaaaaaaa";
const POSTER = "tip://id/US-eeeeeeeeeeeeeeee";
// theailab.org is a shared host (SHARED_HOST_DOMAINS) and cannot be bound, so the
// commit-path tests carry the same 30 pages under a protectable test domain.
const SITE = "ailab-archive.example";
const MIN = 60 * 1000;
const hex = (c) => c.repeat(64);

beforeAll(async () => { await initCrypto(); });
afterAll(() => {
  for (const [k, v] of Object.entries(_envBefore)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

const { pages: PACK_LINES } = web.readPack(PACK);

function _rename(lines) {
  for (const l of lines) l.url = l.url.replace(/^https?:\/\/(www\.)?theailab\.org/, (m, www) => `https://${www || ""}${SITE}`);
  return lines;
}

// The Test 1 lines under SITE after `mutate`, packed, with the root and page
// count the archiver would sign for them.
function repack({ seq = 1, domain = SITE, mutate = (lines) => lines } = {}) {
  const lines = mutate(_rename(PACK_LINES.map((l) => JSON.parse(JSON.stringify(l)))));
  const { bytes, hash } = web.buildPack({ domain, seq, pages: lines });
  let root = null;   // null when the library refuses the pages (a URL twice)
  try { root = web.packRoot(lines); } catch { /* the test signs a root of its own */ }
  return { bytes, hash, root, page_count: lines.filter((l) => !l.skipped).length, lines };
}

// Serves `routes` (pack hash -> bytes, or a status number) for each source in order.
function fakeFetch(routes) {
  const calls = [];
  async function fetchImpl(url) {
    calls.push(url);
    const r = routes[url];
    if (r === undefined) return new Response("not found", { status: 404 });
    if (r instanceof Error) throw r;
    if (typeof r === "number") return new Response("err", { status: r });
    return new Response(r, { status: 200, headers: { "content-length": String(r.length) } });
  }
  fetchImpl.calls = calls;
  return fetchImpl;
}

function setup({ routes = {}, sources = [SOURCE], clock = null } = {}) {
  const dag = initDAG({ dbPath: ":memory:" });
  const keys = { owner: generateMLDSAKeypair(), poster: generateMLDSAKeypair(), node: generateMLDSAKeypair() };
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: keys.node.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  for (const [tipId, kp] of [[OWNER, keys.owner], [POSTER, keys.poster]]) {
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: kp.publicKey,
      vp_id: VP_ID, verification_tier: "T1", tip_id_type: TIP_ID_TYPES.PERSONAL, founding: false, status: "active",
      registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
    });
    dag.setScore(tipId, 750, 0, 1767225600000);
  }
  const t = nowMs();
  dag.saveDomainBinding({
    domain: SITE, tip_id: OWNER, binding_state: "verified", method: "dns", claimed_at: t - 1000, verified_at: t,
    expires_at: t + DOMAIN_HEALTHY_EXPIRY_MS, consecutive_failures: 0, node_id: NODE_ID,
    claim_signature: "00", binding_signature: "00", tx_id: `tx-${SITE}`,
  });
  const fetchImpl = fakeFetch(routes);
  const log = { info() {}, warn: jest.fn(), error() {} };
  const siteIngest = createSiteIngest({ dag, sources, fetchImpl, log, ...(clock ? { now: () => clock.t } : {}) });
  const handler = createCommitHandler({ dag, nodeId: NODE_ID, siteIngest });
  const siteService = createSiteService({ dag, submitTx: () => {}, websitePages: null });
  return { dag, keys, fetchImpl, log, siteIngest, handler, siteService };
}

let round = 10;
// Commits a snapshot of `pack` (bytes + root + page_count) and waits for its ingest.
async function commitSnapshot(fx, pack, { seq = 1, prev = null, ts = nowMs(), cert = ts, capturedAt = ts - MIN, root = pack.root, visibility = null } = {}) {
  const p = snapshotSchema.buildSigningPayload({
    domain: SITE, seq, prev_snapshot_tx: prev, root, page_count: pack.page_count,
    template_hash: TEST1.template_hash, profile: "cf-web-1", wacz_hash: hex("c"),
    pack_hash: shake256(pack.bytes), ai_signals_hash: hex("e"), captured_at: capturedAt, signer_tip_id: OWNER, visibility,
  });
  const tx = withTxId({ tx_type: TX_TYPES.SITE_SNAPSHOT, timestamp: ts, data: snapshotSchema.buildTxData(p, null), signature: snapshotSchema.sign(p, fx.keys.owner.privateKey) }, fx.dag);
  const res = fx.handler.commitOrderedTxs([tx], round++, { certTimestamp: cert });
  if (res.committed !== 1) throw new Error(`snapshot not committed: ${JSON.stringify(fx.dag.getTxRejection(tx.tx_id))}`);
  await fx.siteIngest.idle();
  return tx;
}

const base = repack();
const real = { bytes: base.bytes, root: base.root, page_count: base.page_count };
const LINES = base.lines;
const firstUrl = LINES[0].url;
const route = (pack) => `${SOURCE}/api/archive/pack/${shake256(pack.bytes)}`;

// ════════════════════════════════════════════════════════════════════════════

describe("pack checks and indexing", () => {
  test("the archiver's Test 1 pack matches its theailab.org record: hash, header, 30 pages, golden root", () => {
    expect(shake256(PACK)).toBe(TEST1.pack_hash);
    const record = { domain: "theailab.org", seq: 1, pack_hash: TEST1.pack_hash, root: TEST1.root, page_count: 30 };
    expect(checkPack(record, PACK)).toHaveLength(30);
    const code = (r) => { try { checkPack(r, PACK); return null; } catch (e) { return [e.code, e.permanent]; } };
    expect(code({ ...record, pack_hash: hex("0") })).toEqual(["pack_hash_mismatch", false]);
    expect(code({ ...record, seq: 2 })).toEqual(["pack_header_mismatch", true]);
    expect(code({ ...record, domain: SITE })).toEqual(["pack_header_mismatch", true]);
    expect(code({ ...record, page_count: 29 })).toEqual(["pack_root_mismatch", true]);
    expect(code({ ...record, root: hex("a") })).toEqual(["pack_root_mismatch", true]);
  });

  test("a committed snapshot is fetched, indexed, and served page by page with a proof the node checks", async () => {
    const fx = setup({ routes: { [route(real)]: real.bytes } });
    const tx = await commitSnapshot(fx, real);

    const st = await fx.dag.getSiteIngest(tx.tx_id);
    expect(st).toEqual(expect.objectContaining({ state: "done", pages: 30, offsite: 0, source: SOURCE, attempts: 1, last_error: null }));
    expect(await fx.dag.listSitePages(tx.tx_id)).toHaveLength(30);
    expect((await fx.siteService.getSnapshot(tx.tx_id)).ingest).toEqual({ state: "done", pages: 30, offsite: 0, attempts: 1, last_error: null });

    const page = await fx.siteService.getPage(SITE, { url: firstUrl });
    expect(page).toEqual(expect.objectContaining({ domain: SITE, url: firstUrl, seq: 1, tx_id: tx.tx_id, root: real.root, changed: null, kept: null }));
    expect(web.verifyPage(firstUrl, page.text_hash, page.proof, real.root)).toBe(true);
    expect(web.verifyPage(LINES[1].url, page.text_hash, page.proof, real.root)).toBe(false);
    await expect(fx.siteService.getPage(SITE, { url: "https://other.example/" })).rejects.toEqual(expect.objectContaining({ status: 404, code: "site_page_not_found" }));

    const key = pageKeyFor(tx.tx_id, firstUrl);
    expect(JSON.parse((await fx.dag.getPerceptualFingerprint(key, 0)).fingerprint).profile).toBe("cf-text-3");
  });

  test("a source that is down or serves other bytes is skipped for the next one", async () => {
    const path_ = `/api/archive/pack/${shake256(real.bytes)}`;
    const fx = setup({
      sources: ["https://a.test", "https://b.test", "https://c.test"],
      routes: { [`https://a.test${path_}`]: 503, [`https://b.test${path_}`]: new Uint8Array([1, 2, 3]), [`https://c.test${path_}`]: real.bytes },
    });
    const tx = await commitSnapshot(fx, real);
    expect((await fx.dag.getSiteIngest(tx.tx_id))).toEqual(expect.objectContaining({ state: "done", source: "https://c.test" }));
    expect(fx.fetchImpl.calls).toHaveLength(3);
  });

  test("a pack that does not give the signed root, or names another snapshot, is refused for good", async () => {
    const wrongRoot = setup({ routes: { [route(real)]: real.bytes } });
    const tx = await commitSnapshot(wrongRoot, real, { root: hex("a") });
    const st = await wrongRoot.dag.getSiteIngest(tx.tx_id);
    expect(st).toEqual(expect.objectContaining({ state: "mismatch", next_attempt_at: Number.MAX_SAFE_INTEGER }));
    expect(st.last_error).toMatch(/^pack_root_mismatch/);
    expect(await wrongRoot.dag.listSitePages(tx.tx_id)).toHaveLength(0);
    expect((await wrongRoot.siteService.getSnapshot(tx.tx_id)).ingest.state).toBe("mismatch");
    await expect(wrongRoot.siteService.getPage(SITE, { url: firstUrl })).rejects.toEqual(expect.objectContaining({ status: 422, code: "site_snapshot_pack_mismatch" }));
    await wrongRoot.siteIngest.retryDue();
    await wrongRoot.siteIngest.idle();
    expect((await wrongRoot.dag.getSiteIngest(tx.tx_id)).attempts).toBe(1);

    const otherSeq = repack({ seq: 2 });
    const fx = setup({ routes: { [route(otherSeq)]: otherSeq.bytes } });
    const tx2 = await commitSnapshot(fx, otherSeq);
    expect(await fx.dag.getSiteIngest(tx2.tx_id)).toEqual(expect.objectContaining({ state: "mismatch", last_error: expect.stringMatching(/^pack_header_mismatch/) }));

    // A URL twice in one pack: the owner could prove either text, so packRoot refuses it.
    const twice = repack({ mutate: (lines) => { lines[5].url = lines[4].url; return lines; } });
    const dup = setup({ routes: { [route(twice)]: twice.bytes } });
    const txd = await commitSnapshot(dup, { ...twice, root: real.root, page_count: 30 });
    expect(await dup.dag.getSiteIngest(txd.tx_id)).toEqual(expect.objectContaining({ state: "mismatch", last_error: expect.stringMatching(/^pack_root_mismatch/) }));
  });

  test("when no source has the pack, ingest retries with backoff", async () => {
    const clock = { t: nowMs() };
    const routes = { [route(real)]: new Error("connect ECONNREFUSED") };
    const fx = setup({ routes, clock });
    const tx = await commitSnapshot(fx, real);
    const st = await fx.dag.getSiteIngest(tx.tx_id);
    expect(st).toEqual(expect.objectContaining({ state: "failed", attempts: 1, next_attempt_at: clock.t + SITE_INGEST.RETRY_BASE_MS }));
    expect(st.last_error).toMatch(/^pack_unavailable/);

    await fx.siteIngest.retryDue();
    await fx.siteIngest.idle();
    expect((await fx.dag.getSiteIngest(tx.tx_id)).attempts).toBe(1);   // not due yet

    routes[route(real)] = real.bytes;
    clock.t += SITE_INGEST.RETRY_BASE_MS;
    await fx.siteIngest.retryDue();
    await fx.siteIngest.idle();
    expect(await fx.dag.getSiteIngest(tx.tx_id)).toEqual(expect.objectContaining({ state: "done", attempts: 2, pages: 30 }));
  });

  test("a snapshot installed without passing this node's commit path is found by reconcile", async () => {
    const fx = setup({ routes: { [route(real)]: real.bytes } });
    const t = nowMs();
    fx.dag.saveSiteSnapshot({
      tx_id: hex("4"), domain: SITE, seq: 1, prev_snapshot_tx: null, root: real.root, page_count: 30,
      template_hash: TEST1.template_hash, profile: "cf-web-1", wacz_hash: hex("c"), pack_hash: shake256(real.bytes),
      ai_signals_hash: hex("e"), captured_at: t - MIN, signer_tip_id: OWNER, witness_vp_id: null, registered_at: t,
    });
    await fx.siteIngest.reconcile();
    await fx.siteIngest.idle();
    expect((await fx.dag.getSiteIngest(hex("4"))).state).toBe("done");
  });

  test("an off-site page stays in the root but is never indexed or served", async () => {
    const away = "https://accounts.example.com/login";
    const pack = repack({ mutate: (lines) => { lines[3].url = away; return lines; } });
    const fx = setup({ routes: { [route(pack)]: pack.bytes } });
    const tx = await commitSnapshot(fx, pack);
    expect(await fx.dag.getSiteIngest(tx.tx_id)).toEqual(expect.objectContaining({ state: "done", pages: 30, offsite: 1 }));
    expect(fx.log.warn).toHaveBeenCalledWith(expect.stringContaining("1 off-site page(s)"));
    expect(await fx.dag.getPerceptualFingerprint(pageKeyFor(tx.tx_id, away), 0)).toBeNull();
    await expect(fx.siteService.getPage(SITE, { url: away })).rejects.toEqual(expect.objectContaining({ status: 404, code: "site_page_not_found" }));
    const page = await fx.siteService.getPage(SITE, { url: firstUrl });
    expect(web.verifyPage(firstUrl, page.text_hash, page.proof, pack.root)).toBe(true);
  });
});

describe("versions", () => {
  test("the next snapshot reports, per page, whether it changed and the share of paragraph keys kept", async () => {
    const t0 = nowMs() - 40 * MIN;
    const changedUrl = LINES[2].url;
    const v2 = repack({
      seq: 2,
      mutate: (lines) => {
        const l = lines[2];
        l.paragraph_keys = l.paragraph_keys.slice(0, Math.floor(l.paragraph_keys.length / 2));
        l.page_hash = hex("1");
        l.text_hash = hex("2");
        return lines;
      },
    });
    const fx = setup({ routes: { [route(real)]: real.bytes, [route(v2)]: v2.bytes } });
    const tx1 = await commitSnapshot(fx, real, { ts: t0, capturedAt: t0 - MIN });
    await commitSnapshot(fx, v2, { seq: 2, prev: tx1.tx_id, ts: t0 + 20 * MIN, capturedAt: t0 + 15 * MIN });

    const before = LINES[2].paragraph_keys.length;
    const page = await fx.siteService.getPage(SITE, { url: changedUrl });
    expect(page).toEqual(expect.objectContaining({ seq: 2, changed: true }));
    expect(page.kept).toBeCloseTo(Math.floor(before / 2) / before, 6);
    expect(await fx.siteService.getPage(SITE, { url: firstUrl })).toEqual(expect.objectContaining({ seq: 2, changed: false, kept: 1 }));
    expect(web.verifyPage(changedUrl, page.text_hash, page.proof, v2.root)).toBe(true);

    const old = await fx.siteService.getPage(SITE, { url: changedUrl, at: String(t0) });
    expect(old).toEqual(expect.objectContaining({ seq: 1, text_hash: LINES[2].text_hash }));
    await expect(fx.siteService.getPage(SITE, { url: changedUrl, at: String(t0 - 10 * MIN) }))
      .rejects.toEqual(expect.objectContaining({ status: 404, code: "site_snapshot_not_found" }));
  });
});

describe("similar", () => {
  test("paragraph keys find the page, and keys other sites also hold count for less", async () => {
    const fx = setup({ routes: { [route(real)]: real.bytes } });
    const tx = await commitSnapshot(fx, real);
    const line = LINES.find((l) => l.paragraph_keys.length >= 20);
    const key = pageKeyFor(tx.tx_id, line.url);
    const copied = line.paragraph_keys.slice(0, 10);

    const alone = (await matchSitePassages(fx.dag, copied, POSTER)).find((h) => h.ctid === key);
    expect(alone).toEqual(expect.objectContaining({ modality: "site_text", shared_keys: 10, weighted: 10, page_keys: line.paragraph_keys.length }));

    fx.dag.saveDocumentPassages(copied.slice(0, 4).map((k) => ({
      profile: SITE_INGEST.PASSAGE_PROFILE, passage_key: k, owner: "tip://id/US-ffffffffffffffff", ctid: `site:${hex("9")}:0000000000000000`, component_idx: 0, unit: null,
    })));
    const shared = (await matchSitePassages(fx.dag, copied, POSTER)).find((h) => h.ctid === key);
    expect(shared.weighted).toBe(8);   // 6 keys only this site holds + 4 keys two sites hold at 1/2
    expect(shared.score).toBeLessThan(alone.score);
  });

  test("a post with a page's text is warned at registration with the archived page", async () => {
    const fx = setup({ routes: { [route(real)]: real.bytes } });
    const tx = await commitSnapshot(fx, real);
    const line = LINES.find((l) => l.text && l.text.tier === "char");
    const scoring = initScoring(fx.dag, {});
    const contentService = createContentService({
      dag: fx.dag, scoring,
      config: { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: fx.keys.node.privateKey, mediaLimits: { max_text_bytes: 1_000_000, max_image_bytes: 0, max_video_bytes: 0, max_audio_bytes: 0 } },
      submitTx: (t) => { fx.dag.addTx(t); fx.dag.saveMempoolTx(t); },
    });
    const items = [{ kind: "text", role: "caption", perceptual: line.text }];
    const fingerprints = { profile: "cf-fingerprints-1", count: 1, encoding: "gzip+base64", data: zlib.gzipSync(Buffer.from(JSON.stringify(items))).toString("base64") };
    const content = "A post that reposts a theailab.org page.";
    const fields = {
      origin_code: "OH", registered_urls: ["https://blog.example.net/copy/"], extras: {},
      authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: POSTER, tip_id_type: "personal" }],
      signer_tip_id: POSTER, attribution_mode: "self", fingerprint_commit: contentSchema.fingerprintsCommit(fingerprints),
    };
    const payload = contentSchema.buildSigningPayload(fields, shake256(tipNormalize(content)));
    const out = await contentService.register({
      ...fields, cna_version: contentSchema.CURRENT_CNA_VERSION, content, content_type: "text",
      signature: contentSchema.sign(payload, fx.keys.poster.privateKey), fingerprints,
    });
    expect(out.near_duplicates).toEqual([]);
    expect(out.near_duplicate_sites).toEqual([expect.objectContaining({
      domain: SITE, url: line.url, seq: 1, snapshot_tx: tx.tx_id, signer_tip_id: OWNER,
      similarity: expect.objectContaining({ modality: "text", score: 1 }),
    })]);
  });
});

describe("off the consensus thread", () => {
  afterEach(() => jest.restoreAllMocks());

  test("the pack is unzipped, parsed and checked on the worker, never on the main thread", async () => {
    const fx = setup({ routes: { [route(real)]: real.bytes } });
    const readPack = jest.spyOn(web, "readPack");
    const packRoot = jest.spyOn(web, "packRoot");
    const tx = await commitSnapshot(fx, real);
    expect(await fx.dag.getSiteIngest(tx.tx_id)).toEqual(expect.objectContaining({ state: "done", pages: 30 }));
    expect(readPack).not.toHaveBeenCalled();
    expect(packRoot).not.toHaveBeenCalled();
  });

  test("each page keeps the same proof the library builds, so a read never rebuilds the tree", async () => {
    const fx = setup({ routes: { [route(real)]: real.bytes } });
    const tx = await commitSnapshot(fx, real);
    const rows = await fx.dag.listSitePages(tx.tx_id);
    const leaves = LINES.map((l) => ({ url: l.url, leaf: web.leafHash(l.url, l.text_hash) }));
    for (const r of rows) expect(decodeProof(r.proof)).toEqual(web.merkleProof(leaves, r.url));
  });

  test("proofs match the library for odd and single-page trees, and a page that does not verify gets none", () => {
    for (const n of [1, 2, 7, 29]) {
      const lines = LINES.slice(0, n);
      const record = { root: web.packRoot(lines) };
      const leaves = lines.map((l) => ({ url: l.url, leaf: web.leafHash(l.url, l.text_hash) }));
      pageProofs(record, lines).forEach((p, i) => expect(decodeProof(p)).toEqual(web.merkleProof(leaves, lines[i].url)));
    }
    expect(pageProofs({ root: hex("a") }, LINES.slice(0, 3))).toEqual([null, null, null]);
    expect(decodeProof(null)).toBeNull();
    expect(decodeProof("x".repeat(65))).toBeNull();
    expect(decodeProof("l" + hex("a") + "r")).toBeNull();
  });
});

describe("private snapshots", () => {
  test("the record commits but its pack is never fetched, and a page read says why", async () => {
    const fx = setup({ routes: { [route(real)]: real.bytes } });
    const tx = await commitSnapshot(fx, real, { visibility: "private" });

    expect(fx.fetchImpl.calls).toHaveLength(0);
    expect(fx.dag.getSiteSnapshot(tx.tx_id).visibility).toBe("private");
    expect(await fx.dag.getSiteIngest(tx.tx_id)).toEqual(expect.objectContaining({ state: "private", next_attempt_at: Number.MAX_SAFE_INTEGER }));
    expect(await fx.dag.listSitePages(tx.tx_id)).toHaveLength(0);

    const snap = await fx.siteService.getSnapshot(tx.tx_id);
    expect(snap).toEqual(expect.objectContaining({ visibility: "private" }));
    expect(snap.ingest.state).toBe("private");
    expect(fx.siteService.listSnapshots(SITE).snapshots[0].visibility).toBe("private");
    await expect(fx.siteService.getPage(SITE, { url: firstUrl }))
      .rejects.toEqual(expect.objectContaining({ status: 404, code: "site_snapshot_private" }));

    await fx.siteIngest.reconcile();
    await fx.siteIngest.idle();
    expect(fx.fetchImpl.calls).toHaveLength(0);
  });

  test("a public snapshot after a private one is indexed, with nothing earlier to compare", async () => {
    const t0 = nowMs() - 40 * MIN;
    const v2 = repack({ seq: 2 });
    const fx = setup({ routes: { [route(real)]: real.bytes, [route(v2)]: v2.bytes } });
    const tx1 = await commitSnapshot(fx, real, { ts: t0, capturedAt: t0 - MIN, visibility: "private" });
    const tx2 = await commitSnapshot(fx, v2, { seq: 2, prev: tx1.tx_id, ts: t0 + 20 * MIN, capturedAt: t0 + 15 * MIN });

    expect(fx.dag.getSiteSnapshot(tx2.tx_id).visibility).toBeUndefined();
    expect(fx.fetchImpl.calls).toEqual([route(v2)]);
    expect(await fx.siteService.getPage(SITE, { url: firstUrl })).toEqual(expect.objectContaining({ seq: 2, changed: null, kept: null }));
    await expect(fx.siteService.getPage(SITE, { url: firstUrl, at: String(t0) }))
      .rejects.toEqual(expect.objectContaining({ code: "site_snapshot_private" }));
  });
});
