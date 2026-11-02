/**
 * @file tests/perceptual/document-match.test.js
 * @description Similar documents (cf-doc-1) on every backend, with real library
 * fingerprints (tests/fixtures/documents): copies and converted copies are
 * listed first, a copied chapter next, documents sharing only common text last
 * and weighted by how many owners hold it, an unrelated document never; scans
 * match by page image; a document and a post find each other by text.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { MemoryStore, SQLiteStore } = require("../../src/dag");
const { KnexAdapter } = require("../../src/db/knex-adapter");
const { ingestFingerprint, buildIngestRows } = require("../../src/perceptual/ingest");
const { findSimilarCtids } = require("../../src/perceptual/similar");
const documentIndex = require("../../src/perceptual/document-index");
const textIndex = require("../../src/perceptual/text-index");

const fixture = (name) => require(`../fixtures/documents/${name}.json`);
const ctid = (name) => `tip://c/OH-doc-${name}`;

const logStub = { info() { }, warn() { }, error() { } };
const tmpDirs = [];
const knexes = [];
async function knexStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-doc-match-"));
  tmpDirs.push(dir);
  const a = new KnexAdapter("better-sqlite3", { dbName: path.join(dir, "doc.db") }, logStub);
  await a.migrate();
  knexes.push(a);
  return a;
}
const BACKENDS = [
  ["MemoryStore", async () => new MemoryStore()],
  ["SQLiteStore", async () => new SQLiteStore(":memory:")],
  ["KnexAdapter", knexStore],
];

afterEach(() => {
  documentIndex.configure({});
  textIndex.configure({});
});
afterAll(() => {
  for (const a of knexes) { try { a.close(); } catch { /* ignore */ } }
  for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true });
});

function saveRecord(dag, id, owner) {
  dag.saveContent({
    ctid: id, origin_code: "OH", content_hash: "ab".repeat(32), author_tip_id: owner, signer_tip_id: owner,
    authors: [{ tip_id: owner }], attribution_mode: "self", extras: {}, cna_version: "CNA-2.2", status: "registered",
    registered_at: 1793448000000, tx_id: `tx-${id}`, registered_urls: [], media: [],
  });
}

async function add(dag, name, owner, fp = fixture(name), componentIdx = 0) {
  saveRecord(dag, ctid(name), owner);
  await ingestFingerprint(dag, fp, { ctid: ctid(name), componentIdx, createdAt: 1, owner });
}

async function similar(dag, name) {
  await dag.flush();
  return findSimilarCtids(dag, ctid(name), { limit: 20 });
}

const byCtid = (hits) => new Map(hits.map((h) => [h.ctid, h]));

describe.each(BACKENDS)("%s", (_name, make) => {
  async function corpus({ licenceOwners = ["tip://id/US-l1", "tip://id/US-l2", "tip://id/US-l3"] } = {}) {
    const dag = await make();
    await add(dag, "original", "tip://id/US-author");
    await add(dag, "resaved", "tip://id/US-r");
    await add(dag, "exported", "tip://id/US-e");
    await add(dag, "chapter", "tip://id/US-c");
    await add(dag, "reworded", "tip://id/US-w");
    await add(dag, "unrelated", "tip://id/US-u");
    await add(dag, "licence_a", licenceOwners[0]);
    await add(dag, "licence_b", licenceOwners[1]);
    await add(dag, "licence_c", licenceOwners[2]);
    return dag;
  }

  test("copies first, then the copied chapter and the reworded copy, common text last, unrelated never", async () => {
    const dag = await corpus();
    const hits = await similar(dag, "original");
    const order = hits.map((h) => h.ctid);
    const at = (n) => order.indexOf(ctid(n));

    expect(at("unrelated")).toBe(-1);
    for (const n of ["resaved", "exported", "chapter", "reworded", "licence_a", "licence_b", "licence_c"]) expect(at(n)).toBeGreaterThanOrEqual(0);
    expect(Math.max(at("resaved"), at("exported"))).toBeLessThan(at("chapter"));
    expect(at("chapter")).toBeLessThan(at("reworded"));
    expect(at("reworded")).toBeLessThan(Math.min(at("licence_a"), at("licence_b"), at("licence_c")));

    const m = byCtid(hits);
    const exported = m.get(ctid("exported"));
    expect(exported.modality).toBe("document");
    expect(exported.metric).toMatchObject({ same_wording: true, cross_format: true });
    expect(exported.metric.shared_text).toMatchObject({ a_in_b: 1, b_in_a: 1 });
    const chapter = m.get(ctid("chapter")).metric.shared_text;
    expect(chapter.chars).toBeGreaterThan(4000);
    expect(chapter.at_a).toEqual([[2, 3]]);
    // Besides the two compared, four owners hold the licence (two copies, two
    // licence documents): each of its passages weighs 1 / (1 + 4).
    const licence = m.get(ctid("licence_a")).metric.shared_text;
    expect(licence.score / licence.chars).toBeCloseTo(1 / 5, 2);
  });

  test("owners are counted, not records: one owner's three licence documents count once", async () => {
    const spread = byCtid(await similar(await corpus(), "original")).get(ctid("licence_a"));
    const one = "tip://id/US-same";
    const single = byCtid(await similar(await corpus({ licenceOwners: [one, one, one] }), "original")).get(ctid("licence_a"));
    expect(single.metric.shared_text.chars).toBe(spread.metric.shared_text.chars);
    // Only the two copies' owners are left besides the two compared.
    expect(single.metric.shared_text.score / single.metric.shared_text.chars).toBeCloseTo(1 / 3, 2);
    expect(single.score).toBeGreaterThan(spread.score);
  });

  test("passage keys held by more owners than the cap find no candidates", async () => {
    documentIndex.configure({ maxKeyOwners: 2 });
    const order = (await similar(await corpus(), "original")).map((h) => h.ctid);
    expect(order).toContain(ctid("resaved"));   // same wording
    expect(order).toContain(ctid("chapter"));   // its passages are held by two owners
    for (const n of ["licence_a", "licence_b", "licence_c"]) expect(order).not.toContain(ctid(n));
  });

  test("a copy found from the other side: the chapter lists every document holding it first", async () => {
    const order = (await similar(await corpus(), "chapter")).map((h) => h.ctid);
    expect(new Set(order.slice(0, 3))).toEqual(new Set([ctid("original"), ctid("resaved"), ctid("exported")]));
    expect(order).not.toContain(ctid("unrelated"));
  });

  test("scans match by page image; a document without text gets no text row", async () => {
    const dag = await make();
    await add(dag, "scan", "tip://id/US-s1");
    await add(dag, "scan_copy", "tip://id/US-s2");
    await add(dag, "original", "tip://id/US-author");
    const hits = await similar(dag, "scan");
    expect(hits.map((h) => h.ctid)).toEqual([ctid("scan_copy")]);
    expect(hits[0].metric.textless_pages).toEqual({ a: 2, b: 2, shared: 2 });
    expect(await dag.findDocumentsByTextHash("cf-doc-1", fixture("scan").text_hash)).toEqual([]);
  });

  test("a scanned page and the same image posted alone find each other", async () => {
    const dag = await make();
    await add(dag, "scan", "tip://id/US-s1");
    const page = fixture("scan").textless_pages[0];
    saveRecord(dag, ctid("photo"), "tip://id/US-p");
    await ingestFingerprint(dag, { profile: "cf-image-1", kind: "image", pdq: page.pdq, quality: page.quality }, { ctid: ctid("photo"), owner: "tip://id/US-p" });
    const fromScan = await similar(dag, "scan");
    expect(fromScan).toEqual([expect.objectContaining({ ctid: ctid("photo"), modality: "image" })]);
    const fromPhoto = await similar(dag, "photo");
    expect(fromPhoto).toEqual([expect.objectContaining({ ctid: ctid("scan"), modality: "image" })]);
  });

  test("a post with a document's text and the document find each other", async () => {
    const dag = await make();
    await add(dag, "licence_a", "tip://id/US-l1");
    saveRecord(dag, ctid("post"), "tip://id/US-p");
    await ingestFingerprint(dag, fixture("licence_a").text, { ctid: ctid("post"), owner: "tip://id/US-p" });
    const fromPost = await similar(dag, "post");
    expect(fromPost).toEqual([expect.objectContaining({ ctid: ctid("licence_a"), modality: "text", score: 1 })]);
    const fromDoc = await similar(dag, "licence_a");
    expect(fromDoc).toEqual([expect.objectContaining({ ctid: ctid("post"), modality: "text", score: 1 })]);
  });

  test("a band rebuild covers documents' own text", async () => {
    const dag = await make();
    await add(dag, "original", "tip://id/US-author");
    await add(dag, "reworded", "tip://id/US-w");
    await dag.flush();
    await textIndex.rebuild(dag, "b42r3");
    expect(textIndex.status(dag, "b42r3")).toMatchObject({ state: "complete", texts: 2, bands: 84 });
    textIndex.configure({ scheme: "b42r3" });
    const hits = await similar(dag, "original");
    expect(hits.map((h) => h.ctid)).toEqual([ctid("reworded")]);
  });

  test("index rows for a document: text, one passage row per distinct key, page images", async () => {
    const rows = buildIngestRows(fixture("original"), { ctid: "c", owner: "o" });
    expect(rows.document.text).toMatchObject({ ctid: "c", profile: "cf-doc-1", text_hash: fixture("original").text_hash, chars: fixture("original").chars_covered });
    expect(new Set(rows.document.passages.map((p) => p.passage_key)).size).toBe(rows.document.passages.length);
    expect(rows.bands).toHaveLength(32);
    expect(buildIngestRows(fixture("scan"), { ctid: "s", owner: "o" }).codes).toHaveLength(2);
    expect(() => buildIngestRows(fixture("original"), { ctid: "c" })).toThrow(/owner/);
  });
});
