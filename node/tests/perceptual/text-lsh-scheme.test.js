/**
 * @file tests/perceptual/text-lsh-scheme.test.js
 * @description Text LSH band schemes: each scheme keeps its own band rows, the
 * configured scheme answers, a shadow scheme is indexed and timed but never
 * answers, and an index the node has not built is rebuilt in the background
 * (resuming after a restart) before it may answer.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { PROFILE: TEXT_PROFILE } = require("tip-content-fingerprint/src/text/constants");
const { jaccardEstimate } = require("tip-content-fingerprint/src/text/compare");
const { MemoryStore, SQLiteStore } = require("../../src/dag");
const { KnexAdapter } = require("../../src/db/knex-adapter");
const { log } = require("../../src/logger");
const textIndex = require("../../src/perceptual/text-index");
const { buildIngestRows, ingestFingerprint } = require("../../src/perceptual/ingest");
const { matchText } = require("../../src/perceptual/matcher");

const mkText = (vals) => ({ profile: TEXT_PROFILE, kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash: vals });
const A = Array.from({ length: 128 }, (_, i) => (i * 7 + 13) % 100000);
// 45 of 128 values kept (about 0.35): b42r3 band 0 (values 0-2) survives whole,
// while every run of 4 keeps at least one changed value, so no b32r4 band does.
const KEPT = new Set([0, 1, 2]);
for (let p = 4; p < 128; p++) if (p % 4 === 1 || (p % 4 === 2 && p < 48)) KEPT.add(p);
const REWORDED = A.map((v, i) => (KEPT.has(i) ? v : v + 900000));
const B42 = `${TEXT_PROFILE}/b42r3`;

const logStub = { info() { }, warn() { }, error() { } };
const tmpDirs = [];
const knexes = [];
async function knexStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-text-lsh-"));
  tmpDirs.push(dir);
  const a = new KnexAdapter("better-sqlite3", { dbName: path.join(dir, "lsh.db") }, logStub);
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
  textIndex.configure({});
  jest.restoreAllMocks();
});
afterAll(() => {
  for (const a of knexes) { try { a.close(); } catch { /* ignore */ } }
  for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true });
});

const settle = () => new Promise((r) => setImmediate(r));

describe("schemes", () => {
  test("bands follow the scheme: 32 under the bare profile for b32r4, 42 under its own for b42r3", () => {
    const b32 = textIndex.bandRows(mkText(A), "c1", ["b32r4"]);
    const b42 = textIndex.bandRows(mkText(A), "c1", ["b42r3"]);
    expect(b32).toHaveLength(32);
    expect(new Set(b32.map((b) => b.profile))).toEqual(new Set([TEXT_PROFILE]));
    expect(b42).toHaveLength(42);
    expect(new Set(b42.map((b) => b.profile))).toEqual(new Set([B42]));
    expect(buildIngestRows(mkText(A), { ctid: "c1" }).bands).toHaveLength(32);
    textIndex.configure({ shadow: "b42r3" });
    expect(buildIngestRows(mkText(A), { ctid: "c1" }).bands).toHaveLength(74);
  });

  test("an unknown scheme fails at boot naming the setting; a shadow equal to the answer is ignored", () => {
    expect(() => textIndex.configure({ scheme: "b9r9" })).toThrow(/TIP_TEXT_LSH_SCHEME: unknown text LSH scheme "b9r9"/);
    expect(() => textIndex.configure({ shadow: "b9r9" })).toThrow(/TIP_TEXT_LSH_SHADOW/);
    textIndex.configure({ scheme: "b42r3", shadow: "b42r3" });
    expect(textIndex.shadowScheme()).toBeNull();
    expect(textIndex.ingestSchemes()).toEqual(["b42r3"]);
  });
});

describe.each(BACKENDS)("%s", (_name, make) => {
  test("a reworded copy at about 0.35: b32r4 misses it, b42r3 finds it once its index is built", async () => {
    expect(jaccardEstimate(A, REWORDED)).toBeGreaterThanOrEqual(0.3);
    expect(jaccardEstimate(A, REWORDED)).toBeLessThan(0.4);
    const dag = await make();
    await ingestFingerprint(dag, mkText(A), { ctid: "OH-A" });
    await dag.flush();
    expect(await matchText(dag, mkText(REWORDED))).toEqual([]);

    textIndex.configure({ scheme: "b42r3" });
    const warn = jest.spyOn(log, "warn").mockImplementation(() => { });
    textIndex.start(dag).stop();   // startup only: no index for b42r3 yet
    expect(textIndex.isReady(dag, "b42r3")).toBe(false);
    expect(await matchText(dag, mkText(REWORDED))).toEqual([]);
    expect(warn.mock.calls.some(([m]) => /text near-duplicate matching is OFF: the b42r3 index is building/.test(m))).toBe(true);

    expect(await textIndex.rebuild(dag, "b42r3")).toBe(true);
    await dag.flush();
    const hits = await matchText(dag, mkText(REWORDED));
    expect(hits.map((h) => h.ctid)).toEqual(["OH-A"]);
    expect(hits[0].similarity).toBeCloseTo(45 / 128, 5);
    expect(textIndex.status(dag, "b42r3")).toMatchObject({ state: "complete", texts: 1, bands: 42 });
  });

  test("batched reads: fingerprints by ctid for one component, and a keyset scan of text rows", async () => {
    const dag = await make();
    for (const id of ["OH-c", "OH-a", "OH-b"]) await ingestFingerprint(dag, mkText(A), { ctid: id });
    await ingestFingerprint(dag, { profile: "cf-image-1", kind: "image", pdq: "ab".repeat(32), quality: 90 }, { ctid: "OH-img" });
    await ingestFingerprint(dag, mkText(A), { ctid: "OH-a", componentIdx: 1 });
    await dag.flush();
    const got = await dag.getPerceptualFingerprintsByCtids(["OH-b", "OH-missing", "OH-a"], 0);
    expect(got.map((r) => r.ctid).sort()).toEqual(["OH-a", "OH-b"]);
    expect(got.every((r) => r.component_idx === 0 && typeof r.fingerprint === "string")).toBe(true);
    const page1 = await dag.listTextFingerprintsAfter("", -1, 2);
    expect(page1.map((r) => [r.ctid, r.component_idx])).toEqual([["OH-a", 0], ["OH-a", 1]]);
    const page2 = await dag.listTextFingerprintsAfter("OH-a", 1, 10);
    expect(page2.map((r) => [r.ctid, r.component_idx])).toEqual([["OH-b", 0], ["OH-c", 0]]);
  });

  test("candidate search stays inside the profile it is given", async () => {
    const dag = await make();
    textIndex.configure({ shadow: "b42r3" });
    await ingestFingerprint(dag, mkText(A), { ctid: "OH-A" });
    await dag.flush();
    const b32 = textIndex.bandRows(mkText(A), "q", ["b32r4"]).map((b) => b.band_hash);
    const b42 = textIndex.bandRows(mkText(A), "q", ["b42r3"]).map((b) => b.band_hash);
    expect(await dag.findMinhashCandidates(TEXT_PROFILE, b32)).toEqual(["OH-A"]);
    expect(await dag.findMinhashCandidates(B42, b42)).toEqual(["OH-A"]);
    expect(await dag.findMinhashCandidates(B42, b32.slice(0, 32))).toEqual([]);
    expect(await dag.findMinhashCandidates(TEXT_PROFILE, [])).toEqual([]);
  });
});

describe("shadow mode", () => {
  test("ingest writes both indexes; lookups answer from b32r4 while b42r3 is timed and logged", async () => {
    const dag = new MemoryStore();
    textIndex.configure({ shadow: "b42r3" });
    await textIndex.start(dag).done;   // nothing stored yet: the b42r3 build completes at once
    expect(textIndex.isReady(dag, "b42r3")).toBe(true);
    await ingestFingerprint(dag, mkText(A), { ctid: "OH-A" });
    const info = jest.spyOn(log, "info").mockImplementation(() => { });
    const before = textIndex.statsSnapshot().series.find((s) => s.scheme === "b42r3" && s.role === "shadow");
    const matchesBefore = before ? before.matches : 0;

    expect(await matchText(dag, mkText(REWORDED), { excludeCtid: "OH-copy" })).toEqual([]);
    await settle(); await settle();

    const line = info.mock.calls.map(([m]) => m).find((m) => m.startsWith("text-lsh shadow "));
    const entry = JSON.parse(line.slice("text-lsh shadow ".length));
    expect(entry).toMatchObject({ query: "OH-copy", answer: "b32r4", b32r4: { candidates: 0, matches: [] } });
    expect(entry.b42r3.candidates).toBe(1);
    expect(entry.b42r3.matches).toEqual([["OH-A", Math.round((45 / 128) * 1000) / 1000]]);
    const shadow = textIndex.statsSnapshot().series.find((s) => s.scheme === "b42r3" && s.role === "shadow");
    expect(shadow.matches - matchesBefore).toBe(1);
  });
});

describe("startup check", () => {
  test("b32r4 with no record is complete: ingest has always written it", () => {
    const dag = new MemoryStore();
    textIndex.start(dag);
    expect(textIndex.isReady(dag, "b32r4")).toBe(true);
    expect(JSON.parse(dag.getConsensusMeta("text_lsh_index:b32r4"))).toMatchObject({ state: "complete", legacy: true });
  });

  test("a rebuild cut short resumes after its cursor, and the index stays off until complete", async () => {
    const dag = new MemoryStore();
    for (const id of ["OH-1", "OH-2", "OH-3"]) await ingestFingerprint(dag, mkText(A), { ctid: id });
    dag.setConsensusMeta("text_lsh_index:b42r3", JSON.stringify({ state: "building", started_at: 1, after: ["OH-1", 0], texts: 1, bands: 42 }));
    textIndex.configure({ scheme: "b42r3" });
    const job = textIndex.start(dag);
    expect(textIndex.isReady(dag, "b42r3")).toBe(false);
    await job.done;
    expect(textIndex.status(dag, "b42r3")).toMatchObject({ state: "complete", texts: 3, bands: 126, started_at: 1 });
    const b42 = textIndex.bandRows(mkText(A), "q", ["b42r3"]).map((b) => b.band_hash);
    // OH-1 was before the cursor (a real earlier run had built it); the resumed run did not redo it.
    expect((await dag.findMinhashCandidates(B42, b42)).sort()).toEqual(["OH-2", "OH-3"]);
  });

  test("an index the node stops writing goes stale and is rebuilt, not trusted, when configured again", async () => {
    const dag = new MemoryStore();
    textIndex.start(dag);   // b32r4 complete (legacy)
    textIndex.configure({ scheme: "b42r3" });
    await textIndex.start(dag).done;
    expect(JSON.parse(dag.getConsensusMeta("text_lsh_index:b32r4")).state).toBe("stale");
    await ingestFingerprint(dag, mkText(A), { ctid: "OH-later" });   // b42r3 bands only

    textIndex.configure({});
    const job = textIndex.start(dag);
    expect(textIndex.isReady(dag, "b32r4")).toBe(false);
    await job.done;
    expect(textIndex.isReady(dag, "b32r4")).toBe(true);
    const b32 = textIndex.bandRows(mkText(A), "q", ["b32r4"]).map((b) => b.band_hash);
    expect(await dag.findMinhashCandidates(TEXT_PROFILE, b32)).toEqual(["OH-later"]);
  });
});
