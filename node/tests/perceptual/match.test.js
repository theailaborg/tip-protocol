"use strict";

const { MemoryStore, SQLiteStore } = require("../../src/dag");
const { ingestFingerprint } = require("../../src/perceptual/ingest");
const { matchText, matchImage } = require("../../src/perceptual/matcher");

// ── text ───────────────────────────────────────────────────────────────────
const mkText = (vals) => ({ profile: "cf-text-2", kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash: vals });
const A = Array.from({ length: 128 }, (_, i) => (i * 7 + 13) % 100000);
const NEAR = A.map((v, i) => (i < 10 ? v + 1 : v)); // ~10/128 changed -> Jaccard ~0.92, shares bands
const FAR = A.map((v) => v + 500000);                // shares no band -> Jaccard 0

async function exerciseText(dag) {
  ingestFingerprint(dag, mkText(A), { ctid: "OH-A" });
  const hits = await matchText(dag, mkText(NEAR));
  expect(hits.map((h) => h.ctid)).toContain("OH-A");
  expect(hits.find((h) => h.ctid === "OH-A").similarity).toBeGreaterThan(0.8);
  expect((await matchText(dag, mkText(FAR))).find((h) => h.ctid === "OH-A")).toBeUndefined();
  expect((await matchText(dag, mkText(A), { excludeCtid: "OH-A" })).find((h) => h.ctid === "OH-A")).toBeUndefined();
}

// ── image ──────────────────────────────────────────────────────────────────
const mkImg = (pdq, quality = 95) => ({ profile: "cf-image-1", kind: "image", pdq, quality });
const PDQ = "ab".repeat(32);            // 64-hex (256-bit)
const PDQ_NEAR = "cd" + PDQ.slice(2);   // chunk 0 changed (~6 bits) -> shares chunks 1..15
const PDQ_FAR = "54".repeat(32);        // every byte differs -> Hamming 256, shares no chunk

async function exerciseImage(dag) {
  ingestFingerprint(dag, mkImg(PDQ), { ctid: "OH-img" });
  const hits = await matchImage(dag, mkImg(PDQ_NEAR, 90));
  expect(hits.map((h) => h.ctid)).toContain("OH-img");
  expect(hits.find((h) => h.ctid === "OH-img").distance).toBeLessThanOrEqual(31);
  expect((await matchImage(dag, mkImg(PDQ_FAR, 90))).find((h) => h.ctid === "OH-img")).toBeUndefined();
  expect((await matchImage(dag, mkImg(PDQ), { excludeCtid: "OH-img" })).find((h) => h.ctid === "OH-img")).toBeUndefined();
}

describe("perceptual matcher", () => {
  describe("text near-duplicate (LSH candidate-gen + Jaccard verify)", () => {
    test("MemoryStore", async () => { await exerciseText(new MemoryStore()); });
    test("SQLiteStore", async () => { const s = new SQLiteStore(":memory:"); await exerciseText(s); s.db.close(); });
  });
  describe("image near-duplicate (MIH candidate-gen + Hamming verify)", () => {
    test("MemoryStore", async () => { await exerciseImage(new MemoryStore()); });
    test("SQLiteStore", async () => { const s = new SQLiteStore(":memory:"); await exerciseImage(s); s.db.close(); });
  });
});
