"use strict";

const { MemoryStore, SQLiteStore } = require("../../src/dag");
const { ingestFingerprint } = require("../../src/perceptual/ingest");
const { matchText, matchImage, matchVideo, matchAudio } = require("../../src/perceptual/matcher");

// ── text ───────────────────────────────────────────────────────────────────
const mkText = (vals) => ({ profile: "cf-text-2", kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash: vals });
const A = Array.from({ length: 128 }, (_, i) => (i * 7 + 13) % 100000);
const NEAR = A.map((v, i) => (i < 10 ? v + 1 : v)); // ~10/128 changed -> Jaccard ~0.92, shares bands
const FAR = A.map((v) => v + 500000);                // shares no band -> Jaccard 0

async function exerciseText(dag) {
  await ingestFingerprint(dag, mkText(A), { ctid: "OH-A" });
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
  await ingestFingerprint(dag, mkImg(PDQ), { ctid: "OH-img" });
  const hits = await matchImage(dag, mkImg(PDQ_NEAR, 90));
  expect(hits.map((h) => h.ctid)).toContain("OH-img");
  expect(hits.find((h) => h.ctid === "OH-img").distance).toBeLessThanOrEqual(31);
  expect((await matchImage(dag, mkImg(PDQ_FAR, 90))).find((h) => h.ctid === "OH-img")).toBeUndefined();
  expect((await matchImage(dag, mkImg(PDQ), { excludeCtid: "OH-img" })).find((h) => h.ctid === "OH-img")).toBeUndefined();
}

// ── video ──────────────────────────────────────────────────────────────────
const vframe = (pdq, i, q = 80) => ({ frame: i, timestamp: i + 0.5, pdq, quality: q });
const A_PDQS = ["11", "22", "33", "44"].map((b) => b.repeat(32)); // 4 frames, 64-hex each
const videoA = { profile: "cf-video-1", kind: "video", features: A_PDQS.map((p, i) => vframe(p, i)) };
// re-encode: flip 1 bit in each frame's first byte -> per-frame Hamming 1 (< 31), shares chunks
const flip1 = (hex) => (parseInt(hex.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0") + hex.slice(2);
const videoNear = { profile: "cf-video-1", kind: "video", features: A_PDQS.map((p, i) => vframe(flip1(p), i)) };
// unrelated: every byte differs, shares no chunk
const videoFar = { profile: "cf-video-1", kind: "video", features: ["ab", "cd", "ef", "9a"].map((b, i) => vframe(b.repeat(32), i)) };

async function exerciseVideo(dag) {
  await ingestFingerprint(dag, videoA, { ctid: "OH-vid" });
  const hits = await matchVideo(dag, videoNear);
  expect(hits.map((h) => h.ctid)).toContain("OH-vid");
  expect(hits.find((h) => h.ctid === "OH-vid").targetMatchPct).toBeGreaterThanOrEqual(80);
  expect((await matchVideo(dag, videoFar)).find((h) => h.ctid === "OH-vid")).toBeUndefined();
  expect((await matchVideo(dag, videoA, { excludeCtid: "OH-vid" })).find((h) => h.ctid === "OH-vid")).toBeUndefined();
}

// ── audio ──────────────────────────────────────────────────────────────────
const mkAudio = (landmarks, landmarkCount) => ({
  profile: "cf-audio-landmark-1", kind: "audio",
  landmarkCount: landmarkCount != null ? landmarkCount : landmarks.length, landmarks,
});
const audioBase = Array.from({ length: 50 }, (_, i) => ({ hash: 1000 + i, t: i })); // 50 distinct landmarks
const audioClip = mkAudio(audioBase);
// query = a later sub-clip (frames 10..49 of the same source, its clock reset to 0):
// shares 40 landmarks, all at a constant +10 offset -> one tall histogram bin
const audioNear = mkAudio(audioBase.slice(10).map((lm, j) => ({ hash: lm.hash, t: j })));
const audioFar = mkAudio(audioBase.map((lm) => ({ hash: lm.hash + 999999, t: lm.t }))); // shares no hash

async function exerciseAudio(dag) {
  await ingestFingerprint(dag, audioClip, { ctid: "OH-aud" });
  const hits = await matchAudio(dag, audioNear);
  expect(hits.map((h) => h.ctid)).toContain("OH-aud");
  const hit = hits.find((h) => h.ctid === "OH-aud");
  expect(hit.score).toBeGreaterThanOrEqual(10);
  expect(hit.offset).toBe(10); // constant query->target time shift
  expect((await matchAudio(dag, audioFar)).find((h) => h.ctid === "OH-aud")).toBeUndefined();
  expect((await matchAudio(dag, audioClip, { excludeCtid: "OH-aud" })).find((h) => h.ctid === "OH-aud")).toBeUndefined();
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
  describe("video near-duplicate (per-frame MIH + bidirectional overlap)", () => {
    test("MemoryStore", async () => { await exerciseVideo(new MemoryStore()); });
    test("SQLiteStore", async () => { const s = new SQLiteStore(":memory:"); await exerciseVideo(s); s.db.close(); });
  });
  describe("audio near-duplicate (landmark inverted-index + offset histogram)", () => {
    test("MemoryStore", async () => { await exerciseAudio(new MemoryStore()); });
    test("SQLiteStore", async () => { const s = new SQLiteStore(":memory:"); await exerciseAudio(s); s.db.close(); });
  });
});
