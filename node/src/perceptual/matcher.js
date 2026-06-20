"use strict";

// Perceptual matcher (query side): given a query fingerprint, find near-duplicate
// content already in the off-DAG index. Candidate-generation uses the package's
// pure key helpers (LSH bands) against minhash_band; each candidate is then
// verified with the package's pure Jaccard estimate. Returns an ADVISORY list of
// near-duplicate ctids (never a verdict).
//
// async on purpose so it works over both the sync stores (MemoryStore/SQLiteStore
// return values directly; await is a no-op) and the async KnexAdapter.
//
// Deep-imports only the dependency-free helpers so the node never pulls the
// compute-only deps (@noble / decoders). See my-notes/PERCEPTUAL_INDEX_PLAN.md.

const { lshBands } = require("tip-content-fingerprint/src/text/lsh");
const { jaccardEstimate } = require("tip-content-fingerprint/src/text/compare");
const { queryKeys } = require("tip-content-fingerprint/src/image/mih");
const { hammingHex } = require("tip-content-fingerprint/src/image/hamming");

const TEXT_FLAG_THRESHOLD = 0.30; // reviewer-panel "possible copy" cutoff
const IMAGE_DISTANCE = 31;        // PDQ Hamming match floor (of 256)
const IMAGE_MIN_QUALITY = 49;     // discard flat/low-detail images
const VIDEO_DISTANCE = 31;        // per-frame PDQ Hamming "<" tolerance
const VIDEO_QUALITY = 50;         // frame quality filter F
const VIDEO_PC = 80;              // target-coverage % required for a match
const VIDEO_PQ = 0;               // query-coverage % (0 = clip-in-longer-video friendly)

// Find indexed texts that are near-duplicates of queryFp (char-tier MinHash only;
// micro-tier is exact-match, handled elsewhere). Returns [{ ctid, similarity }]
// sorted high-to-low, above the threshold.
async function matchText(dag, queryFp, opts) {
  opts = opts || {};
  const threshold = opts.threshold != null ? opts.threshold : TEXT_FLAG_THRESHOLD;
  if (!queryFp || queryFp.kind !== "text" || queryFp.tier !== "char" || !Array.isArray(queryFp.minhash)) {
    return [];
  }

  const bandHashes = lshBands(queryFp.minhash);
  const candidates = await dag.findMinhashCandidates(queryFp.profile, bandHashes);

  const out = [];
  for (const ctid of candidates) {
    if (opts.excludeCtid && ctid === opts.excludeCtid) continue;
    const row = await dag.getPerceptualFingerprint(ctid, 0);
    if (!row) continue;
    let candFp;
    try {
      candFp = JSON.parse(row.fingerprint);
    } catch {
      continue;
    }
    if (!Array.isArray(candFp.minhash)) continue;
    const similarity = jaccardEstimate(queryFp.minhash, candFp.minhash);
    if (similarity >= threshold) out.push({ ctid, similarity });
  }
  out.sort((a, b) => b.similarity - a.similarity);
  return out;
}

// Find indexed images that are near-duplicates of queryFp. MIH candidate-gen on
// phash_code, then full-Hamming verify (<= distanceThreshold), quality-gated.
// Returns [{ ctid, distance }] sorted closest-first.
async function matchImage(dag, queryFp, opts) {
  opts = opts || {};
  const maxDistance = opts.distanceThreshold != null ? opts.distanceThreshold : IMAGE_DISTANCE;
  const minQuality = opts.minQuality != null ? opts.minQuality : IMAGE_MIN_QUALITY;
  if (!queryFp || queryFp.kind !== "image" || typeof queryFp.pdq !== "string") return [];
  if (queryFp.quality != null && queryFp.quality < minQuality) return []; // unreliable query

  const candidates = await dag.findPhashCandidates(queryFp.profile, "image", queryKeys(queryFp.pdq));

  const best = new Map(); // ctid -> smallest distance seen
  for (const c of candidates) {
    if (opts.excludeCtid && c.ctid === opts.excludeCtid) continue;
    if (c.quality != null && c.quality < minQuality) continue;
    const distance = hammingHex(queryFp.pdq, c.pdq);
    if (distance <= maxDistance) {
      const prev = best.get(c.ctid);
      if (prev == null || distance < prev) best.set(c.ctid, distance);
    }
  }
  return [...best.entries()]
    .map(([ctid, distance]) => ({ ctid, distance }))
    .sort((a, b) => a.distance - b.distance);
}

// Bidirectional frame-set overlap, mirroring the package's compareVideo
// (matchTwoHashBrute): coverage = number of A-frames with ANY B-frame within
// Hamming < D. Reimplemented here (not imported) because the package's video
// module pulls the wasm decode stack at load; only the pure hammingHex is used.
function _coverage(A, B, D) {
  let n = 0;
  for (const a of A) {
    for (const b of B) {
      if (hammingHex(a.pdq, b.pdq) < D) { n++; break; }
    }
  }
  return n;
}

// Find indexed videos that are near-duplicates of queryFp. Per query frame: MIH
// candidate-gen on phash_code (modality 'video') -> candidate ctids; then fetch
// each candidate's full frame set and score the bidirectional overlap. Returns
// [{ ctid, queryMatchPct, targetMatchPct }] for matches (target coverage >= Pc).
async function matchVideo(dag, queryFp, opts) {
  opts = opts || {};
  const D = opts.distanceTolerance != null ? opts.distanceTolerance : VIDEO_DISTANCE;
  const F = opts.qualityTolerance != null ? opts.qualityTolerance : VIDEO_QUALITY;
  const Pc = opts.pc != null ? opts.pc : VIDEO_PC;
  const Pq = opts.pq != null ? opts.pq : VIDEO_PQ;
  if (!queryFp || queryFp.kind !== "video" || !Array.isArray(queryFp.features)) return [];

  const q = queryFp.features.filter((f) => typeof f.pdq === "string" && (f.quality == null || f.quality >= F));
  if (!q.length) return [];

  const ctids = new Set();
  for (const f of q) {
    for (const c of await dag.findPhashCandidates(queryFp.profile, "video", queryKeys(f.pdq))) {
      ctids.add(c.ctid);
    }
  }

  const out = [];
  for (const ctid of ctids) {
    if (opts.excludeCtid && ctid === opts.excludeCtid) continue;
    const rows = await dag.getPhashCodesByCtid(ctid);
    const t = rows.filter((r) => r.modality === "video" && (r.quality == null || r.quality >= F));
    if (!t.length) continue;
    const queryMatchPct = (_coverage(q, t, D) * 100) / q.length;
    const targetMatchPct = (_coverage(t, q, D) * 100) / t.length;
    if (queryMatchPct >= Pq && targetMatchPct >= Pc) out.push({ ctid, queryMatchPct, targetMatchPct });
  }
  out.sort((a, b) => b.targetMatchPct - a.targetMatchPct);
  return out;
}

module.exports = {
  matchText, matchImage, matchVideo,
  TEXT_FLAG_THRESHOLD, IMAGE_DISTANCE, IMAGE_MIN_QUALITY, VIDEO_DISTANCE, VIDEO_QUALITY, VIDEO_PC, VIDEO_PQ,
};
