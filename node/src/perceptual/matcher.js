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

const TEXT_FLAG_THRESHOLD = 0.30; // reviewer-panel "possible copy" cutoff

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

module.exports = { matchText, TEXT_FLAG_THRESHOLD };
