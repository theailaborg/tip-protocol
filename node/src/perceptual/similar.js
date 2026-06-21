"use strict";

// Perceptual "similar content" orchestration. Given a ctid already in the
// off-DAG index, use ITS OWN stored fingerprints (one per component) as queries
// against the index, then aggregate the hits across every component/modality by
// ctid, keeping each candidate's best normalised score. Returns the top-N
// candidate ctids with a 0-1 score + the raw per-modality metric, for the
// caller (content-service) to enrich into UI cards.
//
// Single-node for now: only matches content this node has ingested. Cross-node
// coverage arrives with off-DAG perceptual_fingerprint replication (GH issue).

const { matchText, matchImage, matchVideo, matchAudio, IMAGE_DISTANCE } = require("./matcher");

// Map each modality's native metric onto a common 0-1 "more similar = higher"
// scale so candidates from different modalities can be ranked together.
function _normScore(modality, hit) {
  if (modality === "text") return hit.similarity;                                   // 0-1 (Jaccard)
  // Divide by IMAGE_DISTANCE+1, not IMAGE_DISTANCE: a match at the inclusive floor
  // (distance === IMAGE_DISTANCE) is still a real near-dup, so it must score > 0
  // instead of collapsing to 0 and dropping out of the ranked top-N.
  if (modality === "image") return 1 - Math.min(hit.distance, IMAGE_DISTANCE) / (IMAGE_DISTANCE + 1); // Hamming -> (0,1]
  if (modality === "video") return hit.targetMatchPct / 100;                        // % -> 0-1
  if (modality === "audio") return Math.min(1, hit.scoreRatio);                     // ratio (already 0-1)
  return 0;
}

// The raw per-modality metric, preserved so the UI can show the real figure
// (distance / similarity / coverage) alongside the normalised score.
function _rawMetric(modality, hit) {
  if (modality === "text") return { similarity: hit.similarity };
  if (modality === "image") return { distance: hit.distance };
  if (modality === "video") return { target_match_pct: hit.targetMatchPct, query_match_pct: hit.queryMatchPct };
  // NB: key is `landmark_matches`, NOT `score` — a `score` key here would clobber
  // the card's normalised 0-1 `score` when the metric is spread into it.
  if (modality === "audio") return { landmark_matches: hit.score, score_ratio: hit.scoreRatio };
  return {};
}

async function _matchFor(dag, modality, fp, ctid) {
  const opts = { excludeCtid: ctid };
  if (modality === "text") return matchText(dag, fp, opts);
  if (modality === "image") return matchImage(dag, fp, opts);
  if (modality === "video") return matchVideo(dag, fp, opts);
  if (modality === "audio") return matchAudio(dag, fp, opts);
  return [];
}

async function findSimilarCtids(dag, ctid, opts = {}) {
  // Advisory + optional: a store without the perceptual index (some test
  // doubles, future minimal backends) simply has no similar content.
  if (typeof dag.getPerceptualFingerprint !== "function") return [];
  const limit = opts.limit != null ? opts.limit : 5;
  const best = new Map(); // candidate ctid -> { score, modality, component_idx, metric }

  // Walk the source content's components (contiguous from 0) and query each.
  for (let i = 0; ; i++) {
    const row = await dag.getPerceptualFingerprint(ctid, i);
    if (!row) break;
    let fp;
    try {
      fp = JSON.parse(row.fingerprint);
    } catch {
      continue;
    }
    const hits = await _matchFor(dag, row.modality, fp, ctid);
    for (const hit of hits) {
      const score = _normScore(row.modality, hit);
      const prev = best.get(hit.ctid);
      if (!prev || score > prev.score) {
        best.set(hit.ctid, { score, modality: row.modality, component_idx: i, metric: _rawMetric(row.modality, hit) });
      }
    }
  }

  return [...best.entries()]
    .map(([id, m]) => ({ ctid: id, ...m }))
    // Tie-break by ctid so the top-N is reproducible across backends (Map
    // insertion order differs between MemoryStore scan and SQLite/PG row order).
    .sort((a, b) => (b.score - a.score) || (a.ctid < b.ctid ? -1 : a.ctid > b.ctid ? 1 : 0))
    .slice(0, limit);
}

module.exports = { findSimilarCtids };
