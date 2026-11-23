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

const { sampleKeys } = require("tip-content-fingerprint/src/document/passages");
const { matchText, matchImage, matchVideo, matchAudio, IMAGE_DISTANCE } = require("./matcher");
const { matchDocument } = require("./document-index");
const { isSitePageKey } = require("./site-ingest");
const { SITE_INGEST, DOCUMENT_MATCH } = require("../../../shared/constants");

const SITE_RANK_FACTOR = 4;   // several versions of one page can match; the caller keeps one per page

// Same grouping as document-index: exact owner counts to 16, then powers of two.
function _ownerBucket(n) {
  return n <= 16 ? n : 2 ** Math.floor(Math.log2(n));
}

// Site pages that hold the query's paragraph keys. A key held by n site owners
// (the query's own excluded) weighs 1/n, so text many sites carry (an embedded
// player's help, ad copy) counts for little. Score: the weighted share of the
// page's keys found in the query.
async function matchSitePassages(dag, keys, owner) {
  if (!keys.length || typeof dag.countDocumentPassageOwners !== "function") return [];
  const profile = SITE_INGEST.PASSAGE_PROFILE;
  const groups = new Map();
  for (const r of await dag.countDocumentPassageOwners(profile, keys, owner)) {
    const n = Number(r.owners);
    if (n < 1 || n > DOCUMENT_MATCH.MAX_KEY_OWNERS) continue;
    const b = _ownerBucket(n);
    if (!groups.has(b)) groups.set(b, []);
    groups.get(b).push(r.passage_key);
  }
  const cands = new Map();
  for (const [n, group] of groups) {
    for (const r of await dag.findDocumentPassageCandidates(profile, group)) {
      const c = cands.get(r.ctid) || { ctid: r.ctid, shared: 0, weighted: 0 };
      c.shared += r.shared;
      c.weighted += r.shared / n;
      cands.set(r.ctid, c);
    }
  }
  const ranked = [...cands.values()].filter((c) => c.weighted >= 1)
    .sort((a, b) => (b.weighted - a.weighted) || (a.ctid < b.ctid ? -1 : 1))
    .slice(0, DOCUMENT_MATCH.MAX_CANDIDATES);
  const hits = [];
  for (const c of ranked) {
    const page = await dag.getSitePage(c.ctid);
    if (!page || Number(page.offsite)) continue;
    const total = page.paragraph_keys ? page.paragraph_keys.split(" ").filter(Boolean).length : 0;
    if (!total) continue;
    hits.push({
      ctid: c.ctid, modality: "site_text", score: Math.min(1, c.weighted / total),
      shared_keys: c.shared, page_keys: total, weighted: Math.round(c.weighted * 1000) / 1000,
    });
  }
  return hits;
}

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
  if (modality === "document") return hit.score;                                    // documentScore (already 0-1)
  if (modality === "site_text") return hit.score;                                   // weighted key containment (0-1)
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
  if (modality === "document") {
    const c = hit.compare;
    return {
      shared_text: c.shared_text,
      same_wording: c.same_wording,
      cross_format: c.cross_format,
      text_similarity: c.text_similarity,
      images: c.images,
      textless_pages: c.textless_pages,
      units: c.units && { a: c.units.a, b: c.units.b, shared: c.units.shared, reordered: c.units.reordered },
    };
  }
  if (modality === "site_text") return { shared_keys: hit.shared_keys, page_keys: hit.page_keys, weighted: hit.weighted };
  return {};
}

// A hit carries its own `modality` when it differs from the query's: a document
// also finds posts by its text and images posted alone by its pictures.
async function _matchFor(dag, modality, fp, ctid, owner) {
  const opts = { excludeCtid: ctid };
  if (modality === "text") return matchText(dag, fp, opts);
  if (modality === "image") return matchImage(dag, fp, opts);
  if (modality === "video") return matchVideo(dag, fp, opts);
  if (modality === "audio") return matchAudio(dag, fp, opts);
  if (modality === "document") {
    const docs = await matchDocument(dag, fp, { excludeCtid: ctid, owner });
    const texts = fp.text ? await matchText(dag, fp.text, { ...opts, documents: false }) : [];
    const pages = fp.passages ? await matchSitePassages(dag, [...new Set(sampleKeys(fp.passages))], owner) : [];
    return [...docs, ...texts.map((h) => ({ ...h, modality: "text" })), ...pages];
  }
  return [];
}

// Content ctids and site pages ranked apart, so site hits never displace content.
function _rank(best, limit, sites) {
  return [...best.entries()]
    .filter(([id]) => isSitePageKey(id) === sites)
    .map(([id, m]) => ({ ctid: id, ...m }))
    // Tie-break by ctid so the top-N is reproducible across backends (Map
    // insertion order differs between MemoryStore scan and SQLite/PG row order).
    .sort((a, b) => (b.score - a.score) || (a.ctid < b.ctid ? -1 : a.ctid > b.ctid ? 1 : 0))
    .slice(0, limit);
}

async function findSimilarCtids(dag, ctid, opts = {}) {
  return (await findSimilar(dag, ctid, opts)).content;
}

// { content, sites }: content ctids as findSimilarCtids, and site page keys
// (up to SITE_RANK_FACTOR x limit, for the caller to keep one per page).
async function findSimilar(dag, ctid, opts = {}) {
  // Advisory + optional: a store without the perceptual index (some test
  // doubles, future minimal backends) simply has no similar content.
  if (typeof dag.getPerceptualFingerprint !== "function") return { content: [], sites: [] };
  const limit = opts.limit != null ? opts.limit : 5;
  const best = new Map(); // candidate ctid -> { score, modality, component_idx, metric }
  const rec = dag.getContent(ctid);
  const owner = rec ? rec.author_tip_id : null;

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
    const hits = await _matchFor(dag, row.modality, fp, ctid, owner);
    for (const hit of hits) {
      const modality = hit.modality || row.modality;
      const score = _normScore(modality, hit);
      const prev = best.get(hit.ctid);
      if (!prev || score > prev.score) {
        best.set(hit.ctid, { score, modality, component_idx: i, metric: _rawMetric(modality, hit) });
      }
    }
  }

  return { content: _rank(best, limit, false), sites: _rank(best, limit * SITE_RANK_FACTOR, true) };
}

// Register-time variant of findSimilarCtids: matches the REQUEST's parsed
// fingerprint items (this content isn't indexed yet) instead of stored rows;
// same per-component match, best-hit-per-ctid aggregation, and ordering.
async function matchFingerprintItems(dag, items, opts = {}) {
  return (await matchFingerprintItemsWithSites(dag, items, opts)).content;
}

async function matchFingerprintItemsWithSites(dag, items, opts = {}) {
  // Advisory + optional , same escape hatch as findSimilarCtids for stores
  // without the perceptual index (test doubles, minimal backends).
  if (typeof dag.getPerceptualFingerprint !== "function") return { content: [], sites: [] };
  if (!Array.isArray(items) || items.length === 0) return { content: [], sites: [] };
  const limit = opts.limit != null ? opts.limit : 5;
  const best = new Map(); // candidate ctid -> { score, modality, component_idx, metric }

  for (let i = 0; i < items.length; i++) {
    const fp = items[i] && items[i].perceptual;
    if (!fp || typeof fp.kind !== "string") continue;
    const hits = await _matchFor(dag, fp.kind, fp, opts.excludeCtid || null, opts.owner || null);
    for (const hit of hits) {
      const modality = hit.modality || fp.kind;
      const score = _normScore(modality, hit);
      const prev = best.get(hit.ctid);
      if (!prev || score > prev.score) {
        best.set(hit.ctid, { score, modality, component_idx: i, metric: _rawMetric(modality, hit) });
      }
    }
  }

  return { content: _rank(best, limit, false), sites: _rank(best, limit * SITE_RANK_FACTOR, true) };
}

module.exports = { findSimilarCtids, findSimilar, matchFingerprintItems, matchFingerprintItemsWithSites, matchSitePassages };
