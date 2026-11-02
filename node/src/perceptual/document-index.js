"use strict";

// Similar documents (cf-doc-1). Candidates come from the same wording
// (text_hash), shared passages and the document's picture and page images; each
// is then measured with the library's compareDocument, which says how much text
// the two share and where. Advisory, never a copy verdict. The text MinHash is
// not a document signal: two large unrelated texts in one language can pass 0.30.
//
// There is no list of common text (licences, disclaimers, templates):
// compareDocument weights each shared passage by 1 / (1 + other owners holding
// it), counted from the index, so text that many people hold sorts last.

const { compareDocument } = require("tip-content-fingerprint/src/document/compare");
const { sampleKeys } = require("tip-content-fingerprint/src/document/passages");
const { MIN_SHARED_CHARS } = require("tip-content-fingerprint/src/document/constants");
const { queryKeys } = require("tip-content-fingerprint/src/image/mih");
const { hammingHex } = require("tip-content-fingerprint/src/image/hamming");
const { PROFILE: IMAGE_PROFILE, DISTANCE_THRESHOLD, MIN_QUALITY } = require("tip-content-fingerprint/src/image");
const { DOCUMENT_FINGERPRINT, DOCUMENT_MATCH } = require("../../../shared/constants");

// Candidates with the same wording or a shared image are compared before those
// found only through shared passages.
const TIER = Object.freeze({ SAME_WORDING: 0, CONFIRMED: 1, PASSAGES: 2 });

let _maxKeyOwners = DOCUMENT_MATCH.MAX_KEY_OWNERS;

function configure({ maxKeyOwners } = {}) {
  _maxKeyOwners = Number.isSafeInteger(maxKeyOwners) && maxKeyOwners > 0 ? maxKeyOwners : DOCUMENT_MATCH.MAX_KEY_OWNERS;
}

function maxKeyOwners() { return _maxKeyOwners; }

const _yield = () => new Promise((resolve) => setImmediate(resolve));

function _evenSample(arr, n) {
  if (arr.length <= n) return arr;
  const out = [];
  for (let i = 0; i < n; i++) out.push(arr[Math.floor((i * (arr.length - 1)) / (n - 1))]);
  return out;
}

// compareDocument's `owners` for one pair: `others` counts owners besides the
// query's, and the candidate's owner holds every key the two share.
function _pairOwners(others, queryOwner, candidateOwner) {
  const self = candidateOwner !== queryOwner ? 1 : 0;
  return { get: (key) => Math.max(0, (others.get(key) || 0) - self) };
}

// One 0-1 figure to rank against other modalities: shared text (0.5 at one
// paragraph of text no one else holds), or the share of scanned pages that are
// the same image.
function documentScore(cmp) {
  const st = cmp.shared_text;
  const shared = st ? st.score / (st.score + MIN_SHARED_CHARS) : 0;
  const tp = cmp.textless_pages;
  const pages = tp && tp.shared ? tp.shared / Math.max(tp.a, tp.b) : 0;
  return Math.max(shared, pages);
}

function _listable(cmp) {
  if (!cmp.textless_pages) return false; // not comparable: reject tier or another profile
  return Boolean((cmp.shared_text && cmp.shared_text.worth_listing) || cmp.textless_pages.shared > 0);
}

// Returns document hits [{ ctid, component_idx, modality: "document", score,
// compare }] sorted by score, then image hits [{ ctid, modality: "image",
// distance }] for pictures or pages that match an image posted alone.
async function matchDocument(dag, queryFp, opts = {}) {
  if (!queryFp || queryFp.kind !== "document" || queryFp.tier === "reject" || queryFp.profile !== DOCUMENT_FINGERPRINT.PROFILE) {
    return [];
  }
  const profile = queryFp.profile;
  const exclude = opts.excludeCtid || null;
  const owner = opts.owner || null;
  const candidates = new Map();
  const rows = new Map();
  const add = (ctid, componentIdx, tier, weight) => {
    if (ctid === exclude) return;
    const key = `${ctid}|${componentIdx}`;
    const c = candidates.get(key);
    if (!c) candidates.set(key, { ctid, component_idx: componentIdx, tier, weight });
    else { c.tier = Math.min(c.tier, tier); c.weight += weight; }
  };

  if (queryFp.chars_covered > 0) {
    for (const r of await dag.findDocumentsByTextHash(profile, queryFp.text_hash)) add(r.ctid, r.component_idx, TIER.SAME_WORDING, 0);
  }

  // Only keys someone holds come back; their counts leave out the query's owner.
  const keys = queryFp.passages ? [...new Set(sampleKeys(queryFp.passages))] : [];
  const others = new Map();
  for (const r of keys.length ? await dag.countDocumentPassageOwners(profile, keys, owner) : []) others.set(r.passage_key, r.owners);
  const usable = keys.filter((k) => others.has(k) && others.get(k) <= _maxKeyOwners);
  for (const r of usable.length ? await dag.findDocumentPassageCandidates(profile, usable) : []) {
    add(r.ctid, r.component_idx, TIER.PASSAGES, r.shared);
  }

  const imageHits = await _matchImages(dag, queryFp, exclude, rows, add);

  const ranked = [...candidates.values()]
    .sort((a, b) => (a.tier - b.tier) || (b.weight - a.weight) || (a.ctid < b.ctid ? -1 : a.ctid > b.ctid ? 1 : a.component_idx - b.component_idx))
    .slice(0, DOCUMENT_MATCH.MAX_CANDIDATES);
  const hits = [];
  for (const c of ranked) {
    const rec = dag.getContent(c.ctid);
    if (!rec) continue;
    const key = `${c.ctid}|${c.component_idx}`;
    const row = rows.has(key) ? rows.get(key) : await dag.getPerceptualFingerprint(c.ctid, c.component_idx);
    if (!row || row.modality !== "document") continue;
    let fp;
    try { fp = JSON.parse(row.fingerprint); } catch { continue; }
    const cmp = compareDocument(queryFp, fp, { owners: _pairOwners(others, owner, rec.author_tip_id) });
    if (_listable(cmp)) hits.push({ ctid: c.ctid, component_idx: c.component_idx, modality: "document", score: documentScore(cmp), compare: cmp });
    await _yield();
  }
  hits.sort((a, b) => (b.score - a.score)
    || ((b.compare.shared_text ? b.compare.shared_text.chars : 0) - (a.compare.shared_text ? a.compare.shared_text.chars : 0))
    || (a.ctid < b.ctid ? -1 : a.ctid > b.ctid ? 1 : 0));
  return [...hits, ...imageHits];
}

// Pictures and drawn page images, probed in one candidate query. A match in
// another document makes it a candidate; a match with an image posted alone is
// an image hit.
async function _matchImages(dag, queryFp, exclude, rows, add) {
  const usable = [...(queryFp.images || []), ...(queryFp.textless_pages || [])]
    .filter((p) => typeof p.pdq === "string" && p.quality >= MIN_QUALITY);
  if (!usable.length) return [];
  const probes = _evenSample(usable, DOCUMENT_MATCH.IMAGE_PROBES);
  const merged = Array.from({ length: 16 }, () => new Set());
  for (const p of probes) {
    const k = queryKeys(p.pdq);
    for (let i = 0; i < 16; i++) for (const v of k[i]) merged[i].add(v);
  }
  const best = new Map();
  for (const c of await dag.findPhashCandidates(IMAGE_PROFILE, "image", merged.map((s) => [...s]))) {
    if (c.ctid === exclude || c.quality < MIN_QUALITY) continue;
    let d = Infinity;
    for (const p of probes) d = Math.min(d, hammingHex(p.pdq, c.pdq));
    if (d > DISTANCE_THRESHOLD) continue;
    const key = `${c.ctid}|${c.component_idx}`;
    if (!best.has(key) || d < best.get(key).distance) best.set(key, { ctid: c.ctid, component_idx: c.component_idx, distance: d });
  }
  const images = new Map();
  for (const [key, hit] of best) {
    const row = await dag.getPerceptualFingerprint(hit.ctid, hit.component_idx);
    rows.set(key, row);
    if (!row) continue;
    if (row.modality === "document") add(hit.ctid, hit.component_idx, TIER.CONFIRMED, 0);
    else if (!images.has(hit.ctid) || hit.distance < images.get(hit.ctid).distance) {
      images.set(hit.ctid, { ctid: hit.ctid, modality: "image", distance: hit.distance });
    }
  }
  return [...images.values()].sort((a, b) => a.distance - b.distance);
}

module.exports = { configure, maxKeyOwners, matchDocument, documentScore };
