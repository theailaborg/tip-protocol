"use strict";

// Similar documents (cf-doc-1): candidates by same wording, shared passages and
// shared scanned pages, each measured with the library's compareDocument.

const { compareDocument } = require("tip-content-fingerprint/src/document/compare");
const { sampleKeys } = require("tip-content-fingerprint/src/document/passages");
const { MIN_SHARED_CHARS } = require("tip-content-fingerprint/src/document/constants");
const { hammingHex } = require("tip-content-fingerprint/src/image/hamming");
const { PROFILE: IMAGE_PROFILE, DISTANCE_THRESHOLD, MIN_QUALITY } = require("tip-content-fingerprint/src/image");
const { evenSample, mergedProbeKeys } = require("./matcher");
const { DOCUMENT_FINGERPRINT, DOCUMENT_MATCH } = require("../../../shared/constants");

// Same wording and shared scanned pages are compared before passage-only candidates.
const TIER = Object.freeze({ SAME_WORDING: 0, CONFIRMED: 1, PASSAGES: 2 });

let _maxKeyOwners = DOCUMENT_MATCH.MAX_KEY_OWNERS;

function configure({ maxKeyOwners } = {}) {
  _maxKeyOwners = Number.isSafeInteger(maxKeyOwners) && maxKeyOwners > 0 ? maxKeyOwners : DOCUMENT_MATCH.MAX_KEY_OWNERS;
}

function maxKeyOwners() { return _maxKeyOwners; }

const _yield = () => new Promise((resolve) => setImmediate(resolve));

// Keys are queried in groups of equal owner counts (exact to 16, then by power
// of two), so a candidate's rank weighs each key 1 / (1 + owners) as the score does.
function _ownerBucket(n) {
  return n <= 16 ? n : 2 ** Math.floor(Math.log2(n));
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
  const groups = new Map();
  for (const [key, n] of others) {
    if (n > _maxKeyOwners) continue;
    const b = _ownerBucket(n);
    if (!groups.has(b)) groups.set(b, []);
    groups.get(b).push(key);
  }
  for (const [n, group] of groups) {
    for (const r of await dag.findDocumentPassageCandidates(profile, group)) add(r.ctid, r.component_idx, TIER.PASSAGES, r.shared / (1 + n));
  }

  const imageHits = await _matchImages(dag, queryFp, exclude, add);

  const ranked = [...candidates.values()]
    .sort((a, b) => (a.tier - b.tier) || (b.weight - a.weight) || (a.ctid < b.ctid ? -1 : a.ctid > b.ctid ? 1 : a.component_idx - b.component_idx))
    .slice(0, DOCUMENT_MATCH.MAX_CANDIDATES);
  const hits = [];
  for (const c of ranked) {
    const rec = dag.getContent(c.ctid);
    if (!rec) continue;
    const row = await dag.getPerceptualFingerprint(c.ctid, c.component_idx);
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

// Pictures and scanned pages, probed in one candidate query. Only a shared
// scanned page makes another document a candidate (a shared picture never lists
// one); a picture or page that matches an image posted alone is an image hit.
async function _matchImages(dag, queryFp, exclude, add) {
  const usable = (list, page) => (list || [])
    .filter((p) => typeof p.pdq === "string" && p.quality >= MIN_QUALITY)
    .map((p) => ({ pdq: p.pdq, page }));
  const probes = evenSample([...usable(queryFp.images, false), ...usable(queryFp.textless_pages, true)], DOCUMENT_MATCH.IMAGE_PROBES);
  if (!probes.length) return [];
  const best = new Map();
  for (const c of await dag.findPhashCandidates(IMAGE_PROFILE, "image", mergedProbeKeys(probes.map((p) => p.pdq)))) {
    if (c.ctid === exclude || c.quality < MIN_QUALITY) continue;
    let distance = Infinity;
    let page = false;
    for (const p of probes) {
      const d = hammingHex(p.pdq, c.pdq);
      if (d < distance) distance = d;
      if (p.page && d <= DISTANCE_THRESHOLD) page = true;
    }
    if (distance > DISTANCE_THRESHOLD) continue;
    const key = `${c.ctid}|${c.component_idx}`;
    const b = best.get(key);
    if (!b) best.set(key, { ctid: c.ctid, component_idx: c.component_idx, distance, page });
    else { b.distance = Math.min(b.distance, distance); b.page = b.page || page; }
  }
  const nearest = [...best.values()].sort((a, b) => a.distance - b.distance).slice(0, DOCUMENT_MATCH.IMAGE_HITS);
  if (!nearest.length) return [];
  const modality = new Map();
  for (const r of await dag.getPerceptualModalities([...new Set(nearest.map((h) => h.ctid))])) {
    modality.set(`${r.ctid}|${r.component_idx}`, r.modality);
  }
  const images = new Map();
  for (const hit of nearest) {
    const m = modality.get(`${hit.ctid}|${hit.component_idx}`);
    if (m === "document") {
      if (hit.page) add(hit.ctid, hit.component_idx, TIER.CONFIRMED, 0);
    } else if (m === "image" && !images.has(hit.ctid)) {
      images.set(hit.ctid, { ctid: hit.ctid, modality: "image", distance: hit.distance });
    }
  }
  return [...images.values()];
}

module.exports = { configure, maxKeyOwners, matchDocument, documentScore };
