"use strict";

// Similar documents (cf-doc-1). Candidates come from the same wording
// (text_hash), shared passages, the document's text bands and its picture and
// page images; each is then measured with the library's compareDocument, which
// says how much text the two share and where. Advisory, never a copy verdict.
//
// There is no list of common text (licences, disclaimers, templates):
// compareDocument weights each shared passage by 1 / (1 + other owners holding
// it), counted from the index, so text that many people hold sorts last.

const { compareDocument } = require("tip-content-fingerprint/src/document/compare");
const { passageKeys } = require("tip-content-fingerprint/src/document/passages");
const { MIN_SHARED_CHARS } = require("tip-content-fingerprint/src/document/constants");
const { lshBands } = require("tip-content-fingerprint/src/text/lsh");
const { jaccardEstimate } = require("tip-content-fingerprint/src/text/compare");
const { queryKeys } = require("tip-content-fingerprint/src/image/mih");
const { hammingHex } = require("tip-content-fingerprint/src/image/hamming");
const { PROFILE: IMAGE_PROFILE, DISTANCE_THRESHOLD, MIN_QUALITY } = require("tip-content-fingerprint/src/image");
const textIndex = require("./text-index");
const { TEXT_FLAG_THRESHOLD } = require("./matcher");
const { DOCUMENT_FINGERPRINT, DOCUMENT_MATCH } = require("../../../shared/constants");

// Candidates found by an independent signal are compared before those found
// only through shared passages.
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

// passage key -> owners other than `a` and `b`. Keys over the cap have no holder
// rows, so their count comes from the total.
function _otherOwners(holders, totals, a, b) {
  return {
    get(key) {
      const set = holders.get(key);
      if (set) return set.size - (set.has(a) ? 1 : 0) - (b !== a && set.has(b) ? 1 : 0);
      const total = totals.get(key);
      return total == null ? 0 : Math.max(0, total - (a === b ? 1 : 2));
    },
  };
}

// One 0-1 figure to rank against other modalities: shared text (0.5 at one
// paragraph of text no one else holds), the text MinHash at or over the flag
// line, or the share of scanned pages that are the same image.
function documentScore(cmp) {
  const st = cmp.shared_text;
  const shared = st ? st.score / (st.score + MIN_SHARED_CHARS) : 0;
  const text = cmp.text_similarity >= TEXT_FLAG_THRESHOLD ? cmp.text_similarity : 0;
  const tp = cmp.textless_pages;
  const pages = tp && tp.shared ? tp.shared / Math.max(tp.a, tp.b) : 0;
  return Math.max(shared, text, pages);
}

function _listable(cmp) {
  if (!cmp.textless_pages) return false; // not comparable: reject tier or another profile
  return Boolean((cmp.shared_text && cmp.shared_text.worth_listing)
    || cmp.text_similarity >= TEXT_FLAG_THRESHOLD
    || cmp.textless_pages.shared > 0);
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

  const keys = [...new Set(passageKeys(queryFp.passages).map((k) => k.key))];
  const totals = new Map();
  for (const r of keys.length ? await dag.countDocumentPassageOwners(profile, keys) : []) totals.set(r.passage_key, r.owners);
  const usable = keys.filter((k) => totals.has(k) && totals.get(k) <= _maxKeyOwners);
  const holders = new Map();
  for (const r of usable.length ? await dag.findDocumentPassages(profile, usable) : []) {
    let set = holders.get(r.passage_key);
    if (!set) holders.set(r.passage_key, (set = new Set()));
    set.add(r.owner);
    add(r.ctid, r.component_idx, TIER.PASSAGES, 1 / totals.get(r.passage_key));
  }

  const text = queryFp.text;
  const scheme = textIndex.answerScheme();
  if (text && text.tier === "char" && Array.isArray(text.minhash) && textIndex.isReady(dag, scheme)) {
    const found = (await dag.findMinhashCandidates(textIndex.bandProfile(text.profile, scheme), lshBands(text.minhash, { scheme })))
      .filter((c) => c !== exclude);
    for (const d of found.length ? await dag.getDocumentTextsByCtids(found) : []) {
      let fp;
      try { fp = JSON.parse(d.text); } catch { continue; }
      if (Array.isArray(fp.minhash) && jaccardEstimate(text.minhash, fp.minhash) >= TEXT_FLAG_THRESHOLD) add(d.ctid, d.component_idx, TIER.CONFIRMED, 0);
    }
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
    const cmp = compareDocument(queryFp, fp, { owners: _otherOwners(holders, totals, opts.owner || null, rec.author_tip_id) });
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
