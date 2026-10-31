"use strict";

// Registered again: someone else registered the very same content (same
// normalized content_hash) after you did. The first author hears about it in
// their Inbox, and both record pages say who came first.
//
// Read side only, never consensus. Every dashboard and record view reads
// this and each lookup costs the Lab, so nothing scans history per request:
// one index per DAG is built from history once (the first read after start)
// and the commit handler adds each new registration as it commits
// (noteRegistration). The index holds only content hashes that more than one
// record shares, and which TIP-IDs took part; the records themselves are read
// from the committed content rows, so a retraction takes effect at once.
//
// Who is "first": the earliest live record (registered_at, then CTID).
// Left out on purpose:
//   - the same TIP-ID (signer or byline author) on both records,
//   - an organization and its active team members,
//   - two records that share any byline author,
//   - replies and comments (parent_url): "Great post!" twice under one post
//     is not a copy anyone needs to hear about.
// Only copies registered from the activation instant count, so the day this
// ships nobody's Inbox fills with history.

const { TX_TYPES, CONTENT_STATUS, TIP_ID_TYPES, REGISTERED_AGAIN_ACTIVATION_MS } = require("../../../shared/constants");
const { shake256 } = require("../../../shared/crypto");
const { toIso } = require("../../../shared/time");
const roster = require("../schemas/_org-members");

const _override = process.env.NODE_ENV === "production" ? NaN : parseInt(process.env.TIP_REGISTERED_AGAIN_ACTIVATION_MS, 10);
const ACTIVATION_MS = Number.isFinite(_override) ? _override : REGISTERED_AGAIN_ACTIVATION_MS;
if (Number.isFinite(_override)) {
  console.warn(`[registered-again] TIP_REGISTERED_AGAIN_ACTIVATION_MS override in effect: ${toIso(ACTIVATION_MS)}`);
}

// Text that normalizes to nothing (only emoji, punctuation or symbols) with no
// media hashes to shake256(""), which every such post shares: never a copy.
const EMPTY_TEXT_HASH = shake256("");
function isNeverACopy(contentHash) {
  return contentHash === EMPTY_TEXT_HASH;
}

// Text this short is ordinary ("gm", "Thank you so much!"); an exact match
// alone says nothing, so it never raises an alert (it still shows in the
// Inbox). Counted on normalized text (letters and numbers only), so 40 is
// about eight words.
const MIN_ALERT_CHARS = 40;
const ALERT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const INBOX_WINDOW_MS = 90 * 24 * 60 * 60 * 1000;

const _byDag = new WeakMap();   // dag -> { built, groups: Map(hash -> {tips:Set, chars}), byTip: Map(tip -> Set(hash)) }

function _state(dag) {
  let st = _byDag.get(dag);
  if (!st) { st = { built: false, groups: new Map(), byTip: new Map() }; _byDag.set(dag, st); }
  return st;
}

function _tipsOf(d) {
  const out = new Set();
  if (d && d.signer_tip_id) out.add(d.signer_tip_id);
  if (d && d.author_tip_id) out.add(d.author_tip_id);
  for (const a of (d && Array.isArray(d.authors) ? d.authors : [])) if (a && a.tip_id) out.add(a.tip_id);
  return out;
}

function _chars(d) {
  return d && Number.isInteger(d.text_chars) && d.text_chars >= 0 ? d.text_chars : null;
}

function _join(st, hash, tips, chars) {
  let g = st.groups.get(hash);
  if (!g) { g = { tips: new Set(), chars: null }; st.groups.set(hash, g); }
  for (const t of tips) {
    g.tips.add(t);
    let s = st.byTip.get(t);
    if (!s) { s = new Set(); st.byTip.set(t, s); }
    s.add(hash);
  }
  if (g.chars == null && chars != null) g.chars = chars;
}

/** Called by the commit handler after a REGISTER_CONTENT row is saved. */
function noteRegistration(dag, d) {
  if (!d || !d.content_hash || isNeverACopy(d.content_hash)) return;
  const st = _state(dag);
  if (!st.built) return;   // the first read builds everything from history
  const rows = typeof dag.getContentByHash === "function" ? dag.getContentByHash(d.content_hash) : [];
  if (rows.length < 2) return;
  const tips = new Set();
  for (const r of rows) for (const t of _tipsOf(r)) tips.add(t);
  _join(st, d.content_hash, tips, _chars(d));
}

function _build(dag) {
  const st = _state(dag);
  if (st.built || typeof dag.getTxsByType !== "function") return st;
  const seen = new Map();   // hash -> { n, tips:Set, chars }
  for (const t of dag.getTxsByType(TX_TYPES.REGISTER_CONTENT) || []) {
    const d = t && t.data;
    if (!d || !d.content_hash || isNeverACopy(d.content_hash)) continue;
    let s = seen.get(d.content_hash);
    if (!s) { s = { n: 0, tips: new Set(), chars: null }; seen.set(d.content_hash, s); }
    s.n++;
    for (const x of _tipsOf(d)) s.tips.add(x);
    if (s.chars == null) s.chars = _chars(d);
  }
  for (const [hash, s] of seen) if (s.n > 1) _join(st, hash, s.tips, s.chars);
  st.built = true;   // only after the scan succeeded
  return st;
}

function _live(r) {
  return r && r.status !== CONTENT_STATUS.RETRACTED;
}

function _byFirst(a, b) {
  return (a.registered_at - b.registered_at) || String(a.ctid).localeCompare(String(b.ctid));
}

function createRegisteredAgain({ dag }) {
  // Two records whose people are connected never count as a copy.
  function _related(a, b) {
    const ta = _tipsOf(a), tb = _tipsOf(b);
    for (const t of ta) if (tb.has(t)) return true;
    for (const [orgs, others] of [[ta, tb], [tb, ta]]) {
      for (const o of orgs) {
        const id = typeof dag.getIdentity === "function" ? dag.getIdentity(o) : null;
        if (!id || id.tip_id_type !== TIP_ID_TYPES.ORGANIZATION) continue;
        const members = new Set(roster.activeMembers(dag, o).map(m => m.member_tip_id));
        for (const t of others) if (members.has(t)) return true;
      }
    }
    return false;
  }

  // The live records sharing this hash, first one first.
  function _group(hash) {
    return (dag.getContentByHash(hash) || []).filter(_live).sort(_byFirst);
  }

  function _copiesOf(first, rows) {
    if (first.parent_url) return [];
    return rows.filter(r => r.ctid !== first.ctid && !r.parent_url
      && r.registered_at >= ACTIVATION_MS && !_related(first, r));
  }

  function _substantial(first, chars) {
    if (first.media_canonical_hash) return true;
    if (first.extras && typeof first.extras === "object" && first.extras.title) return true;
    return chars == null || chars >= MIN_ALERT_CHARS;
  }

  /** For the first author's Inbox: one entry per record of theirs that was
   *  registered again by others in the last 90 days, newest copy first. */
  function againFor(tipId, now) {
    const st = _build(dag);
    const out = [];
    for (const hash of st.byTip.get(tipId) || []) {
      const rows = _group(hash);
      if (rows.length < 2) continue;
      const first = rows[0];
      if (!_tipsOf(first).has(tipId)) continue;
      const copies = _copiesOf(first, rows).filter(r => r.registered_at >= now - INBOX_WINDOW_MS);
      if (!copies.length) continue;
      copies.sort((a, b) => b.registered_at - a.registered_at);
      const latest = copies[0].registered_at;
      const g = st.groups.get(hash);
      out.push({
        first, copies, latest,
        alert: now - latest <= ALERT_WINDOW_MS && _substantial(first, g ? g.chars : null),
      });
    }
    return out.sort((a, b) => b.latest - a.latest);
  }

  /** For a record page: the earlier record this one matches (when someone
   *  else registered it first), and the later copies (when this one is the
   *  first). Both lists leave out connected people and replies. */
  function forRecord(rec) {
    const none = { earlier: null, later: [] };
    if (!rec || !rec.content_hash || rec.parent_url || isNeverACopy(rec.content_hash)) return none;
    const st = _build(dag);
    if (!st.groups.has(rec.content_hash)) return none;
    const rows = _group(rec.content_hash);
    if (rows.length < 2) return none;
    const first = rows[0];
    if (first.ctid === rec.ctid) {
      return { earlier: null, later: _copiesOf(first, rows).sort(_byFirst) };
    }
    const isCopy = _copiesOf(first, rows).some(r => r.ctid === rec.ctid);
    return { earlier: isCopy ? first : null, later: [] };
  }

  return { againFor, forRecord, ACTIVATION_MS };
}

/** Forget the index (after a snapshot install replaced history without
 *  applying it); the next read rebuilds it from history. */
function resetRegisteredAgain(dag) {
  _byDag.delete(dag);
}

module.exports = { createRegisteredAgain, noteRegistration, resetRegisteredAgain, isNeverACopy, MIN_ALERT_CHARS };
