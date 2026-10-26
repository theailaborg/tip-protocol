"use strict";

// Owner takeovers, read back for people: which record lost which page address
// to the site's owner, and when. Used by the content record (released_urls)
// and the Inbox of the old record's author.
//
// Every record view and every dashboard reads this, and each lookup costs the
// Lab, so it never scans transaction history per request. One index per DAG
// is built from history once (the first read after start), and the commit
// handler adds each new takeover as it commits (noteTakeovers). No table or
// column is added: the index is a read cache, and a row is shown only while
// its effect holds (the old record no longer lists the address and the
// owner's record does).

const { TX_TYPES } = require("../../../shared/constants");

const _byDag = new WeakMap();   // dag -> { built, rows: Map(key -> row) }

function _state(dag) {
  let st = _byDag.get(dag);
  if (!st) { st = { built: false, rows: new Map() }; _byDag.set(dag, st); }
  return st;
}

function _add(st, d, ts) {
  if (!d || !Array.isArray(d.url_takeovers)) return;
  for (const k of d.url_takeovers) {
    if (!k || !k.ctid || !k.url) continue;
    let host = null;
    try { host = new URL(k.url).hostname; } catch { /* keep null */ }
    const row = {
      url: k.url, ctid: k.ctid, tip_id: k.tip_id || null, domain: host,
      to_ctid: d.ctid, to_tip_id: d.signer_tip_id || d.author_tip_id || null, at: ts,
    };
    st.rows.set(`${k.url}\n${k.ctid}\n${d.ctid}`, row);
  }
}

/** Called by the commit handler when a tx carrying url_takeovers applies. */
function noteTakeovers(dag, d, ts) {
  _add(_state(dag), d, ts);
}

function createUrlTakeovers({ dag }) {
  function _rows() {
    const st = _state(dag);
    if (!st.built && typeof dag.getTxsByType === "function") {
      for (const type of [TX_TYPES.REGISTER_CONTENT, TX_TYPES.UPDATE_REGISTERED_URLS]) {
        for (const t of dag.getTxsByType(type) || []) _add(st, t && t.data, t && t.timestamp);
      }
      st.built = true;   // only after the scan succeeded
    }
    return st.rows;
  }

  // The row's effect still holds on the committed records.
  function _holds(r) {
    const loser = dag.getContent(r.ctid), winner = dag.getContent(r.to_ctid);
    if (!loser || !winner || !Array.isArray(winner.registered_urls)) return false;
    return !(loser.registered_urls || []).includes(r.url) && winner.registered_urls.includes(r.url);
  }

  /** Addresses this record released to a site's owner, oldest first. */
  function releasedBy(ctid) {
    const out = [];
    for (const r of _rows().values()) if (r.ctid === ctid && _holds(r)) out.push(r);
    return out.sort((a, b) => a.at - b.at);
  }

  /** Takeovers of this TIP-ID's records (as signer or byline author) since
   *  `sinceMs`, newest first. */
  function takenFrom(tipId, sinceMs = 0) {
    const out = [];
    for (const r of _rows().values()) {
      if (r.at < sinceMs || !_holds(r)) continue;
      const loser = dag.getContent(r.ctid);
      if (r.tip_id === tipId || (loser && loser.author_tip_id === tipId)) out.push(r);
    }
    return out.sort((a, b) => b.at - a.at);
  }

  return { releasedBy, takenFrom };
}

/** Forget the index (after a snapshot install replaced history without
 *  applying it); the next read rebuilds it from history. */
function resetTakeovers(dag) {
  _byDag.delete(dag);
}

module.exports = { createUrlTakeovers, noteTakeovers, resetTakeovers };
