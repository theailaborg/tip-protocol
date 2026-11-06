/**
 * @file @tip-protocol/node/src/lib/month-buckets.js
 * @description Calendar months in an IANA time zone, for the My Content
 * summary on GET /v1/content (node 2.9.6).
 *
 * A fixed UTC offset puts a record made just after midnight on the 1st in the
 * wrong month whenever daylight saving differs between then and now, so the
 * reader's zone NAME is used: each month's real start instant is worked out
 * once (two Intl lookups per month), then every record is placed by a binary
 * search. Every store hands this the same (time, is_email) pairs, so the
 * summary is identical on every backend by construction.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const FORMATTERS = new Map();
const FORMATTERS_MAX = 64;

function _formatter(tz) {
  let f = FORMATTERS.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat("en-US", {
      timeZone: tz, hourCycle: "h23",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
    if (FORMATTERS.size >= FORMATTERS_MAX) FORMATTERS.clear();
    FORMATTERS.set(tz, f);
  }
  return f;
}

/** True when `tz` is a time zone this runtime knows ("UTC", "America/New_York"). */
function isTimeZone(tz) {
  try { _formatter(tz); return true; } catch { return false; }
}

// Wall-clock fields of `ms` in `tz`.
function _wall(ms, tz) {
  const w = {};
  for (const p of _formatter(tz).formatToParts(ms)) {
    if (p.type !== "literal") w[p.type] = Number(p.value);
  }
  return w;
}

// Minutes-precise offset of `tz` from UTC at instant `ms`, in ms.
function _offsetAt(ms, tz) {
  const w = _wall(ms, tz);
  return Date.UTC(w.year, w.month - 1, w.day, w.hour, w.minute, w.second) - Math.floor(ms / 1000) * 1000;
}

// The instant local midnight starts month `m` (1-based, may overflow) of year `y`.
function _monthStart(y, m, tz) {
  const guess = Date.UTC(y, m - 1, 1);
  const first = guess - _offsetAt(guess, tz);
  return guess - _offsetAt(first, tz);
}

function _key(y, m) {
  const yy = y + Math.floor((m - 1) / 12);
  const mm = (((m - 1) % 12) + 12) % 12 + 1;
  return yy + "-" + String(mm).padStart(2, "0");
}

/**
 * rows: [{ t: registered_at ms, e: is_email boolean }]
 * → { total, posts, emails, latest_at, months: [{ month: "YYYY-MM", posts, emails }] },
 *   months newest first, only months that hold something.
 */
function summarize(rows, tz = "UTC") {
  const out = { total: 0, posts: 0, emails: 0, latest_at: null, months: [] };
  let min = Infinity, max = -Infinity;
  for (const r of rows) {
    if (!Number.isFinite(r.t)) continue;
    if (r.t < min) min = r.t;
    if (r.t > max) max = r.t;
  }
  if (min === Infinity) return out;
  const w = _wall(min, tz);
  const starts = [], keys = [];
  for (let m = w.month; ; m++) {
    const s = _monthStart(w.year, m, tz);
    if (s > max) break;
    starts.push(s);
    keys.push(_key(w.year, m));
  }
  const counts = keys.map(k => ({ month: k, posts: 0, emails: 0 }));
  for (const r of rows) {
    if (!Number.isFinite(r.t)) continue;
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= r.t) lo = mid; else hi = mid - 1;
    }
    if (r.e) { counts[lo].emails++; out.emails++; } else { counts[lo].posts++; out.posts++; }
    out.total++;
  }
  out.latest_at = max;
  out.months = counts.filter(c => c.posts || c.emails).reverse();
  return out;
}

module.exports = { summarize, isTimeZone };
