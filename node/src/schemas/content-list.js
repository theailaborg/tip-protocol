/**
 * @file @tip-protocol/node/src/schemas/content-list.js
 * @description Query validation for GET /v1/content (explorer list).
 *
 * Owns ALL request-level validation per the project rule (validateRequest
 * lives in schemas/, never inline in services). Read-only endpoint, so
 * validation is shape + bounds:
 *
 *   limit      1..100, default 20
 *   cursor     opaque base64url of { t: registered_at_ms, c: ctid } from a
 *              prior response's next_cursor
 *   author     tip://id/... (exact match)
 *   origin     one of ORIGIN_CODES
 *   status     one of CONTENT_STATUS values
 *   has_media  "1" | "true" → only rows with media attached
 *   url        exact registered_urls entry
 *   parent_url exact parent_url match; anti-spam gated in content-service.list
 *   kind       "email" (extras.email records) | "post" (everything else)
 *   from, to   registered_at range in ms, from inclusive, to exclusive
 *   q          2..100 chars, matched against the ctid, registered_urls and
 *              extras.title (ASCII case-insensitive); needs author or bylined
 *   include    "summary": counts per month (posts and emails) for the
 *              author, returned beside the first page; needs author
 *   tz         IANA time zone for the summary's months (default UTC)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError } = require("./_common");
const { isTimeZone } = require("../lib/month-buckets");
const { CONTENT_STATUS } = require("../../../shared/constants");
const { ORIGIN_CODES } = require("./content-register");

const TIP_ID_RE = /^tip:\/\/id\/[A-Z]{2,}-[0-9a-f]{16}$/;
const CTID_RE = /^tip:\/\/c\/[A-Z]{2}-[0-9a-f]{14}-[0-9a-f]{4}$/;
const STATUSES = Object.values(CONTENT_STATUS);

const LIMIT_DEFAULT = 20;
const LIMIT_MAX = 100;
const KINDS = ["email", "post"];
const Q_MIN = 2;
const Q_MAX = 100;
// Year 2286 in ms; anything past it is a typo, not a date.
const TIME_MAX = 9_999_999_999_999;
const TZ_NAME_MAX = 64;

// SQLite lower() folds ASCII only, so every store folds ASCII only and a
// search gives the same rows on every backend.
function asciiLower(s) {
  return String(s).replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

function _time(raw, name) {
  const s = String(raw);
  const n = /^\d{1,13}$/.test(s) ? Number(s) : NaN;
  if (!Number.isInteger(n) || n > TIME_MAX) {
    throw schemaError(400, `${name} must be a time in milliseconds`, `${name}_invalid`);
  }
  return n;
}

function encodeCursor(row) {
  return Buffer.from(JSON.stringify({ t: row.registered_at, c: row.ctid })).toString("base64url");
}

function decodeCursor(raw) {
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
  } catch {
    throw schemaError(400, "cursor is not a valid pagination token", "cursor_invalid");
  }
  if (!parsed || !Number.isInteger(parsed.t) || typeof parsed.c !== "string" || !CTID_RE.test(parsed.c)) {
    throw schemaError(400, "cursor is not a valid pagination token", "cursor_invalid");
  }
  return { t: parsed.t, c: parsed.c };
}

/**
 * Validate + normalise the list query. Returns the canonical options
 * object the dag's listContent expects.
 */
function validateRequest(query = {}) {
  const out = {
    limit: LIMIT_DEFAULT,
    cursor: null,
    author: null,
    bylined: null,
    origin: null,
    status: null,
    hasMedia: null,
    url: null,
    parentUrl: null,
    kind: null,
    from: null,
    to: null,
    q: null,
    summary: false,
    tz: "UTC",
  };

  if (query.limit !== undefined) {
    const n = Number(query.limit);
    if (!Number.isInteger(n) || n < 1 || n > LIMIT_MAX) {
      throw schemaError(400, `limit must be an integer 1..${LIMIT_MAX}`, "limit_invalid");
    }
    out.limit = n;
  }
  if (query.cursor !== undefined && query.cursor !== "") {
    out.cursor = decodeCursor(String(query.cursor));
  }
  if (query.author !== undefined && query.author !== "") {
    if (!TIP_ID_RE.test(String(query.author))) {
      throw schemaError(400, "author must be a tip://id/ URI", "author_invalid");
    }
    out.author = String(query.author);
  }
  // Posts that credit this identity in authors[] without owning them (an org
  // post with the person on the byline). Mutually exclusive with author.
  if (query.bylined !== undefined && query.bylined !== "") {
    if (!TIP_ID_RE.test(String(query.bylined))) {
      throw schemaError(400, "bylined must be a tip://id/ URI", "bylined_invalid");
    }
    if (out.author) throw schemaError(400, "author and bylined cannot be combined", "bylined_invalid");
    out.bylined = String(query.bylined);
  }
  if (query.origin !== undefined && query.origin !== "") {
    const o = String(query.origin).toUpperCase();
    if (!ORIGIN_CODES.includes(o)) {
      throw schemaError(400, `origin must be one of ${ORIGIN_CODES.join(", ")}`, "origin_invalid");
    }
    out.origin = o;
  }
  if (query.status !== undefined && query.status !== "") {
    const st = String(query.status).toLowerCase();
    if (!STATUSES.includes(st)) {
      throw schemaError(400, `status must be one of ${STATUSES.join(", ")}`, "status_invalid");
    }
    out.status = st;
  }
  if (query.has_media !== undefined && query.has_media !== "") {
    const v = String(query.has_media).toLowerCase();
    if (!["1", "true", "0", "false"].includes(v)) {
      throw schemaError(400, "has_media must be 1/true or 0/false", "has_media_invalid");
    }
    out.hasMedia = v === "1" || v === "true" ? true : null;
  }
  // Exact registered-URL lookup. Used by the VP portal's advisory
  // duplicate-URL check (read-only): "is this URL already on the DAG?".
  // Matches an entry of the registered_urls array exactly.
  if (query.url !== undefined && query.url !== "") {
    const s = String(query.url);
    if (s.length > 2048) {
      throw schemaError(400, "url must be 2048 characters or fewer", "url_invalid");
    }
    let parsed;
    try { parsed = new URL(s); } catch { throw schemaError(400, "url must be a valid URL", "url_invalid"); }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw schemaError(400, "url must be an http(s) URL", "url_invalid");
    }
    out.url = s;
  }
  // Parent-context lookup: "what responses point at this post?". Unlike `url`
  // this is a many-to-one match, so content-service.list applies the anti-spam
  // gating before returning rows.
  if (query.parent_url !== undefined && query.parent_url !== "") {
    const s = String(query.parent_url);
    if (s.length > 2048) {
      throw schemaError(400, "parent_url must be 2048 characters or fewer", "parent_url_invalid");
    }
    let parsed;
    try { parsed = new URL(s); } catch { throw schemaError(400, "parent_url must be a valid URL", "parent_url_invalid"); }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw schemaError(400, "parent_url must be an http(s) URL", "parent_url_invalid");
    }
    out.parentUrl = s;
  }
  // My Content sections: emails apart from everything else.
  if (query.kind !== undefined && query.kind !== "") {
    const k = String(query.kind).toLowerCase();
    if (!KINDS.includes(k)) {
      throw schemaError(400, `kind must be one of ${KINDS.join(", ")}`, "kind_invalid");
    }
    out.kind = k;
  }
  if (query.from !== undefined && query.from !== "") out.from = _time(query.from, "from");
  if (query.to !== undefined && query.to !== "") out.to = _time(query.to, "to");
  if (out.from !== null && out.to !== null && out.from >= out.to) {
    throw schemaError(400, "from must be earlier than to", "range_invalid");
  }
  // Search stays inside one person's list: a global substring scan would read
  // the whole table on every keystroke. (author is indexed; a bylined list
  // already scans authors[], and search adds a filter to that same scan.)
  if (query.q !== undefined && String(query.q).trim() !== "") {
    const q = String(query.q).trim();
    if (q.length < Q_MIN || q.length > Q_MAX) {
      throw schemaError(400, `q must be ${Q_MIN} to ${Q_MAX} characters`, "q_invalid");
    }
    if (!out.author && !out.bylined) {
      throw schemaError(400, "q needs author or bylined", "q_needs_author");
    }
    out.q = asciiLower(q);
  }
  if (query.include !== undefined && query.include !== "") {
    const toks = String(query.include).split(",").map((t) => t.trim());
    if (toks.includes("summary")) {
      if (!out.author) throw schemaError(400, "include=summary needs author", "summary_needs_author");
      out.summary = true;
    }
  }
  // A zone NAME, not an offset: daylight saving moves the offset, and a fixed
  // one files a record made just after midnight on the 1st under the wrong month.
  // A well-formed name this runtime does not know (Chrome's "Etc/Unknown", or
  // a zone newer than the node's ICU) counts in UTC rather than failing the
  // page; the summary says which zone it used.
  if (query.tz !== undefined && query.tz !== "") {
    const tz = String(query.tz);
    if (tz.length > TZ_NAME_MAX || !/^[A-Za-z0-9_+\-/]+$/.test(tz)) {
      throw schemaError(400, "tz must be an IANA time zone such as America/New_York", "tz_invalid");
    }
    out.tz = isTimeZone(tz) ? tz : "UTC";
  }

  return out;
}

module.exports = { validateRequest, encodeCursor, decodeCursor, asciiLower, LIMIT_MAX, LIMIT_DEFAULT, KINDS };
