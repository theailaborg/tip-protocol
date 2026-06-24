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
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError } = require("./_common");
const { CONTENT_STATUS } = require("../../../shared/constants");
const { ORIGIN_CODES } = require("./content-register");

const TIP_ID_RE = /^tip:\/\/id\/[A-Z]{2}-[0-9a-f]{16}$/;
const CTID_RE = /^tip:\/\/c\/[A-Z]{2}-[0-9a-f]{14}-[0-9a-f]{4}$/;
const STATUSES = Object.values(CONTENT_STATUS);

const LIMIT_DEFAULT = 20;
const LIMIT_MAX = 100;

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
    origin: null,
    status: null,
    hasMedia: null,
    url: null,
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

  return out;
}

module.exports = { validateRequest, encodeCursor, decodeCursor, LIMIT_MAX, LIMIT_DEFAULT };
