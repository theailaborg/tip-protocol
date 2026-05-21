/**
 * @file @tip-protocol/node/src/middleware/timestamp-format.js
 * @description Boundary timestamp normalisation.
 *
 * Internal code uses integer epoch ms for every timestamp (see
 * shared/time.js). External clients (browser extension, VP app,
 * third-party tooling) consume ISO 8601 strings on the API surface.
 * This middleware is the single conversion seam:
 *
 *   - Outgoing (response): walks the JSON body before serialising and
 *     converts any allow-listed integer field to ISO 8601 via toIso().
 *     Strings already in ISO form pass through unchanged — useful while
 *     the internal write sites migrate file-by-file.
 *
 *   - Incoming (request): walks req.body and converts any allow-listed
 *     ISO 8601 string field to integer ms via fromIso(). Numeric fields
 *     pass through unchanged so callers may submit either form.
 *
 * The allow-list is the explicit set of TIP wire-shape timestamp field
 * names. Adding a new timestamp field requires adding its name here —
 * the safest default (don't touch unknown fields) prevents accidental
 * munging of unrelated `*_at`-suffixed string columns (e.g. a future
 * `referenced_at` URL fragment).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { toIso, fromIso, isValidMs } = require("../../../shared/time");

// Every field name that carries a TIP timestamp value on the wire.
// Keep alphabetical for grep-ability; add new names here, not at
// individual call sites. Round counters (`triggered_at_round` etc.)
// are intentionally excluded — they're integers but not timestamps.
const TIMESTAMP_FIELDS = new Set([
  "cert_timestamp",
  "claimed_at",
  "committed_at",
  "confirmed_at",
  "confirmed_at_ms",
  "created_at",
  "decided_at",
  "expires_at",
  "received_at",
  "registered_at",
  "revoked_at",
  "signed_at",
  "timestamp",
  "triggered_at",
  "verified_at",
  "verified_since",
]);

// Walk an arbitrary JSON-shaped value, mutating timestamp fields in
// place. Mutation rather than copy because response bodies can be
// large (long activity feeds, paginated DAG dumps) and a deep clone
// would double the allocations on every API call.
function _walk(node, transform) {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) _walk(item, transform);
    return;
  }
  for (const key of Object.keys(node)) {
    const val = node[key];
    if (TIMESTAMP_FIELDS.has(key)) {
      const replaced = transform(val);
      if (replaced !== undefined) node[key] = replaced;
    } else if (val !== null && typeof val === "object") {
      _walk(val, transform);
    }
  }
}

// Response side: integer ms → ISO. Already-ISO strings, nulls, and
// undefined values pass through (let the existing surface stay during
// the migration). Throws-on-implausibility surfaces via toIso's own
// guard rather than being swallowed here — a stack trace on a bad
// boundary value is preferable to a silently-corrupt response.
function _msToIso(v) {
  if (typeof v === "number" && isValidMs(v)) return toIso(v);
  return undefined;
}

// Request side: ISO string → integer ms. Already-ms numbers pass
// through. Empty / null / non-string values are left for the
// downstream validator to reject with its own error message.
function _isoToMs(v) {
  if (typeof v === "string" && v.length > 0) {
    try { return fromIso(v); }
    catch { return undefined; }
  }
  return undefined;
}

// Express middleware factory. Mounts before route handlers; mutates
// req.body on entry, wraps res.json on exit. Safe to compose with the
// existing requestId / error-handler / validate stack — no shared
// state, no async work.
//
// During the ISO → ms migration the incoming half is disabled by
// default: schema validators currently typecheck claimed_at /
// verified_at as strings, and silently converting those values to
// numbers would surface as a 400 to legitimate callers. Once those
// validators move onto isValidMs (the chain-shape migration commit),
// callers flip { incoming: true } on for the symmetric behaviour.
function createTimestampFormat({ outgoing = true, incoming = false } = {}) {
  return function timestampFormat(req, res, next) {
    if (incoming && req.body && typeof req.body === "object") {
      _walk(req.body, _isoToMs);
    }
    if (outgoing) {
      const originalJson = res.json.bind(res);
      res.json = function patchedJson(body) {
        if (body && typeof body === "object") {
          _walk(body, _msToIso);
        }
        return originalJson(body);
      };
    }
    next();
  };
}

// Default export: outgoing-only, matches what api.js wires up today.
const timestampFormat = createTimestampFormat();

module.exports = {
  timestampFormat,
  createTimestampFormat,
  TIMESTAMP_FIELDS, // exported for tests + the future grep-based CI guardrail
};
