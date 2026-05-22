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
 *     converts a field iff its key matches the TIP timestamp naming
 *     pattern AND its value is a plausible epoch-ms integer
 *     (`isValidMs`). Strings already in ISO form, nulls, and
 *     non-ms numbers pass through unchanged.
 *
 *   - Incoming (request): walks req.body and converts a field iff its
 *     key matches the pattern AND its value is a strict-ISO 8601
 *     string (the canonical form `toIso()` produces). Numeric values
 *     pass through; malformed / non-canonical strings stay as-is for
 *     the downstream validator to reject with its own error.
 *
 * Field detection is pattern-based rather than an explicit allow-list.
 * The pattern (`TIMESTAMP_PATTERN`) covers the TIP naming conventions:
 * `*_at`, `*_at_ms`, camelCase `*At`, `*_deadline`, `*_since`, plus
 * exact names `timestamp` / `cert_timestamp` / `at`. False positives
 * are guarded by two layers:
 *
 *   1. `TIMESTAMP_EXCLUDE` removes pattern-matching non-timestamp
 *      names (`*_at_round` round counters, `ack_signed_ats` array of
 *      timestamps).
 *   2. The value-shape check on each direction (isValidMs out,
 *      STRICT_ISO_RE in) means a non-timestamp value held under a
 *      timestamp-shaped key is a pass-through, not a corruption.
 *
 * Convention-as-contract: name your wire timestamp `*_at` / `*At` and
 * the middleware handles it. This eliminates the recurring "added a
 * field, forgot to update the allow-list, integer ms leaks to clients"
 * bug class that surfaced repeatedly during UAT (lastRoundAdvanceAt,
 * decision_window_ends_at, node_seen_at, ...).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { toIso, fromIso, isValidMs } = require("../../../shared/time");

// Any field name following TIP timestamp conventions.
//   .+_at            snake_case suffix:   registered_at, node_seen_at,
//                                         decision_window_ends_at, ...
//   .+_ms            ms-suffixed:         bft_time_genesis_ms,
//                                         confirmed_at_ms, rejected_at_ms.
//                                         Many `_ms` fields are durations
//                                         (timeout / window / interval),
//                                         but those are sub-MS_FLOOR
//                                         small integers and the
//                                         isValidMs gate skips them.
//   .+[a-z]At        camelCase suffix:    lastAdvanceAt, rotationAt,
//                                         lastRoundAdvanceAt
//   .+_deadline      filing_deadline, commit_deadline, reveal_deadline
//   .+_since         verified_since
//   timestamp        tx.timestamp, cert.timestamp
//   cert_timestamp   explicit (no `_at` suffix)
//   at               short form used by /v1/dag/tx/:txId/outcome
const TIMESTAMP_PATTERN = /^(.+_at|.+_ms|.+[a-z]At|.+_deadline|.+_since|timestamp|cert_timestamp|at)$/;

// Pattern-matching names that are NOT timestamps.
//   *_at_round      round counters — small integers, not epoch ms
//   ack_signed_ats  plural: array of signed_at values
const TIMESTAMP_EXCLUDE = /(_at_round$|^ack_signed_ats$)/;

// Strict ISO 8601 — only the canonical form `toIso()` produces. Rejects
// date-only ("2026-03-15"), US-style ("03/15/2026"), and anything that
// `new Date()` would parse loosely. Keeping the round-trip
// `toIso(fromIso(s)) === s` invariant requires this strictness on the
// incoming side; otherwise non-canonical input silently coerces.
const STRICT_ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;

function _isTimestampField(key) {
  return TIMESTAMP_PATTERN.test(key) && !TIMESTAMP_EXCLUDE.test(key);
}

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
    if (_isTimestampField(key)) {
      const replaced = transform(val);
      if (replaced !== undefined) node[key] = replaced;
    }
    if (val !== null && typeof val === "object") {
      _walk(val, transform);
    }
  }
}

// Response side: integer ms → ISO. Only plausible epoch-ms integers
// convert (isValidMs gate); strings (already-ISO), nulls, non-ms
// numbers, and undefined all pass through. This value gate is what
// makes pattern-based key detection safe — e.g. a key named `at`
// holding a node-id string is left untouched.
function _msToIso(v) {
  if (typeof v === "number" && isValidMs(v)) return toIso(v);
  return undefined;
}

// Request side: strict-ISO string → integer ms. Non-canonical strings
// (date-only, locale formats, trailing garbage) pass through for the
// downstream validator to reject. Already-ms numbers pass through
// unchanged so callers may submit either form.
function _isoToMs(v) {
  if (typeof v === "string" && STRICT_ISO_RE.test(v)) {
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
  TIMESTAMP_PATTERN,
  TIMESTAMP_EXCLUDE,
  STRICT_ISO_RE,
  isTimestampField: _isTimestampField,
};
