/**
 * @file tip-protocol/shared/time.js
 * @description Single source of truth for timestamp representation.
 *
 * TIP uses integer epoch milliseconds (UTC) as the internal representation
 * for every timestamp. This is the same representation that the consensus
 * layer already uses for `cert.timestamp` (BFT-Time median of acks) and
 * `ack.signed_at` (signature scope). Making the application layer match
 * removes the parse-back-to-ms cost that ~14 sites used to pay.
 *
 * Rules:
 *   - Internal code: only `nowMs()`. Never `Date.now()` inline, never
 *     `new Date().toISOString()` for timestamp production.
 *   - API responses: a single middleware walks known timestamp fields and
 *     calls `toIso(ms)` on the way out, so external clients (FE, browser
 *     extension, VP app) keep consuming ISO 8601 with no behavior change.
 *   - API requests: the symmetric middleware calls `fromIso(iso)` on the
 *     way in, so callers may submit either form.
 *
 * Why ms (not HLC, not ISO, not seconds):
 *   - BFT-Time at the cert layer already uses ms — adopting ms throughout
 *     means one representation across the codebase.
 *   - HLC solves a problem (causal-key-ordering across non-Byzantine
 *     replicas) that TIP doesn't have; consensus already provides total
 *     order, and BFT-Time provides Byzantine-tolerant wall-clock.
 *   - ISO strings cost a parse at every comparison site and use ~3× more
 *     bytes on the wire and in storage.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

function nowMs() {
  return Date.now();
}

function nowIso() {
  return toIso(nowMs());
}

// Future deadline at nowMs() + offsetMs. Used everywhere TIP computes
// a "commit window closes at" / "appeal filing deadline" / etc. Callers
// pass the offset already in ms (e.g. JURY.COMMIT_WINDOW_HOURS * 3600000),
// keeping unit-conversion at the call site. Returns plain integer ms so
// downstream comparisons are direct integer ops.
function nowPlusMs(offsetMs) {
  if (!Number.isFinite(offsetMs)) {
    throw new TypeError(`nowPlusMs: expected finite number, got ${offsetMs}`);
  }
  return nowMs() + offsetMs;
}

function toIso(ms) {
  // Output-side conversion: format any integer ms. Implausibility checks
  // (pre-2025 floor, seconds-as-ms catcher) live on isValidMs for the
  // ingress boundary; rejecting them here would surprise legitimate
  // callers formatting historical / test-fixture timestamps.
  if (!Number.isFinite(ms)) {
    throw new TypeError(`toIso: expected finite number, got ${ms === null ? "null" : typeof ms}`);
  }
  return new Date(ms).toISOString();
}

function fromIso(iso) {
  if (typeof iso !== "string" || iso.length === 0) {
    throw new TypeError(`fromIso: expected non-empty string, got ${iso === null ? "null" : typeof iso}`);
  }
  const ms = new Date(iso).getTime();
  if (!Number.isFinite(ms)) {
    throw new TypeError(`fromIso: invalid ISO 8601 input "${iso}"`);
  }
  return ms;
}

// Plausible-epoch floor. Anything before 2025-01-01 UTC is either an
// uninitialised value, a unit-ms mix-up (e.g. seconds passed as ms), or
// a corrupt deserialisation. Genesis-anchored "after genesis" enforcement
// is a separate concern owned by tx-validator (which has access to
// GENESIS_TIMESTAMP); this floor is the generic implausibility filter.
const MS_FLOOR_2025_01_01_UTC = 1735689600000;

function isValidMs(v) {
  return Number.isInteger(v)
    && v >= MS_FLOOR_2025_01_01_UTC
    && v <= Number.MAX_SAFE_INTEGER;
}

module.exports = { nowMs, nowIso, nowPlusMs, toIso, fromIso, isValidMs, MS_FLOOR_2025_01_01_UTC };
