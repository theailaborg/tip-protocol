/**
 * @file @tip-protocol/node/src/validators/website-gate.js
 * @description Activation gate for website protection, shared by the
 * business rules and the domain schemas so both decide from one instant.
 *
 * Consensus gate: IDENTICAL fleet-wide or nodes diverge. The env override
 * exists to activate it on an isolated cluster before the network date.
 * Callers pass the frozen tx.timestamp (commit time) or the timestamp the
 * API is about to stamp on the tx, never a wall clock read later.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { WEBSITE_PROTECTION_ACTIVATION_MS, URL_TAKEOVER_ACTIVATION_MS, TIP_ID_TYPES } = require("../../../shared/constants");
const { toIso } = require("../../../shared/time");

// The override changes commit rules, so a production node that set it alone
// would fork from the network: it is honoured only outside production.
const _override = process.env.NODE_ENV === "production" ? NaN : parseInt(process.env.TIP_WEBSITE_PROTECTION_ACTIVATION_MS, 10);
const GATE_MS = Number.isFinite(_override) ? _override : WEBSITE_PROTECTION_ACTIVATION_MS;
if (Number.isFinite(_override)) {
  // eslint-disable-next-line no-console
  console.warn(`[website-gate] TIP_WEBSITE_PROTECTION_ACTIVATION_MS override in effect: ${toIso(GATE_MS)}`);
}

function websiteProtectionOn(atMs) {
  return Number.isFinite(atMs) && atMs >= GATE_MS;
}

// Owner takeover has its own, later instant (same override rules).
const _tOverride = process.env.NODE_ENV === "production" ? NaN : parseInt(process.env.TIP_URL_TAKEOVER_ACTIVATION_MS, 10);
const TAKEOVER_MS = Number.isFinite(_tOverride) ? _tOverride : URL_TAKEOVER_ACTIVATION_MS;

function takeoverOn(atMs) {
  return websiteProtectionOn(atMs) && Number.isFinite(atMs) && atMs >= TAKEOVER_MS;
}

// Before the gate only organizations bind domains; from it, people can
// protect their own sites too.
function mayBindDomain(tipIdType, atMs) {
  const t = tipIdType || TIP_ID_TYPES.PERSONAL;
  if (t === TIP_ID_TYPES.ORGANIZATION) return true;
  return t === TIP_ID_TYPES.PERSONAL && websiteProtectionOn(atMs);
}

module.exports = { websiteProtectionOn, takeoverOn, mayBindDomain, GATE_MS, TAKEOVER_MS };
