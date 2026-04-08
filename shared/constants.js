/**
 * @file tip-protocol/shared/constants.js
 * @description Protocol-wide constants for TIP v2.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

// ─── Origin codes ─────────────────────────────────────────────────────────────
const ORIGIN = Object.freeze({
  OH: "OH", // Original Human
  AA: "AA", // AI-Assisted
  AG: "AG", // AI-Generated
  MX: "MX", // Mixed/Composite
});

const ORIGIN_LABELS = Object.freeze({
  OH: "Original Human",
  AA: "AI-Assisted",
  AG: "AI-Generated",
  MX: "Mixed / Composite",
});

// ─── Trust tiers ─────────────────────────────────────────────────────────────
const TIERS = Object.freeze([
  { min: 850, max: 1000, name: "HIGHLY_TRUSTED", label: "Highly Trusted", color: "#1A8A5C" },
  { min: 650, max:  849, name: "TRUSTED",        label: "Trusted",        color: "#2563A8" },
  { min: 400, max:  649, name: "VERIFIED",       label: "Verified",       color: "#A88B15" },
  { min: 200, max:  399, name: "CAUTION",        label: "Caution",        color: "#C07318" },
  { min:   0, max:  199, name: "NOT_TRUSTED",    label: "Not Trusted",    color: "#C53030" },
]);

function getTier(score) {
  return TIERS.find(t => score >= t.min && score <= t.max) || TIERS[4];
}

// ─── Scoring events ───────────────────────────────────────────────────────────
const SCORE_EVENTS = Object.freeze({
  INITIAL_NO_ATTESTATION:    {  delta:    0, start: 500 },
  INITIAL_WITH_ATTESTATION:  {  delta:   50, start: 550 },
  CONTENT_VERIFIED:          {  delta: "+2_to_+5"       }, // weighted
  OH_CONFIRMED_AG_1ST:       {  delta: -100              },
  OH_CONFIRMED_AA:           {  delta:  -40              },
  AA_CONFIRMED_AG:           {  delta:  -25              },
  AG_CONFIRMED_OH:           {  delta:    0              }, // conservative labelling
  MISMATCH_2ND_OFFENSE:      {  delta: -200              },
  MISMATCH_3RD_OFFENSE:      {  delta: -350              },
  FACTUAL_FALSEHOOD_MINOR:   {  delta:  -75              },
  FACTUAL_FALSEHOOD_MAJOR:   {  delta: -300              },
  SUCCESSFUL_APPEAL:         {  delta: "restore_50pct"   },
  CLEAN_90_DAYS:             {  delta:  +10              },
  DEVICE_COMPROMISE_PENDING: {  delta:  -15              },
});

// ─── Transaction types ────────────────────────────────────────────────────────
const TX_TYPES = Object.freeze({
  // Identity
  REGISTER_IDENTITY:        "REGISTER_IDENTITY",
  UPDATE_DEVICE_BINDING:    "UPDATE_DEVICE_BINDING",
  LINK_PLATFORM:            "LINK_PLATFORM",
  // Content
  REGISTER_CONTENT:         "REGISTER_CONTENT",
  UPDATE_ORIGIN:            "UPDATE_ORIGIN",
  // Trust
  CONTENT_VERIFIED:         "CONTENT_VERIFIED",
  CONTENT_DISPUTED:         "CONTENT_DISPUTED",
  ADJUDICATION_RESULT:      "ADJUDICATION_RESULT",
  APPEAL_FILED:             "APPEAL_FILED",
  SCORE_UPDATE:             "SCORE_UPDATE",
  // Revocation
  REVOKE_VOLUNTARY:         "REVOKE_VOLUNTARY",
  REVOKE_VP:                "REVOKE_VP",
  REVOKE_DECEASED:          "REVOKE_DECEASED",
  REVOKE_DEVICE:            "REVOKE_DEVICE",
  // Governance
  VP_REGISTERED:            "VP_REGISTERED",
  VP_SUSPENDED:             "VP_SUSPENDED",
  NODE_REGISTERED:          "NODE_REGISTERED",
  MERKLE_ROOT_PUBLISHED:    "MERKLE_ROOT_PUBLISHED",
});

// ─── Pre-scan thresholds (v2 FIX-03) ─────────────────────────────────────────
const PRESCAN_THRESHOLDS = Object.freeze({
  default:     0.85,
  floor:       0.80,
  ceiling:     0.94,
  byType: {
    conversational: 0.82,
    news:           0.85,
    creative:       0.87,
    academic:       0.92,
    legal:          0.93,
  },
});

// ─── Score display modes (v2 FIX-06) ─────────────────────────────────────────
const SCORE_DISPLAY = Object.freeze({
  FULL_PUBLIC:    "FULL_PUBLIC",
  TIER_ONLY:      "TIER_ONLY",   // default
  VERIFIED_ONLY:  "VERIFIED_ONLY",
});

// ─── Jurisdiction tiers (v2 FIX-08) ──────────────────────────────────────────
const JURISDICTION_TIERS = Object.freeze({
  GREEN: "green",
  AMBER: "amber",
  RED:   "red",
});

// ─── HTTP headers ─────────────────────────────────────────────────────────────
const HTTP_HEADERS = Object.freeze({
  AUTHOR:       "TIP-Author",
  CONTENT:      "TIP-Content",
  ORIGIN:       "TIP-Origin",
  TRUST_SCORE:  "TIP-Trust-Score",
  SIGNATURE:    "TIP-Signature",
  TIER:         "TIP-Tier",
  VP_ID:        "TIP-VP-ID",
});

// ─── API paths ────────────────────────────────────────────────────────────────
const API_PATHS = Object.freeze({
  HEALTH:             "/health",
  // Identity
  IDENTITY_REGISTER:  "/v1/identity/register",
  IDENTITY_RESOLVE:   "/v1/identity/:tipId",
  IDENTITY_SCORE:     "/v1/identity/:tipId/score",
  IDENTITY_HISTORY:   "/v1/identity/:tipId/history",
  // Content
  CONTENT_REGISTER:   "/v1/content/register",
  CONTENT_RESOLVE:    "/v1/content/:ctid",
  CONTENT_VERIFY:     "/v1/content/:ctid/verify",
  CONTENT_DISPUTE:    "/v1/content/:ctid/dispute",
  // DAG
  DAG_TX:             "/v1/dag/tx",
  DAG_TX_BY_ID:       "/v1/dag/tx/:txId",
  // Revocations
  REVOCATIONS:        "/v1/revocations",
  // VP
  VP_REGISTER:        "/v1/vp/register",
  VP_RESOLVE:         "/v1/vp/:vpId",
  // Dedup (ZK proof — never returns hash)
  DEDUP_CHECK:        "/v1/dedup/check",
  MERKLE_ROOT:        "/v1/dedup/merkle-root",
  // Node
  NODE_INFO:          "/v1/node/info",
  NODE_PEERS:         "/v1/node/peers",
  NODE_SYNC:          "/v1/node/sync",
});

// ─── Protocol metadata ────────────────────────────────────────────────────────
const PROTOCOL = Object.freeze({
  name:       "Trust Identity Protocol",
  short:      "TIP",
  version:    "2.0.0",
  specUrl:    "https://theailab.org/trust-identity-protocol",
  license:    "CC-BY-4.0",
  issuer:     "The AI Lab Intelligence Unobscured, Inc.",
  issuerUrl:  "https://theailab.org",
});

module.exports = {
  ORIGIN,
  ORIGIN_LABELS,
  TIERS,
  getTier,
  SCORE_EVENTS,
  TX_TYPES,
  PRESCAN_THRESHOLDS,
  SCORE_DISPLAY,
  JURISDICTION_TIERS,
  HTTP_HEADERS,
  API_PATHS,
  PROTOCOL,
};
