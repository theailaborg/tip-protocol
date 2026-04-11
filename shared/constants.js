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
  CONTENT_RETRACTION:        {  delta:  -50              },
  DEVICE_COMPROMISE_PENDING: {  delta:  -15              },
});

// ─── Verification caps ───────────────────────────────────────────────────────
const VERIFY_CAPS = Object.freeze({
  PER_CONTENT:        5,     // max +5 per CTID
  PER_DAY:            5,     // max +5 per creator per day
  PER_MONTH:          30,    // max +30 per creator per month
  BASE_DELTA:         2,     // base credit per verification
  HIGH_TRUST_DELTA:   3,     // bonus for verifier score >= HIGH_TRUST_MIN (1.5x)
  HIGH_TRUST_MIN:     800,   // minimum score for high-trust bonus
});

// ─── Dispute & Jury constants ─────────────────────────────────────────────────
const DISPUTE = Object.freeze({
  MIN_SCORE_TO_DISPUTE:    400,    // Verified tier or above
  DISPUTER_STAKE:          15,     // points held in escrow
  FRIVOLOUS_PENALTY:       5,      // deducted from stake if auto-dismissed (<30%)
  UPHELD_BONUS:            5,      // bonus to disputer if dispute upheld
  VINDICATION_BONUS:       5,      // bonus to creator if dispute auto-dismissed
});

const JURY = Object.freeze({
  SIZE:                    7,      // jurors per dispute
  MIN_SCORE:              700,     // minimum score for jury eligibility
  JUROR_STAKE:             10,     // points staked per juror
  MAJORITY_VOTE:           3,      // votes needed if 2 abstain (otherwise 4)
  COMMIT_WINDOW_HOURS:     72,     // hours to submit vote commitment
  REVEAL_WINDOW_HOURS:     6,      // hours after commit window to reveal
  QUORUM:                  5,      // minimum reveals needed (else escalate to Stage 3)
  MAJORITY_BONUS:          3,      // bonus for voting with majority
  MINORITY_PENALTY:        10,     // net loss for voting against majority (stake forfeited)
  NO_SHOW_PENALTY:         10,     // net loss for failing to reveal
  MAX_SAME_COUNTRY:        3,      // geographic diversity cap
  COOLDOWN_DAYS:           7,      // days before juror can serve same creator again
});

const APPEAL = Object.freeze({
  APPELLANT_STAKE:         25,     // higher bar than dispute stake
  MIN_EXPERT_SCORE:       850,     // experts must be highly trusted
  EXPERT_COUNT:            3,      // experts per appeal
  MIN_VOTES:               2,      // minimum non-abstain votes from experts
  FILING_WINDOW_HOURS:     48,     // hours after ADJUDICATION_RESULT to file
  COMMIT_WINDOW_HOURS:     72,     // 3 days for expert commit (same as jury)
  REVEAL_WINDOW_HOURS:     6,      // 6 hours for expert reveal (same as jury)
  OVERTURN_BONUS:          10,     // bonus to appellant if appeal succeeds
});

const AI_CLASSIFIER = Object.freeze({
  AUTO_DISMISS_THRESHOLD:  0.30,   // <30% → auto-dismiss, dispute is frivolous
  HIGH_CONFIDENCE:         0.90,   // >90% → escalate with high-confidence flag
  TIMEOUT_SECONDS:         60,     // max time for AI inference
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
  CONTENT_RETRACTED:        "CONTENT_RETRACTED",
  // Trust
  CONTENT_VERIFIED:         "CONTENT_VERIFIED",
  CONTENT_DISPUTED:         "CONTENT_DISPUTED",
  // Adjudication
  AI_CLASSIFIER_RESULT:     "AI_CLASSIFIER_RESULT",
  JURY_SUMMONS:             "JURY_SUMMONS",
  JURY_VOTE_COMMIT:         "JURY_VOTE_COMMIT",
  JURY_VOTE_REVEAL:         "JURY_VOTE_REVEAL",
  ADJUDICATION_RESULT:      "ADJUDICATION_RESULT",
  APPEAL_FILED:             "APPEAL_FILED",
  APPEAL_RESULT:            "APPEAL_RESULT",
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
  version:    "1.0.0",
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
  VERIFY_CAPS,
  DISPUTE,
  JURY,
  APPEAL,
  AI_CLASSIFIER,
  TX_TYPES,
  PRESCAN_THRESHOLDS,
  SCORE_DISPLAY,
  JURISDICTION_TIERS,
  HTTP_HEADERS,
  API_PATHS,
  PROTOCOL,
};
