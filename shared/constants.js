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

// ─── Jury votes ─────────────────────────────────────────────────────────────
const VOTE = Object.freeze({
  MATCH: "MATCH",
  MISMATCH: "MISMATCH",
  ABSTAIN: "ABSTAIN",
});
const JURY_VOTES = Object.freeze([VOTE.MATCH, VOTE.MISMATCH, VOTE.ABSTAIN]);

// ─── Verdicts ───────────────────────────────────────────────────────────────
const VERDICT = Object.freeze({
  UPHELD: "UPHELD",
  DISMISSED: "DISMISSED",
  CONSERVATIVE_LABEL: "CONSERVATIVE_LABEL",
  NO_QUORUM: "NO_QUORUM",
});

// ─── Content statuses ───────────────────────────────────────────────────────
const CONTENT_STATUS = Object.freeze({
  REGISTERED: "registered",
  VERIFIED: "verified",
  PENDING_REVIEW: "pending_review",
  DISPUTED: "disputed",
  RETRACTED: "retracted",
});

// ─── Protocol-tunable constants (VERIFY_CAPS, DISPUTE, JURY, APPEAL, etc.) ──
// These now live in shared/protocol-constants.js, loaded from the genesis block.
// Import them from there: const { JURY, DISPUTE } = require("./protocol-constants");

// ─── Transaction types ────────────────────────────────────────────────────────
const TX_TYPES = Object.freeze({
  // Identity
  REGISTER_IDENTITY: "REGISTER_IDENTITY",
  UPDATE_DEVICE_BINDING: "UPDATE_DEVICE_BINDING",
  LINK_PLATFORM: "LINK_PLATFORM",
  // Content
  REGISTER_CONTENT: "REGISTER_CONTENT",
  UPDATE_ORIGIN: "UPDATE_ORIGIN",
  CONTENT_RETRACTED: "CONTENT_RETRACTED",
  // Trust
  CONTENT_VERIFIED: "CONTENT_VERIFIED",
  CONTENT_DISPUTED: "CONTENT_DISPUTED",
  // Adjudication
  AI_CLASSIFIER_RESULT: "AI_CLASSIFIER_RESULT",
  JURY_SUMMONS: "JURY_SUMMONS",
  JURY_VOTE_COMMIT: "JURY_VOTE_COMMIT",
  JURY_VOTE_REVEAL: "JURY_VOTE_REVEAL",
  ADJUDICATION_RESULT: "ADJUDICATION_RESULT",
  APPEAL_FILED: "APPEAL_FILED",
  APPEAL_RESULT: "APPEAL_RESULT",
  SCORE_UPDATE: "SCORE_UPDATE",
  // Revocation
  REVOKE_VOLUNTARY: "REVOKE_VOLUNTARY",
  REVOKE_VP: "REVOKE_VP",
  REVOKE_DECEASED: "REVOKE_DECEASED",
  REVOKE_DEVICE: "REVOKE_DEVICE",
  // Governance
  VP_REGISTERED: "VP_REGISTERED",
  VP_SUSPENDED: "VP_SUSPENDED",
  NODE_REGISTERED: "NODE_REGISTERED",
  MERKLE_ROOT_PUBLISHED: "MERKLE_ROOT_PUBLISHED",
});


// ─── Score display modes (v2 FIX-06) ─────────────────────────────────────────
const SCORE_DISPLAY = Object.freeze({
  FULL_PUBLIC: "FULL_PUBLIC",
  TIER_ONLY: "TIER_ONLY",   // default
  VERIFIED_ONLY: "VERIFIED_ONLY",
});

// ─── Jurisdiction tiers (v2 FIX-08) ──────────────────────────────────────────
const JURISDICTION_TIERS = Object.freeze({
  GREEN: "green",
  AMBER: "amber",
  RED: "red",
});

// ─── HTTP headers ─────────────────────────────────────────────────────────────
const HTTP_HEADERS = Object.freeze({
  AUTHOR: "TIP-Author",
  CONTENT: "TIP-Content",
  ORIGIN: "TIP-Origin",
  TRUST_SCORE: "TIP-Trust-Score",
  SIGNATURE: "TIP-Signature",
  TIER: "TIP-Tier",
  VP_ID: "TIP-VP-ID",
});

// ─── API paths ────────────────────────────────────────────────────────────────
const API_PATHS = Object.freeze({
  HEALTH: "/health",
  // Identity
  IDENTITY_REGISTER: "/v1/identity/register",
  IDENTITY_RESOLVE: "/v1/identity/:tipId",
  IDENTITY_SCORE: "/v1/identity/:tipId/score",
  IDENTITY_HISTORY: "/v1/identity/:tipId/history",
  // Content
  CONTENT_REGISTER: "/v1/content/register",
  CONTENT_RESOLVE: "/v1/content/:ctid",
  CONTENT_VERIFY: "/v1/content/:ctid/verify",
  CONTENT_DISPUTE: "/v1/content/:ctid/dispute",
  // DAG
  DAG_TX: "/v1/dag/tx",
  DAG_TX_BY_ID: "/v1/dag/tx/:txId",
  // Revocations
  REVOCATIONS: "/v1/revocations",
  // VP
  VP_REGISTER: "/v1/vp/register",
  VP_RESOLVE: "/v1/vp/:vpId",
  // Dedup (ZK proof — never returns hash)
  DEDUP_CHECK: "/v1/dedup/check",
  MERKLE_ROOT: "/v1/dedup/merkle-root",
  // Node
  NODE_INFO: "/v1/node/info",
  NODE_PEERS: "/v1/node/peers",
  NODE_SYNC: "/v1/node/sync",
});

// ─── Protocol metadata ────────────────────────────────────────────────────────
const PROTOCOL = Object.freeze({
  name: "Trust Identity Protocol",
  short: "TIP",
  version: require("../package.json").version,
  specUrl: "https://theailab.org/trust-identity-protocol",
  license: "CC-BY-4.0",
  issuer: "The AI Lab Intelligence Unobscured, Inc.",
  issuerUrl: "https://theailab.org",
});

module.exports = {
  ORIGIN,
  ORIGIN_LABELS,
  VOTE,
  JURY_VOTES,
  VERDICT,
  CONTENT_STATUS,
  TX_TYPES,
  SCORE_DISPLAY,
  JURISDICTION_TIERS,
  HTTP_HEADERS,
  API_PATHS,
  PROTOCOL,
};
