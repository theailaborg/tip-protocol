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
});

// Frozen lookup set built once from TX_TYPES values. Used by validators and
// services that need O(1) "is this a known tx type?" checks (tx-validator,
// activity feed type filter, etc.) without each caller rebuilding the set.
const TX_TYPE_SET = Object.freeze(new Set(Object.values(TX_TYPES)));


// ─── Tx-rejection reason codes (#64 follow-up: no-loss invariant) ───────────
// Stable wire-format identifiers for why a tx that was admitted past the
// API layer didn't make it into dag.txs. Persisted into the
// `tx_rejections` table by every drop site between mempool admission and
// commit, surfaced via `GET /v1/dag/tx/:txId/outcome`. See dag.js
// `saveTxRejection`.
//
// Adding a new reason: keep the value snake_case and stable forever — old
// rows will outlive any rename. Removing one is a wire-compat break.
const TX_REJECTION_REASON = Object.freeze({
  // Site 1 — mempool admission (post-API, pre-batch)
  MEMPOOL_FULL:                    "mempool_full",
  MEMPOOL_MISSING_TX_ID:           "missing_tx_id",
  // Site 2 — mempool TTL eviction
  MEMPOOL_TTL_EXPIRED:             "mempool_ttl_expired",
  // Site 3 — consensus-layer drops (narwhal handleIncomingBatch)
  BATCH_BEYOND_HORIZON:            "batch_beyond_horizon",
  BATCH_SIG_INVALID:               "batch_sig_invalid",
  BATCH_AUTHOR_UNREGISTERED:       "batch_author_unregistered",
  BATCH_EQUIVOCATION:              "batch_equivocation",
  BATCH_DECODE_FAILED:             "batch_decode_failed",
  // Site 4 — commit-handler revalidation (business-rules check at commit time)
  IDENTITY_ALREADY_REGISTERED:     "identity_already_registered",
  CONTENT_ALREADY_REGISTERED:      "content_already_registered",
  VERIFIER_NOT_AUTHORIZED:         "verifier_not_authorized",
  CLEAN_RECORD_VIOLATION:          "clean_record_violation",
  REVALIDATION_FAILED:             "revalidation_failed",
  // Site 5 — generic fallback for unexpected drops; always logs detail.
  TX_DECODE_FAILED:                "tx_decode_failed",
});

// ─── Media size limits (defaults — node config can override via env) ─────────
const MEDIA_LIMITS = Object.freeze({
  max_video_bytes:  5 * 1024 * 1024 * 1024,   // 5 GB
  max_image_bytes:  50 * 1024 * 1024,          // 50 MB
  max_audio_bytes:  500 * 1024 * 1024,         // 500 MB
  max_text_bytes:   10 * 1024 * 1024,          // 10 MB
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
  // State attestation (2f+1-signed root from latest commit)
  STATE_ROOT: "/v1/state-root",
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
  TX_TYPE_SET,
  TX_REJECTION_REASON,
  SCORE_DISPLAY,
  JURISDICTION_TIERS,
  MEDIA_LIMITS,
  HTTP_HEADERS,
  API_PATHS,
  PROTOCOL,
};
