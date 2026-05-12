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

// ─── Dispute reasons ────────────────────────────────────────────────────────
// Protocol vocabulary — enum of accepted values for the `reason` field on a
// CONTENT_DISPUTED tx. Adding a reason is a code change (new verdict path,
// signature fields, eligibility rules, score effects), so this lives with
// other code-level enums, not in genesis tunables. Today only origin
// disputes are wired; the (declared_origin, claimed_origin) pair plus the
// eligibility matrix in business-rules.canDispute carries the
// classification.
const DISPUTE_REASON = Object.freeze({
  ORIGIN_MISMATCH: "origin_mismatch",
});
const DISPUTE_REASONS = Object.freeze(Object.values(DISPUTE_REASON));

// ─── Canonical signing schema versions ────────────────────────────────────────
// One entry per signing schema in node/src/signing/. Bump on any
// schema change (field added/removed/renamed); commit-handler dispatches
// on the version found in tx.data so older committed txs keep verifying
// under their original schema (replay correctness). Spec docs:
// docs/CONTENT_SIGNING.md (CNA-2.2 → REGISTER_CONTENT).
// Canonical Content Normalization Algorithm versions, per tx type that
// signs content. Each entry carries:
//   - `versions` — every CNA version ever released for this tx type.
//     Verification accepts any value in this array so historical txs
//     (signed under earlier CNA versions) keep verifying forever
//     (replay correctness / chain integrity).
//   - `current`  — the CNA version new submissions are signed under.
//     The canonical-payload builder forces this string into the signed
//     payload's `cna` field; clients can't pick a different one.
//
// CNA defines the algorithm that turns raw content bytes into the
// canonical bytes hashed into `content_hash`. Implementation lives
// in `shared/crypto.js#tipNormalize`. See docs/CONTENT_SIGNING.md.
const CNA_VERSIONS = Object.freeze({
  REGISTER_CONTENT: Object.freeze({
    versions: Object.freeze(["CNA-2.2"]),
    current:  "CNA-2.2",
  }),
});

// Per-author entry in CNA-2.2 `authors[]` has exactly these 5 keys.
// Reject-on-extra is enforced at canonical-builder time so client
// junk never gets bound to the signature.
const CNA22_AUTHOR_KEYS = Object.freeze([
  "key_mode", "role", "signed", "tip_id", "tip_id_type",
]);

// Canonical `attribution_mode` values per docs/CONTENT_SIGNING.md §2.
// Locks the enum so any non-listed value is rejected at canonical-builder
// time. Default is SELF for the personal/self-publishing case.
//   - SELF      signer IS the author (most personal-creator submissions)
//   - EMPLOYED  signer is publishing on behalf of one or more authors
//               under an employer/agency relationship (e.g. newsroom)
//   - HOSTED    signer is a platform / host publishing third-party
//               content the platform itself doesn't claim authorship of
const ATTRIBUTION_MODES = Object.freeze({
  SELF:     "self",
  EMPLOYED: "employed",
  HOSTED:   "hosted",
});
const ATTRIBUTION_MODE_VALUES = Object.freeze(Object.values(ATTRIBUTION_MODES));

// Canonical `tip_id_type` values — the kind of TIP-ID an identity is.
// Locked enum; rejected at REGISTER_IDENTITY validation time and at
// REGISTER_CONTENT author cross-check time.
//   - PERSONAL      individual human (default for personal creators)
//   - ORGANIZATION  an org / outlet / platform — required to claim a
//                   domain binding, sign content on behalf of authors,
//                   etc. VP attests at REGISTER_IDENTITY time; the
//                   registrant can't self-claim.
const TIP_ID_TYPES = Object.freeze({
  PERSONAL:     "personal",
  ORGANIZATION: "organization",
});
const TIP_ID_TYPE_VALUES = Object.freeze(Object.values(TIP_ID_TYPES));

// ─── Domain binding ──────────────────────────────────────────────────────────
// Org-only claim of "TIP-ID X operates publishing surface at <domain>".
// Two-step flow: user-signed claim → node-verified DNS/HTTP proof → DAG tx
// (BIND_DOMAIN) signed by the verifying node. Spec: my-notes/DOMAIN_VERIFICATION.md.
const DOMAIN_BINDING_STATUS = Object.freeze({
  PENDING:             "pending_verification",  // claim recorded, awaiting node verify
  VERIFIED:            "verified",                // node observed proof and committed to DAG
  VERIFICATION_FAILED: "verification_failed",     // last re-check failed (record kept for audit)
  UNVERIFIED:          "unverified",              // no claim or binding exists
});
const DOMAIN_BINDING_STATUS_VALUES = Object.freeze(Object.values(DOMAIN_BINDING_STATUS));

const DOMAIN_VERIFICATION_METHODS = Object.freeze({
  HTTP: "http",   // GET https://<domain>/.well-known/tip-protocol.json
  DNS:  "dns",    // TXT _tip-protocol.<domain> contains "tip-id=<tip_id>"
  AUTO: "auto",   // try HTTP, fall back to DNS
});
const DOMAIN_VERIFICATION_METHOD_VALUES = Object.freeze(Object.values(DOMAIN_VERIFICATION_METHODS));

// DNS host prefix for the TXT record (case-insensitive). Substring match for
// `tip-id=<tip_id>` is performed against every TXT value at this hostname,
// so additional keys can coexist (`v=tip1; tip-id=...; verified=true`).
const DOMAIN_DNS_TXT_PREFIX = "_tip-protocol";

// HTTP well-known path served by the publisher; must return JSON with at
// least { domain, tip_id, public_key } — the node matches both fields
// against the claim and the DAG identity record.
const DOMAIN_WELL_KNOWN_PATH = "/.well-known/tip-protocol.json";

// How long a pending domain claim (POST /v1/domain/register) is honoured
// before /verify rejects it as stale. 7 days gives an operator a generous
// window to publish the DNS / well-known record without forcing a fresh
// canonical signing round.
const DOMAIN_PENDING_CLAIM_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// Canonical reasons an UNBIND_DOMAIN tx may carry. Locked enum — rejected
// at schema-build time so the signed payload always carries a known value.
const DOMAIN_UNBIND_REASONS = Object.freeze({
  OWNER_REVOKED:     "owner_revoked",      // claimant TIP-ID emitted a voluntary revoke
  TIP_ID_REVOKED:    "tip_id_revoked",     // claimant TIP-ID was revoked (cascade)
  VERIFICATION_LOST: "verification_lost",  // re-verify failed past the grace window
  ADMIN_ACTION:      "admin_action",       // governance-driven removal
});
const DOMAIN_UNBIND_REASON_VALUES = Object.freeze(Object.values(DOMAIN_UNBIND_REASONS));

// ─── Domain binding renewal (v2 prep slots) ──────────────────────────────────
// Canonical state already carries `expires_at` and `consecutive_failures`
// per binding so the adaptive-expiry renewal feature can land as a pure
// code-add (new RENEW_DOMAIN tx + scheduler) without a second schema
// migration. Until v2 ships, every binding is set to {expires_at =
// verified_at + DOMAIN_HEALTHY_EXPIRY_MS, consecutive_failures = 0} at
// BIND_DOMAIN commit time. Read paths surface `expires_at` so consumers
// can already apply their own freshness policy.
const DOMAIN_HEALTHY_EXPIRY_MS    = 30 * 24 * 60 * 60 * 1000;  // 30 days — refreshed on successful renewal
const DOMAIN_RETRY_EXPIRY_MS      = 1 * 24 * 60 * 60 * 1000;   // 1 day — refreshed on transient failure
const DOMAIN_MAX_FAILURES         = 5;                          // consecutive failures → binding flips to unverified
const DOMAIN_RENEWAL_WINDOW_MS    = 60 * 60 * 1000;             // 1 hour — scheduler look-ahead
const DOMAIN_SCHEDULER_INTERVAL_MS = 10 * 60 * 1000;            // 10 min — scheduler tick cadence

// ─── Protocol-tunable constants (VERIFY_CAPS, DISPUTE, JURY, APPEAL, etc.) ──
// These now live in shared/protocol-constants.js, loaded from the genesis block.
// Import them from there: const { JURY, DISPUTE } = require("./protocol-constants");

// ─── Transaction types ────────────────────────────────────────────────────────
const TX_TYPES = Object.freeze({
  // Identity
  REGISTER_IDENTITY: "REGISTER_IDENTITY",
  UPDATE_DEVICE_BINDING: "UPDATE_DEVICE_BINDING",
  LINK_PLATFORM: "LINK_PLATFORM",
  // Domain binding (org-only)
  BIND_DOMAIN: "BIND_DOMAIN",
  UNBIND_DOMAIN: "UNBIND_DOMAIN",
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
  // Consensus committee rotation (§4 + #34 chain-of-trust). Carries the
  // new committee's [{node_id, public_key}] records along with ≥2f+1
  // signatures from the PREVIOUS committee endorsing the transition.
  // Pubkeys travel inline so a snapshot-importing joiner can verify the
  // chain without trusting the peer-provided nodes table.
  COMMITTEE_ROTATION: "COMMITTEE_ROTATION",
});

// Frozen lookup set built once from TX_TYPES values. Used by validators and
// services that need O(1) "is this a known tx type?" checks (tx-validator,
// activity feed type filter, etc.) without each caller rebuilding the set.
const TX_TYPE_SET = Object.freeze(new Set(Object.values(TX_TYPES)));

// ─── Dispute timeline / episode constants ───────────────────────────────────
// Read-side projection helpers used by node/src/services/dispute-service.js
// to build the dispute case + timeline view. Pure data — no consensus role.

// Public dispute_id is the first DISPUTE_SHORT_ID_LEN hex chars of
// dispute_tx_id. 48 bits is well clear of collision risk for dispute volume,
// short enough for URLs and copy-paste. Lookup is a prefix scan; ambiguous
// prefixes return 409 so callers can extend.
const DISPUTE_SHORT_ID_LEN = 12;

// Tx types that belong to a dispute episode (everything except the
// CONTENT_DISPUTED root tx itself, which always anchors the episode).
// Order here is irrelevant — used as an enumeration set; sort order
// across an episode is governed by DISPUTE_EVENT_PRIORITY.
const DISPUTE_EPISODE_TX_TYPES = Object.freeze([
  TX_TYPES.AI_CLASSIFIER_RESULT,
  TX_TYPES.JURY_SUMMONS,
  TX_TYPES.JURY_VOTE_COMMIT,
  TX_TYPES.JURY_VOTE_REVEAL,
  TX_TYPES.ADJUDICATION_RESULT,
  TX_TYPES.APPEAL_FILED,
  TX_TYPES.APPEAL_RESULT,
]);

// Logical-event ordering used as a SECONDARY sort key in
// collectEpisodeEvents. Many events in a dispute episode are produced in
// the same atomic submitBatch (CONTENT_DISPUTED + AI_CLASSIFIER_RESULT +
// 7× JURY_SUMMONS, all built from `new Date().toISOString()` calls within
// microseconds), so they share an ISO timestamp at millisecond resolution.
// Sorting on timestamp alone tiebreaks via tx_id (a content hash with no
// semantic meaning), which can put "AI screening" above "Dispute filed"
// in the UI even though the dispute logically precedes its own classifier.
// This priority restores the human-meaningful order whenever timestamps
// collide. Pure data, no DAG state, no determinism risk.
const DISPUTE_EVENT_PRIORITY = Object.freeze({
  [TX_TYPES.CONTENT_DISPUTED]:     0,
  [TX_TYPES.AI_CLASSIFIER_RESULT]: 1,
  [TX_TYPES.JURY_SUMMONS]:         2,
  [TX_TYPES.JURY_VOTE_COMMIT]:     3,
  [TX_TYPES.JURY_VOTE_REVEAL]:     4,
  [TX_TYPES.ADJUDICATION_RESULT]:  5,
  [TX_TYPES.APPEAL_FILED]:         6,
  [TX_TYPES.APPEAL_RESULT]:        7,
});


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
  DOMAIN_ALREADY_CLAIMED:          "domain_already_claimed",
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
  DAG_TX_OUTCOME: "/v1/dag/tx/:txId/outcome",
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
  DISPUTE_REASON,
  DISPUTE_REASONS,
  CNA_VERSIONS,
  CNA22_AUTHOR_KEYS,
  ATTRIBUTION_MODES,
  ATTRIBUTION_MODE_VALUES,
  TIP_ID_TYPES,
  TIP_ID_TYPE_VALUES,
  DOMAIN_BINDING_STATUS,
  DOMAIN_BINDING_STATUS_VALUES,
  DOMAIN_VERIFICATION_METHODS,
  DOMAIN_VERIFICATION_METHOD_VALUES,
  DOMAIN_DNS_TXT_PREFIX,
  DOMAIN_WELL_KNOWN_PATH,
  DOMAIN_PENDING_CLAIM_TTL_MS,
  DOMAIN_UNBIND_REASONS,
  DOMAIN_UNBIND_REASON_VALUES,
  DOMAIN_HEALTHY_EXPIRY_MS,
  DOMAIN_RETRY_EXPIRY_MS,
  DOMAIN_MAX_FAILURES,
  DOMAIN_RENEWAL_WINDOW_MS,
  DOMAIN_SCHEDULER_INTERVAL_MS,
  TX_TYPES,
  TX_TYPE_SET,
  DISPUTE_SHORT_ID_LEN,
  DISPUTE_EPISODE_TX_TYPES,
  DISPUTE_EVENT_PRIORITY,
  TX_REJECTION_REASON,
  SCORE_DISPLAY,
  JURISDICTION_TIERS,
  MEDIA_LIMITS,
  HTTP_HEADERS,
  API_PATHS,
  PROTOCOL,
};
