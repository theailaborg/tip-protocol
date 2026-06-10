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
  // Async prescan: content has been registered but the classifier
  // verdict hasn't landed yet. Flips to REGISTERED or PENDING_REVIEW
  // when PRESCAN_COMPLETED applies. Downstream consumers (h=48 reviewer
  // trigger, grace windows, disputes) gate on prescan_status='completed'
  // and don't act on PENDING_PRESCAN rows.
  PENDING_PRESCAN: "pending_prescan",
});

// ─── Classifier client (outbound HTTP) ─────────────────────────────────────
// Per-call ceilings for the prescan worker's classifier HTTP calls. Same
// on every node — they affect operational timing, not consensus output.
// Text-only cold start (ollama) is ~33s; file-bearing cold start (ONNX
// vision) is ~118s — both warm to a few seconds.
const CLASSIFIER_CLIENT = Object.freeze({
  TEXT_TIMEOUT_MS: 60_000,
  FILE_TIMEOUT_MS: 180_000,
});

// ─── Prescan tiers ──────────────────────────────────────────────────────────
// Vocabulary enum for the 4-tier categorical model. Threshold values that
// decide which probability falls into which tier live in genesis under
// `prescan.tier_thresholds` (accessed via PRESCAN_TIER_THRESHOLDS from
// shared/protocol-constants.js) — same pattern as the existing
// PRESCAN_THRESHOLDS legacy field.
const PRESCAN_TIERS = Object.freeze({
  LOW: "low",
  ELEVATED: "elevated",
  HIGH: "high",
  CRITICAL: "critical",
});

const PRESCAN_TIER_VALUES = Object.freeze([
  PRESCAN_TIERS.LOW,
  PRESCAN_TIERS.ELEVATED,
  PRESCAN_TIERS.HIGH,
  PRESCAN_TIERS.CRITICAL,
]);

// Short, neutral one-liner returned in the registration response per tier.
// Intended as a fallback for *non-UI consumers* (CLI, plugin authors,
// third-party integrations) — the rich post-registration warning copy
// belongs to the FE, which composes it from the structured `prescan`
// descriptor returned alongside this field (tier, probability,
// decision_window_ends_at, actions_available, etc.). See
// my-notes/POST_REGISTRATION_FLOW.md for the FE-owned copy contract.
const PRESCAN_NOTES = Object.freeze({
  [PRESCAN_TIERS.LOW]: null,
  [PRESCAN_TIERS.ELEVATED]: "AI-pattern signals detected; updating the origin within the decision window has zero penalty.",
  [PRESCAN_TIERS.HIGH]: "AI flagged this content at HIGH confidence. Either keep your declaration (an independent reviewer will examine it after the decision window) or update the origin in-window at zero penalty.",
  [PRESCAN_TIERS.CRITICAL]: "AI flagged this content at VERY HIGH confidence. Either keep your declaration (an independent reviewer will examine it after the decision window) or update the origin in-window at zero penalty. Reviewer-confirmed AI involvement carries a significant penalty.",
});

// Confidence-label enum returned in the structured `prescan` descriptor.
// Aliases the tier with the more human-readable "very_high" for CRITICAL.
// Stable contract — FE keys its i18n strings off these values.
const CONFIDENCE_LABELS = Object.freeze({
  [PRESCAN_TIERS.LOW]: "low",
  [PRESCAN_TIERS.ELEVATED]: "elevated",
  [PRESCAN_TIERS.HIGH]: "high",
  [PRESCAN_TIERS.CRITICAL]: "very_high",
});

// Allowed values in `prescan.actions_available`. The FE decides which
// buttons to render based on what the backend says is permitted for
// this tier + state. Backend-owned source of truth so a future protocol
// change (e.g., removing "retract" at a certain tier) propagates without
// a coordinated FE deploy.
const PRESCAN_ACTIONS = Object.freeze({
  KEEP: "keep",
  CHANGE_ORIGIN: "change_origin",
  RETRACT: "retract",
});

// Allowed values in `prescan.consequence_if_confirmed`. Drives the
// severity badge on the FE.
const PRESCAN_CONSEQUENCES = Object.freeze({
  NONE: "none",
  PENALTY: "penalty",
  SIGNIFICANT_PENALTY: "significant_penalty",
});

// Allowed values in `prescan.next_step_if_kept`. Tells the FE what
// happens when the creator does nothing during the decision window.
const PRESCAN_NEXT_STEPS = Object.freeze({
  NONE: "none",
  INDEPENDENT_REVIEWER_AT_WINDOW_END: "independent_reviewer_at_window_end",
});

// ─── Prescan-review state ──────────────────────────────────────────────────
// Lifecycle states for a `prescan_reviews` row. State machine:
//
//   triggered → (creator self-corrects via UPDATE_ORIGIN)    → closed_self_correct
//   triggered → reviewer DISMISSES (AI's flag was wrong)     → closed_dismissed
//   triggered → reviewer CONFIRMS (AI's flag was right)      → confirmed
//   confirmed → (creator accepts correction privately)       → closed_accepted_private
//   confirmed → (24h elapses without creator action)         → escalated_to_dispute
//   triggered → assigned reviewer recuses                    → recused
const PRESCAN_REVIEW_STATES = Object.freeze({
  TRIGGERED: "triggered",                              // reviewer assigned, awaiting decision
  CLOSED_SELF_CORRECT: "closed_self_correct",          // creator updated origin within window
  CLOSED_DISMISSED: "closed_dismissed",                // reviewer said "AI's flag was wrong"
  CONFIRMED: "confirmed",                              // reviewer said "AI's flag was right"; creator decision window open
  CLOSED_ACCEPTED_PRIVATE: "closed_accepted_private",  // creator accepted correction privately
  ESCALATED_TO_DISPUTE: "escalated_to_dispute",        // auto-escalated to CONTENT_DISPUTED after creator window
  RECUSED: "recused",                                  // reviewer recused; reassigned (terminal for this review_id slot)
});

const PRESCAN_REVIEW_STATE_VALUES = Object.freeze(Object.values(PRESCAN_REVIEW_STATES));

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
    current: "CNA-2.2",
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
  SELF: "self",
  EMPLOYED: "employed",
  HOSTED: "hosted",
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
  PERSONAL: "personal",
  ORGANIZATION: "organization",
});
const TIP_ID_TYPE_VALUES = Object.freeze(Object.values(TIP_ID_TYPES));

// ─── Domain binding ──────────────────────────────────────────────────────────
// Org-only claim of "TIP-ID X operates publishing surface at <domain>".
// Two-step flow: user-signed claim → node-verified DNS/HTTP proof → DAG tx
// (BIND_DOMAIN) signed by the verifying node. Spec: my-notes/DOMAIN_VERIFICATION.md.
const DOMAIN_BINDING_STATUS = Object.freeze({
  PENDING: "pending_verification",  // claim recorded, awaiting node verify
  VERIFIED: "verified",                // node observed proof and committed to DAG
  VERIFICATION_FAILED: "verification_failed",     // last re-check failed (record kept for audit)
  UNVERIFIED: "unverified",              // no claim or binding exists
});
const DOMAIN_BINDING_STATUS_VALUES = Object.freeze(Object.values(DOMAIN_BINDING_STATUS));

const DOMAIN_VERIFICATION_METHODS = Object.freeze({
  HTTP: "http",   // GET https://<domain>/.well-known/tip-protocol.json
  DNS: "dns",    // TXT _tip-protocol.<domain> contains "tip-id=<tip_id>"
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
  OWNER_REVOKED: "owner_revoked",      // claimant TIP-ID emitted a voluntary revoke
  TIP_ID_REVOKED: "tip_id_revoked",     // claimant TIP-ID was revoked (cascade)
  VERIFICATION_LOST: "verification_lost",  // re-verify failed past the grace window
  ADMIN_ACTION: "admin_action",       // governance-driven removal
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
const DOMAIN_HEALTHY_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;  // 30 days — refreshed on successful renewal
const DOMAIN_RETRY_EXPIRY_MS = 1 * 24 * 60 * 60 * 1000;   // 1 day — refreshed on transient failure
const DOMAIN_MAX_FAILURES = 5;                          // consecutive failures → binding flips to unverified
const DOMAIN_RENEWAL_WINDOW_MS = 60 * 60 * 1000;             // 1 hour — scheduler look-ahead
const DOMAIN_SCHEDULER_INTERVAL_MS = 10 * 60 * 1000;            // 10 min — scheduler tick cadence

// ─── Protocol-tunable constants (VERIFY_CAPS, DISPUTE, JURY, APPEAL, etc.) ──
// These now live in shared/protocol-constants.js, loaded from the genesis block.
// Import them from there: const { JURY, DISPUTE } = require("./protocol-constants");

// ─── Interest taxonomy ──────────────────────────────────────────────────────
// Curated vocabulary users select from on their profile (UPDATE_PROFILE.interests).
//
//   - Seeded with INITIAL_INTERESTS_SEED at first boot (every honest node
//     starts with the identical list — same code, same constant).
//   - Extended at runtime via INTEREST_REGISTERED txs, VP-attested (matches
//     VP_REGISTERED / NODE_REGISTERED governance pattern). New interests
//     can be added without a code release.
//   - Slug uniqueness enforced at commit (interests_registry PK on slug);
//     semantic-dupe prevention is off-chain federation policy (VP UI warns
//     about similar slugs before signing).
const INTEREST_SLUG_REGEX = /^[a-z][a-z0-9-]{1,38}[a-z0-9]$/;   // 3–40 chars, lowercase + digits + hyphens, starts with letter, no trailing hyphen
const INTEREST_LABEL_MAX_LEN = 80;
const MAX_INTERESTS_PER_PROFILE = 10;   // ceiling on tx.data.interests array length

// Closed category enum. Taxonomy at this level is far more stable than
// individual interests, so locking the category vocabulary in code is
// acceptable — adding a new top-level category is a code release. Adding
// a new interest UNDER an existing category is dynamic via
// INTEREST_REGISTERED. Used by validators (reject unknown category) and
// by the FE to group the checkbox list visually.
const INTEREST_CATEGORIES = Object.freeze({
  TECH: "tech",
  SCIENCE: "science",
  HUMANITIES: "humanities",
  ARTS: "arts",
  BUSINESS: "business",
  LIFESTYLE: "lifestyle",
});
const INTEREST_CATEGORY_VALUES = Object.freeze(new Set(Object.values(INTEREST_CATEGORIES)));

// ─── Platform-link (social account linking) ─────────────────────────────────
// Used by schemas/link-platform.validateRequest + schemas/unlink-platform.
// Adding a new platform here lets users link it without any other code
// change; handle extraction also needs a regex entry in
// services/bio-fetcher.EXTRACTORS.
const PLATFORM_MAX_LENGTH = 50;

// Server-side replay-attack window. The user's signed claim's claimed_at
// must be within this many ms of the API node's nowMs() — older claims
// are rejected at validateRequest.
const CLAIM_MAX_AGE_MS = 15 * 60 * 1000;

const ALLOWED_PLATFORMS = Object.freeze({
  twitter: [/^https?:\/\/(www\.)?(twitter|x)\.com\/[^/?#]/i],
  x: [/^https?:\/\/(www\.)?(twitter|x)\.com\/[^/?#]/i],
  linkedin: [/^https?:\/\/(www\.)?linkedin\.com\/in\/[^/?#]/i],
  youtube: [
    /^https?:\/\/(www\.)?youtube\.com\/@[^/?#]/i,
    /^https?:\/\/(www\.)?youtube\.com\/c\/[^/?#]/i,
    /^https?:\/\/(www\.)?youtube\.com\/channel\/[^/?#]/i,
  ],
  facebook: [/^https?:\/\/(www\.)?facebook\.com\/[^/?#]/i],
  instagram: [/^https?:\/\/(www\.)?instagram\.com\/[^/?#]/i],
  reddit: [/^https?:\/\/(www\.)?reddit\.com\/u(?:ser)?\/[^/?#]/i],
  github: [/^https?:\/\/(www\.)?github\.com\/[^/?#]/i],
  medium: [
    /^https?:\/\/(www\.)?medium\.com\/@[^/?#]/i,
    /^https?:\/\/[^.]+\.medium\.com/i,
  ],
  soundcloud: [/^https?:\/\/(www\.)?soundcloud\.com\/[^/?#]/i],
  tiktok: [/^https?:\/\/(www\.)?tiktok\.com\/@[^/?#]/i],
  spotify: [/^https?:\/\/open\.spotify\.com\/[^/?#]/i],
  substack: [/^https?:\/\/[^.]+\.substack\.com/i],
  devto: [/^https?:\/\/(www\.)?dev\.to\/[^/?#]/i],
  bluesky: [/^https?:\/\/bsky\.app\/profile\/[^/?#]/i],
  threads: [/^https?:\/\/(www\.)?threads\.net\/@[^/?#]/i],
  mastodon: [/^https?:\/\/[^/]+\/@[^/?#]/i],
});

// Platforms that render bios with JavaScript or are login-gated — static
// HTML scraping cannot verify ownership. Linking these requires a VP
// OAuth proof on the link request (vp_oauth_signature + vp_id).
const OAUTH_REQUIRED_PLATFORMS = Object.freeze(new Set([
  "twitter", "x", "instagram", "tiktok", "threads", "facebook", "linkedin", "youtube",
]));

const INITIAL_INTERESTS_SEED = Object.freeze([
  // Tech
  { slug: "ai-ml", label: "AI & Machine Learning", category: "tech" },
  { slug: "web-dev", label: "Web Development", category: "tech" },
  { slug: "devops", label: "DevOps & Infrastructure", category: "tech" },
  { slug: "crypto-blockchain", label: "Crypto & Blockchain", category: "tech" },
  { slug: "cybersecurity", label: "Cybersecurity", category: "tech" },
  { slug: "data-science", label: "Data Science", category: "tech" },
  // Science
  { slug: "climate", label: "Climate Science", category: "science" },
  { slug: "biology", label: "Biology & Life Sciences", category: "science" },
  { slug: "physics", label: "Physics & Cosmology", category: "science" },
  { slug: "chemistry", label: "Chemistry", category: "science" },
  { slug: "neuroscience", label: "Neuroscience", category: "science" },
  { slug: "space-exploration", label: "Space Exploration", category: "science" },
  // Humanities
  { slug: "philosophy", label: "Philosophy", category: "humanities" },
  { slug: "history", label: "History", category: "humanities" },
  { slug: "psychology", label: "Psychology", category: "humanities" },
  { slug: "economics", label: "Economics", category: "humanities" },
  { slug: "politics", label: "Politics & Policy", category: "humanities" },
  // Arts
  { slug: "music", label: "Music", category: "arts" },
  { slug: "film", label: "Film & TV", category: "arts" },
  { slug: "literature", label: "Literature", category: "arts" },
  { slug: "visual-arts", label: "Visual Arts & Design", category: "arts" },
  { slug: "gaming", label: "Gaming", category: "arts" },
  // Business
  { slug: "startups", label: "Startups & Entrepreneurship", category: "business" },
  { slug: "investing", label: "Investing & Finance", category: "business" },
  { slug: "marketing", label: "Marketing & Branding", category: "business" },
  // Lifestyle
  { slug: "fitness-health", label: "Fitness & Health", category: "lifestyle" },
  { slug: "food-cooking", label: "Food & Cooking", category: "lifestyle" },
  { slug: "travel", label: "Travel", category: "lifestyle" },
  { slug: "sports", label: "Sports", category: "lifestyle" },
  { slug: "parenting", label: "Parenting & Family", category: "lifestyle" },
]);

// ─── Transaction types ────────────────────────────────────────────────────────
const TX_TYPES = Object.freeze({
  // Identity
  REGISTER_IDENTITY: "REGISTER_IDENTITY",
  UPDATE_DEVICE_BINDING: "UPDATE_DEVICE_BINDING",
  UPDATE_PROFILE: "UPDATE_PROFILE",
  LINK_PLATFORM: "LINK_PLATFORM",
  UNLINK_PLATFORM: "UNLINK_PLATFORM",
  // GH #60 — key rotation + recovery. Both append a new entity_keys row
  // and close the prior active one atomically at commit. KEY_ROTATED is
  // signed by the OLD key (user proves possession); KEY_RECOVERY is
  // signed by an approving VP (user lost OLD key; VP attests recovery
  // after off-chain re-verification).
  KEY_ROTATED: "KEY_ROTATED",
  KEY_RECOVERY: "KEY_RECOVERY",
  // Prescan review pipeline — human reviewer auditing whether the AI
  // prescan's HIGH/CRITICAL flag was correct. Single-reviewer gate
  // between prescan flag and public CONTENT_DISPUTED. On DAG for
  // federation consistency; UI policy filters dismissed reviews from
  // public surfaces.
  PRESCAN_REVIEW_TRIGGERED: "PRESCAN_REVIEW_TRIGGERED",
  PRESCAN_REVIEW_DISMISSED: "PRESCAN_REVIEW_DISMISSED",
  PRESCAN_REVIEW_CONFIRMED: "PRESCAN_REVIEW_CONFIRMED",
  PRESCAN_REVIEW_RECUSED: "PRESCAN_REVIEW_RECUSED",
  // Async prescan: emitted by the worker on the assigned API node (or a
  // failover leader) once the classifier call returns. Carries the
  // probability/tier/modality breakdown for downstream consumers.
  PRESCAN_COMPLETED: "PRESCAN_COMPLETED",
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
  // Node self-service update of its public API base URL. Envelope-signed
  // by the node's own registered key — only the node itself can repoint
  // where peers redirect reviewers for its media bytes.
  NODE_ENDPOINT_UPDATED: "NODE_ENDPOINT_UPDATED",
  // Interest taxonomy — VP-attested registry entries. Each tx adds a
  // {slug, label} row to interests_registry. Users reference these slugs
  // in their UPDATE_PROFILE.interests selection. Genesis seeds the initial
  // taxonomy from INITIAL_INTERESTS_SEED below; later additions arrive
  // through this tx type.
  INTEREST_REGISTERED: "INTEREST_REGISTERED",
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
  [TX_TYPES.CONTENT_DISPUTED]: 0,
  [TX_TYPES.AI_CLASSIFIER_RESULT]: 1,
  [TX_TYPES.JURY_SUMMONS]: 2,
  [TX_TYPES.JURY_VOTE_COMMIT]: 3,
  [TX_TYPES.JURY_VOTE_REVEAL]: 4,
  [TX_TYPES.ADJUDICATION_RESULT]: 5,
  [TX_TYPES.APPEAL_FILED]: 6,
  [TX_TYPES.APPEAL_RESULT]: 7,
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
  MEMPOOL_FULL: "mempool_full",
  MEMPOOL_MISSING_TX_ID: "missing_tx_id",
  // Site 2 — mempool TTL eviction
  MEMPOOL_TTL_EXPIRED: "mempool_ttl_expired",
  // Site 3 — consensus-layer drops (narwhal handleIncomingBatch)
  BATCH_BEYOND_HORIZON: "batch_beyond_horizon",
  BATCH_SIG_INVALID: "batch_sig_invalid",
  BATCH_AUTHOR_UNREGISTERED: "batch_author_unregistered",
  BATCH_EQUIVOCATION: "batch_equivocation",
  BATCH_DECODE_FAILED: "batch_decode_failed",
  // Site 4 — commit-handler revalidation (business-rules check at commit time)
  IDENTITY_ALREADY_REGISTERED: "identity_already_registered",
  CONTENT_ALREADY_REGISTERED: "content_already_registered",
  DOMAIN_ALREADY_CLAIMED: "domain_already_claimed",
  VERIFIER_NOT_AUTHORIZED: "verifier_not_authorized",
  CLEAN_RECORD_VIOLATION: "clean_record_violation",
  REVALIDATION_FAILED: "revalidation_failed",
  // Site 5 — generic fallback for unexpected drops; always logs detail.
  TX_DECODE_FAILED: "tx_decode_failed",
});

// ─── Media size limits (defaults — node config can override via env) ─────────
const MEDIA_LIMITS = Object.freeze({
  max_video_bytes: 5 * 1024 * 1024 * 1024,   // 5 GB
  max_image_bytes: 50 * 1024 * 1024,          // 50 MB
  max_audio_bytes: 500 * 1024 * 1024,         // 500 MB
  max_text_bytes: 10 * 1024 * 1024,          // 10 MB
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

// GH #51 — crypto agility. Algorithm identifier for each key-bearing
// row (identities, nodes, verification_providers). Bound to the KEY
// rather than to each signature so:
//   - signatures stay compact (no per-sig overhead)
//   - no JWT-style "alg: none" downgrade attack possible
//   - future algorithm rotation = KEY_ROTATED tx replacing key + algorithm atomically
// Genesis bootstrap defaults every key to ML_DSA_65; new algorithms
// add a branch in verifyWithAlgorithm and a new constant here.
const SIGNATURE_ALGORITHM = Object.freeze({
  ML_DSA_65: "ml-dsa-65",
  // Future:
  // ML_DSA_87:                          "ml-dsa-87",                              // larger pq, stronger margin
  // SLH_DSA_128S:                       "slh-dsa-128s",                           // FIPS 205 stateless hash-based
  // HYBRID_ML_DSA_65_ECDSA_P256:        "hybrid-ml-dsa-65-ecdsa-p256",            // transition hybrid
});
const SIGNATURE_ALGORITHM_VALUES = Object.freeze(new Set(Object.values(SIGNATURE_ALGORITHM)));
const SIGNATURE_ALGORITHM_DEFAULT = SIGNATURE_ALGORITHM.ML_DSA_65;

// GH #51 — enum of tip_id-bearing field names on tx.data. Schemas
// whose SIGNED_BY = "subject" declare `SUBJECT_TIP_ID_FIELD` as one of
// these values so the signature dispatcher knows which field on
// tx.data carries the subject's tip_id. Centralised so the set is
// type-locked (no typos) and Python parity uses the same enum.
const TIP_ID_FIELDS = Object.freeze({
  TIP_ID: "tip_id",                       // most schemas (register-identity, update-profile, register-domain, ...)
  SIGNER_TIP_ID: "signer_tip_id",         // content-register (CNA-2.2 attributed publisher)
  REVIEWER_TIP_ID: "reviewer_tip_id",     // prescan-review-confirmed / dismissed / recused
  AUTHOR_TIP_ID: "author_tip_id",         // prescan-review-accept-correction / dispute, update-origin, content-retracted
  JUROR_TIP_ID: "juror_tip_id",           // jury vote commit / reveal
  APPELLANT_TIP_ID: "appellant_tip_id",   // appeal filed
  VERIFIER_TIP_ID: "verifier_tip_id",     // content-verified
  DISPUTER_TIP_ID: "disputer_tip_id",     // content-disputed (user-mode)
});
const TIP_ID_FIELD_VALUES = Object.freeze(new Set(Object.values(TIP_ID_FIELDS)));

// GH #51 — VP-id field discriminator. Same pattern as TIP_ID_FIELDS:
// VP-signed schemas declare WHICH field on tx.data carries the
// signing VP's vp_id, since the codebase has three usages today:
//   - "vp_id" for new registrations (REGISTER_IDENTITY)
//   - "approving_vp_id" for council-style attestations (VP_REGISTERED, NODE_REGISTERED)
//   - "issuing_vp_id" for revocations (REVOKE_*)
const VP_ID_FIELDS = Object.freeze({
  VP_ID: "vp_id",
  APPROVING_VP_ID: "approving_vp_id",
  ISSUING_VP_ID: "issuing_vp_id",
});
const VP_ID_FIELD_VALUES = Object.freeze(new Set(Object.values(VP_ID_FIELDS)));

// GH #51 — unified signature storage. The set of kinds that a schema's
// SIGNED_BY discriminator can take. Each kind tells `verifyTxSignature`
// how to resolve the signer's public key:
//   - "subject" → look up via schema.resolveSubject(tx, dag) (defaults
//                  to dag.getIdentity(tx.data.tip_id) when the schema
//                  doesn't override)
//   - "node"    → dag.getNode(tx.data.node_id).public_key
//   - "vp"      → dag.getVerificationProvider(tx.data.vp_id).public_key
//                  (covers both regular VP-signed txs and the founding-
//                   VP-signed ring identities at genesis — same lookup
//                   path, same trust model, just different context)
const SIGNED_BY_KIND = Object.freeze({
  SUBJECT: "subject",
  NODE: "node",
  VP: "vp",
});
const SIGNED_BY_KIND_VALUES = Object.freeze(new Set(Object.values(SIGNED_BY_KIND)));

// GH #51 — unified signature storage. The two scopes a schema can
// declare for its tx.signature:
//   - "envelope" → outer signature over canonicalTx(tx) (whole envelope:
//                   tx_type + data + timestamp + prev)
//   - "body"     → signature over a schema-declared subset of tx.data;
//                   typical for client-signed flows where the client
//                   computes the payload BEFORE the node adds chain
//                   metadata (timestamp, prev, tx_id)
const SIGNATURE_SCOPE = Object.freeze({
  ENVELOPE: "envelope",
  BODY: "body",
});
const SIGNATURE_SCOPE_VALUES = Object.freeze(new Set(Object.values(SIGNATURE_SCOPE)));

module.exports = {
  ORIGIN,
  ORIGIN_LABELS,
  VOTE,
  JURY_VOTES,
  VERDICT,
  CONTENT_STATUS,
  CLASSIFIER_CLIENT,
  PRESCAN_TIERS,
  PRESCAN_TIER_VALUES,
  PRESCAN_NOTES,
  CONFIDENCE_LABELS,
  PRESCAN_ACTIONS,
  PRESCAN_CONSEQUENCES,
  PRESCAN_NEXT_STEPS,
  PRESCAN_REVIEW_STATES,
  PRESCAN_REVIEW_STATE_VALUES,
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
  SIGNED_BY_KIND,
  SIGNED_BY_KIND_VALUES,
  SIGNATURE_SCOPE,
  SIGNATURE_SCOPE_VALUES,
  SIGNATURE_ALGORITHM,
  SIGNATURE_ALGORITHM_VALUES,
  SIGNATURE_ALGORITHM_DEFAULT,
  TIP_ID_FIELDS,
  TIP_ID_FIELD_VALUES,
  VP_ID_FIELDS,
  VP_ID_FIELD_VALUES,
  INTEREST_SLUG_REGEX,
  INTEREST_LABEL_MAX_LEN,
  MAX_INTERESTS_PER_PROFILE,
  INTEREST_CATEGORIES,
  INTEREST_CATEGORY_VALUES,
  INITIAL_INTERESTS_SEED,
  PLATFORM_MAX_LENGTH,
  CLAIM_MAX_AGE_MS,
  ALLOWED_PLATFORMS,
  OAUTH_REQUIRED_PLATFORMS,
};
