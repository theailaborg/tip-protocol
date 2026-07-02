/**
 * @file shared/protocol-constants.js
 * @description Immutable protocol constants loaded from the genesis block.
 *
 * These are NOT configuration. They are protocol-level values that must be
 * identical across every node in the network. If two nodes disagree on any
 * constant, they will compute different scores and the network forks.
 *
 * Usage:
 *   const PC = require("./protocol-constants");
 *   // At boot (once):
 *   PC.init(genesisPayload.protocol_constants);
 *   // Everywhere else:
 *   const jurySize = PC.get().jury.size;
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const LC = require("./local-config");

let _instance = null;

/**
 * Initialize protocol constants from genesis block.
 *
 * Idempotent on identical payload: calling init twice with the same constants
 * is a no-op so defensive callers (CLIs, scripts, tests) don't have to
 * coordinate. Re-init with a *different* payload throws — that is the
 * fork-risk failure mode (one path quietly switches the constants the other
 * path computed against), so it must be loud.
 *
 * Each entry point owns one init call:
 *   - node:   node/src/index.js
 *   - cli:    cli/src/index.js
 *   - seed:   scripts/seed.js
 *   - tests:  node/tests/jest-setup.js (jest setupFiles)
 */
function init(protocolConstants) {
  if (!protocolConstants || typeof protocolConstants !== "object") {
    throw new Error("ProtocolConstants: invalid genesis protocol_constants");
  }
  if (_instance !== null) {
    if (_deepEqual(_instance, protocolConstants)) return _instance;
    throw new Error(
      "ProtocolConstants already initialized with a DIFFERENT payload — refusing to overwrite. " +
      "Two code paths disagree on genesis; this would silently fork the network. " +
      "Audit every PC.init() call site and ensure they all read from the same getGenesisPayload()."
    );
  }
  _instance = deepFreeze(protocolConstants);
  return _instance;
}

/**
 * Get the initialized protocol constants. Throws if init() hasn't run.
 *
 * No auto-fallback: the previous fallback created a hidden second init path
 * that fired on first getter access during module-load (e.g. a top-level
 * `const X = NETWORK.Y;`), and then collided with the explicit init call.
 * Callers must guarantee init has run before any backward-compat accessor
 * is touched. If you hit this from a new entry point, load genesis once at
 * boot and call PC.init(payload.protocol_constants).
 */
function get() {
  if (_instance === null) {
    throw new Error(
      "ProtocolConstants not initialized — call PC.init(genesisPayload.protocol_constants) " +
      "before any backward-compat accessor (CONSENSUS, NETWORK, JURY, etc.)."
    );
  }
  return _instance;
}

/**
 * Structural equality check. Used by init() to allow idempotent re-init on
 * the same payload while rejecting divergent payloads.
 */
function _deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== "object" || typeof b !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  for (const k of ka) {
    if (!Object.prototype.hasOwnProperty.call(b, k)) return false;
    if (!_deepEqual(a[k], b[k])) return false;
  }
  return true;
}

/**
 * Check if constants are initialized.
 */
function isInitialized() {
  return _instance !== null;
}

/**
 * Reset (for testing only — never in production).
 */
function _resetForTesting() {
  _instance = null;
}

/**
 * Deep freeze an object — prevents modification at any depth.
 */
function deepFreeze(obj) {
  if (obj === null || typeof obj !== "object") return obj;
  Object.freeze(obj);
  for (const key of Object.keys(obj)) {
    if (typeof obj[key] === "object" && obj[key] !== null && !Object.isFrozen(obj[key])) {
      deepFreeze(obj[key]);
    }
  }
  return obj;
}

// ── Backward-compatible accessors ─────────────────────────────────────────
// These match the old constant names from shared/constants.js.
// All files import from here instead of defining their own lazy getters.

const _j = () => get().jury;
const _p = () => get().penalties;
const _t = () => get().tiers;
const _v = () => get().verify_caps;
const _ps = () => get().prescan;

const VERIFY_CAPS = {
  get PER_CONTENT() { return _v().per_content; },
  get PER_DAY() { return _v().per_day; },
  get PER_MONTH() { return _v().per_month; },
  get BASE_DELTA() { return _v().base_delta; },
  get HIGH_TRUST_DELTA() { return _v().high_trust_delta; },
  get HIGH_TRUST_MIN() { return _v().high_trust_min; },
};

const DISPUTE = {
  get MIN_SCORE_TO_DISPUTE() { return _j().dispute_filing_min_score; },
  get DISPUTER_STAKE() { return _j().dispute_stake; },        // positive amount, code applies -
  get FRIVOLOUS_PENALTY() { return _j().frivolous_dismiss_fee; }, // positive amount, code applies -
  get UPHELD_BONUS() { return _j().upheld_bonus; },
  get VINDICATION_BONUS() { return _j().vindication_bonus; },
  // Phase 3 abuse prevention: at most N CONTENT_DISPUTED txs by a
  // single disputer_tip_id within the trailing window. v1: 5 / 30d.
  get MAX_PER_FILER_PER_WINDOW() { return _j().max_disputes_per_filer_per_window; },
  get FILER_WINDOW_MS() { return _j().dispute_filer_window_ms; },
};

const JURY = {
  get SIZE() { return _j().jury_size; },
  get MIN_SCORE() { return _j().jury_min_score; },
  get MIN_SCORE_FALLBACK() { return _j().jury_min_score_fallback; },  // Pass-3 floor in selectJury — see jury.js _pickWithGeoCap
  get JUROR_STAKE() { return _j().jury_stake; },           // positive amount
  get MAJORITY_VOTE() { return _j().jury_majority_vote; },
  get COMMIT_WINDOW_HOURS() { return _j().jury_commit_hours; },
  get REVEAL_WINDOW_HOURS() { return _j().jury_reveal_hours; },
  get QUORUM() { return _j().jury_min_reveals; },
  // Per-role bonuses
  get JUROR_MAJORITY_BONUS() { return _j().jury_majority_bonus; },          // +3
  get EXPERT_MAJORITY_BONUS() { return _j().expert_majority_bonus; },        // +7
  // Per-role minority penalties (genesis stores negative; return positive magnitude)
  get JUROR_MINORITY_PENALTY() { return Math.abs(_j().jury_minority_penalty); },    // 8
  get EXPERT_MINORITY_PENALTY() { return Math.abs(_j().expert_minority_penalty); }, // 10
  // No-show split: no-commit (never submitted commit tx) vs no-reveal (committed, didn't reveal)
  get JUROR_NO_COMMIT_PENALTY() { return Math.abs(_j().jury_no_commit_penalty); },  // 1
  get JUROR_NO_REVEAL_PENALTY() { return Math.abs(_j().jury_no_reveal_penalty); },  // 8
  get EXPERT_NO_COMMIT_PENALTY() { return Math.abs(_j().expert_no_commit_penalty); }, // 1
  get EXPERT_NO_REVEAL_PENALTY() { return Math.abs(_j().expert_no_reveal_penalty); }, // 10
  get MAX_SAME_COUNTRY() { return _j().jury_max_same_country; },
};

const APPEAL = {
  get APPELLANT_STAKE() { return _j().appeal_stake; },         // positive amount, code applies -
  get MIN_EXPERT_SCORE() { return _j().expert_min_score; },
  get MIN_EXPERT_SCORE_FALLBACK() { return _j().expert_min_score_fallback; },  // Pass-3 floor in selectExperts
  get MAX_SAME_COUNTRY() { return _j().appeal_max_same_country; },              // tighter than jury cap; was hardcoded as 2
  get EXPERT_COUNT() { return _j().expert_panel_size; },
  get MIN_VOTES() { return _j().expert_min_votes; },
  get FILING_WINDOW_HOURS() { return _j().appeal_window_hours; },
  get COMMIT_WINDOW_HOURS() { return _j().appeal_commit_hours; },
  get REVEAL_WINDOW_HOURS() { return _j().appeal_reveal_hours; },
  get OVERTURN_BONUS() { return _j().appeal_win_bonus; },
};

const AI_CLASSIFIER = {
  get AUTO_DISMISS_THRESHOLD() { return _j().ai_auto_dismiss_threshold; },
  get HIGH_CONFIDENCE() { return _j().ai_auto_escalate_threshold; },
  get TIMEOUT_SECONDS() { return _j().ai_timeout_seconds; },
};

// Per-pair offense escalation. Each genesis array is [1st, 2nd, 3rd+] —
// first-offense penalties are severity-scaled (OH→AG worst, AA→AG mildest),
// and repeat offenses preserve that scaling instead of collapsing onto the
// OH→AG ladder. Prior `MISMATCH_2ND_OFFENSE` / `_3RD_OFFENSE` aliases (both
// reading `oh_as_ag`) over-penalised repeat AA→AG / OH→AA offenders.
const SCORE_EVENTS = {
  // Penalties — genesis stores negative values directly
  get CONTENT_RETRACTION() { return { delta: _p().retraction }; },
  get DEVICE_COMPROMISE_PENDING() { return { delta: _p().device_compromise }; },
  get OH_CONFIRMED_AG_1ST() { return { delta: _p().oh_as_ag[0] }; },
  get OH_CONFIRMED_AG_2ND() { return { delta: _p().oh_as_ag[1] }; },
  get OH_CONFIRMED_AG_3RD() { return { delta: _p().oh_as_ag[2] }; },
  get OH_CONFIRMED_AA_1ST() { return { delta: _p().oh_as_aa[0] }; },
  get OH_CONFIRMED_AA_2ND() { return { delta: _p().oh_as_aa[1] }; },
  get OH_CONFIRMED_AA_3RD() { return { delta: _p().oh_as_aa[2] }; },
  get AA_CONFIRMED_AG_1ST() { return { delta: _p().aa_as_ag[0] }; },
  get AA_CONFIRMED_AG_2ND() { return { delta: _p().aa_as_ag[1] }; },
  get AA_CONFIRMED_AG_3RD() { return { delta: _p().aa_as_ag[2] }; },
  get FACTUAL_FALSEHOOD_MINOR() { return { delta: _p().minor_falsehood }; },
  get FACTUAL_FALSEHOOD_MAJOR() { return { delta: _p().major_falsehood }; },
  // Bonuses — positive values
  get CLEAN_90_DAYS() { return { delta: get().reputation.clean_period_bonus }; },
};

const PRESCAN_THRESHOLDS = {
  get default() { return _ps().default; },
  get floor() { return _ps().floor; },
  get ceiling() { return _ps().ceiling; },
};

// 4-tier categorical thresholds for the spec's Content Verification flow.
// Read from genesis so they're consensus-aligned across the federation.
const PRESCAN_TIER_THRESHOLDS = {
  get elevated() { return _ps().tier_thresholds.elevated; },
  get high() { return _ps().tier_thresholds.high; },
  get critical() { return _ps().tier_thresholds.critical; },
};

// Creator-history calibration buckets (Claim Group G / FIX-03).
const CALIBRATION_THRESHOLDS = {
  get MODERATE_MIN() { return _ps().calibration.moderate_min; },
  get VETERAN_MIN() { return _ps().calibration.veteran_min; },
};

// Async-prescan worker config + content-type taxonomy + modality weights.
// Read from genesis so they're consensus-aligned across the federation.
// See my-notes/ASYNC_PRESCAN_ARCHITECTURE.md for the full design.
const PRESCAN_WORKER = {
  get MAX_RETRIES_ON_DEGRADED() { return _ps().worker_max_retries_on_degraded; },
  get MAX_RETRIES_ON_ERROR() { return _ps().worker_max_retries_on_error; },
  get RETRY_BACKOFF_MS() { return _ps().worker_retry_backoff_ms; },
  get CLAIM_TIMEOUT_MS() { return _ps().worker_claim_timeout_ms; },
  get TAKEOVER_AFTER_MS() { return _ps().takeover_after_ms; },
  get FAIL_OPEN_AFTER_MS() { return _ps().fail_open_after_ms; },
  get POLL_AFTER_MS() { return _ps().poll_after_ms; },
  get POLL_MAX_ATTEMPTS() { return _ps().poll_max_attempts; },
};

const CONTENT_TYPE = {
  get VALID_TYPES() { return _ps().valid_content_types; },
  get ARTICLE_TEXT_THRESHOLD_CHARS() { return _ps().article_text_threshold_chars; },
};

// Per-content-type lift coefficients for the primary-floor aggregator.
// Primary modality (matches content_type) is the floor; values listed
// are lift coefficients for non-primary modalities — only positive
// secondary-vs-primary gaps contribute. See genesis.js comment for the
// per-row reasoning.
const MODALITY_WEIGHTS = {
  get text() { return _ps().modality_weights.text; },
  get image() { return _ps().modality_weights.image; },
  get audio() { return _ps().modality_weights.audio; },
  get video() { return _ps().modality_weights.video; },
  get multi() { return _ps().modality_weights.multi; },
  get DEGRADED_MULTIPLIER() { return _ps().degraded_weight_multiplier; },
};

const _cl = () => get().content_limits;
const CONTENT_LIMITS = {
  get TEXT_MAX_BYTES() { return _cl().text_max_bytes; },
  get IMAGE_MAX_BYTES() { return _cl().image_max_bytes; },
  get AUDIO_MAX_BYTES() { return _cl().audio_max_bytes; },
  get VIDEO_MAX_BYTES() { return _cl().video_max_bytes; },
  get MEDIA_ITEMS_MAX() { return _cl().media_items_max; },
  get REQUEST_BODY_MAX_BYTES() { return _cl().request_body_max_bytes; },
};

const _rv = () => get().reviewer;
const REVIEWER = {
  get MIN_SCORE() { return _rv().min_score; },
  get MAX_OVERTURN_RATE() { return _rv().max_overturn_rate; },
  get ACCURACY_SAMPLE_SIZE() { return _rv().accuracy_sample_size; },
  // Creator's accept-private vs auto-escalation window after a
  // PRESCAN_REVIEW_CONFIRMED. After this elapses, the scheduler emits
  // an auto-cascade CONTENT_DISPUTED on the creator's behalf.
  get CREATOR_DECISION_WINDOW_MS() { return _rv().creator_decision_window_ms; },
  // Signed delta applied to the creator's score on accept-correction.
  // Negative — Option 1 still carries a small penalty; smaller than the
  // dispute pipeline's OH→AA range so accepting privately is strictly
  // cheaper than letting auto-escalation run.
  get ACCEPT_CORRECTION_SCORE_DELTA() { return _rv().accept_correction_score_delta; },
  // Age threshold (ms since registered_at) at which the creator-facing
  // "your flagged content is approaching review" notification surfaces
  // on the dashboard. Halfway through the 48h flagged grace by default.
  get CREATOR_WARNING_AGE_MS() { return _rv().creator_warning_age_ms; },
  // Age (ms since the assignment's cert.ts) at which auto-recuse
  // fires on behalf of an inactive assigned reviewer. The trigger
  // emits a node-signed PRESCAN_REVIEW_RECUSED past this threshold;
  // content.status flips back to REGISTERED and the next round's
  // trigger picks a fresh reviewer.
  get AUTO_RECUSE_AGE_MS() { return _rv().auto_recuse_age_ms; },
  // Bonus paid to the reviewer for completing review work correctly.
  // Stacks on top of DISPUTE.UPHELD_BONUS when their CONFIRM holds up
  // through Stage-2 (or Stage-3 reversal). Paid alone when the case
  // closes without a public dispute (DISMISS or accept-private).
  get CORRECT_BONUS() { return _rv().reviewer_correct_bonus; },
  // Signed delta (negative) clawed back from a reviewer whose DISMISS is
  // later proven wrong by an UPHELD dispute. Same sign convention as
  // accept_correction_score_delta: stored negative, applied directly.
  // Default -5 cancels reviewer_correct_bonus (net 0 for a wrong dismiss).
  get WRONG_DISMISS_CLAWBACK() { return _rv().reviewer_wrong_dismiss_clawback; },
  // Availability gate: more than MAX_NOSHOW_RECUSALS sla_expired
  // auto-recusals within the reviewer's last NOSHOW_SAMPLE_SIZE resolved
  // assignments pauses them from selection. Hard filter — see
  // reviewer-selection.getReviewerNoShowCount.
  get MAX_NOSHOW_RECUSALS() { return _rv().max_noshow_recusals; },
  get NOSHOW_SAMPLE_SIZE() { return _rv().noshow_sample_size; },
};

const _cg = () => get().content_grace;
const CONTENT_GRACE = {
  get UNFLAGGED_MS() { return _cg().unflagged_ms; },
  get FLAGGED_MS() { return _cg().flagged_ms; },
};

// Media retention windows — three-case model. Clock anchor depends on
// the ctid's lifecycle:
//
//   BASE_RETENTION_MS     — never-disputed content. Clock starts at
//                           registered_at.
//   POST_ADJUDICATION_MS  — content with only ADJUDICATION_RESULT (no
//                           appeal). Clock starts at adjudication.ts.
//                           Length > appeal-filing window so a late
//                           appeal can't race the sweep.
//   POST_APPEAL_MS        — content with APPEAL_RESULT (terminal).
//                           Clock starts at appeal.ts.
//   ORPHAN_UPLOAD_MS      — bytes uploaded that no content row ever
//                           referenced. Catches abandoned drafts.
const _mr = () => get().media_retention;
const MEDIA_RETENTION = {
  get BASE_RETENTION_MS()    { return _mr().base_retention_ms; },
  get POST_ADJUDICATION_MS() { return _mr().post_adjudication_ms; },
  get POST_APPEAL_MS()       { return _mr().post_appeal_ms; },
  get ORPHAN_UPLOAD_MS()     { return _mr().orphan_upload_ms; },
};

const _c = () => get().consensus;
const _n = () => get().network;
const _r = () => get().reputation;
const _sc = () => get().score;

const CONSENSUS = {
  get ROUND_TIMEOUT_MS() { return LC.ROUND_TIMEOUT_MS; },
  get BATCH_WAIT_MS() { return LC.BATCH_WAIT_MS; },
  get CONSENSUS_SUMMARY_INTERVAL_MS() { return LC.CONSENSUS_SUMMARY_INTERVAL_MS; },
  get VOTES_RETENTION_ROUNDS() { return _c().votes_retention_rounds ?? 5; },
  get MAX_TXS_PER_CERTIFICATE() { return _c().max_txs_per_certificate; },
  get MEMPOOL_MAX_SIZE() { return LC.MEMPOOL_MAX_SIZE; },
  get MEMPOOL_TX_TTL_SECONDS() { return LC.MEMPOOL_TX_TTL_SECONDS; },
  get CERTIFICATE_MAX_BYTES() { return _c().certificate_max_bytes; },
  get SYNC_BATCH_SIZE() { return LC.SYNC_BATCH_SIZE; },
  get ORDERED_HASH_CACHE_SIZE() { return LC.ORDERED_HASH_CACHE_SIZE; },
  get MAX_MSGS_PER_PEER_PER_SEC() { return LC.MAX_MSGS_PER_PEER_PER_SEC; },
  get SYNC_MAX_RETRIES() { return LC.SYNC_MAX_RETRIES; },
  get SYNC_RETRY_BASE_MS() { return LC.SYNC_RETRY_BASE_MS; },
  get HANDSHAKE_TIMEOUT_MS() { return LC.HANDSHAKE_TIMEOUT_MS; },
  get HANDSHAKE_MAX_RETRIES() { return LC.HANDSHAKE_MAX_RETRIES; },
  get HANDSHAKE_REHANDSHAKE_INTERVAL_MS() { return LC.HANDSHAKE_REHANDSHAKE_INTERVAL_MS; },
  get HANDSHAKE_REAUTH_GRACE_MS() { return LC.HANDSHAKE_REAUTH_GRACE_MS; },
  get CONNECTION_MONITOR_PING_TIMEOUT_FLOOR_MS() { return LC.CONNECTION_MONITOR_PING_TIMEOUT_FLOOR_MS; },
  get SYNC_FROM_PEER_TOLERANCE_ROUNDS() { return LC.SYNC_FROM_PEER_TOLERANCE_ROUNDS; },
  get GC_DEPTH() { return _c().gc_depth ?? 500; },
  get GC_INTERVAL_COMMITS() { return LC.GC_INTERVAL_COMMITS; },
  get ANTI_ENTROPY_INTERVAL_MS() { return LC.ANTI_ENTROPY_INTERVAL_MS; },
  get ANTI_ENTROPY_PEER_TIMEOUT_MS() { return LC.ANTI_ENTROPY_PEER_TIMEOUT_MS; },
  // Snapshot-install collision retry: when two minority nodes race into
  // byzantine_fork recovery, the second may hit a peer that's busy serving
  // the first. Retry the SAME peer this many times with this delay before
  // giving up and moving to the next candidate. See anti-entropy.js (#47).
  get SNAPSHOT_BUSY_RETRY_MS() { return LC.SNAPSHOT_BUSY_RETRY_MS; },
  get SNAPSHOT_BUSY_RETRY_ATTEMPTS() { return LC.SNAPSHOT_BUSY_RETRY_ATTEMPTS; },
  // Per-call deadline for direct ack stream send (#46) and ack-request
  // round-trip (#48). Caps a slow / hung peer from blocking the local
  // stuck-round retry path. Used in network/node.js sendAckDirect +
  // sendAckRequest.
  get ACK_STREAM_TIMEOUT_MS() { return LC.ACK_STREAM_TIMEOUT_MS; },
  // How long bullshark parks a deferred anchor waiting for missing parent certs
  // before triggering snapshot resync. Must be >> gossipsub mesh rebuild time
  // (~10-15s after a reconnect) so transiently missing certs (gossip-lag, not
  // genuinely gone) have time to arrive before the timer fires. A 15-20s pause
  // creates cert gaps that gossipsub fills in ~25-30s post-reconnect; 60s gives
  // comfortable headroom. Only genuinely GC'd certs (50-60s+ pauses) will still
  // be missing at 60s and require a snapshot resync.
  get BULLSHARK_DEFER_MS() { return _c().bullshark_defer_ms ?? 60000; },
  get SYNC_DIVERGENCE_GRACE_MS() { return LC.SYNC_DIVERGENCE_GRACE_MS; },
  // Sub-quorum escape: when narwhal is ready but has made no round progress
  // for > this duration, anti-entropy fires a snapshot resync to reset join
  // state + reconnect. Catches the "silently dropped libp2p connection
  // → 2/4 certs forever" class the existing byzantine_fork escape doesn't
  // cover. See anti-entropy.js sub_quorum escape (issue #13).
  get SUB_QUORUM_ESCAPE_MS() { return _c().sub_quorum_escape_ms ?? 60000; },
  // Rounds below committed_round to re-pull on sub_quorum escape, healing an
  // uncommitted-frontier partition. Per-node tuning (no chain-fork risk), so it
  // lives in local-config.
  get FRONTIER_RECONCILE_LOOKBACK_ROUNDS() { return LC.FRONTIER_RECONCILE_LOOKBACK_ROUNDS; },
  // #47 Active heartbeat / peer-liveness probe. Each node pings every
  // authorized peer every HEARTBEAT_INTERVAL_MS over /tip/heartbeat/1.0.0.
  // HEARTBEAT_TIMEOUT_MS caps a slow/hung peer's response. After
  // HEARTBEAT_SUSPECT_MISSES consecutive timeouts, onPeerSuspect fires.
  get HEARTBEAT_INTERVAL_MS() { return _c().heartbeat_interval_ms ?? 5000; },
  get HEARTBEAT_TIMEOUT_MS() { return _c().heartbeat_timeout_ms ?? 3000; },
  get HEARTBEAT_SUSPECT_MISSES() { return _c().heartbeat_suspect_misses ?? 3; },
  get ROTATION_COORD_REBROADCAST_INTERVAL_MS() { return LC.ROTATION_COORD_REBROADCAST_INTERVAL_MS; },
  // Pull-repair single-tx fetch: per-node tunables (no chain-fork risk), so a
  // tight timeout and small byte cap vs the GB-scale full cert sync.
  get ROTATION_REPAIR_TIMEOUT_MS() { return LC.ROTATION_REPAIR_TIMEOUT_MS; },
  get ROTATION_REPAIR_MAX_RESPONSE_BYTES() { return LC.ROTATION_REPAIR_MAX_RESPONSE_BYTES; },
  // Producer-pause liveness bound: a stuck boundary past this is logged loudly
  // and surfaced as a metric. Observability only; never bypasses the pause.
  // Transport auto-heal: after this many consecutive outbound send failures to a
  // peer, force-close + re-dial (rebuild the half-dead connection). Cooldown
  // bounds re-dial churn. Per-node operational tunables.
  get CHANNEL_HEAL_FAIL_THRESHOLD() { return LC.CHANNEL_HEAL_FAIL_THRESHOLD; },
  get CHANNEL_HEAL_COOLDOWN_MS() { return LC.CHANNEL_HEAL_COOLDOWN_MS; },
  get SYNC_TOTAL_TIMEOUT_MS() { return LC.SYNC_TOTAL_TIMEOUT_MS; },
  get SYNC_MAX_RESPONSE_BYTES() { return LC.SYNC_MAX_RESPONSE_BYTES; },
  // Tier-3 local tunable (shared/local-config.js). Currently has NO consumer in
  // the codebase. WARNING: if this is ever wired into cert.timestamp validity
  // (i.e. used to accept/reject a cert), it becomes state-determining (Tier-2)
  // and MUST move back into the agreed genesis block — a divergent per-node
  // value would then fork the chain. Keep it consumer-free while it lives here.
  get MAX_ROUND_DURATION_MS() { return LC.MAX_ROUND_DURATION_MS; },
  get BFT_TIME_GENESIS_MS() { return _c().bft_time_genesis_ms ?? 0; },
  // Time-based rotation epochs. The boundary index of a BFT timestamp is
  // k(T) = floor((T - BFT_TIME_GENESIS_MS) / EPOCH_DURATION_MS); a rotation is
  // due when a committed anchor's timestamp lands in a later boundary index
  // than the latest rotation's committed_at. Wall-clock epochs hold regardless
  // of round cadence (dev 4 min, prod 24h).
  get EPOCH_DURATION_MS() { return _c().epoch_duration_ms ?? 240000; },
  // Rounds between a rotation tx's commit and its activation. The record is
  // on-chain LEAD rounds before effective_round, so every node applies it to
  // committee_history ahead of activation; commit-handler rejects a rotation
  // whose effective_round is not in the future, so a late commit can never
  // flip a committee retroactively.
  get ROTATION_ACTIVATION_LEAD_ROUNDS() { return _c().rotation_activation_lead_rounds ?? 200; },
  // Presence buckets per epoch for committee admission: an epoch is split into
  // N equal time slices (prod 24h/24 = hourly; dev 4min/24 = 10s) and a node
  // qualifies by participating in >= pct of DISTINCT slices. Time-presence,
  // not raw counts, so burst participation can't game admission.
  get EPOCH_PARTICIPATION_BUCKETS() { return _c().epoch_participation_buckets ?? 24; },
  // Committee admission threshold for the next rotation. The qualifying check
  // is `participation_count >= ceil(anchors_in_period * pct / 100)`, where
  // anchors_in_period is the consensus_index delta of the finishing rotation
  // (counted, not predicted, so it holds at any round cadence).
  get COMMITTEE_ROTATION_PARTICIPATION_PCT_OF_INTERVAL() {
    return _c().committee_rotation_participation_pct_of_interval
      ?? _c().committee_rotation_min_participation_pct
      ?? 70;
  },
};

const NETWORK = {
  get HANDSHAKE_PROTOCOL() { return _n().handshake_protocol; },
  get SNAPSHOT_PROTOCOL() { return _n().snapshot_protocol; },
  get SNAPSHOT_LENGTH_PREFIX_BYTES() { return _n().snapshot_length_prefix_bytes; },
  get SNAPSHOT_MAX_FRAME_BYTES() { return _n().snapshot_max_frame_bytes; },
  get SYNC_STATUS_PROTOCOL() { return _n().sync_status_protocol ?? "/tip/sync-status/1.0.0"; },
  get PEER_ANNOUNCE_PROTOCOL() { return _n().peer_announce_protocol ?? "/tip/peer-announce/1.0.0"; },
  get HEARTBEAT_PROTOCOL() { return _n().heartbeat_protocol ?? "/tip/heartbeat/1.0.0"; },
  get ORIGIN_GRACE_PERIOD_HOURS() { return _n().origin_grace_period_hours; },
  get REVOCATION_CASCADE_DAYS() { return _n().revocation_cascade_days; },
};

const REPUTATION = {
  get CLEAN_PERIOD_DAYS() { return _r().clean_period_days; },
  get CLEAN_PERIOD_BONUS() { return _r().clean_period_bonus; },
  get DISPUTE_CLEARED_BONUS() { return _r().dispute_cleared_bonus; },
};

const SCORE = {
  get MAX_TOTAL() { return _sc().max_total; },
  get MAX_IDENTITY() { return _sc().max_identity; },
  get MAX_CONTENT() { return _sc().max_content; },
  get MAX_REPUTATION() { return _sc().max_reputation; },
  get MAX_LONGEVITY() { return _sc().max_longevity; },
  get INITIAL_IDENTITY() { return _sc().initial_identity; },
};

// Identity-score sub-block — per-account social linking lives here.
// Per spec (TIP_Scoring_v2): each linked social adds +5 up to a +30 cap;
// the bonus arrives as discrete SCORE_UPDATE txs (issues.md Scoring #11),
// not as a boolean flag on REGISTER_IDENTITY.
const IDENTITY = {
  get SOCIAL_LINK_BONUS() { return get().identity.social_link_bonus; },
  get MAX_SOCIAL_ACCOUNTS() { return get().identity.max_social_accounts; },
  get MAX_SOCIAL_BONUS() { return get().identity.max_social_bonus; },
};

// SOCIAL_LINK — convenience alias exposing the same identity sub-block
// constants under a feature-oriented name. Imported by identity-service
// and link-platform tests without having to reach for IDENTITY.
const SOCIAL_LINK = {
  get SOCIAL_LINK_BONUS() { return get().identity.social_link_bonus; },
  get MAX_SOCIAL_ACCOUNTS() { return get().identity.max_social_accounts; },
  get MAX_SOCIAL_BONUS() { return get().identity.max_social_bonus; },
};

function getTier(score) {
  const t = _t();
  if (score >= t.highly_trusted) return { name: "HIGHLY_TRUSTED", label: "Highly Trusted", color: "#1A8A5C" };
  if (score >= t.trusted) return { name: "TRUSTED", label: "Trusted", color: "#2563A8" };
  if (score >= t.verified) return { name: "VERIFIED", label: "Verified", color: "#A88B15" };
  if (score >= t.caution) return { name: "CAUTION", label: "Caution", color: "#C07318" };
  return { name: "NOT_TRUSTED", label: "Not Trusted", color: "#C53030" };
}

module.exports = {
  // Core singleton
  init, get, isInitialized, _resetForTesting,
  // Backward-compatible accessors (import these instead of shared/constants.js)
  VERIFY_CAPS, DISPUTE, JURY, APPEAL, AI_CLASSIFIER, SCORE_EVENTS,
  PRESCAN_THRESHOLDS, PRESCAN_TIER_THRESHOLDS, CALIBRATION_THRESHOLDS,
  PRESCAN_WORKER, CONTENT_TYPE, MODALITY_WEIGHTS, CONTENT_LIMITS,
  REVIEWER, CONTENT_GRACE, MEDIA_RETENTION,
  CONSENSUS, NETWORK, REPUTATION, SCORE, IDENTITY, SOCIAL_LINK, getTier,
};
