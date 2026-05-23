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
  get MAJORITY_BONUS() { return _j().jury_majority_bonus; },
  get MINORITY_PENALTY() { return Math.abs(_j().jury_minority_penalty); }, // genesis stores -10, return 10
  get NO_SHOW_PENALTY() { return Math.abs(_j().jury_no_show_penalty); },  // genesis stores -10, return 10
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
};

const _cg = () => get().content_grace;
const CONTENT_GRACE = {
  get UNFLAGGED_MS() { return _cg().unflagged_ms; },
  get FLAGGED_MS() { return _cg().flagged_ms; },
};

const _c = () => get().consensus;
const _n = () => get().network;
const _r = () => get().reputation;
const _sc = () => get().score;

const CONSENSUS = {
  get ROUND_TIMEOUT_MS() { return _c().round_timeout_ms; },
  get BATCH_WAIT_MS() { return _c().batch_wait_ms; },
  get CONSENSUS_SUMMARY_INTERVAL_MS() { return _c().consensus_summary_interval_ms ?? 60000; },
  get VOTES_RETENTION_ROUNDS() { return _c().votes_retention_rounds ?? 5; },
  get MAX_TXS_PER_CERTIFICATE() { return _c().max_txs_per_certificate; },
  get MEMPOOL_MAX_SIZE() { return _c().mempool_max_size; },
  get MEMPOOL_TX_TTL_SECONDS() { return _c().mempool_tx_ttl_seconds; },
  get CERTIFICATE_MAX_BYTES() { return _c().certificate_max_bytes; },
  get SYNC_BATCH_SIZE() { return _c().sync_batch_size; },
  get ORDERED_HASH_CACHE_SIZE() { return _c().ordered_hash_cache_size; },
  get MAX_MSGS_PER_PEER_PER_SEC() { return _c().max_msgs_per_peer_per_sec; },
  get SYNC_MAX_RETRIES() { return _c().sync_max_retries; },
  get SYNC_RETRY_BASE_MS() { return _c().sync_retry_base_ms; },
  get PARTICIPANT_INACTIVE_ROUNDS() { return _c().participant_inactive_rounds; },
  get HANDSHAKE_TIMEOUT_MS() { return _c().handshake_timeout_ms; },
  get HANDSHAKE_MAX_RETRIES() { return _c().handshake_max_retries; },
  get GC_DEPTH() { return _c().gc_depth ?? 500; },
  get GC_INTERVAL_COMMITS() { return _c().gc_interval_commits ?? 10; },
  get ANTI_ENTROPY_INTERVAL_MS() { return _c().anti_entropy_interval_ms ?? 4000; },
  get ANTI_ENTROPY_PEER_TIMEOUT_MS() { return _c().anti_entropy_peer_timeout_ms ?? 2000; },
  // Snapshot-install collision retry: when two minority nodes race into
  // byzantine_fork recovery, the second may hit a peer that's busy serving
  // the first. Retry the SAME peer this many times with this delay before
  // giving up and moving to the next candidate. See anti-entropy.js (#47).
  get SNAPSHOT_BUSY_RETRY_MS() { return _c().snapshot_busy_retry_ms ?? 5000; },
  get SNAPSHOT_BUSY_RETRY_ATTEMPTS() { return _c().snapshot_busy_retry_attempts ?? 1; },
  // Per-call deadline for direct ack stream send (#46) and ack-request
  // round-trip (#48). Caps a slow / hung peer from blocking the local
  // stuck-round retry path. Used in network/node.js sendAckDirect +
  // sendAckRequest.
  get ACK_STREAM_TIMEOUT_MS() { return _c().ack_stream_timeout_ms ?? 3000; },
  // How long bullshark parks a deferred anchor waiting for missing parent certs
  // before triggering snapshot resync. Must be >> gossipsub mesh rebuild time
  // (~10-15s after a reconnect) so transiently missing certs (gossip-lag, not
  // genuinely gone) have time to arrive before the timer fires. A 15-20s pause
  // creates cert gaps that gossipsub fills in ~25-30s post-reconnect; 60s gives
  // comfortable headroom. Only genuinely GC'd certs (50-60s+ pauses) will still
  // be missing at 60s and require a snapshot resync.
  get BULLSHARK_DEFER_MS() { return _c().bullshark_defer_ms ?? 60000; },
  get SYNC_DIVERGENCE_GRACE_MS() { return _c().sync_divergence_grace_ms ?? 30000; },
  // Sub-quorum escape: when narwhal is ready but has made no round progress
  // for > this duration, anti-entropy fires a snapshot resync to reset join
  // state + reconnect. Catches the "silently dropped libp2p connection
  // → 2/4 certs forever" class the existing byzantine_fork escape doesn't
  // cover. See anti-entropy.js sub_quorum escape (issue #13).
  get SUB_QUORUM_ESCAPE_MS() { return _c().sub_quorum_escape_ms ?? 60000; },
  get ROTATION_COORD_REBROADCAST_INTERVAL_MS() { return _c().rotation_coord_rebroadcast_interval_ms ?? 1500; },
  get SYNC_TOTAL_TIMEOUT_MS() { return _c().sync_total_timeout_ms ?? 30000; },
  get SYNC_MAX_RESPONSE_BYTES() { return _c().sync_max_response_bytes ?? 1073741824; },
  // BFT Time — cert.timestamp validation bounds. See genesis.js consensus block.
  get MAX_ROUND_DURATION_MS() { return _c().max_round_duration_ms ?? 300000; },
  get BFT_TIME_GENESIS_MS() { return _c().bft_time_genesis_ms ?? 0; },
  // §4 + #34 + #75: rotation-period committee model. See genesis.js consensus block.
  get COMMITTEE_ROTATION_INTERVAL_COMMITS() { return _c().committee_rotation_interval_commits ?? 100; },
  // Committee admission threshold for next rotation. The qualifying check is
  // `participation_count >= ceil(INTERVAL_COMMITS * pct / 100)`, where the
  // count is RAW anchor-walk credits (not a fraction of total participation).
  // So with INTERVAL=100 and pct=70 the threshold is `>= 70 credits` — easy
  // to clear since one anchor walk yields several credits per active node.
  // Genesis JSON key kept as committee_rotation_min_participation_pct for
  // backward compat with existing chain configs.
  get COMMITTEE_ROTATION_PARTICIPATION_PCT_OF_INTERVAL() {
    return _c().committee_rotation_participation_pct_of_interval
      ?? _c().committee_rotation_min_participation_pct
      ?? 70;
  },
  // #75 atomic boundary — rotation N's effective_round is deterministically
  // N * EPOCH_LENGTH_ROUNDS, where each Bullshark wave is 2 rounds (propose +
  // vote). Every node maps round → rotation_number identically via
  // epochOf(round) = floor(round / EPOCH_LENGTH_ROUNDS). Producer-pause and
  // validator-park use this to ensure both sides of cert validation agree on
  // which committee applies to a given round.
  get EPOCH_LENGTH_ROUNDS() { return this.COMMITTEE_ROTATION_INTERVAL_COMMITS * 2; },
  // Submit the rotation tx LEAD anchors BEFORE its boundary so it has time
  // to be anchored + commit-handler-applied by the time effective_round
  // arrives. Without lead-time, all nodes pause production at the boundary
  // (no rotation in CH yet) → no certs produced → rotation tx never anchored
  // → permanent halt.
  //
  // Auto-scaling default: 1% of INTERVAL_COMMITS with a floor of 10 anchors.
  //   Testnet (INTERVAL=100):    max(10, 1)   = 10  (~20 sec)
  //   Production (INTERVAL=43200): max(10, 432) = 432 (~14 min, Sui-style)
  // Operators can override via genesis param for unusually-slow networks.
  get COMMITTEE_ROTATION_SUBMIT_LEAD_ANCHORS() {
    return _c().committee_rotation_submit_lead_anchors
      ?? Math.max(10, Math.floor(this.COMMITTEE_ROTATION_INTERVAL_COMMITS / 100));
  },
};

const NETWORK = {
  get HANDSHAKE_PROTOCOL() { return _n().handshake_protocol; },
  get SNAPSHOT_PROTOCOL() { return _n().snapshot_protocol; },
  get SNAPSHOT_LENGTH_PREFIX_BYTES() { return _n().snapshot_length_prefix_bytes; },
  get SNAPSHOT_MAX_FRAME_BYTES() { return _n().snapshot_max_frame_bytes; },
  get SYNC_STATUS_PROTOCOL() { return _n().sync_status_protocol ?? "/tip/sync-status/1.0.0"; },
  get PEER_ANNOUNCE_PROTOCOL() { return _n().peer_announce_protocol ?? "/tip/peer-announce/1.0.0"; },
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
  get SOCIAL_LINK_BONUS()   { return get().identity.social_link_bonus; },
  get MAX_SOCIAL_ACCOUNTS() { return get().identity.max_social_accounts; },
  get MAX_SOCIAL_BONUS()    { return get().identity.max_social_bonus; },
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
  REVIEWER, CONTENT_GRACE,
  CONSENSUS, NETWORK, REPUTATION, SCORE, IDENTITY, SOCIAL_LINK, getTier,
};
