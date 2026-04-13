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
 * Can only be called once — subsequent calls throw.
 */
function init(protocolConstants) {
  if (_instance !== null) {
    throw new Error("ProtocolConstants already initialized — cannot reinitialize");
  }
  if (!protocolConstants || typeof protocolConstants !== "object") {
    throw new Error("ProtocolConstants: invalid genesis protocol_constants");
  }
  _instance = deepFreeze(protocolConstants);
  return _instance;
}

/**
 * Get the initialized protocol constants.
 * If not yet initialized, auto-loads from genesis.
 */
function get() {
  if (_instance === null) {
    // Auto-initialize from genesis if available
    try {
      const { getGenesisPayload } = require("../node/src/genesis");
      const payload = getGenesisPayload();
      if (payload?.protocol_constants) {
        init(payload.protocol_constants);
      }
    } catch {
      // Genesis not available (e.g. in browser extension or SDK context)
    }
  }
  if (_instance === null) {
    throw new Error("ProtocolConstants not initialized — load genesis first");
  }
  return _instance;
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
};

const JURY = {
  get SIZE() { return _j().jury_size; },
  get MIN_SCORE() { return _j().jury_min_score; },
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

const SCORE_EVENTS = {
  // Penalties — genesis stores negative values directly
  get CONTENT_RETRACTION() { return { delta: _p().retraction }; },
  get DEVICE_COMPROMISE_PENDING() { return { delta: _p().device_compromise }; },
  get OH_CONFIRMED_AG_1ST() { return { delta: _p().oh_as_ag[0] }; },
  get MISMATCH_2ND_OFFENSE() { return { delta: _p().oh_as_ag[1] }; },
  get MISMATCH_3RD_OFFENSE() { return { delta: _p().oh_as_ag[2] }; },
  get OH_CONFIRMED_AA() { return { delta: _p().oh_as_aa[0] }; },
  get AA_CONFIRMED_AG() { return { delta: _p().aa_as_ag[0] }; },
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

const _c = () => get().consensus;
const _n = () => get().network;
const _r = () => get().reputation;

const CONSENSUS = {
  get ROUND_TIMEOUT_MS() { return _c().round_timeout_ms; },
  get MAX_TXS_PER_CERTIFICATE() { return _c().max_txs_per_certificate; },
  get MEMPOOL_MAX_SIZE() { return _c().mempool_max_size; },
  get MEMPOOL_TX_TTL_SECONDS() { return _c().mempool_tx_ttl_seconds; },
  get CERTIFICATE_MAX_BYTES() { return _c().certificate_max_bytes; },
  get SYNC_BATCH_SIZE() { return _c().sync_batch_size; },
  get ORDERED_HASH_CACHE_SIZE() { return _c().ordered_hash_cache_size; },
  get MAX_MSGS_PER_PEER_PER_SEC() { return _c().max_msgs_per_peer_per_sec; },
};

const NETWORK = {
  get MERKLE_PUBLISH_HOURS() { return _n().merkle_publish_hours; },
  get ORIGIN_GRACE_PERIOD_HOURS() { return _n().origin_grace_period_hours; },
  get REVOCATION_CASCADE_DAYS() { return _n().revocation_cascade_days; },
};

const REPUTATION = {
  get CLEAN_PERIOD_DAYS() { return _r().clean_period_days; },
  get CLEAN_PERIOD_BONUS() { return _r().clean_period_bonus; },
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
  PRESCAN_THRESHOLDS, CONSENSUS, NETWORK, REPUTATION, getTier,
};
