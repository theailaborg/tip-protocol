"use strict";

const { nowMs } = require("../../../shared/time");

const {
  signTransaction, computeTxId,
} = require("../../../shared/crypto");
const {
  PRESCAN_THRESHOLDS,
  PRESCAN_TIER_THRESHOLDS,
  CALIBRATION_THRESHOLDS,
  CONTENT_GRACE,
  REVIEWER,
} = require("../../../shared/protocol-constants");
const {
  ORIGIN, PRESCAN_TIERS,
  CONFIDENCE_LABELS, PRESCAN_ACTIONS,
  PRESCAN_CONSEQUENCES, PRESCAN_NEXT_STEPS,
} = require("../../../shared/constants");
const { log } = require("../logger");

/**
 * Assign content-addressed tx_id (no node signature).
 */
function withTxId(txBody) {
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

/**
 * Sign a tx with the node's registered key (for auto/system txs only).
 */
function nodeSignedAuto(txBody, config) {
  txBody.data.node_id = config.nodeRegisteredId || config.nodeId;
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, config.nodePrivateKey);
}

/**
 * Threshold table for tier classification. The `contentType` parameter is a
 * v2 hook — when content categorization is wired in, thresholds can be
 * content-type-specific (legal text higher, casual chat lower). For v1 the
 * parameter is accepted and ignored; every content uses the spec defaults.
 */
function getTierThresholds(contentType = null) {
  return PRESCAN_TIER_THRESHOLDS;
}

/**
 * Map raw probability to a tier label using the threshold table.
 *
 * This is the "spec-pure" tier — no calibration applied. Useful for audit
 * display and as input to adjustTier(). The persisted tier on the content
 * row is the calibrated one (adjustTier output); raw_tier is derivable
 * any time from the persisted probability + this function.
 */
function computeRawTier(probability, contentType = null) {
  const t = getTierThresholds(contentType);
  if (probability >= t.critical) return PRESCAN_TIERS.CRITICAL;
  if (probability >= t.high)     return PRESCAN_TIERS.HIGH;
  if (probability >= t.elevated) return PRESCAN_TIERS.ELEVATED;
  return PRESCAN_TIERS.LOW;
}

/**
 * Apply creator-history calibration to a raw tier (Claim Group G / FIX-03).
 *
 * Veterans with clean track records get a one-tier-down adjustment as
 * benefit-of-doubt — AI classifiers have non-zero false-positive rates, and
 * a creator with 200+ verified OH pieces has demonstrated they consistently
 * write legitimate human content. Never shifts 2 tiers (CRITICAL→ELEVATED
 * skip) — prevents "build clean history, then post AI as OH" gaming at the
 * 0.98+ probability end.
 *
 * LOW and ELEVATED never adjusted (already not flagged; calibration would
 * be a no-op).
 */
function adjustTier(rawTier, creatorHistory) {
  if (rawTier === PRESCAN_TIERS.LOW || rawTier === PRESCAN_TIERS.ELEVATED) return rawTier;
  const verifiedCount = creatorHistory?.verified_oh_count || 0;
  if (verifiedCount >= CALIBRATION_THRESHOLDS.VETERAN_MIN) {
    if (rawTier === PRESCAN_TIERS.CRITICAL) return PRESCAN_TIERS.HIGH;
    if (rawTier === PRESCAN_TIERS.HIGH)     return PRESCAN_TIERS.ELEVATED;
  } else if (verifiedCount >= CALIBRATION_THRESHOLDS.MODERATE_MIN) {
    if (rawTier === PRESCAN_TIERS.HIGH) return PRESCAN_TIERS.ELEVATED;
    // CRITICAL stays for moderate creators — too suspicious to demote at 0.98+
  }
  return rawTier;
}

// Origin codes that go through prescan. OH and AA both claim human-primary
// authorship (OH = no AI, AA = AI-assisted), so an HIGH/CRITICAL classifier
// signal suggests under-declaration: OH→AA/AG or AA→AG. AG and MX already
// maximally disclose AI involvement — no further "downgrade" exists, so
// running the classifier on them produces no useful action.
const PRESCAN_ELIGIBLE_ORIGINS = new Set([ORIGIN.OH, ORIGIN.AA]);

/**
 * Dev-only: read TIP_DEV_FORCE_PRESCAN_TIER and return a forced tier
 * for prescan-eligible origins. Returns null in production, or when
 * the env is unset / invalid, or when the origin isn't eligible.
 *
 * Accepted values (case-insensitive):
 *   "high" | "HIGH"           — always returns HIGH
 *   "critical" | "CRITICAL"   — always returns CRITICAL
 *   "random"                  — coin-flip HIGH or CRITICAL per call
 *
 * Consumers:
 *   - Synchronous preScanContent() — used in dispute-service inline checks
 *   - Async prescan worker — short-circuits classifier when forced; lets
 *     dev test the review/flagged content UI without needing the classifier
 *     to actually flag something
 */
function devForcedPrescanTier(originCode) {
  if (process.env.NODE_ENV === "production") return null;
  if (!PRESCAN_ELIGIBLE_ORIGINS.has(originCode)) return null;
  const raw = process.env.TIP_DEV_FORCE_PRESCAN_TIER;
  if (!raw) return null;
  const v = String(raw).toLowerCase();
  if (v === "high") return PRESCAN_TIERS.HIGH;
  if (v === "critical") return PRESCAN_TIERS.CRITICAL;
  if (v === "random") {
    return Math.random() < 0.5 ? PRESCAN_TIERS.HIGH : PRESCAN_TIERS.CRITICAL;
  }
  return null;
}

// Internal alias kept for the sync preScanContent path below — same impl.
const _devForcedPrescanTier = devForcedPrescanTier;

/**
 * AI pre-scan for content origin mismatch detection.
 *
 * Runs for OH and AA origin codes (both claim human-primary authorship).
 * AG and MX skip prescan — they already disclose AI involvement.
 *
 * Returns:
 *   flagged       — boolean; back-compat signal driven by the legacy adaptive
 *                   threshold. Existing callers (commit-handler) still read
 *                   this to set initial content status. Migrate to `tier`.
 *   probability   — raw classifier output [0.0, 1.0]
 *   raw_tier      — tier from probability alone (spec-pure)
 *   tier          — calibrated tier (raw_tier + creator-history adjustment)
 *   threshold     — legacy adaptive threshold value (retained for back-compat)
 */
function preScanContent(content, originCode, creatorHistory, contentType = null) {
  if (!PRESCAN_ELIGIBLE_ORIGINS.has(originCode)) {
    return {
      flagged: false,
      probability: 0,
      raw_tier: PRESCAN_TIERS.LOW,
      tier: PRESCAN_TIERS.LOW,
    };
  }

  // Dev-only override for UI testing of the prescan-review flow. Set
  // TIP_DEV_FORCE_PRESCAN_TIER to one of: "high" | "critical" | "random"
  // (random = 50/50 HIGH/CRITICAL coin flip). Production paths are
  // unaffected — env is read every call so a quick `export` toggles it
  // without restarting. Gated on NODE_ENV !== "production" so production
  // deployments physically can't honour it even if the env leaks in.
  const forced = _devForcedPrescanTier(originCode);
  if (forced) {
    return {
      flagged: true,
      probability: forced === PRESCAN_TIERS.CRITICAL ? 0.99 : 0.93,
      raw_tier: forced,
      tier: forced,
      threshold: 0.7,
      forced_by_dev_env: true,
    };
  }

  const words = content.split(/\s+/);
  const wordCount = words.length;
  if (wordCount < 20) {
    return {
      flagged: false,
      probability: 0.1,
      raw_tier: PRESCAN_TIERS.LOW,
      tier: PRESCAN_TIERS.LOW,
    };
  }

  const uniqueRatio = new Set(words).size / wordCount;
  const avgWordLen = words.reduce((s, w) => s + w.length, 0) / wordCount;
  const hasLongSentences = (content.match(/[.!?]/g) || []).length < wordCount / 25;

  let probability = 0;
  if (uniqueRatio < 0.55) probability += 0.2;
  if (avgWordLen > 5.5) probability += 0.15;
  if (hasLongSentences) probability += 0.1;

  // Legacy adaptive threshold — drives the back-compat `flagged` boolean.
  // Existing commit-handler reads d.prescan_flagged to set initial PENDING_REVIEW
  // status. Will be removed once consumers migrate to `tier` (Phase 2).
  const verifiedCount = creatorHistory?.verified_oh_count || 0;
  const legacyThreshold = verifiedCount > 200
    ? PRESCAN_THRESHOLDS.ceiling
    : verifiedCount > 50
      ? 0.90
      : PRESCAN_THRESHOLDS.default;

  // New tier-based output. raw_tier comes straight from probability; tier
  // applies creator-history calibration on top (Claim G).
  const rawTier = computeRawTier(probability, contentType);
  const tier = adjustTier(rawTier, creatorHistory);

  return {
    flagged: probability > legacyThreshold,
    probability,
    raw_tier: rawTier,
    tier,
    threshold: legacyThreshold,
  };
}

/**
 * Create a tx submitter. Always routes through consensus mempool.
 * Single code path — consensus runs even with 1 node (quorum=1, instant commit).
 *
 * @param {Object} consensusRef  { current: consensus }
 * @returns {{ submitTx: Function, submitBatch: Function }}
 */
function createTxSubmitter(consensusRef) {
  /**
   * Submit a single tx to consensus mempool.
   * @param {Object} tx  Validated tx with tx_id
   * @returns {{ tx_id: string }}
   */
  function submitTx(tx) {
    if (!consensusRef?.current) throw { status: 503, error: "Consensus not available" };
    const result = consensusRef.current.addTx(tx);
    if (!result.added) throw { status: 503, error: `Transaction not accepted: ${result.reason}` };
    return { tx_id: tx.tx_id };
  }

  /**
   * Submit multiple txs as an atomic batch to consensus mempool.
   * All txs in the batch will be committed together or not at all.
   * Used for dispute (9 txs), appeal (4 txs), revocation cascade (2+ txs).
   * @param {Array<Object>} txs  Validated txs with tx_ids
   * @returns {{ tx_ids: string[], batch_id: string }}
   */
  function submitBatch(txs) {
    if (!consensusRef?.current) throw { status: 503, error: "Consensus not available" };
    if (!txs || txs.length === 0) throw { status: 400, error: "Empty batch" };

    const txIds = [];
    for (const tx of txs) {
      const result = consensusRef.current.addTx(tx);
      if (!result.added) {
        // Rollback: remove already-added txs from this batch
        for (const addedId of txIds) consensusRef.current.mempool.remove([addedId]);
        throw { status: 503, error: `Batch rejected: tx ${tx.tx_id?.slice(0, 16)}: ${result.reason}` };
      }
      txIds.push(tx.tx_id);
    }

    return { tx_ids: txIds, batch_id: txs[0].tx_id };
  }

  return { submitTx, submitBatch };
}

/**
 * Build the structured `prescan` descriptor returned alongside content
 * registration / resolution responses. Backend-owned source of truth for
 * what the FE needs to render the post-registration warning UX:
 *
 *   - tier / confidence_label / probability / flagged   — what the AI said
 *   - decision_window_ms + decision_window_ends_at      — timer for the
 *       creator's free-correction window. Driven by the actual
 *       CONTENT_GRACE constants so a protocol change propagates without
 *       any FE deploy.
 *   - actions_available[]                                — which buttons
 *       to render (keep / change_origin / retract). Backend-owned so a
 *       future tier-specific change (e.g., disable retract at CRITICAL)
 *       is a constants edit, not a FE deploy.
 *   - consequence_if_confirmed                           — severity hint
 *       for the warning badge (none / penalty / significant_penalty).
 *   - next_step_if_kept                                  — what happens
 *       if the creator does nothing during the window.
 *   - post_confirm_decision_window_ms + reviewer_sla_ms  — pre-loaded
 *       timing constants so the FE timer at the *next* state (post-
 *       CONFIRMED 24h window, reviewer SLA) is also live, not hardcoded.
 *
 * Detailed user-facing prose lives in the FE (i18n string tables keyed
 * off these structured fields). See my-notes/POST_REGISTRATION_FLOW.md.
 *
 * @param {Object} preScan         Output of preScanContent().
 * @param {string} originCode      The declared origin (OH / AA / AG / MX).
 * @param {string} registeredAt    ISO timestamp of registration.
 * @param {boolean} [originChanged]  True if the creator has already
 *                                 updated the origin since registration —
 *                                 we drop CHANGE_ORIGIN from
 *                                 actions_available and the FE should
 *                                 suppress the prescan warning banner.
 * @returns {Object} structured descriptor (see fields above).
 */
function buildPrescanDescriptor({ preScan, originCode, registeredAt, originChanged = false }) {
  const tier = preScan?.tier || PRESCAN_TIERS.LOW;
  const base = {
    tier,
    confidence_label: CONFIDENCE_LABELS[tier] || tier,
    probability: typeof preScan?.probability === "number" ? preScan.probability : 0,
    flagged: !!preScan?.flagged,
  };

  // LOW — nothing more to surface; the FE shouldn't render any banner.
  if (tier === PRESCAN_TIERS.LOW) return base;

  const registeredMs = registeredAt ? registeredAt : nowMs();

  // Helper — once the creator has already self-corrected, change_origin
  // is no longer a meaningful action (you can keep updating origins, but
  // for the prescan warning UX it's resolved). Retract is still allowed
  // because it's the protocol-level "withdraw content entirely" exit.
  const buildActions = (full) => {
    if (!originChanged) return full;
    return full.filter(a => a !== PRESCAN_ACTIONS.CHANGE_ORIGIN);
  };

  // ELEVATED — soft 24h window, no reviewer step downstream. Retract
  // isn't surfaced because the soft tier alone isn't a reason to pull
  // content; the creator can still retract via the normal action,
  // but the descriptor doesn't suggest it.
  if (tier === PRESCAN_TIERS.ELEVATED) {
    const ms = CONTENT_GRACE.UNFLAGGED_MS;
    return {
      ...base,
      decision_window_ms: ms,
      decision_window_ends_at: registeredMs + ms,
      actions_available: buildActions([PRESCAN_ACTIONS.KEEP, PRESCAN_ACTIONS.CHANGE_ORIGIN]),
      consequence_if_confirmed: PRESCAN_CONSEQUENCES.NONE,
      next_step_if_kept: PRESCAN_NEXT_STEPS.NONE,
    };
  }

  // HIGH / CRITICAL — 48h window then reviewer.
  const ms = CONTENT_GRACE.FLAGGED_MS;
  return {
    ...base,
    decision_window_ms: ms,
    decision_window_ends_at: registeredMs + ms,
    actions_available: buildActions([PRESCAN_ACTIONS.KEEP, PRESCAN_ACTIONS.CHANGE_ORIGIN, PRESCAN_ACTIONS.RETRACT]),
    consequence_if_confirmed: tier === PRESCAN_TIERS.CRITICAL
      ? PRESCAN_CONSEQUENCES.SIGNIFICANT_PENALTY
      : PRESCAN_CONSEQUENCES.PENALTY,
    // When the creator has already self-corrected, the trigger SQL
    // filter excludes the row (origin_code != 'OH'). Reflect that
    // explicitly so the FE doesn't promise a reviewer step that won't
    // happen.
    next_step_if_kept: originChanged
      ? PRESCAN_NEXT_STEPS.NONE
      : PRESCAN_NEXT_STEPS.INDEPENDENT_REVIEWER_AT_WINDOW_END,
    post_confirm_decision_window_ms: REVIEWER.CREATOR_DECISION_WINDOW_MS,
    reviewer_sla_ms: REVIEWER.AUTO_RECUSE_AGE_MS,
  };
}

module.exports = {
  withTxId,
  nodeSignedAuto,
  createTxSubmitter,
  preScanContent,
  computeRawTier,
  getTierThresholds,
  adjustTier,
  buildPrescanDescriptor,
  devForcedPrescanTier,
};
