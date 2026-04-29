/**
 * @file @tip-protocol/node/src/score-effects.js
 * @description Single source of truth for "what does a tx do to a score".
 *
 * Two callers, identical math:
 *
 *   commit-handler (in-memory cache write):
 *     const target = scoreTargetTipId(tx);
 *     if (target) {
 *       const cur = dag.getScore(target) || INITIAL_STATE;
 *       const next = applyScoreEffect(tx, cur);
 *       dag.setScore(target, next.score, next.offense_count, tx.timestamp);
 *     }
 *
 *   scoring.computeScore (full-history replay):
 *     let state = INITIAL_STATE;
 *     for (const tx of txs) {
 *       state = applyScoreEffect(tx, state);
 *     }
 *     return state;
 *
 * Without this single source of truth the two paths drift — see
 * issues.md Node #38: a social_attested REGISTER_IDENTITY produced 550
 * via commit-handler and 600 via the old `computeScore` switch (score
 * absolute-set to 550 AND a +50 delta both fired). Live federation
 * forked when the scheduler's 12h recompute task ran on N1+N2 and
 * inflated their founding scores; N3 hadn't crossed its recompute
 * window so it stayed at the commit-handler value. State_merkle_root
 * diverged, byzantine-fork canary ticked >24K times.
 *
 * Pure functions: no DAG access, no side effects, deterministic across
 * every node. Same `(tx, current)` → same `next` everywhere.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES, ORIGIN, VERDICT } = require("../../shared/constants");
const { SCORE_EVENTS, SCORE } = require("../../shared/protocol-constants");

/**
 * Default state for an unknown tip_id — score starts at genesis's
 * `score.initial_identity` (deferred via getter so this module can be
 * required before PC.init runs in test setup). Frozen flips to true
 * after any revocation; positive deltas zero out post-freeze.
 */
function initialState() {
  return { score: SCORE.INITIAL_IDENTITY, offense_count: 0, frozen: false };
}

/**
 * Which tip_id does this tx's score effect target? null if no effect.
 *
 * `getTxsByTipId(tipId)` already filters to {data.tip_id === tipId OR
 * data.author_tip_id === tipId}; this helper is the inverse — given a
 * tx, identify the score subject. commit-handler uses it to know which
 * row to read+write.
 */
function scoreTargetTipId(tx) {
  const d = tx.data || {};
  switch (tx.tx_type) {
    case TX_TYPES.REGISTER_IDENTITY:
      return d.tip_id || null;

    case TX_TYPES.CONTENT_VERIFIED:
    case TX_TYPES.CONTENT_RETRACTED:
      return d.author_tip_id || null;

    case TX_TYPES.SCORE_UPDATE:
      return d.tip_id || null;

    // ADJUDICATION_RESULT carries the author penalty in
    // `tx.data.author_score_delta` (precomputed by jury.js via
    // `adjudicationDelta` so APPEAL_RESULT can reverse the exact value).
    //
    // PENALTY-ONLY INVARIANT (`< 0`): the verdict tx is the only
    // inline-score-effect channel in the system; every other party's
    // outcome (jurors, disputer, future vindication bonus per Scoring
    // #12) flows through separate SCORE_UPDATE txs in the same batch.
    // Author bonuses (e.g. DISMISSED vindication) MUST follow that
    // pattern — they don't ride here. A positive value reaching this
    // path means the verdict tx is malformed; refusing to apply it is
    // defensive and keeps the inline channel exclusively for the
    // appeal-reversal use case it exists to serve.
    case TX_TYPES.ADJUDICATION_RESULT:
      if (d.verdict === VERDICT.UPHELD && Number.isFinite(d.author_score_delta) && d.author_score_delta < 0) {
        return d.author_tip_id || null;
      }
      return null;

    // APPEAL_RESULT is purely orchestration — overturn-driven score
    // adjustments (penalty reversal, fresh penalty, appellant
    // bonus/penalty) are emitted as discrete SCORE_UPDATE txs in the
    // appeal batch by jury.js. The verdict tx itself doesn't move any
    // score row; it only flips offense_count via the freeze rule below.
    case TX_TYPES.APPEAL_RESULT:
      return null;

    case TX_TYPES.REVOKE_VOLUNTARY:
    case TX_TYPES.REVOKE_VP:
    case TX_TYPES.REVOKE_DECEASED:
    case TX_TYPES.REVOKE_DEVICE:
      return d.tip_id || null;

    default:
      return null;
  }
}

/**
 * Apply this tx's score effect to `current` and return the next state.
 *
 * @param {Object} tx       Committed transaction
 * @param {Object} current  { score, offense_count, frozen }
 * @returns {{ score, offense_count, frozen, delta, reason }}
 */
function applyScoreEffect(tx, current) {
  const cur = current || initialState();
  const d = tx.data || {};

  let nextScore = cur.score;
  let nextOffense = cur.offense_count;
  let nextFrozen = cur.frozen;
  let delta = 0;
  let reason = "";

  switch (tx.tx_type) {

    case TX_TYPES.REGISTER_IDENTITY: {
      // No delta. `cur.score` is `score.initial_identity` by construction
      // (initialState() seeds an unknown tipId with the genesis value),
      // and REGISTER_IDENTITY can only fire once per tipId — so the
      // score doesn't change here. The scores row gets created because
      // the caller writes when the row didn't exist, not because the
      // value changed. Per spec (TIP_Scoring_v2), the legacy +50 social
      // attestation bonus is gone; social bonuses now arrive as separate
      // SCORE_UPDATE txs (issues.md Scoring #11, +5 per linked account
      // up to identity.max_social_bonus = +30).
      reason = "Registration";
      break;
    }

    case TX_TYPES.CONTENT_VERIFIED: {
      // weighted_delta is computed at API time (caps applied) and frozen
      // in tx.data so every node applies the same number deterministically.
      delta = Number.isFinite(d.weighted_delta) ? d.weighted_delta : 0;
      reason = `Content verified (${d.ctid || ""})`;
      break;
    }

    case TX_TYPES.CONTENT_RETRACTED: {
      delta = SCORE_EVENTS.CONTENT_RETRACTION.delta;
      reason = `Content retracted (${d.ctid || ""})`;
      break;
    }

    case TX_TYPES.SCORE_UPDATE: {
      delta = Number.isFinite(d.delta) ? d.delta : 0;
      reason = d.reason || "Score update";
      break;
    }

    case TX_TYPES.ADJUDICATION_RESULT: {
      // Author penalty for an UPHELD verdict. Pre-computed by jury.js
      // (`adjudicationDelta` below) and embedded in tx.data so
      // APPEAL_RESULT can read the exact value back to reverse it on
      // overturn. Treating ADJUDICATION_RESULT as a score-effect tx
      // (rather than a no-op that rides on a separate SCORE_UPDATE)
      // keeps the verdict tx self-contained and matches Cosmos's
      // slashing pattern. Tracked migration to a fully unified
      // SCORE_UPDATE channel as Node #62.
      if (d.verdict === VERDICT.UPHELD && Number.isFinite(d.author_score_delta) && d.author_score_delta < 0) {
        delta = d.author_score_delta;
        reason = `Adjudication: UPHELD on ${d.ctid || ""}`;
        nextOffense += 1;
      }
      break;
    }

    case TX_TYPES.REVOKE_VOLUNTARY:
    case TX_TYPES.REVOKE_VP:
    case TX_TYPES.REVOKE_DECEASED:
      nextFrozen = true;
      reason = `Revoked (${tx.tx_type})`;
      break;

    case TX_TYPES.REVOKE_DEVICE: {
      delta = SCORE_EVENTS.DEVICE_COMPROMISE_PENDING.delta;
      nextFrozen = true;
      reason = "Device compromise — re-verification required";
      break;
    }

    case TX_TYPES.APPEAL_RESULT: {
      // No direct delta. If overturned a Stage 2 UPHELD, that offense no
      // longer counts — reverse the offense_count increment so future
      // adjudications see the right penalty tier.
      if (d.overturned && d.stage2_verdict === VERDICT.UPHELD && nextOffense > 0) {
        nextOffense -= 1;
      }
      break;
    }

    default:
      break;
  }

  // Freeze rule: after any revocation, positive deltas are zeroed.
  // Penalties still apply.
  if (nextFrozen && delta > 0) delta = 0;

  // Uniform clamp — every path adds delta to cur.score and clamps to
  // genesis's `score.max_total` (currently 1000). No tx_type branching
  // here: REGISTER_IDENTITY's delta is 0 by construction, so cur.score
  // passes through unchanged.
  if (delta !== 0) {
    nextScore = Math.max(0, Math.min(SCORE.MAX_TOTAL, cur.score + delta));
  }

  return {
    score: nextScore,
    offense_count: nextOffense,
    frozen: nextFrozen,
    delta,
    reason,
  };
}

/**
 * Calculate the author penalty for an adjudication outcome.
 * Implements the asymmetric penalty structure (TIP_Scoring_v2 spec §
 * "Negative Events"): scaling by current offense count and origin
 * mismatch class.
 *
 * Pre-compute helper for jury.js — embedded in
 * `ADJUDICATION_RESULT.tx.data.author_score_delta` at batch-build time
 * so APPEAL_RESULT can reverse the exact same value on overturn.
 * Lives in score-effects.js because the offense-scaling logic is part
 * of the score model; jury.js only needs to ask "what's the delta for
 * this verdict on this offense count?".
 *
 * @param {Object} data                     ADJUDICATION_RESULT-shape
 *                                          object with declared_origin,
 *                                          confirmed_origin, verdict,
 *                                          and optional type/severity
 * @param {number} currentOffenseCount      Offense count BEFORE this
 *                                          verdict applies
 * @returns {number} Score delta (negative for penalty, 0 for none)
 */
function adjudicationDelta(data, currentOffenseCount) {
  const { declared_origin, confirmed_origin, verdict } = data;

  if (verdict === VERDICT.DISMISSED) return 0;
  if (verdict === VERDICT.CONSERVATIVE_LABEL) return 0; // AG declared as OH — never penalised
  if (verdict !== VERDICT.UPHELD) return 0;             // unknown verdict — no penalty

  // Most serious: declared OH, confirmed AG
  if (declared_origin === ORIGIN.OH && confirmed_origin === ORIGIN.AG) {
    if (currentOffenseCount >= 2) return SCORE_EVENTS.MISMATCH_3RD_OFFENSE.delta;
    if (currentOffenseCount >= 1) return SCORE_EVENTS.MISMATCH_2ND_OFFENSE.delta;
    return SCORE_EVENTS.OH_CONFIRMED_AG_1ST.delta;
  }

  // Declared OH, confirmed AA
  if (declared_origin === ORIGIN.OH && confirmed_origin === ORIGIN.AA) {
    if (currentOffenseCount >= 1) return SCORE_EVENTS.MISMATCH_2ND_OFFENSE.delta;
    return SCORE_EVENTS.OH_CONFIRMED_AA.delta;
  }

  // Declared AA, confirmed AG
  if (declared_origin === ORIGIN.AA && confirmed_origin === ORIGIN.AG) {
    if (currentOffenseCount >= 1) return SCORE_EVENTS.MISMATCH_2ND_OFFENSE.delta;
    return SCORE_EVENTS.AA_CONFIRMED_AG.delta;
  }

  // Factual falsehood (separate from origin)
  if (data.type === "FACTUAL_FALSEHOOD") {
    const severity = data.severity || "minor";
    return severity === "major"
      ? SCORE_EVENTS.FACTUAL_FALSEHOOD_MAJOR.delta
      : SCORE_EVENTS.FACTUAL_FALSEHOOD_MINOR.delta;
  }

  return 0;
}

module.exports = {
  initialState,
  scoreTargetTipId,
  applyScoreEffect,
  adjudicationDelta,
};
