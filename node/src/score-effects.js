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

    // CONTENT_VERIFIED / CONTENT_RETRACTED no longer carry a score
    // effect here — they emit a paired SCORE_UPDATE that handles the
    // delta. Returning null keeps commit-handler from doing a wasted
    // read-and-no-write cycle for these txs.
    case TX_TYPES.CONTENT_VERIFIED:
    case TX_TYPES.CONTENT_RETRACTED:
      return null;

    case TX_TYPES.SCORE_UPDATE:
      return d.tip_id || null;

    // RESULT txs route to the author so applyScoreEffect runs and
    // adjusts offense_count. Score deltas live elsewhere — in paired
    // SCORE_UPDATE txs in the same atomic batch, built by jury.js
    // (`buildAdjudicationBatch` for Stage-2, `buildAppealBatch` for
    // Stage-3). The architectural rule:
    //   RESULT  → offense_count (the verdict decides "did an offense
    //             happen?")
    //   SCORE_UPDATE → score delta (single channel for all numeric
    //                  changes)
    // `author_score_delta` stays on the ADJUDICATION_RESULT tx data as
    // informational metadata — it's the audit trail and the value
    // `buildAppealBatch` reads to compute the exact reversal on overturn.
    case TX_TYPES.ADJUDICATION_RESULT:
      if (d.verdict === VERDICT.UPHELD && d.author_tip_id) return d.author_tip_id;
      return null;

    case TX_TYPES.APPEAL_RESULT:
      // Route to author when Stage-3 affects offense_count: any overturn,
      // OR NO_QUORUM→UPHELD (first verdict applying an offense). Other
      // outcomes (confirms, NO_QUORUM→DISMISSED, NO_QUORUM→CONSERVATIVE)
      // leave offense_count unchanged so no routing is needed.
      if (d.author_tip_id && (
        d.overturned
        || (d.stage2_verdict === VERDICT.NO_QUORUM && d.verdict === VERDICT.UPHELD)
      )) return d.author_tip_id;
      return null;

    // REVOKE_* still routes via the inline channel because the freeze
    // flag (`frozen=true`) is a state flip applied by applyScoreEffect,
    // not a score delta. Score-side penalty for REVOKE_DEVICE (when
    // that flow gets implemented) must be emitted as a paired
    // SCORE_UPDATE alongside.
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
      // No score effect here — paired SCORE_UPDATE in the same batch
      // (emitted by content-service.verify) carries the delta.
      // Single-channel rule: SCORE_UPDATE owns score deltas.
      break;
    }

    case TX_TYPES.CONTENT_RETRACTED: {
      // No score effect here — paired SCORE_UPDATE emitted by
      // content-service.retract carries the delta.
      break;
    }

    case TX_TYPES.SCORE_UPDATE: {
      delta = Number.isFinite(d.delta) ? d.delta : 0;
      reason = d.reason || "Score update";
      break;
    }

    case TX_TYPES.ADJUDICATION_RESULT: {
      // Architectural rule: RESULT txs own offense_count (the verdict
      // decides whether an offense happened); SCORE_UPDATE txs own
      // score deltas. ADJUDICATION_RESULT therefore increments
      // offense_count inline on UPHELD, but DOES NOT apply
      // `author_score_delta` as a score change here — the Stage-2
      // batch emits a paired SCORE_UPDATE for the author penalty
      // (see `jury.buildAdjudicationBatch`). The `author_score_delta`
      // field stays in tx.data as informational metadata (audit trail
      // + reversal lookup by `jury.buildAppealBatch`).
      //
      // NO_QUORUM / DISMISSED / CONSERVATIVE_LABEL all fall through as
      // no-ops here: only UPHELD constitutes an "offense" against the
      // author. Quorum-failure isn't the author's fault, dismissal
      // means the dispute had no merit, conservative-label means the
      // author under-claimed (honest direction).
      if (d.verdict === VERDICT.UPHELD && d.author_tip_id) {
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
      // Inline freeze flag stays here (it's a state flip, not a score
      // delta). The compromise penalty must be emitted as a paired
      // SCORE_UPDATE by whichever service builds the REVOKE_DEVICE tx
      // (no live emission point yet — wire it up when that flow exists).
      nextFrozen = true;
      break;
    }

    case TX_TYPES.APPEAL_RESULT: {
      // Offense_count adjustment — three cases where Stage-3 alters
      // the final offense state:
      //   UPHELD → DISMISSED (overturn): Stage-2 incremented; reverse (-1)
      //   DISMISSED → UPHELD (overturn): Stage-2 didn't increment but
      //                                   Stage-3 says UPHELD → +1
      //   NO_QUORUM → UPHELD: Stage-2 had no offense decision; Stage-3
      //                       is the first verdict → +1
      // Other paths (UPHELD→UPHELD confirm, DISMISSED→DISMISSED confirm,
      // NO_QUORUM→DISMISSED, NO_QUORUM→CONSERVATIVE_LABEL) leave
      // offense_count unchanged.
      // Score reversals / fresh penalties ride on paired SCORE_UPDATE
      // txs in the same batch — see jury.buildAppealBatch.
      if (d.overturned && d.stage2_verdict === VERDICT.UPHELD && nextOffense > 0) {
        nextOffense -= 1;
      } else if (d.overturned && d.stage2_verdict === VERDICT.DISMISSED && d.verdict === VERDICT.UPHELD) {
        nextOffense += 1;
      } else if (d.stage2_verdict === VERDICT.NO_QUORUM && d.verdict === VERDICT.UPHELD) {
        nextOffense += 1;
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

  // Per-pair offense escalation. Each pair's [1st, 2nd, 3rd+] tuple lives
  // in genesis (`penalties.oh_as_ag / oh_as_aa / aa_as_ag`); we read the
  // index that matches the offense count. Preserves severity scaling on
  // repeat offenses — a repeat AA→AG offender no longer gets the OH→AG
  // escalation (-200/-350) applied to them.

  // Most serious: declared OH, confirmed AG
  if (declared_origin === ORIGIN.OH && confirmed_origin === ORIGIN.AG) {
    if (currentOffenseCount >= 2) return SCORE_EVENTS.OH_CONFIRMED_AG_3RD.delta;
    if (currentOffenseCount >= 1) return SCORE_EVENTS.OH_CONFIRMED_AG_2ND.delta;
    return SCORE_EVENTS.OH_CONFIRMED_AG_1ST.delta;
  }

  // Declared OH, confirmed AA
  if (declared_origin === ORIGIN.OH && confirmed_origin === ORIGIN.AA) {
    if (currentOffenseCount >= 2) return SCORE_EVENTS.OH_CONFIRMED_AA_3RD.delta;
    if (currentOffenseCount >= 1) return SCORE_EVENTS.OH_CONFIRMED_AA_2ND.delta;
    return SCORE_EVENTS.OH_CONFIRMED_AA_1ST.delta;
  }

  // Declared AA, confirmed AG
  if (declared_origin === ORIGIN.AA && confirmed_origin === ORIGIN.AG) {
    if (currentOffenseCount >= 2) return SCORE_EVENTS.AA_CONFIRMED_AG_3RD.delta;
    if (currentOffenseCount >= 1) return SCORE_EVENTS.AA_CONFIRMED_AG_2ND.delta;
    return SCORE_EVENTS.AA_CONFIRMED_AG_1ST.delta;
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
