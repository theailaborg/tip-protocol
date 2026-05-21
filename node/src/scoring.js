/**
 * @file @tip-protocol/node/src/scoring.js
 * @description TIP Trust Scoring Engine — Deterministic from DAG history.
 *
 * Core invariant:
 *   Given the same DAG transaction history, every protocol-compliant node
 *   MUST compute the same trust score for any TIP-ID.
 *
 * Score range: 0 to 1000 (integer)
 * Starting score: 500 (no attestation) or 550 (social attestation)
 *
 * This engine is called:
 *   - On every new score-affecting transaction
 *   - On API requests to /v1/identity/:tipId/score
 *   - During full score recomputation (sync, audit)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { TX_TYPES } = require("../../shared/constants");
const { getTier, JURY } = require("../../shared/protocol-constants");
const { signTransaction, computeTxId } = require("../../shared/crypto");
const { applyScoreEffect, scoreTargetTipId, initialState, adjudicationDelta } = require("./score-effects");

function initScoring(dag, config) {

  /**
   * Replay tipId's transaction history and return the score timeline.
   *
   * Read-only: does NOT write to the scores table. The scores table is
   * derived state, part of state_merkle_root (#31), and its sole writer
   * is `commit-handler._applyScoreEffect` (#38). This function exists
   * for the score-history API endpoint and for diagnostics — anything
   * that needs the timeline rather than just the current value.
   *
   * Both this replay and commit-handler call into `score-effects.js`
   * `applyScoreEffect(tx, current)` so the math is byte-identical.
   *
   * @param {string} tipId
   * @returns {{ score: number, tier: Object, offense_count: number, history: Array }}
   */
  function computeScore(tipId) {
    const txs = dag.getTxsByTipId(tipId);

    // Sort by timestamp ascending for deterministic replay
    txs.sort((a, b) => a.timestamp - b.timestamp);

    let state = initialState();
    const history = [];

    for (const tx of txs) {
      // Filter to txs that target THIS tipId. `getTxsByTipId` returns
      // any tx that mentions tipId in `data.tip_id` OR `data.author_tip_id`,
      // but the score effect only fires on the role we are. (e.g. an
      // ADJUDICATION_RESULT mentions the author but its score impact
      // rides on the SCORE_UPDATE batch — `scoreTargetTipId` enforces
      // this and returns null for verdict txs.)
      const target = scoreTargetTipId(tx);
      if (target !== tipId) continue;

      const next = applyScoreEffect(tx, state);
      history.push({
        tx_id: tx.tx_id,
        tx_type: tx.tx_type,
        delta: next.delta,
        score_after: next.score,
        reason: next.reason,
        timestamp: tx.timestamp,
      });
      state = next;
    }

    return {
      score: state.score,
      tier: getTier(state.score),
      offense_count: state.offense_count,
      history,
    };
  }

  /**
   * Build a signed SCORE_UPDATE tx WITHOUT writing to DAG and WITHOUT mutating
   * the score cache. The tx is meant to be submitted through `submitBatch`
   * so it flows through consensus mempool → Bullshark → commit-handler, where
   * `commit-handler.js`'s SCORE_UPDATE case applies the cache mutation
   * deterministically on every node (with first-wins dedup by
   * `(tip_id, ctid, reason)` to prevent multiple-submitter double-counting).
   *
   * `getRecentPrev` is a function (not the result) so each call captures the
   * caller's view of the prev-ring at build time — matches the
   * `dispute-service.js` pattern.
   *
   * @param {Object} args
   * @param {string} args.tipId         The TIP-ID this score event applies to
   * @param {number} args.delta         Score delta (positive or negative)
   * @param {string} args.reason        Human-readable reason — included in dedup key
   * @param {string|null} args.ctid     Related content-id, if any (dedup key)
   * @param {string|null} args.relatedTxId  ADJUDICATION_RESULT / APPEAL_RESULT tx_id
   * @param {string} args.timestamp     ISO timestamp for the tx
   * @param {Function} args.getRecentPrev  () => string[]  prev-ring snapshot
   * @param {Object} args.config        Node config (provides node_id + private key)
   * @returns {Object} signed tx with tx_id
   */
  function buildScoreUpdateTx({ tipId, delta, reason, ctid = null, relatedTxId = null, timestamp, getRecentPrev, config }) {
    const txBody = {
      tx_type: TX_TYPES.SCORE_UPDATE,
      timestamp,
      prev: typeof getRecentPrev === "function" ? getRecentPrev() : [],
      data: {
        tip_id: tipId,
        delta,
        reason,
        ctid,
        related_tx_id: relatedTxId,
        node_id: config.nodeRegisteredId || config.nodeId,
      },
    };
    txBody.tx_id = computeTxId(txBody);
    return signTransaction(txBody, config.nodePrivateKey);
  }

  /**
   * Get a tip_id's current score. Reads the scores table directly —
   * never writes. The scores table is the source of truth at runtime;
   * commit-handler is its sole writer (#38). Falls back to a replay-
   * derived value for tip_ids with no row yet (e.g. a query racing the
   * REGISTER_IDENTITY commit). The replay uses the SAME pure function
   * commit-handler does, so the value is byte-identical to what
   * commit-handler will write a moment later.
   *
   * @param {string} tipId
   * @returns {{ score, tier, offense_count }}
   */
  function getScore(tipId) {
    const cached = dag.getScore(tipId);
    if (cached) {
      return { score: cached.score, tier: getTier(cached.score), offense_count: cached.offense_count };
    }
    const derived = computeScore(tipId);
    return { score: derived.score, tier: derived.tier, offense_count: derived.offense_count };
  }

  /**
   * Check if a TIP-ID is eligible to serve on jury — score >= genesis's
   * `jury.jury_min_score` (currently 700), not revoked, not suspended.
   */
  function isJuryEligible(tipId) {
    if (dag.isRevoked(tipId)) return false;
    const s = getScore(tipId);
    return s.score >= JURY.MIN_SCORE;
  }

  /**
   * Compute what the adjudication penalty would be for a given author + verdict data.
   * Used by jury.js to store exact delta in ADJUDICATION_RESULT tx.
   */
  function getAdjudicationDelta(authorTipId, verdictData) {
    const { offense_count } = computeScore(authorTipId);
    return adjudicationDelta(verdictData, offense_count);
  }

  return {
    computeScore,
    buildScoreUpdateTx,
    getScore,
    isJuryEligible,
    getAdjudicationDelta,
  };
}

module.exports = { initScoring };
