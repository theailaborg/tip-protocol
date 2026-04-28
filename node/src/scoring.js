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

const { TX_TYPES, ORIGIN, VERDICT } = require("../../shared/constants");
const { SCORE_EVENTS, getTier } = require("../../shared/protocol-constants");
const { signTransaction, computeTxId } = require("../../shared/crypto");
const { log } = require("./logger");

function initScoring(dag, config) {

  /**
   * Compute (or recompute) trust score for a TIP-ID from full DAG history.
   * This is the authoritative deterministic computation.
   * For production performance, the result is cached in the scores table and
   * only recomputed on new events.
   *
   * @param {string} tipId
   * @returns {{ score: number, tier: Object, offense_count: number, history: Array }}
   */
  function computeScore(tipId) {
    const txs = dag.getTxsByTipId(tipId);

    // Sort by timestamp ascending for deterministic replay
    txs.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    let score = 500;
    let offenseCount = 0;
    let frozen = false; // true after any revocation — blocks positive deltas
    const history = [];

    for (const tx of txs) {
      let delta = 0;
      let reason = "";

      switch (tx.tx_type) {

        case TX_TYPES.REGISTER_IDENTITY:
          score = tx.data.attested || tx.data.social_attested ? 550 : 500;
          reason = tx.data.attested || tx.data.social_attested ? "Registration with social attestation (+50)" : "Registration";
          delta = tx.data.attested || tx.data.social_attested ? 50 : 0;
          // clean record start tracked by scheduler via ADJUDICATION_RESULT txs
          break;

        case TX_TYPES.REGISTER_CONTENT:
          delta = 0;
          reason = `Content registered: ${tx.data.ctid || "unknown"} (${tx.data.origin_code || "?"})`;
          break;

        case TX_TYPES.CONTENT_DISPUTED:
          delta = 0;
          reason = tx.data.auto
            ? `Auto-dispute: ${tx.data.reason || "pre-scan"} on ${tx.data.ctid || "unknown"}`
            : `Dispute filed on ${tx.data.ctid || "unknown"}`;
          break;

        case TX_TYPES.CONTENT_VERIFIED:
          // +2 to +5 weighted by verifier trust score; daily cap applied
          delta = tx.data.weighted_delta || 2;
          reason = `Content verified (${tx.data.ctid})`;
          break;

        case TX_TYPES.ADJUDICATION_RESULT:
          delta = _adjudicationDelta(tx.data, offenseCount);
          reason = `Adjudication: ${tx.data.verdict} on ${tx.data.ctid}`;
          if (delta < 0) {
            offenseCount++;
            // offense tracked by scheduler for clean record eligibility
          }
          break;

        case TX_TYPES.APPEAL_RESULT:
          // If appeal overturned a Stage 2 UPHELD → that offense no longer counts
          if (tx.data.overturned && tx.data.stage2_verdict === VERDICT.UPHELD && offenseCount > 0) {
            offenseCount--;
          }
          // delta = 0 here — appeal score effects are applied via SCORE_UPDATE txs
          break;

        case TX_TYPES.SCORE_UPDATE:
          delta = tx.data.delta || 0;
          reason = tx.data.reason || "Score update";
          break;

        case TX_TYPES.CONTENT_RETRACTED:
          // Author penalty for retraction. Commit-handler applies the
          // same delta to the score cache deterministically; this case
          // is for from-scratch replay (full computeScore on this tipId).
          delta = SCORE_EVENTS.CONTENT_RETRACTION.delta;
          reason = `Content retracted: ${tx.data.ctid || "unknown"}`;
          break;

        case TX_TYPES.REVOKE_DEVICE:
          delta = SCORE_EVENTS.DEVICE_COMPROMISE_PENDING.delta;
          reason = "Device compromise pending re-verification";
          frozen = true;
          break;

        case TX_TYPES.REVOKE_VP:
          reason = "Revoked by VP (fraud/violation)";
          frozen = true;
          break;

        case TX_TYPES.REVOKE_VOLUNTARY:
          reason = "Voluntary revocation";
          frozen = true;
          break;

        case TX_TYPES.REVOKE_DECEASED:
          reason = "Deceased";
          frozen = true;
          break;

        default:
          break;
      }

      // Frozen: block positive deltas after revocation (penalties still apply)
      if (frozen && delta > 0) delta = 0;

      if (delta !== 0) {
        score = Math.max(0, Math.min(1000, score + delta));
      }
      if (reason) {
        history.push({
          tx_id: tx.tx_id,
          tx_type: tx.tx_type,
          delta,
          score_after: score,
          reason,
          timestamp: tx.timestamp,
        });
      }
    }

    // 90-day clean record bonus is applied by the scheduler as a real
    // SCORE_UPDATE tx (reason: "clean_record_bonus"). computeScore() replays
    // it naturally via the SCORE_UPDATE case above — no special logic needed.

    const tier = getTier(score);
    // Only persist to the scores table when there's real tx history. An
    // unknown tipId with no txs isn't a registered identity — writing a row
    // would invent state no other node would derive.
    if (txs.length > 0) {
      dag.setScore(tipId, score, offenseCount);
    }

    return { score, tier, offense_count: offenseCount, history };
  }

  /**
   * Calculate score delta for an adjudication outcome.
   * Implements the asymmetric penalty structure (v2 spec).
   */
  function _adjudicationDelta(data, currentOffenseCount) {
    const { declared_origin, confirmed_origin, verdict } = data;

    if (verdict === VERDICT.DISMISSED) return 0;
    if (verdict === VERDICT.CONSERVATIVE_LABEL) return 0; // AG declared as OH — never penalised
    if (verdict !== VERDICT.UPHELD) return 0; // unknown verdict — no penalty

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
   * Get score with fast path (from cache; fallback to full recompute).
   * @param {string} tipId
   * @returns {{ score, tier, offense_count }}
   */
  function getScore(tipId) {
    const cached = dag.getScore(tipId);
    if (cached) {
      return { score: cached.score, tier: getTier(cached.score), offense_count: cached.offense_count };
    }
    return computeScore(tipId);
  }

  /**
   * Recompute all scores from DAG history (used after node sync).
   * Can be expensive on large DAGs — run asynchronously.
   */
  async function recomputeAll() {
    const txs = dag.getTxsByType(TX_TYPES.REGISTER_IDENTITY);
    log.info(`Recomputing scores for ${txs.length} identities...`);
    for (const tx of txs) {
      if (tx.data?.tip_id) {
        computeScore(tx.data.tip_id);
      }
    }
    log.info("Score recomputation complete");
  }

  /**
   * Check if a TIP-ID is eligible to serve on jury (score >= 700, not revoked, not suspended).
   */
  function isJuryEligible(tipId) {
    if (dag.isRevoked(tipId)) return false;
    const s = getScore(tipId);
    return s.score >= 700;
  }

  /**
   * Compute what the adjudication penalty would be for a given author + verdict data.
   * Used by jury.js to store exact delta in ADJUDICATION_RESULT tx.
   */
  function getAdjudicationDelta(authorTipId, verdictData) {
    const { offense_count } = computeScore(authorTipId);
    return _adjudicationDelta(verdictData, offense_count);
  }

  return {
    computeScore,
    buildScoreUpdateTx,
    getScore,
    recomputeAll,
    isJuryEligible,
    getAdjudicationDelta,
  };
}

module.exports = { initScoring };
