/**
 * @file @tip-protocol/node/src/consensus/prescan-review-trigger.js
 * @description Post-round trigger for the prescan-review pipeline. Mirrors
 * the verdict-trigger / clean-record-trigger pattern: invoked by
 * commit-handler at the end of each round with `cert.timestamp` as the
 * deterministic clock.
 *
 * Two consensus-affecting triggers live here:
 *
 *   1. h=48 PRESCAN_REVIEW_TRIGGERED — for HIGH/CRITICAL-tier content
 *      that was registered with `override=true` and has been sitting in
 *      status=REGISTERED for more than CONTENT_GRACE.FLAGGED_MS without
 *      a creator UPDATE_ORIGIN, emit a node-signed
 *      PRESCAN_REVIEW_TRIGGERED carrying the deterministically-selected
 *      reviewer assignment.
 *
 *   2. h=R+24 auto-escalation — for reviews in state=confirmed where the
 *      creator's CREATOR_DECISION_WINDOW_MS has elapsed since the
 *      confirmation, emit an auto-cascade CONTENT_DISPUTED to push the
 *      content into the formal dispute pipeline. The review's state flip
 *      to ESCALATED_TO_DISPUTE happens in commit-handler when
 *      CONTENT_DISPUTED applies (single source of truth — works for
 *      user-filed disputes during the window too).
 *
 * Why this lives in `consensus/` and not in `scheduler.js`: nodes' local
 * wall clocks drift; scheduler-driven emits produce duplicate
 * submissions and (historically) forked live federations. Using
 * `cert.timestamp` (BFT median of acks.signed_at) as the clock makes
 * the "X hours elapsed" check identical on every node.
 *
 * Leader-gating: round-modulo leader picks one emitter per round. Other
 * nodes' submissions would be caught by commit-handler's first-wins
 * dedup (duplicate-trigger check in `_statefulCheck`), but emitting from
 * every node would flood the mempool needlessly.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256, computeTxId, signTransaction } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { TX_TYPES, PRESCAN_REVIEW_STATES, RECUSAL_REASONS } = require("../../../shared/constants");
const { selectReviewer } = require("../reviewer-selection");
const { getLogger } = require("../logger");

const log = getLogger("tip.prescan-review-trigger");

/**
 * @param {Object} deps
 * @param {Object}   deps.dag           DAG store
 * @param {Object}   deps.scoring       Scoring engine — used by selectReviewer
 * @param {Object}   deps.config        Node config (signs node-emitted txs)
 * @param {Function} deps.submitTx      Consensus tx submitter
 * @param {Function} [deps.getCommittee] (round) => string[]  Active node_ids.
 *   Round-modulo leader gating; defaults to "every node fires" when omitted
 *   (same fall-through as verdict-trigger / clean-record-trigger).
 */
function createPrescanReviewTrigger({ dag, scoring, config, submitTx, getCommittee }) {
  if (!dag) throw new Error("prescan-review-trigger: dag required");

  const _myNodeId = config?.nodeRegisteredId || config?.nodeId;
  const _nodePrivateKey = config?.nodePrivateKey;

  function _isMyRoundLeader(round) {
    if (typeof getCommittee !== "function") return true;
    const committee = getCommittee(round);
    if (!Array.isArray(committee) || committee.length === 0) return true;
    const sorted = [...committee].sort();
    const idx = Math.abs(Math.trunc(round)) % sorted.length;
    return sorted[idx] === _myNodeId;
  }

  function checkPending(certTimestamp, round) {
    if (!Number.isFinite(certTimestamp) || certTimestamp <= 0) return;
    if (!config || typeof submitTx !== "function") return;
    if (!_nodePrivateKey || !_myNodeId) return;

    if (Number.isFinite(round) && !_isMyRoundLeader(round)) return;

    _emitDueReviews(certTimestamp, round);
    _emitAutoEscalations(certTimestamp, round);
    _emitAutoRecusals(certTimestamp, round);
  }

  function _emitDueReviews(certTimestamp, round) {
    let candidates;
    try {
      candidates = dag.getContentsNeedingReview(certTimestamp);
    } catch (err) {
      log.warn(`getContentsNeedingReview failed: ${err.message}`);
      return;
    }
    if (!candidates || candidates.length === 0) return;

    for (const content of candidates) {
      try {
        const reviewId = _deriveReviewId(content.ctid, round);
        const { reviewer, pass, poolSize } = selectReviewer(dag, scoring, {
          reviewId, ctid: content.ctid, round,
          authorTipId: content.author_tip_id,
        });
        if (!reviewer) {
          log.warn(`No eligible reviewer for ${content.ctid} at round ${round} (poolSize=${poolSize})`);
          continue;
        }

        const tx = _buildTriggeredTx({
          reviewId,
          ctid: content.ctid,
          creatorTipId: content.author_tip_id,
          assignedReviewerTipId: reviewer,
          round,
        });

        try {
          submitTx(tx);
          log.info(`Review proposed for ${content.ctid} → ${reviewer} (review_id=${reviewId}, pass=${pass})`);
        } catch (err) {
          const reason = err?.error || err?.message || String(err);
          log.debug(`Review trigger submission deferred for ${content.ctid}: ${reason}`);
        }
      } catch (err) {
        log.warn(`Review trigger failed for ${content.ctid}: ${err.message}`);
      }
    }
  }

  function _emitAutoEscalations(certTimestamp, round) {
    let reviews;
    try {
      reviews = dag.getReviewsNeedingAutoEscalation(certTimestamp);
    } catch (err) {
      log.warn(`getReviewsNeedingAutoEscalation failed: ${err.message}`);
      return;
    }
    if (!reviews || reviews.length === 0) return;

    for (const review of reviews) {
      try {
        // Idempotency — another node may have already auto-escalated.
        // The review's state would still be CONFIRMED here (apply hasn't
        // landed yet), so check for an existing CONTENT_DISPUTED.
        const existing = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, review.ctid);
        if (existing && existing.length > 0) continue;

        const tx = _buildAutoDisputeTx({
          ctid: review.ctid,
          reviewId: review.review_id,
          suggestedOrigin: review.suggested_origin,
        });

        try {
          submitTx(tx);
          log.info(`Auto-escalation proposed for ${review.ctid} (review_id=${review.review_id})`);
        } catch (err) {
          const reason = err?.error || err?.message || String(err);
          log.debug(`Auto-escalation submission deferred for ${review.ctid}: ${reason}`);
        }
      } catch (err) {
        log.warn(`Auto-escalation failed for ${review.review_id}: ${err.message}`);
      }
    }
  }

  function _buildTriggeredTx({ reviewId, ctid, creatorTipId, assignedReviewerTipId, round }) {
    const txBody = {
      tx_type: TX_TYPES.PRESCAN_REVIEW_TRIGGERED,
      timestamp: nowMs(),
      prev: dag.getRecentPrev(),
      data: {
        review_id: reviewId,
        ctid,
        creator_tip_id: creatorTipId,
        assigned_reviewer_tip_id: assignedReviewerTipId,
        node_id: _myNodeId,
        triggered_at_round: round,
      },
    };
    txBody.tx_id = computeTxId(txBody);
    return signTransaction(txBody, _nodePrivateKey);
  }

  function _buildAutoDisputeTx({ ctid, reviewId, suggestedOrigin }) {
    const txBody = {
      tx_type: TX_TYPES.CONTENT_DISPUTED,
      timestamp: nowMs(),
      prev: dag.getRecentPrev(),
      data: {
        ctid,
        reason: "creator_decision_window_expired",
        auto: true,
        node_id: _myNodeId,
        source_review_id: reviewId,
        suggested_origin: suggestedOrigin || null,
      },
    };
    txBody.tx_id = computeTxId(txBody);
    return signTransaction(txBody, _nodePrivateKey);
  }

  /**
   * Reviewer-SLA auto-recuse — for each TRIGGERED review whose
   * triggered_at_ms is older than REVIEWER.AUTO_RECUSE_AGE_MS,
   * emit a node-signed PRESCAN_REVIEW_RECUSED. Commit-handler's
   * apply flips review.state to RECUSED and content.status back
   * to REGISTERED; the next round's _emitDueReviews then re-picks
   * the content and emits a fresh PRESCAN_REVIEW_TRIGGERED with a
   * new (deterministic) assignment.
   */
  function _emitAutoRecusals(certTimestamp, round) {
    let reviews;
    try {
      reviews = dag.getReviewsNeedingAutoRecuse(certTimestamp);
    } catch (err) {
      log.warn(`getReviewsNeedingAutoRecuse failed: ${err.message}`);
      return;
    }
    if (!reviews || reviews.length === 0) return;

    for (const review of reviews) {
      try {
        const tx = _buildAutoRecuseTx({ reviewId: review.review_id });
        try {
          submitTx(tx);
          log.info(`Auto-recuse proposed for review_id=${review.review_id} (assigned=${review.assigned_reviewer})`);
        } catch (err) {
          const reason = err?.error || err?.message || String(err);
          log.debug(`Auto-recuse submission deferred for ${review.review_id}: ${reason}`);
        }
      } catch (err) {
        log.warn(`Auto-recuse failed for ${review.review_id}: ${err.message}`);
      }
    }
  }

  function _buildAutoRecuseTx({ reviewId }) {
    const txBody = {
      tx_type: TX_TYPES.PRESCAN_REVIEW_RECUSED,
      timestamp: nowMs(),
      prev: dag.getRecentPrev(),
      data: {
        review_id: reviewId,
        auto: true,
        node_id: _myNodeId,
        recusal_reason: RECUSAL_REASONS.SLA_EXPIRED,
      },
    };
    txBody.tx_id = computeTxId(txBody);
    return signTransaction(txBody, _nodePrivateKey);
  }

  return { checkPending };
}

/**
 * Deterministic review_id from ctid + round so every honest node arrives
 * at the same id when triggering the same content on the same round. The
 * commit-handler duplicate-trigger check dedupes if multiple nodes race
 * past the leader gate, but matching review_id ensures the second
 * submission is treated as the SAME review (not a different review for
 * the same ctid).
 */
function _deriveReviewId(ctid, round) {
  const h = shake256(`prescan_review:${ctid}:${round}`).slice(0, 32);
  return `pr_${h}`;
}

module.exports = { createPrescanReviewTrigger, _deriveReviewId };
