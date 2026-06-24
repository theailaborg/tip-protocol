/**
 * @file @tip-protocol/node/src/services/review-service.js
 * @description Reviewer + creator decision endpoints for the prescan-
 * review pipeline (Phase 2.6).
 *
 *   dismiss(reviewId, body)          → PRESCAN_REVIEW_DISMISSED
 *   confirm(reviewId, body)          → PRESCAN_REVIEW_CONFIRMED
 *   acceptCorrection(reviewId, body) → UPDATE_ORIGIN (commit-handler
 *                                      auto-flips the review row to
 *                                      CLOSED_ACCEPTED_PRIVATE)
 *   getReview(reviewId)              → projection
 *
 * Structure: every action delegates ALL request validation to its
 * schema module's `validateRequest` (declarative shape, DAG lookups,
 * state-machine gating, signature verification). The service body
 * deals exclusively with building + submitting the tx. Same canonical
 * payload at API time and consensus replay, by construction.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES, PRESCAN_REVIEW_STATES } = require("../../../shared/constants");
const { nowMs, nowPlusMs } = require("../../../shared/time");
const { REVIEWER, JURY, DISPUTE } = require("../../../shared/protocol-constants");
const { selectJury } = require("../jury");
const { validateTransaction } = require("../validators/tx-validator");
const dismissedSchema = require("../schemas/prescan-review-dismissed");
const confirmedSchema = require("../schemas/prescan-review-confirmed");
const recusedSchema = require("../schemas/prescan-review-recused");
const acceptCorrectionSchema = require("../schemas/prescan-review-accept-correction");
const disputeSchema = require("../schemas/prescan-review-dispute");
const { schemaError } = require("../schemas/_common");
const { withTxId, nodeSignedAuto } = require("./helpers");
const { isEligibleReviewer, getReviewerAccuracy } = require("../reviewer-selection");
const { getLogger } = require("../logger");

const log = getLogger("tip.review");

const OUTCOME_LABELS = Object.freeze({
  [PRESCAN_REVIEW_STATES.TRIGGERED]: "PENDING",
  [PRESCAN_REVIEW_STATES.CONFIRMED]: "AWAITING_CREATOR_DECISION",
  [PRESCAN_REVIEW_STATES.CLOSED_DISMISSED]: "DISMISSED",
  [PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE]: "ACCEPTED_PRIVATE",
  [PRESCAN_REVIEW_STATES.CLOSED_SELF_CORRECT]: "SELF_CORRECTED",
  [PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE]: "ESCALATED",
  [PRESCAN_REVIEW_STATES.RECUSED]: "RECUSED",
});

// Score-history → review attribution. Two paths:
//   1. review-tagged reasons embed the review_id directly (review_dismissed:pr_…,
//      review_accepted_private:pr_…, review_correct_bonus[*]:pr_…) — match by
//      substring.
//   2. dispute-lifecycle reasons name the ctid but not the review_id ("Dispute
//      filing stake on tip://c/…", "Dispute upheld on tip://c/…", "Appeal
//      overturned: Stage 2 settlement reversed on tip://c/…"). Only an
//      ESCALATED review can legitimately own these, and we time-bound by the
//      next review's triggered_at so consecutive disputes on the same ctid
//      don't bleed across rows.
function _matchesReview(historyEntry, review, winStartMs, winEndMs, isEscalated) {
  const reason = historyEntry.reason || "";
  if (reason.includes(review.review_id)) return true;
  if (!isEscalated) return false;
  if (!reason.includes(review.ctid)) return false;
  if (!/^(Dispute|Appeal)\b/.test(reason)) return false;
  const ts = historyEntry.timestamp;
  return ts >= winStartMs && ts < winEndMs;
}

function createReviewService({ dag, scoring, submitTx, submitBatch, config }) {

  function getReview(reviewId) {
    const review = dag.getPrescanReview(reviewId);
    if (!review) throw schemaError(404, `Review not found: ${reviewId}`, "review_not_found");
    const content = dag.getContent(review.ctid);
    return {
      review_id: review.review_id,
      ctid: review.ctid,
      creator_tip_id: review.creator_tip_id,
      assigned_reviewer: review.assigned_reviewer,
      state: review.state,
      triggered_at_round: review.triggered_at_round,
      decided_at_round: review.decided_at_round,
      confirmed_at_round: review.confirmed_at_round,
      confirmed_at_ms: review.confirmed_at_ms,
      decision_note: review.decision_note,
      suggested_origin: review.suggested_origin,
      content_status: content ? content.status : null,
      content_origin_code: content ? content.origin_code : null,
    };
  }

  function dismiss(reviewId, body) {
    const safeBody = { ...(body || {}), review_id: reviewId };
    dismissedSchema.validateRequest(safeBody, { dag });

    const reviewer = dag.getIdentity(safeBody.reviewer_tip_id);
    const payload = dismissedSchema.buildSigningPayload(safeBody);
    if (!dismissedSchema.verifySignature(payload, safeBody.signature, reviewer.public_key)) {
      throw schemaError(403, "Reviewer signature verification failed", "signature_invalid");
    }

    const review = dag.getPrescanReview(reviewId);
    const timestamp = nowMs();
    const tx = withTxId({
      tx_type: TX_TYPES.PRESCAN_REVIEW_DISMISSED,
      timestamp,
      prev: dag.getRecentPrev(),
      data: {
        review_id: reviewId,
        reviewer_tip_id: safeBody.reviewer_tip_id,
        // #40 — creator sees the verdict on their content. Outside the
        // reviewer's signed payload {review_id, reviewer_tip_id}, so the
        // signature still verifies.
        creator_tip_id: review?.creator_tip_id ?? null,
        decision_note: safeBody.decision_note ?? null,
      },
      signature: safeBody.signature,
    });
    const validation = validateTransaction(tx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    // Single-channel rule: the reviewer's "case closed cleanly" bonus
    // (+REVIEWER.CORRECT_BONUS) rides alongside the DISMISSED record
    // in the same batch. No public dispute will follow a DISMISS, so
    // the reward settles immediately — no Stage-2 verdict path to wait
    // on. Penalty path is symmetric only for CONFIRM (see jury.js
    // ADJUDICATION_RESULT batch).
    const scoreTx = scoring.buildScoreUpdateTx({
      tipId: safeBody.reviewer_tip_id,
      delta: REVIEWER.CORRECT_BONUS,
      reason: `review_dismissed:${reviewId}`,
      ctid: review?.ctid || null,
      relatedTxId: tx.tx_id,
      timestamp,
      getRecentPrev: () => dag.getRecentPrev(),
      config,
    });

    submitBatch([tx, scoreTx]);
    log.info(`Review dismissed: ${reviewId} by ${safeBody.reviewer_tip_id} (+${REVIEWER.CORRECT_BONUS})`);
    return { review_id: reviewId, tx_id: tx.tx_id, score_tx_id: scoreTx.tx_id, confirmation: "proposed" };
  }

  function confirm(reviewId, body) {
    const safeBody = { ...(body || {}), review_id: reviewId };
    confirmedSchema.validateRequest(safeBody, { dag });

    const reviewer = dag.getIdentity(safeBody.reviewer_tip_id);
    const payload = confirmedSchema.buildSigningPayload(safeBody);
    if (!confirmedSchema.verifySignature(payload, safeBody.signature, reviewer.public_key)) {
      throw schemaError(403, "Reviewer signature verification failed", "signature_invalid");
    }

    const review = dag.getPrescanReview(reviewId);
    const tx = withTxId({
      tx_type: TX_TYPES.PRESCAN_REVIEW_CONFIRMED,
      timestamp: nowMs(),
      prev: dag.getRecentPrev(),
      data: {
        review_id: reviewId,
        reviewer_tip_id: safeBody.reviewer_tip_id,
        // #40 — creator sees the verdict; outside the signed payload.
        creator_tip_id: review?.creator_tip_id ?? null,
        suggested_origin: safeBody.suggested_origin,
        decision_note: safeBody.decision_note ?? null,
      },
      signature: safeBody.signature,
    });
    const validation = validateTransaction(tx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(tx);
    log.info(`Review confirmed: ${reviewId} by ${safeBody.reviewer_tip_id} (suggested=${safeBody.suggested_origin})`);
    return { review_id: reviewId, tx_id: tx.tx_id, confirmation: "proposed" };
  }

  function recuse(reviewId, body) {
    const safeBody = { ...(body || {}), review_id: reviewId };
    recusedSchema.validateRequest(safeBody, { dag });

    const reviewer = dag.getIdentity(safeBody.reviewer_tip_id);
    const payload = recusedSchema.buildSigningPayload(safeBody);
    if (!recusedSchema.verifySignature(payload, safeBody.signature, reviewer.public_key)) {
      throw schemaError(403, "Reviewer signature verification failed", "signature_invalid");
    }

    const review = dag.getPrescanReview(reviewId);
    const tx = withTxId({
      tx_type: TX_TYPES.PRESCAN_REVIEW_RECUSED,
      timestamp: nowMs(),
      prev: dag.getRecentPrev(),
      data: {
        review_id: reviewId,
        reviewer_tip_id: safeBody.reviewer_tip_id,
        // #40 — creator sees the recusal on their content; outside signed payload.
        creator_tip_id: review?.creator_tip_id ?? null,
        recusal_reason: safeBody.recusal_reason ?? null,
      },
      signature: safeBody.signature,
    });
    const validation = validateTransaction(tx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(tx);
    log.info(`Review recused: ${reviewId} by ${safeBody.reviewer_tip_id}`);
    return { review_id: reviewId, tx_id: tx.tx_id, confirmation: "proposed" };
  }

  function acceptCorrection(reviewId, body) {
    const { review, content, new_origin_code } =
      acceptCorrectionSchema.validateRequest(reviewId, body, { dag });

    const timestamp = nowMs();
    const updateTx = withTxId({
      tx_type: TX_TYPES.UPDATE_ORIGIN,
      timestamp,
      prev: dag.getRecentPrev(),
      data: {
        ctid: review.ctid,
        old_origin_code: content.origin_code,
        new_origin_code,
        author_tip_id: body.author_tip_id,
      },
      signature: body.signature,
    });

    // Score penalty batched atomically with the origin update. Accepting
    // the reviewer's CONFIRM still costs the creator
    // REVIEWER.ACCEPT_CORRECTION_SCORE_DELTA (a signed-negative integer)
    // — Option 1 is strictly cheaper than letting auto-escalation run
    // the dispute pipeline (OH→AA range -10..-30) but is not free, so
    // the reviewer-was-right outcome carries economic weight.
    const creatorScoreTx = scoring.buildScoreUpdateTx({
      tipId: body.author_tip_id,
      delta: REVIEWER.ACCEPT_CORRECTION_SCORE_DELTA,
      reason: `accept_correction:${reviewId}`,
      ctid: review.ctid,
      relatedTxId: updateTx.tx_id,
      timestamp,
      getRecentPrev: () => dag.getRecentPrev(),
      config,
    });

    // Reviewer's "case closed without dispute" bonus. The creator
    // accepting the CONFIRM is the reviewer's call being validated —
    // settles immediately, no Stage-2 path needed.
    const reviewerScoreTx = scoring.buildScoreUpdateTx({
      tipId: review.assigned_reviewer,
      delta: REVIEWER.CORRECT_BONUS,
      reason: `review_accepted_private:${reviewId}`,
      ctid: review.ctid,
      relatedTxId: updateTx.tx_id,
      timestamp,
      getRecentPrev: () => dag.getRecentPrev(),
      config,
    });

    submitBatch([updateTx, creatorScoreTx, reviewerScoreTx]);
    log.info(`Accept-correction proposed: review=${reviewId} ctid=${review.ctid} ${content.origin_code} → ${new_origin_code} (creator=${REVIEWER.ACCEPT_CORRECTION_SCORE_DELTA}, reviewer=+${REVIEWER.CORRECT_BONUS})`);

    return {
      review_id: reviewId,
      ctid: review.ctid,
      old_origin_code: content.origin_code,
      new_origin_code,
      score_delta: REVIEWER.ACCEPT_CORRECTION_SCORE_DELTA,
      reviewer_bonus: REVIEWER.CORRECT_BONUS,
      tx_id: updateTx.tx_id,
      score_tx_id: creatorScoreTx.tx_id,
      reviewer_score_tx_id: reviewerScoreTx.tx_id,
      confirmation: "proposed",
    };
  }

  /**
   * Creator's Option 2 — manually escalate a CONFIRMED prescan-review
   * to a public dispute, before the h=R+24 auto-escalation trigger
   * would fire. Semantically a fast-forward of the auto-escalation
   * path: produces a CONTENT_DISPUTED tx with `auto: true` +
   * `source_review_id`, plus `escalated_by_tip_id` +
   * `escalation_signature` as audit fields proving the creator
   * authorised the early escalation.
   *
   * The reviewer (review.assigned_reviewer) is the formal disputer on
   * the tx: their CONFIRM was the dispute claim, so they own the
   * disputer seat — same dispute-stake economics as any user-filed
   * dispute. The creator triggers the escalation but doesn't stake;
   * the reviewer's `-DISPUTER_STAKE` is paired with the dispute tx in
   * the same batch (single-channel rule). On Stage-2 verdict the
   * existing jury settlement code handles refund/bonus/forfeit for
   * disputerTipId automatically; a small CORRECT_BONUS overlay
   * (jury.buildAdjudicationBatch) recognises the review work on top.
   */
  function dispute(reviewId, body) {
    const { review, content } = disputeSchema.validateRequest(reviewId, body, { dag });

    const timestamp = nowMs();
    const disputeTx = nodeSignedAuto({
      tx_type: TX_TYPES.CONTENT_DISPUTED,
      timestamp,
      prev: dag.getRecentPrev(),
      data: {
        ctid: review.ctid,
        reason: "creator_disagrees_with_reviewer",
        auto: true,
        // The reviewer is the formal disputer — their CONFIRM is the
        // dispute claim. Same stake-on-file pattern as a user-filed
        // dispute: deducted upfront below, refunded on UPHELD /
        // CONSERVATIVE_LABEL, forfeited on DISMISSED.
        disputer_tip_id: review.assigned_reviewer,
        source_review_id: review.review_id,
        suggested_origin: review.suggested_origin || null,
        // Discriminator + cosignature carrying the creator's
        // authorisation of this manual fast-forward (vs. h=R+24 system
        // auto-escalation, which has no cosignature). Consensus replay
        // resolves the creator's key via dag.getKeyValidAt and verifies
        // the cosig over {author_tip_id, ctid, review_id}.
        escalated_by_tip_id: body.author_tip_id,
        cosignatures: [{
          signer_kind: "subject",
          signer_ref:  body.author_tip_id,
          signature:   body.signature,
        }],
        // Mirror the standard dispute fields so jury / dashboard
        // queries that read declared/claimed don't have to special-case.
        declared_origin: content.origin_code,
        claimed_origin: review.suggested_origin || null,
        pre_dispute_status: content.status,
        author_tip_id: review.creator_tip_id,
        stake: DISPUTE.DISPUTER_STAKE,
      },
    }, config);

    // Reviewer's filing-time stake (escrow). Mirrors what
    // dispute-service.fileDispute does for a user-filed dispute —
    // jury batch later refunds on UPHELD / CONSERVATIVE_LABEL or
    // forfeits on DISMISSED.
    const stakeTx = scoring.buildScoreUpdateTx({
      tipId: review.assigned_reviewer,
      delta: -DISPUTE.DISPUTER_STAKE,
      reason: `Dispute filing stake on ${review.ctid}`,
      ctid: review.ctid,
      relatedTxId: disputeTx.tx_id,
      timestamp,
      getRecentPrev: () => dag.getRecentPrev(),
      config,
    });

    // Stage-2 jury selection + summons. selectJury hard-excludes the
    // author + the disputer (now the reviewer, via the disputer_tip_id
    // field on the tx) + revoked + organizations.
    const jury = selectJury(
      dag, scoring,
      disputeTx.tx_id,
      review.creator_tip_id,        // authorTipId
      review.assigned_reviewer,     // disputerTipId (now formal on tx too)
    );
    if (jury.insufficient) {
      log.warn(`Manual escalation jury: insufficient jurors for ${review.ctid} (${jury.jurors.length}/${JURY.SIZE})`);
    }

    const commitDeadline = nowPlusMs(JURY.COMMIT_WINDOW_HOURS * 3600000);
    const revealDeadline = nowPlusMs((JURY.COMMIT_WINDOW_HOURS + JURY.REVEAL_WINDOW_HOURS) * 3600000);

    const batch = [disputeTx, stakeTx];
    for (const jurorTipId of jury.jurors) {
      const summonsTx = nodeSignedAuto({
        tx_type: TX_TYPES.JURY_SUMMONS,
        timestamp: nowMs(),
        prev: dag.getRecentPrev(),
        data: {
          ctid: review.ctid,
          dispute_tx_id: disputeTx.tx_id,
          juror_tip_id: jurorTipId,
          stake: JURY.JUROR_STAKE,
          seed: jury.seed,
          identity_count: jury.identityCount,
          commit_deadline: commitDeadline,
          reveal_deadline: revealDeadline,
        },
      }, config);
      batch.push(summonsTx);
    }

    submitBatch(batch);
    log.info(`Review manually escalated to dispute: ${reviewId} by ${body.author_tip_id} (${batch.length} txs, ${jury.jurors.length} jurors, reviewer ${review.assigned_reviewer} staked -${DISPUTE.DISPUTER_STAKE})`);
    return {
      review_id: reviewId,
      ctid: review.ctid,
      tx_id: disputeTx.tx_id,
      jurors: jury.jurors,
      jurors_count: jury.jurors.length,
      jurors_insufficient: jury.insufficient,
      commit_deadline: commitDeadline,
      reveal_deadline: revealDeadline,
      confirmation: "proposed",
    };
  }

  function listReviewsByReviewer(reviewerTipId) {
    if (!dag.getIdentity(reviewerTipId)) {
      throw schemaError(404, `Identity not found: ${reviewerTipId}`, "identity_not_found");
    }
    const reviews = dag.getPrescanReviewsByReviewer(reviewerTipId) || [];
    if (reviews.length === 0) {
      return { reviewer_tip_id: reviewerTipId, count: 0, reviews: [] };
    }

    const scoreHistory = scoring ? (scoring.computeScore(reviewerTipId).history || []) : [];

    // Per-review attribution windows: bound each review's dispute-lifecycle
    // deltas by [this.triggered_at_ms, next.triggered_at_ms) so an earlier
    // ESCALATED on the same ctid doesn't capture a later dispute's events.
    const byTimeAsc = [...reviews].sort((a, b) =>
      (a.triggered_at_ms ?? 0) - (b.triggered_at_ms ?? 0)
    );

    const projected = byTimeAsc.map((review, ix) => {
      const next = byTimeAsc[ix + 1];
      const winStartMs = review.triggered_at_ms ?? 0;
      const winEndMs = next?.triggered_at_ms ?? Number.POSITIVE_INFINITY;

      const isEscalated = review.state === PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE;
      const score_deltas = scoreHistory
        .filter(h => _matchesReview(h, review, winStartMs, winEndMs, isEscalated))
        .map(h => ({
          tx_id: h.tx_id, delta: h.delta, score_after: h.score_after,
          reason: h.reason, timestamp: h.timestamp,
        }));
      const net_score_impact = score_deltas.reduce((s, d) => s + d.delta, 0);

      const dispute = isEscalated
        ? _projectDispute(review, reviewerTipId, winStartMs, winEndMs)
        : null;

      return {
        review_id: review.review_id,
        ctid: review.ctid,
        creator_tip_id: review.creator_tip_id,
        state: review.state,
        outcome: OUTCOME_LABELS[review.state] || review.state.toUpperCase(),
        triggered_at_round: review.triggered_at_round,
        triggered_at_ms: review.triggered_at_ms,
        decided_at_round: review.decided_at_round,
        confirmed_at_round: review.confirmed_at_round,
        confirmed_at_ms: review.confirmed_at_ms,
        decision_note: review.decision_note,
        suggested_origin: review.suggested_origin,
        dispute,
        score_deltas,
        net_score_impact,
      };
    });

    projected.reverse();
    return { reviewer_tip_id: reviewerTipId, count: projected.length, reviews: projected };
  }

  function _projectDispute(review, reviewerTipId, winStartMs, winEndMs) {
    const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, review.ctid)
      .filter(t => t.data?.disputer_tip_id === reviewerTipId)
      .filter(t => {
        const ts = t.timestamp;
        return ts >= winStartMs && ts < winEndMs;
      })
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const disputeTx = disputeTxs[0];
    if (!disputeTx) return null;

    const after = (tx) => tx.timestamp > disputeTx.timestamp && tx.timestamp < winEndMs;
    const adjudication = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, review.ctid)
      .filter(after).sort((a, b) => a.timestamp.localeCompare(b.timestamp))[0];
    const appeal = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_RESULT, review.ctid)
      .filter(after).sort((a, b) => a.timestamp.localeCompare(b.timestamp))[0];

    return {
      dispute_tx_id: disputeTx.tx_id,
      filed_at: disputeTx.timestamp,
      stage2_verdict: adjudication?.data?.verdict ?? null,
      stage2_resolved_at: adjudication?.timestamp ?? null,
      stage3_verdict: appeal?.data?.verdict ?? null,
      stage3_overturned: appeal?.data?.overturned ?? null,
      stage3_resolved_at: appeal?.timestamp ?? null,
    };
  }

  /**
   * Debug / ops projection: every identity that currently passes
   * isEligibleReviewer (Pass 1 strict: consent + score ≥ MIN_SCORE +
   * not revoked + accuracy ≥ 1 − MAX_OVERTURN_RATE). selectReviewer
   * adds cascade passes on top — this view shows ONLY who would land
   * in Pass 1 as of the current DAG state. Read-only; no DAG writes.
   *
   * Author-exclusion isn't applied — that's per-review, not a property
   * of the pool. Callers comparing this to a specific review's
   * selection should pass authorTipId to selectReviewer instead.
   */
  function listReviewerPool() {
    if (!scoring) {
      throw schemaError(500, "scoring engine not wired", "scoring_unavailable");
    }
    const rows = [];
    for (const identity of dag.getAllIdentities()) {
      if (!isEligibleReviewer(dag, scoring, identity.tip_id)) continue;
      rows.push({
        tip_id: identity.tip_id,
        region: identity.region,
        score: scoring.getScore(identity.tip_id).score,
        accuracy: getReviewerAccuracy(dag, identity.tip_id),
      });
    }
    rows.sort((a, b) => a.tip_id.localeCompare(b.tip_id));
    return { pool: rows, count: rows.length };
  }

  return { getReview, dismiss, confirm, recuse, acceptCorrection, dispute, listReviewerPool, listReviewsByReviewer };
}

module.exports = { createReviewService };
