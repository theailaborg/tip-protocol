/**
 * @file @tip-protocol/node/src/reviewer-selection.js
 * @description Deterministic reviewer selection for the prescan-review
 * pipeline. Mirrors `jury.selectJury` but for a single reviewer assigned
 * to a flagged-content review at h=48.
 *
 * Why runtime (not a registry tx): the design decision (Phase 5 of the
 * locked plan) is that reviewer eligibility is a pure function of DAG
 * state — opt-in via `UPDATE_PROFILE { reviewer_consent: true }`,
 * filtered by score / not-author / not-revoked / past-accuracy at
 * selection time. A reviewer whose accuracy drops below the threshold
 * is silently excluded from future pools until it recovers; no
 * "revocation" tx is needed.
 *
 * Determinism: every node running the same DAG state + same
 * (review_id, ctid, round) seed picks the same reviewer. That's the
 * BFT property the scheduler relies on when emitting
 * `PRESCAN_REVIEW_TRIGGERED` with `assigned_reviewer_tip_id`.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256 } = require("../../shared/crypto");
const { TX_TYPES, VERDICT, PRESCAN_REVIEW_STATES, TIP_ID_TYPES } = require("../../shared/constants");
const { REVIEWER, JURY } = require("../../shared/protocol-constants");

/**
 * Deterministic seeded shuffle (Fisher-Yates with seed bytes instead of
 * Math.random). Same seed → same shuffle on any machine. Duplicated from
 * jury.js intentionally — extracting a shared util would couple two
 * otherwise-independent selection paths.
 */
function _seededShuffle(arr, seedHex) {
  const seedBytes = Buffer.from(seedHex, "hex");
  const shuffled = [...arr];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = seedBytes[i % seedBytes.length] % (i + 1);
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

/**
 * Compute a reviewer's accuracy from their past decisions on the DAG.
 *
 * Only decisions with a *determinable* outcome are scored. The outcome
 * for a CLOSED_DISMISSED or ESCALATED_TO_DISPUTE review is the
 * ADJUDICATION_RESULT verdict on the same ctid; CLOSED_ACCEPTED_PRIVATE
 * is always a "reviewer was right" because the creator accepted the
 * correction. Decisions without an outcome yet (e.g. a recently
 * CLOSED_DISMISSED review where no dispute has happened) are skipped —
 * they don't count for or against accuracy until the pipeline
 * resolves.
 *
 * No data: returns 1.0 (benefit of the doubt). This is the only path
 * by which a brand-new opted-in reviewer can get their first
 * assignment.
 *
 * Counts most-recent ACCURACY_SAMPLE_SIZE decisions (older decisions
 * shouldn't penalize an improving reviewer indefinitely).
 */
function getReviewerAccuracy(dag, reviewerTipId) {
  const decisions = dag.getPrescanReviewsByReviewer(reviewerTipId) || [];
  if (decisions.length === 0) return 1.0;

  let evaluated = 0;
  let correct = 0;

  for (const review of decisions) {
    if (evaluated >= REVIEWER.ACCURACY_SAMPLE_SIZE) break;

    if (review.state === PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE) {
      evaluated++;
      correct++;
      continue;
    }

    if (review.state !== PRESCAN_REVIEW_STATES.CLOSED_DISMISSED
      && review.state !== PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE) {
      continue;
    }

    const adjTxs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, review.ctid);
    const verdict = adjTxs[0]?.data?.verdict;
    if (!verdict) continue;

    evaluated++;

    if (review.state === PRESCAN_REVIEW_STATES.CLOSED_DISMISSED) {
      if (verdict === VERDICT.DISMISSED) correct++;
    } else {
      if (verdict === VERDICT.UPHELD || verdict === VERDICT.CONSERVATIVE_LABEL) correct++;
    }
  }

  if (evaluated === 0) return 1.0;
  return correct / evaluated;
}

/**
 * True iff `tipId` can be assigned to review `authorTipId`'s flagged
 * content. Checks are ordered cheapest → most-expensive so the common
 * "not opted-in" case short-circuits before any score / accuracy work.
 */
function isEligibleReviewer(dag, scoring, tipId, { authorTipId } = {}) {
  if (!tipId) return false;
  if (authorTipId && tipId === authorTipId) return false;

  const identity = dag.getIdentity(tipId);
  if (!identity) return false;

  // Organization identities never adjudicate. Reviewer / juror / expert
  // roles require a human judgment call ("does this look AI-generated?",
  // "did this dispute have merit?"); orgs are entities (companies, AI
  // tools, services) and the protocol explicitly excludes them from
  // any adjudication seat. tip_id_type defaults to "personal" for any
  // pre-tip_id_type-field identity (back-compat default applied at the
  // DB level), so missing values are treated as personal.
  const tipIdType = identity.tip_id_type || TIP_ID_TYPES.PERSONAL;
  if (tipIdType !== TIP_ID_TYPES.PERSONAL) return false;

  const consent = identity.reviewer_consent;
  if (consent !== true && consent !== 1) return false;

  if (typeof dag.isRevoked === "function" && dag.isRevoked(tipId)) return false;

  const score = scoring.getScore(tipId).score;
  if (score < REVIEWER.MIN_SCORE) return false;

  const minAccuracy = 1 - REVIEWER.MAX_OVERTURN_RATE;
  if (getReviewerAccuracy(dag, tipId) < minAccuracy) return false;

  return true;
}

/**
 * Deterministically select a single reviewer for a flagged-content
 * review. Seed = shake256(review_id : round : ctid) — round binds the
 * selection to a specific point in time so a re-trigger at a later
 * round gets a different reviewer.
 *
 * Cascade (mirrors jury._pickWithGeoCap):
 *   Pass 1 — strict: score ≥ REVIEWER.MIN_SCORE AND accuracy ≥
 *            (1 − MAX_OVERTURN_RATE)
 *   Pass 2 — accuracy gate relaxed: score ≥ REVIEWER.MIN_SCORE
 *   Pass 3 — score floor lowered to JURY.MIN_SCORE_FALLBACK
 *            (VERIFIED-tier ultimate floor, shared with jury cascade)
 *
 * Hard excludes (author, no-consent, revoked, unknown identity) apply
 * to every pass — those are security invariants, not preferences.
 * Score and accuracy are soft preferences relaxed in order so a thin
 * eligible pool doesn't stall the review pipeline indefinitely. If
 * even Pass 3 is empty, the assignment is unfilled (`reviewer: null`)
 * and the scheduler retries on the next tick.
 *
 * @returns {{ reviewer: string|null, seed: string, poolSize: number, pass: number }}
 *   `pass` is 0 when no candidate exists at any floor.
 */
function selectReviewer(dag, scoring, { reviewId, ctid, round, authorTipId }) {
  if (!reviewId || !ctid || typeof round !== "number") {
    throw new Error("selectReviewer requires { reviewId, ctid, round }");
  }

  const seed = shake256(`${reviewId}:${round}:${ctid}`);

  const baseline = dag.getAllIdentities()
    .filter(id => _passesHardFilters(dag, id, authorTipId))
    .map(id => ({ ...id, score: scoring.getScore(id.tip_id).score }))
    .sort((a, b) => (a.tip_id < b.tip_id ? -1 : a.tip_id > b.tip_id ? 1 : 0)); // binary, not locale: selection must be identical on every node

  if (baseline.length === 0) {
    return { reviewer: null, seed, poolSize: 0, pass: 0 };
  }

  const minAccuracy = 1 - REVIEWER.MAX_OVERTURN_RATE;

  const pass1 = baseline.filter(c =>
    c.score >= REVIEWER.MIN_SCORE
    && getReviewerAccuracy(dag, c.tip_id) >= minAccuracy);
  if (pass1.length > 0) return _pickFromShuffle(pass1, seed, 1);

  const pass2 = baseline.filter(c => c.score >= REVIEWER.MIN_SCORE);
  if (pass2.length > 0) return _pickFromShuffle(pass2, seed, 2);

  const pass3 = baseline.filter(c => c.score >= JURY.MIN_SCORE_FALLBACK);
  if (pass3.length > 0) return _pickFromShuffle(pass3, seed, 3);

  return { reviewer: null, seed, poolSize: 0, pass: 0 };
}

function _passesHardFilters(dag, identity, authorTipId) {
  if (!identity || !identity.tip_id) return false;
  if (authorTipId && identity.tip_id === authorTipId) return false;
  // Orgs are never eligible for adjudication — see isEligibleReviewer.
  const tipIdType = identity.tip_id_type || TIP_ID_TYPES.PERSONAL;
  if (tipIdType !== TIP_ID_TYPES.PERSONAL) return false;
  const consent = identity.reviewer_consent;
  if (consent !== true && consent !== 1) return false;
  if (typeof dag.isRevoked === "function" && dag.isRevoked(identity.tip_id)) return false;
  return true;
}

function _pickFromShuffle(candidates, seed, pass) {
  const shuffled = _seededShuffle(candidates, seed);
  return { reviewer: shuffled[0].tip_id, seed, poolSize: candidates.length, pass };
}

module.exports = {
  isEligibleReviewer,
  getReviewerAccuracy,
  selectReviewer,
};
