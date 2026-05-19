/**
 * @file tests/scoring/reviewer-payment.test.js
 * @description Score effects for the Phase-5 pre-scan reviewer. The
 * reviewer's CONFIRM is functionally a dispute filing on behalf of the
 * system, so they ride the disputer's settlement matrix at Stage-2 +
 * a fixed REVIEWER.CORRECT_BONUS for the review work itself:
 *
 *   UPHELD             → +UPHELD_BONUS + CORRECT_BONUS  (jury agreed)
 *   CONSERVATIVE_LABEL → +CORRECT_BONUS                  (neutral)
 *   DISMISSED          → -DISPUTER_STAKE                 (overturned)
 *
 * Stage-3 appeal overturns reverse the Stage-2 reviewer settlement and
 * apply a fresh Stage-3-based one, same pattern as disputer / author
 * reversals.
 *
 * Closed-path emissions (no public dispute):
 *
 *   PRESCAN_REVIEW_DISMISSED  → +CORRECT_BONUS (paired with DISMISSED tx
 *                               in review-service.dismiss)
 *   accept-correction         → +CORRECT_BONUS (paired with UPDATE_ORIGIN
 *                               in review-service.acceptCorrection)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256, computeTxId,
} = require(path.join(SHARED, "crypto"));
const {
  TX_TYPES, ORIGIN, VOTE, VERDICT, CONTENT_STATUS, PRESCAN_REVIEW_STATES,
} = require(path.join(SHARED, "constants"));
const { DISPUTE, JURY, REVIEWER } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { buildAdjudicationBatch, buildAppealBatch } = require(path.join(SRC, "jury"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/test";
const CTID = "tip://c/OH-rrrrrrrrrrrrrr-1111";
const REVIEW_ID = "pr_reviewer_payment_test";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  dag.saveVP({
    vp_id: VP_ID, name: "vp1", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
  };
  return { dag, config, scoring: initScoring(dag, config) };
}

function _addTx(dag, body) {
  const tx = { ...body };
  if (!tx.prev) tx.prev = [];
  tx.tx_id = computeTxId(tx);
  dag.addTx(tx);
  return tx;
}

function _seedIdentity(dag, tipId, score = 750) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${tipId}`),
  });
  dag.setScore(tipId, score, 0, "2026-01-01T00:00:00.000Z");
}

/**
 * Seed a full dispute fixture optionally preceded by a CONFIRMED
 * prescan-review escalation. Returns identifiers + summons array.
 */
function _seedDispute(dag, { withReviewerEscalation = true, declaredOrigin = ORIGIN.OH, claimedOrigin = ORIGIN.AG } = {}) {
  const authorTipId = "tip://id/author";
  const disputerTipId = "tip://id/disputer";
  const reviewerTipId = "tip://id/reviewer";
  _seedIdentity(dag, authorTipId, 600);
  _seedIdentity(dag, disputerTipId, 800);
  _seedIdentity(dag, reviewerTipId, 800);

  dag.saveContent({
    ctid: CTID, origin_code: declaredOrigin, content_hash: "00",
    author_tip_id: authorTipId, status: CONTENT_STATUS.DISPUTED,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: "00",
  });

  if (withReviewerEscalation) {
    dag.savePrescanReview({
      review_id: REVIEW_ID, ctid: CTID, creator_tip_id: authorTipId,
      assigned_reviewer: reviewerTipId, triggered_at_round: 1,
      decided_at_round: 2, confirmed_at_round: 2, confirmed_at_ms: Date.now(),
      state: PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE,
      suggested_origin: claimedOrigin, decision_note: "looks like AI",
    });
  }

  const disputeTx = _addTx(dag, {
    tx_type: TX_TYPES.CONTENT_DISPUTED, timestamp: "2026-04-01T00:00:00.000Z",
    data: {
      ctid: CTID, disputer_tip_id: disputerTipId, reason: "origin_mismatch",
      claimed_origin: claimedOrigin, declared_origin: declaredOrigin,
      author_tip_id: authorTipId, pre_dispute_status: CONTENT_STATUS.REGISTERED,
      stake: DISPUTE.DISPUTER_STAKE,
    },
  });

  const summons = [];
  const jurors = [];
  for (let i = 0; i < 7; i++) {
    const j = `tip://id/juror-${i}`;
    _seedIdentity(dag, j, 750);
    jurors.push(j);
    summons.push(_addTx(dag, {
      tx_type: TX_TYPES.JURY_SUMMONS,
      timestamp: `2026-04-01T00:00:0${i % 10}.${(100 + i).toString().padStart(3, "0")}Z`,
      data: {
        ctid: CTID, dispute_tx_id: disputeTx.tx_id, juror_tip_id: j,
        stake: JURY.JUROR_STAKE, seed: shake256("seed"), identity_count: 7,
        commit_deadline: "2030-01-01T00:00:00.000Z",
        reveal_deadline: "2030-01-01T00:00:00.000Z",
      },
    }));
  }

  return { authorTipId, disputerTipId, reviewerTipId, jurors, summons, disputeTx };
}

function _buildReveals(jurors, votes, confirmedOrigin = ORIGIN.AG) {
  return jurors.slice(0, votes.length).map((j, i) => ({
    tx_id: shake256(`reveal-${i}-${votes[i]}`),
    tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: "2026-04-02T00:00:00.000Z",
    data: {
      ctid: CTID, juror_tip_id: j, vote: votes[i],
      salt: shake256(`s${i}`), confirmed_origin: confirmedOrigin,
    },
  }));
}

function _scoreUpdatesFor(txs, tipId) {
  return txs.filter(t => t.tx_type === TX_TYPES.SCORE_UPDATE && t.data?.tip_id === tipId);
}

// ─── Genesis constant ───────────────────────────────────────────────────────

describe("reviewer payment — genesis constant", () => {
  test("REVIEWER.CORRECT_BONUS = 5", () => {
    expect(REVIEWER.CORRECT_BONUS).toBe(5);
  });
});

// ─── Closed-path emissions (no public dispute fired) ────────────────────────

describe("PRESCAN_REVIEW_DISMISSED → reviewer paired bonus", () => {

  function _seedDismissFixture(fx, { reviewState = PRESCAN_REVIEW_STATES.TRIGGERED } = {}) {
    const reviewerKp = generateMLDSAKeypair();
    const reviewerTipId = "tip://id/US-aaaaaaaaaaaaaaaa";
    fx.dag.saveIdentity({
      tip_id: reviewerTipId, region: "US",
      public_key: reviewerKp.publicKey, root_public_key: reviewerKp.publicKey,
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      reviewer_consent: true,
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${reviewerTipId}`),
    });
    fx.dag.setScore(reviewerTipId, 800, 0, "2026-01-01T00:00:00.000Z");
    fx.dag.saveContent({
      ctid: CTID, origin_code: ORIGIN.OH, content_hash: "00",
      author_tip_id: "tip://id/some-author", status: CONTENT_STATUS.PENDING_REVIEW,
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: "00",
    });
    fx.dag.savePrescanReview({
      review_id: REVIEW_ID, ctid: CTID, creator_tip_id: "tip://id/some-author",
      assigned_reviewer: reviewerTipId, triggered_at_round: 1,
      state: reviewState,
    });
    return { reviewerKp, reviewerTipId };
  }

  test("dismiss emits a paired +CORRECT_BONUS SCORE_UPDATE to the reviewer", () => {
    const fx = _setup();
    const { reviewerKp, reviewerTipId } = _seedDismissFixture(fx);

    const submitted = [];
    const { createReviewService } = require(path.join(SRC, "services", "review-service"));
    const service = createReviewService({
      dag: fx.dag, scoring: fx.scoring, config: fx.config,
      submitTx: t => submitted.push(t),
      submitBatch: ts => ts.forEach(t => submitted.push(t)),
    });

    const dismissedSchema = require(path.join(SRC, "schemas", "prescan-review-dismissed"));
    const payload = dismissedSchema.buildSigningPayload({
      review_id: REVIEW_ID, reviewer_tip_id: reviewerTipId, decision_note: "ok",
    });
    const signature = dismissedSchema.sign(payload, reviewerKp.privateKey);

    service.dismiss(REVIEW_ID, {
      reviewer_tip_id: reviewerTipId, decision_note: "ok", signature,
    });

    const reviewerSU = submitted.find(
      t => t.tx_type === TX_TYPES.SCORE_UPDATE && t.data.tip_id === reviewerTipId,
    );
    expect(reviewerSU).toBeDefined();
    expect(reviewerSU.data.delta).toBe(REVIEWER.CORRECT_BONUS);
    expect(reviewerSU.data.delta).toBe(5);
    expect(reviewerSU.data.reason).toBe(`review_dismissed:${REVIEW_ID}`);
    expect(reviewerSU.data.ctid).toBe(CTID);
  });
});

// ─── Accept-private (creator agreed with CONFIRM) ────────────────────────────

describe("acceptCorrection → reviewer paired bonus", () => {

  test("accept-private emits a +CORRECT_BONUS SCORE_UPDATE to the reviewer (atomic with the creator's -10)", () => {
    const fx = _setup();
    const creatorKp = generateMLDSAKeypair();
    const creatorTipId = "tip://id/creator-accept";
    const reviewerTipId = "tip://id/reviewer-accept";
    fx.dag.saveIdentity({
      tip_id: creatorTipId, region: "US",
      public_key: creatorKp.publicKey, root_public_key: creatorKp.publicKey,
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${creatorTipId}`),
    });
    fx.dag.setScore(creatorTipId, 700, 0, "2026-01-01T00:00:00.000Z");
    _seedIdentity(fx.dag, reviewerTipId, 800);
    fx.dag.saveContent({
      ctid: CTID, origin_code: ORIGIN.OH, content_hash: "00",
      author_tip_id: creatorTipId, status: CONTENT_STATUS.PENDING_REVIEW,
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: "00",
    });
    fx.dag.savePrescanReview({
      review_id: REVIEW_ID, ctid: CTID, creator_tip_id: creatorTipId,
      assigned_reviewer: reviewerTipId, triggered_at_round: 1,
      decided_at_round: 2, confirmed_at_round: 2, confirmed_at_ms: Date.now(),
      state: PRESCAN_REVIEW_STATES.CONFIRMED, suggested_origin: "AG",
    });

    const submitted = [];
    const { createReviewService } = require(path.join(SRC, "services", "review-service"));
    const service = createReviewService({
      dag: fx.dag, scoring: fx.scoring, config: fx.config,
      submitTx: t => submitted.push(t),
      submitBatch: ts => ts.forEach(t => submitted.push(t)),
    });

    const { signBody } = require(path.join(SHARED, "crypto"));
    const signature = signBody(
      { author_tip_id: creatorTipId, ctid: CTID, new_origin_code: "AG" },
      creatorKp.privateKey,
    );

    service.acceptCorrection(REVIEW_ID, {
      author_tip_id: creatorTipId, new_origin_code: "AG", signature,
    });

    const reviewerSU = submitted.find(
      t => t.tx_type === TX_TYPES.SCORE_UPDATE && t.data.tip_id === reviewerTipId,
    );
    expect(reviewerSU).toBeDefined();
    expect(reviewerSU.data.delta).toBe(REVIEWER.CORRECT_BONUS);
    expect(reviewerSU.data.delta).toBe(5);
    expect(reviewerSU.data.reason).toBe(`review_accepted_private:${REVIEW_ID}`);
    expect(reviewerSU.data.ctid).toBe(CTID);

    // Sanity: creator's paired penalty also lands in the same batch.
    const creatorSU = submitted.find(
      t => t.tx_type === TX_TYPES.SCORE_UPDATE && t.data.tip_id === creatorTipId,
    );
    expect(creatorSU).toBeDefined();
    expect(creatorSU.data.delta).toBe(REVIEWER.ACCEPT_CORRECTION_SCORE_DELTA);
    expect(creatorSU.data.delta).toBeLessThan(0);
  });
});

// ─── Stage-2 verdict-driven reviewer settlement ─────────────────────────────

describe("Stage-2 verdict — reviewer settlement (CONFIRMED review escalated to dispute)", () => {

  test("UPHELD → reviewer gets +UPHELD_BONUS + CORRECT_BONUS", () => {
    const fx = _setup();
    const ids = _seedDispute(fx.dag);
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(1);
    expect(reviewerSU[0].data.delta).toBe(DISPUTE.UPHELD_BONUS + REVIEWER.CORRECT_BONUS);
    expect(reviewerSU[0].data.delta).toBe(10);
    expect(reviewerSU[0].data.reason).toBe(`review_won:${REVIEW_ID}`);
    expect(reviewerSU[0].data.ctid).toBe(CTID);
  });

  test("CONSERVATIVE_LABEL → reviewer gets +CORRECT_BONUS only", () => {
    const fx = _setup();
    const ids = _seedDispute(fx.dag, {
      declaredOrigin: ORIGIN.AG, claimedOrigin: ORIGIN.OH,
    });
    // 5 MISMATCH + confirmed_origin = OH → CONSERVATIVE_LABEL (AG declared, OH confirmed)
    const reveals = ids.jurors.slice(0, 7).map((j, i) => ({
      tx_id: shake256(`r-cl-${i}`), tx_type: TX_TYPES.JURY_VOTE_REVEAL,
      timestamp: "2026-04-02T00:00:00.000Z",
      data: {
        ctid: CTID, juror_tip_id: j,
        vote: i < 5 ? VOTE.MISMATCH : VOTE.MATCH,
        salt: shake256(`s${i}`), confirmed_origin: ORIGIN.OH,
      },
    }));

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.CONSERVATIVE_LABEL);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(1);
    expect(reviewerSU[0].data.delta).toBe(REVIEWER.CORRECT_BONUS);
    expect(reviewerSU[0].data.delta).toBe(5);
    expect(reviewerSU[0].data.reason).toBe(`review_conservative:${REVIEW_ID}`);
  });

  test("DISMISSED → reviewer takes -DISPUTER_STAKE (full overturn cost)", () => {
    const fx = _setup();
    const ids = _seedDispute(fx.dag);
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(1);
    expect(reviewerSU[0].data.delta).toBe(-DISPUTE.DISPUTER_STAKE);
    expect(reviewerSU[0].data.delta).toBe(-15);
    expect(reviewerSU[0].data.reason).toBe(`review_overturned:${REVIEW_ID}`);
  });

  test("no prior CONFIRMED prescan_review → no reviewer payment (regression guard)", () => {
    const fx = _setup();
    const ids = _seedDispute(fx.dag, { withReviewerEscalation: false });
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);

    // No prescan_review row → reviewer is not even seeded as a tip_id
    // that could receive a SCORE_UPDATE. Filter all SCORE_UPDATE txs and
    // confirm none target a "reviewer" identity.
    const allSUs = out.txs.filter(t => t.tx_type === TX_TYPES.SCORE_UPDATE);
    const reviewerSUs = allSUs.filter(t => t.data?.reason?.startsWith("review_"));
    expect(reviewerSUs).toHaveLength(0);
  });
});

// ─── Stage-3 appeal — reversal of Stage-2 reviewer settlement ───────────────

describe("Stage-3 appeal overturn — reviewer settlement reversal", () => {

  function _seedAppealFixture(dag, stage2Verdict, { declaredOrigin = ORIGIN.OH, claimedOrigin = ORIGIN.AG } = {}) {
    const ids = _seedDispute(dag, { declaredOrigin, claimedOrigin });

    const adjudicationTx = _addTx(dag, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: "2026-04-03T00:00:00.000Z",
      data: {
        ctid: CTID, verdict: stage2Verdict,
        declared_origin: declaredOrigin, confirmed_origin: claimedOrigin,
        author_tip_id: ids.authorTipId, disputer_tip_id: ids.disputerTipId,
        author_score_delta: stage2Verdict === VERDICT.UPHELD ? -100 : 0,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
        reason: "origin_mismatch",
      },
    });

    const appealantTipId = stage2Verdict === VERDICT.UPHELD ? ids.authorTipId : ids.disputerTipId;
    _addTx(dag, {
      tx_type: TX_TYPES.APPEAL_FILED,
      timestamp: "2026-04-04T00:00:00.000Z",
      data: { ctid: CTID, appellant_tip_id: appealantTipId },
    });

    const expertSummons = [];
    const experts = [];
    for (let i = 0; i < 3; i++) {
      const e = `tip://id/expert-${i}`;
      _seedIdentity(dag, e, 900);
      experts.push(e);
      expertSummons.push(_addTx(dag, {
        tx_type: TX_TYPES.JURY_SUMMONS,
        timestamp: `2026-04-04T01:00:0${i}.000Z`,
        data: {
          ctid: CTID, dispute_tx_id: adjudicationTx.tx_id, juror_tip_id: e,
          is_appeal: true, stake: JURY.JUROR_STAKE,
          seed: shake256("expert-seed"), identity_count: 3,
          commit_deadline: "2030-01-01T00:00:00.000Z",
          reveal_deadline: "2030-01-01T00:00:00.000Z",
        },
      }));
    }
    return { ...ids, experts, expertSummons };
  }

  function _buildExpertReveals(experts, votes, confirmedOrigin = ORIGIN.AG) {
    return experts.slice(0, votes.length).map((e, i) => ({
      tx_id: shake256(`e-reveal-${i}-${votes[i]}`),
      tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: "2026-04-05T00:00:00.000Z",
      data: {
        ctid: CTID, juror_tip_id: e, vote: votes[i], is_appeal: true,
        salt: shake256(`es${i}`), confirmed_origin: confirmedOrigin,
      },
    }));
  }

  test("Stage-2 UPHELD → Stage-3 DISMISSED: reverse +10, apply -15 fresh", () => {
    const fx = _setup();
    const ids = _seedAppealFixture(fx.dag, VERDICT.UPHELD);
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);
    expect(out.overturned).toBe(true);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    // Expected: -(+10) reversal + (-15) fresh = two events.
    expect(reviewerSU).toHaveLength(2);
    const reversal = reviewerSU.find(t => t.data.reason.includes("reversed"));
    expect(reversal).toBeDefined();
    expect(reversal.data.delta).toBe(-(DISPUTE.UPHELD_BONUS + REVIEWER.CORRECT_BONUS));
    expect(reversal.data.delta).toBe(-10);
    const fresh = reviewerSU.find(t => t.data.reason === `review_overturned_on_appeal:${REVIEW_ID}`);
    expect(fresh).toBeDefined();
    expect(fresh.data.delta).toBe(-DISPUTE.DISPUTER_STAKE);
    expect(fresh.data.delta).toBe(-15);
  });

  test("Stage-2 DISMISSED → Stage-3 UPHELD: reverse -15, apply +10 fresh", () => {
    const fx = _setup();
    const ids = _seedAppealFixture(fx.dag, VERDICT.DISMISSED);
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);
    expect(out.overturned).toBe(true);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(2);
    const reversal = reviewerSU.find(t => t.data.reason.includes("reversed"));
    expect(reversal).toBeDefined();
    expect(reversal.data.delta).toBe(DISPUTE.DISPUTER_STAKE);
    expect(reversal.data.delta).toBe(15);
    const fresh = reviewerSU.find(t => t.data.reason === `review_won_on_appeal:${REVIEW_ID}`);
    expect(fresh).toBeDefined();
    expect(fresh.data.delta).toBe(DISPUTE.UPHELD_BONUS + REVIEWER.CORRECT_BONUS);
    expect(fresh.data.delta).toBe(10);
  });

  test("Stage-2 UPHELD → Stage-3 UPHELD (confirm, not overturn) → no reviewer events", () => {
    const fx = _setup();
    const ids = _seedAppealFixture(fx.dag, VERDICT.UPHELD);
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);
    expect(out.overturned).toBe(false);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    // No new event — Stage-2 reviewer payment stands.
    expect(reviewerSU).toHaveLength(0);
  });

  test("Stage-2 DISMISSED → Stage-3 DISMISSED (confirm, not overturn) → no reviewer events", () => {
    const fx = _setup();
    const ids = _seedAppealFixture(fx.dag, VERDICT.DISMISSED);
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);
    expect(out.overturned).toBe(false);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    // No new event — Stage-2 reviewer payment (-15) stands.
    expect(reviewerSU).toHaveLength(0);
  });

  test("Stage-3 overturn with NO prior CONFIRMED review → no reviewer event (regression)", () => {
    const fx = _setup();
    // _seedAppealFixture seeds the prescan_review by default — we
    // need to clear it. Reuse the helper then delete the row.
    const ids = _seedAppealFixture(fx.dag, VERDICT.UPHELD);
    // Remove the escalated review row to simulate a dispute filed
    // without a prior prescan-review chain.
    fx.dag.savePrescanReview({
      review_id: REVIEW_ID, ctid: CTID, creator_tip_id: ids.authorTipId,
      assigned_reviewer: ids.reviewerTipId, triggered_at_round: 1,
      state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,  // not "escalated_to_dispute"
    });
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);
    expect(out.overturned).toBe(true);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(0);
  });
});

// ─── Stage-2 NO_QUORUM → Stage-3 first-authoritative-verdict reviewer payment ─

describe("Stage-3 settlement on Stage-2 NO_QUORUM — reviewer first-verdict payment", () => {

  function _seedNoQuorumAppeal(dag, { declaredOrigin = ORIGIN.OH, claimedOrigin = ORIGIN.AG } = {}) {
    const ids = _seedDispute(dag, { declaredOrigin, claimedOrigin });

    // Seed Stage-2 verdict as NO_QUORUM (auto-escalation will produce the
    // Stage-3 settlement). author_score_delta=0 because no penalty fired
    // at Stage-2.
    const adjudicationTx = _addTx(dag, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: "2026-04-03T00:00:00.000Z",
      data: {
        ctid: CTID, verdict: VERDICT.NO_QUORUM,
        declared_origin: declaredOrigin, confirmed_origin: null,
        author_tip_id: ids.authorTipId, disputer_tip_id: ids.disputerTipId,
        author_score_delta: 0,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
        reason: "origin_mismatch",
      },
    });

    // SYSTEM_AUTO_ESCALATION appellant — the node, not a real party.
    _addTx(dag, {
      tx_type: TX_TYPES.APPEAL_FILED,
      timestamp: "2026-04-04T00:00:00.000Z",
      data: { ctid: CTID, appellant_tip_id: "SYSTEM_AUTO_ESCALATION" },
    });

    const expertSummons = [];
    const experts = [];
    for (let i = 0; i < 3; i++) {
      const e = `tip://id/nq-expert-${i}`;
      _seedIdentity(dag, e, 900);
      experts.push(e);
      expertSummons.push(_addTx(dag, {
        tx_type: TX_TYPES.JURY_SUMMONS,
        timestamp: `2026-04-04T01:00:0${i}.000Z`,
        data: {
          ctid: CTID, dispute_tx_id: adjudicationTx.tx_id, juror_tip_id: e,
          is_appeal: true, stake: JURY.JUROR_STAKE,
          seed: shake256("nq-expert-seed"), identity_count: 3,
          commit_deadline: "2030-01-01T00:00:00.000Z",
          reveal_deadline: "2030-01-01T00:00:00.000Z",
        },
      }));
    }
    return { ...ids, experts, expertSummons };
  }

  function _buildExpertReveals(experts, votes, confirmedOrigin = ORIGIN.AG) {
    return experts.slice(0, votes.length).map((e, i) => ({
      tx_id: shake256(`nq-reveal-${i}-${votes[i]}`),
      tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: "2026-04-05T00:00:00.000Z",
      data: {
        ctid: CTID, juror_tip_id: e, vote: votes[i], is_appeal: true,
        salt: shake256(`nqs${i}`), confirmed_origin: confirmedOrigin,
      },
    }));
  }

  test("NO_QUORUM → Stage-3 UPHELD: reviewer gets +UPHELD_BONUS + CORRECT_BONUS (no Stage-2 reversal needed)", () => {
    const fx = _setup();
    const ids = _seedNoQuorumAppeal(fx.dag);
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(1);
    expect(reviewerSU[0].data.delta).toBe(DISPUTE.UPHELD_BONUS + REVIEWER.CORRECT_BONUS);
    expect(reviewerSU[0].data.delta).toBe(10);
    expect(reviewerSU[0].data.reason).toBe(`review_won_no_quorum:${REVIEW_ID}`);
  });

  test("NO_QUORUM → Stage-3 CONSERVATIVE_LABEL: reviewer gets +CORRECT_BONUS only", () => {
    const fx = _setup();
    const ids = _seedNoQuorumAppeal(fx.dag, {
      declaredOrigin: ORIGIN.AG, claimedOrigin: ORIGIN.OH,
    });
    const reveals = ids.experts.slice(0, 3).map((e, i) => ({
      tx_id: shake256(`nq-cl-${i}`), tx_type: TX_TYPES.JURY_VOTE_REVEAL,
      timestamp: "2026-04-05T00:00:00.000Z",
      data: {
        ctid: CTID, juror_tip_id: e, is_appeal: true,
        vote: i < 2 ? VOTE.MISMATCH : VOTE.MATCH,
        salt: shake256(`nqcl${i}`), confirmed_origin: ORIGIN.OH,
      },
    }));

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.CONSERVATIVE_LABEL);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(1);
    expect(reviewerSU[0].data.delta).toBe(REVIEWER.CORRECT_BONUS);
    expect(reviewerSU[0].data.delta).toBe(5);
    expect(reviewerSU[0].data.reason).toBe(`review_conservative_no_quorum:${REVIEW_ID}`);
  });

  test("NO_QUORUM → Stage-3 DISMISSED: reviewer takes -DISPUTER_STAKE", () => {
    const fx = _setup();
    const ids = _seedNoQuorumAppeal(fx.dag);
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(1);
    expect(reviewerSU[0].data.delta).toBe(-DISPUTE.DISPUTER_STAKE);
    expect(reviewerSU[0].data.delta).toBe(-15);
    expect(reviewerSU[0].data.reason).toBe(`review_overturned_no_quorum:${REVIEW_ID}`);
  });
});
