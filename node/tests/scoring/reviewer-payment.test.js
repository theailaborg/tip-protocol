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
 *
 * When `withReviewerEscalation: true`, the dispute is modelled as the
 * creator-initiated escalation flow: `disputer_tip_id = reviewer`
 * (the reviewer is the formal disputer, riding the standard
 * disputer-settlement economics) + `auto: true` + `source_review_id`.
 */
function _seedDispute(dag, { withReviewerEscalation = true, declaredOrigin = ORIGIN.OH, claimedOrigin = ORIGIN.AG } = {}) {
  const authorTipId = "tip://id/author";
  const reviewerTipId = "tip://id/reviewer";
  // When NOT modelling an escalated review, fall back to a third-party
  // disputer (regression-guard scenario for the non-escalation path).
  const fallbackDisputerTipId = "tip://id/disputer";
  _seedIdentity(dag, authorTipId, 600);
  _seedIdentity(dag, reviewerTipId, 800);
  if (!withReviewerEscalation) _seedIdentity(dag, fallbackDisputerTipId, 800);
  // On the escalation path, the reviewer IS the disputer.
  const disputerTipId = withReviewerEscalation ? reviewerTipId : fallbackDisputerTipId;

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
      ...(withReviewerEscalation
        ? { auto: true, source_review_id: REVIEW_ID }
        : {}),
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

  // The reviewer is set as `disputer_tip_id` on the escalation tx, so
  // they ride the standard disputer-settlement economics. On top of
  // that, a CORRECT_BONUS overlay credits them for the review work
  // itself (UPHELD / CONSERVATIVE_LABEL only).
  //
  // Lifetime net per outcome (incl. filing-time -15 stake, charged
  // in review-service.dispute — NOT in the buildAdjudicationBatch
  // batch under test here):
  //   UPHELD             -15 + 15 + 5 + 5 = +10
  //   CONSERVATIVE_LABEL -15 + 15     + 5 = +5
  //   DISMISSED          -15 +  0     + 0 = -15

  test("UPHELD → reviewer gets standard disputer +stake+bonus (+20) AND CORRECT_BONUS overlay (+5)", () => {
    const fx = _setup();
    const ids = _seedDispute(fx.dag);
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    // 2 events expected: disputer settlement + CORRECT_BONUS overlay.
    expect(reviewerSU).toHaveLength(2);
    const settlement = reviewerSU.find(t => t.data.delta === DISPUTE.DISPUTER_STAKE + DISPUTE.UPHELD_BONUS);
    expect(settlement).toBeDefined();
    expect(settlement.data.delta).toBe(20);
    const overlay = reviewerSU.find(t => t.data.delta === REVIEWER.CORRECT_BONUS);
    expect(overlay).toBeDefined();
    expect(overlay.data.delta).toBe(5);
    expect(overlay.data.reason).toBe(`review_correct_bonus:${REVIEW_ID}`);
  });

  test("CONSERVATIVE_LABEL → reviewer gets stake refund (+15) AND CORRECT_BONUS overlay (+5)", () => {
    const fx = _setup();
    const ids = _seedDispute(fx.dag, {
      declaredOrigin: ORIGIN.AG, claimedOrigin: ORIGIN.OH,
    });
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
    expect(reviewerSU).toHaveLength(2);
    const refund = reviewerSU.find(t => t.data.delta === DISPUTE.DISPUTER_STAKE);
    expect(refund).toBeDefined();
    expect(refund.data.delta).toBe(15);
    const overlay = reviewerSU.find(t => t.data.delta === REVIEWER.CORRECT_BONUS);
    expect(overlay).toBeDefined();
    expect(overlay.data.delta).toBe(5);
    expect(overlay.data.reason).toBe(`review_correct_bonus:${REVIEW_ID}`);
  });

  test("DISMISSED → no Stage-2 reviewer events (filing-time -15 stake forfeit is the penalty)", () => {
    const fx = _setup();
    const ids = _seedDispute(fx.dag);
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);

    // No Stage-2 batch events — the stake stays forfeited (already
    // deducted at filing time by review-service.dispute). No
    // CORRECT_BONUS overlay on DISMISSED either.
    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(0);
  });

  test("no prior CONFIRMED prescan_review → fallback disputer settlement only (no CORRECT_BONUS overlay)", () => {
    const fx = _setup();
    const ids = _seedDispute(fx.dag, { withReviewerEscalation: false });
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);

    // The fallback disputer (different identity from the reviewer)
    // gets the standard +20 settlement. No CORRECT_BONUS overlay
    // because there's no escalated_review row linked.
    const overlayMatches = out.txs.filter(
      t => t.tx_type === TX_TYPES.SCORE_UPDATE
        && (t.data?.reason || "").includes("review_correct_bonus"),
    );
    expect(overlayMatches).toHaveLength(0);
  });
});

// ─── Stage-3 appeal — reversal of Stage-2 reviewer settlement ───────────────

describe("Stage-3 appeal overturn — reviewer settlement reversal", () => {

  function _seedAppealFixture(dag, stage2Verdict, { declaredOrigin = ORIGIN.OH, claimedOrigin = ORIGIN.AG, withReviewerEscalation = true } = {}) {
    const ids = _seedDispute(dag, { declaredOrigin, claimedOrigin, withReviewerEscalation });

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

  test("Stage-2 UPHELD → Stage-3 DISMISSED: standard disputer reversal + CORRECT_BONUS reversal", () => {
    const fx = _setup();
    const ids = _seedAppealFixture(fx.dag, VERDICT.UPHELD);
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);
    expect(out.overturned).toBe(true);

    // The reviewer (= disputer_tip_id) sees two reviewer-specific events:
    //   1. Standard disputer-stake/bonus reversal from the disputer-
    //      overturn block (-stake - bonus = -20).
    //   2. CORRECT_BONUS overlay reversal (-5) from our new overlay
    //      reversal — Stage-2 had paid the bonus (UPHELD).
    // Stage-3 DISMISSED pays nothing fresh.
    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(2);
    const disputerReversal = reviewerSU.find(t => t.data.delta === -(DISPUTE.DISPUTER_STAKE + DISPUTE.UPHELD_BONUS));
    expect(disputerReversal).toBeDefined();
    expect(disputerReversal.data.delta).toBe(-20);
    const bonusReversal = reviewerSU.find(t => t.data.reason.includes("review_correct_bonus reversed"));
    expect(bonusReversal).toBeDefined();
    expect(bonusReversal.data.delta).toBe(-REVIEWER.CORRECT_BONUS);
    expect(bonusReversal.data.delta).toBe(-5);
  });

  test("Stage-2 DISMISSED → Stage-3 UPHELD: standard fresh disputer settlement + fresh CORRECT_BONUS", () => {
    const fx = _setup();
    const ids = _seedAppealFixture(fx.dag, VERDICT.DISMISSED);
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);
    expect(out.overturned).toBe(true);

    // The reviewer (= disputer) gets at least these two events from
    // the parts of the batch this test owns:
    //   1. Disputer-overturn settlement: +stake+UPHELD_BONUS = +20.
    //   2. CORRECT_BONUS overlay (fresh on UPHELD): +5.
    // (The reviewer also happens to be the appellant in this fixture
    // — they're the Stage-2 loser — so the existing appellant block
    // adds +APPELLANT_STAKE+OVERTURN_BONUS. That's covered by the
    // appellant economics tests in tests/scoring/dispute-stake-economy
    // and is not the focus of this reviewer-payment test.)
    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    const settlement = reviewerSU.find(t => t.data.delta === DISPUTE.DISPUTER_STAKE + DISPUTE.UPHELD_BONUS);
    expect(settlement).toBeDefined();
    expect(settlement.data.delta).toBe(20);
    const overlay = reviewerSU.find(t => t.data.reason === `review_correct_bonus_on_appeal:${REVIEW_ID}`);
    expect(overlay).toBeDefined();
    expect(overlay.data.delta).toBe(REVIEWER.CORRECT_BONUS);
    expect(overlay.data.delta).toBe(5);
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
    expect(reviewerSU).toHaveLength(0);
  });

  test("Stage-3 overturn with NO escalated review → no CORRECT_BONUS overlay events (regression)", () => {
    const fx = _setup();
    // Seed without the escalated_review state — simulates a normal
    // third-party dispute being appealed.
    const ids = _seedAppealFixture(fx.dag, VERDICT.UPHELD, { withReviewerEscalation: false });
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);
    expect(out.overturned).toBe(true);

    // No CORRECT_BONUS events should be present (no escalated_review row).
    const overlayMatches = out.txs.filter(
      t => t.tx_type === TX_TYPES.SCORE_UPDATE
        && (t.data?.reason || "").includes("review_correct_bonus"),
    );
    expect(overlayMatches).toHaveLength(0);
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

  test("NO_QUORUM → Stage-3 UPHELD: standard disputer settlement (+20) + CORRECT_BONUS overlay (+5)", () => {
    const fx = _setup();
    const ids = _seedNoQuorumAppeal(fx.dag);
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(2);
    const settlement = reviewerSU.find(t => t.data.delta === DISPUTE.DISPUTER_STAKE + DISPUTE.UPHELD_BONUS);
    expect(settlement).toBeDefined();
    expect(settlement.data.delta).toBe(20);
    const overlay = reviewerSU.find(t => t.data.delta === REVIEWER.CORRECT_BONUS);
    expect(overlay).toBeDefined();
    expect(overlay.data.delta).toBe(5);
    expect(overlay.data.reason).toBe(`review_correct_bonus_no_quorum:${REVIEW_ID}`);
  });

  test("NO_QUORUM → Stage-3 CONSERVATIVE_LABEL: stake refund (+15) + CORRECT_BONUS overlay (+5)", () => {
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
    expect(reviewerSU).toHaveLength(2);
    const refund = reviewerSU.find(t => t.data.delta === DISPUTE.DISPUTER_STAKE);
    expect(refund).toBeDefined();
    expect(refund.data.delta).toBe(15);
    const overlay = reviewerSU.find(t => t.data.delta === REVIEWER.CORRECT_BONUS);
    expect(overlay).toBeDefined();
    expect(overlay.data.delta).toBe(5);
    expect(overlay.data.reason).toBe(`review_correct_bonus_no_quorum:${REVIEW_ID}`);
  });

  test("NO_QUORUM → Stage-3 DISMISSED: no Stage-3 batch events for reviewer (stake stays forfeited)", () => {
    const fx = _setup();
    const ids = _seedNoQuorumAppeal(fx.dag);
    const reveals = _buildExpertReveals(ids.experts, [VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH]);

    const out = buildAppealBatch(CTID, reveals, ids.expertSummons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);

    const reviewerSU = _scoreUpdatesFor(out.txs, ids.reviewerTipId);
    expect(reviewerSU).toHaveLength(0);
  });
});
