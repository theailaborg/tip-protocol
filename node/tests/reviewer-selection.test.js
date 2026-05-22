/**
 * @file tests/reviewer-selection.test.js
 * @description Phase 2.4 — reviewer eligibility + deterministic selection.
 *
 * Covers:
 *   - Eligibility filters: consent, score, not-author, not-revoked, accuracy
 *   - getReviewerAccuracy: no history → 1.0, CLOSED_ACCEPTED_PRIVATE → 1.0,
 *       CLOSED_DISMISSED matched/unmatched against ADJUDICATION_RESULT,
 *       ESCALATED_TO_DISPUTE matched/unmatched
 *   - selectReviewer determinism: same (reviewId, ctid, round) → same pick
 *   - selectReviewer changes pick when round changes (re-trigger gets a
 *     different reviewer)
 *   - selectReviewer returns { reviewer: null } on empty pool
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../../shared/time");

const path = require("path");
const SHARED = path.resolve(__dirname, "../../shared");
const SRC = path.resolve(__dirname, "../src");

const { initCrypto, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const {
  isEligibleReviewer, getReviewerAccuracy, selectReviewer,
} = require(path.join(SRC, "reviewer-selection"));
const {
  TX_TYPES, VERDICT, PRESCAN_REVIEW_STATES,
} = require(path.join(SHARED, "constants"));
const { REVIEWER } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const AUTHOR = "tip://id/US-aaaaaaaaaaaaaaaa";
const REV_A = "tip://id/US-1111aaaa1111aaaa";
const REV_B = "tip://id/US-2222bbbb2222bbbb";
const REV_C = "tip://id/US-3333cccc3333cccc";
const REV_D = "tip://id/US-4444dddd4444dddd";
const CTID = "tip://c/OH-11111111111111-0001";

function _setup({ seedScores } = {}) {
  const dag = initDAG({ dbPath: ":memory:" });

  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });

  const identities = [
    { tip_id: AUTHOR, reviewer_consent: false },
    { tip_id: REV_A, reviewer_consent: true },
    { tip_id: REV_B, reviewer_consent: true },
    { tip_id: REV_C, reviewer_consent: true },
    { tip_id: REV_D, reviewer_consent: false },  // not opted in
  ];
  for (const { tip_id, reviewer_consent } of identities) {
    dag.saveIdentity({
      tip_id, region: "US", public_key: "00", root_public_key: "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      reviewer_consent,
      registered_at: 1767225600000, tx_id: shake256(`id:${tip_id}`),
    });
  }

  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
  // Default score-cache: well above REVIEWER.MIN_SCORE (800)
  const scores = seedScores || { [AUTHOR]: 900, [REV_A]: 900, [REV_B]: 900, [REV_C]: 900, [REV_D]: 900 };
  for (const [tipId, score] of Object.entries(scores)) {
    dag.setScore(tipId, score, 0, nowMs());
  }

  return { dag, scoring };
}

describe("isEligibleReviewer — base filters", () => {

  test("opted-in + score≥800 + not author + not revoked → eligible", () => {
    const { dag, scoring } = _setup();
    expect(isEligibleReviewer(dag, scoring, REV_A, { authorTipId: AUTHOR })).toBe(true);
  });

  test("the content author is never eligible", () => {
    const { dag, scoring } = _setup();
    // Even if AUTHOR had reviewer_consent=true, they're excluded as author
    dag.saveIdentity({
      ...dag.getIdentity(AUTHOR),
      reviewer_consent: true,
    });
    expect(isEligibleReviewer(dag, scoring, AUTHOR, { authorTipId: AUTHOR })).toBe(false);
  });

  test("identity without reviewer_consent → not eligible", () => {
    const { dag, scoring } = _setup();
    expect(isEligibleReviewer(dag, scoring, REV_D, { authorTipId: AUTHOR })).toBe(false);
  });

  test("score below REVIEWER.MIN_SCORE → not eligible", () => {
    const { dag, scoring } = _setup({
      seedScores: { [REV_A]: REVIEWER.MIN_SCORE - 1, [REV_B]: 900, [REV_C]: 900, [AUTHOR]: 900 },
    });
    expect(isEligibleReviewer(dag, scoring, REV_A, { authorTipId: AUTHOR })).toBe(false);
    expect(isEligibleReviewer(dag, scoring, REV_B, { authorTipId: AUTHOR })).toBe(true);
  });

  test("revoked identity → not eligible", () => {
    const { dag, scoring } = _setup();
    dag.addRevocation(REV_A, TX_TYPES.REVOKE_VOLUNTARY, nowMs(), shake256("rev:a"));
    expect(isEligibleReviewer(dag, scoring, REV_A, { authorTipId: AUTHOR })).toBe(false);
  });

  test("unknown tip_id → not eligible", () => {
    const { dag, scoring } = _setup();
    expect(isEligibleReviewer(dag, scoring, "tip://id/US-deadbeefdeadbeef", {})).toBe(false);
  });
});

describe("getReviewerAccuracy", () => {

  test("no decisions → 1.0 (benefit of the doubt for new reviewers)", () => {
    const { dag } = _setup();
    expect(getReviewerAccuracy(dag, REV_A)).toBe(1.0);
  });

  test("CLOSED_ACCEPTED_PRIVATE counts as correct (creator agreed)", () => {
    const { dag } = _setup();
    dag.savePrescanReview({
      review_id: "rv_acc1", ctid: CTID, creator_tip_id: AUTHOR,
      assigned_reviewer: REV_A, triggered_at_round: 1,
      decided_at_round: 2, confirmed_at_round: 2,
      state: PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE,
      suggested_origin: "AG",
    });
    expect(getReviewerAccuracy(dag, REV_A)).toBe(1.0);
  });

  test("CLOSED_DISMISSED + jury DISMISSED → correct", () => {
    const { dag } = _setup();
    dag.savePrescanReview({
      review_id: "rv_acc2", ctid: CTID, creator_tip_id: AUTHOR,
      assigned_reviewer: REV_A, triggered_at_round: 1, decided_at_round: 2,
      state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
    });
    // Seed an ADJUDICATION_RESULT tx with verdict=DISMISSED for this ctid
    _seedAdjudicationVerdict(dag, CTID, VERDICT.DISMISSED);

    expect(getReviewerAccuracy(dag, REV_A)).toBe(1.0);
  });

  test("CLOSED_DISMISSED + jury UPHELD → incorrect", () => {
    const { dag } = _setup();
    dag.savePrescanReview({
      review_id: "rv_acc3", ctid: CTID, creator_tip_id: AUTHOR,
      assigned_reviewer: REV_A, triggered_at_round: 1, decided_at_round: 2,
      state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
    });
    _seedAdjudicationVerdict(dag, CTID, VERDICT.UPHELD);

    expect(getReviewerAccuracy(dag, REV_A)).toBe(0.0);
  });

  test("ESCALATED_TO_DISPUTE + jury UPHELD → correct (reviewer confirmed and jury agreed)", () => {
    const { dag } = _setup();
    dag.savePrescanReview({
      review_id: "rv_acc4", ctid: CTID, creator_tip_id: AUTHOR,
      assigned_reviewer: REV_A, triggered_at_round: 1, decided_at_round: 2,
      confirmed_at_round: 2,
      state: PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE,
      suggested_origin: "AG",
    });
    _seedAdjudicationVerdict(dag, CTID, VERDICT.UPHELD);

    expect(getReviewerAccuracy(dag, REV_A)).toBe(1.0);
  });

  test("decisions without verdict yet are skipped (don't count for/against)", () => {
    const { dag } = _setup();
    // One DISMISSED with no adjudication yet (skipped), one CLOSED_ACCEPTED_PRIVATE (correct)
    dag.savePrescanReview({
      review_id: "rv_acc5a", ctid: CTID + "-pending", creator_tip_id: AUTHOR,
      assigned_reviewer: REV_A, triggered_at_round: 1, decided_at_round: 2,
      state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
    });
    dag.savePrescanReview({
      review_id: "rv_acc5b", ctid: CTID, creator_tip_id: AUTHOR,
      assigned_reviewer: REV_A, triggered_at_round: 3, decided_at_round: 4,
      confirmed_at_round: 4,
      state: PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE,
      suggested_origin: "AG",
    });
    expect(getReviewerAccuracy(dag, REV_A)).toBe(1.0);  // 1 evaluated, 1 correct
  });
});

describe("isEligibleReviewer — accuracy gate", () => {

  test("accuracy below (1 - MAX_OVERTURN_RATE) → not eligible", () => {
    const { dag, scoring } = _setup();
    // Seed two DISMISSED decisions, both overturned by UPHELD verdicts
    dag.savePrescanReview({
      review_id: "rv_a1", ctid: "tip://c/OH-aaaaaaaaaaaaaa-0001", creator_tip_id: AUTHOR,
      assigned_reviewer: REV_A, triggered_at_round: 1, decided_at_round: 2,
      state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
    });
    _seedAdjudicationVerdict(dag, "tip://c/OH-aaaaaaaaaaaaaa-0001", VERDICT.UPHELD);
    dag.savePrescanReview({
      review_id: "rv_a2", ctid: "tip://c/OH-bbbbbbbbbbbbbb-0002", creator_tip_id: AUTHOR,
      assigned_reviewer: REV_A, triggered_at_round: 3, decided_at_round: 4,
      state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
    });
    _seedAdjudicationVerdict(dag, "tip://c/OH-bbbbbbbbbbbbbb-0002", VERDICT.UPHELD);

    // accuracy = 0/2 = 0.0; threshold = 1 - 0.30 = 0.70
    expect(getReviewerAccuracy(dag, REV_A)).toBe(0.0);
    expect(isEligibleReviewer(dag, scoring, REV_A, { authorTipId: AUTHOR })).toBe(false);
  });
});

describe("selectReviewer", () => {

  test("deterministic — same inputs return the same reviewer", () => {
    const { dag, scoring } = _setup();
    const r1 = selectReviewer(dag, scoring, {
      reviewId: "rv_d1", ctid: CTID, round: 42, authorTipId: AUTHOR,
    });
    const r2 = selectReviewer(dag, scoring, {
      reviewId: "rv_d1", ctid: CTID, round: 42, authorTipId: AUTHOR,
    });
    expect(r1.reviewer).not.toBeNull();
    expect(r1.reviewer).toBe(r2.reviewer);
    expect(r1.seed).toBe(r2.seed);
    expect(r1.poolSize).toBe(3);  // REV_A, REV_B, REV_C (D not opted-in)
    expect(r1.pass).toBe(1);  // Pass 1 — all three meet strict bar
  });

  test("different round → different shuffle (re-trigger picks a different reviewer eventually)", () => {
    const { dag, scoring } = _setup();
    // Try a few rounds; at least one should produce a different pick.
    // (With 3 eligible reviewers and a 32-byte seed, the chance all
    // four rounds collide on the same index is negligible — but if it
    // ever did we'd see it here.)
    const picks = new Set();
    for (const round of [1, 2, 3, 4, 5, 6]) {
      picks.add(selectReviewer(dag, scoring, {
        reviewId: "rv_d2", ctid: CTID, round, authorTipId: AUTHOR,
      }).reviewer);
    }
    expect(picks.size).toBeGreaterThan(1);
  });

  test("never picks the author", () => {
    const { dag, scoring } = _setup();
    // Even if AUTHOR opts into reviewing, they must not appear as the pick
    const id = dag.getIdentity(AUTHOR);
    dag.saveIdentity({ ...id, reviewer_consent: true });

    for (const round of [1, 2, 3, 4, 5, 10, 99]) {
      const { reviewer } = selectReviewer(dag, scoring, {
        reviewId: "rv_d3", ctid: CTID, round, authorTipId: AUTHOR,
      });
      expect(reviewer).not.toBe(AUTHOR);
    }
  });

  test("empty pool → returns { reviewer: null, poolSize: 0, pass: 0 }", () => {
    const { dag, scoring } = _setup();
    // Revoke all three opted-in reviewers (REV_D wasn't opted in to start)
    for (const tipId of [REV_A, REV_B, REV_C]) {
      dag.addRevocation(tipId, TX_TYPES.REVOKE_VOLUNTARY, nowMs(), shake256(`rev:${tipId}`));
    }
    const r = selectReviewer(dag, scoring, {
      reviewId: "rv_d4", ctid: CTID, round: 1, authorTipId: AUTHOR,
    });
    expect(r.reviewer).toBeNull();
    expect(r.poolSize).toBe(0);
    expect(r.pass).toBe(0);
  });

  test("cascade Pass 2 — accuracy gate relaxed when strict pool is empty", () => {
    const { dag, scoring } = _setup();
    // Give all three opted-in reviewers a poor accuracy record
    for (const reviewer of [REV_A, REV_B, REV_C]) {
      const id = reviewer.split("-")[1].slice(0, 2);
      const ctidFail = `tip://c/OH-${id}${id}${id}${id}${id}${id}${id}-0001`;
      dag.savePrescanReview({
        review_id: `rv_bad_${id}`, ctid: ctidFail, creator_tip_id: AUTHOR,
        assigned_reviewer: reviewer, triggered_at_round: 1, decided_at_round: 2,
        state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
      });
      _seedAdjudicationVerdict(dag, ctidFail, VERDICT.UPHELD);
    }
    // All three have accuracy=0.0 → Pass 1 empty. Score is still ≥ MIN_SCORE → Pass 2 fills.
    const r = selectReviewer(dag, scoring, {
      reviewId: "rv_p2", ctid: CTID, round: 1, authorTipId: AUTHOR,
    });
    expect(r.reviewer).not.toBeNull();
    expect(r.pass).toBe(2);
    expect(r.poolSize).toBe(3);
  });

  test("cascade Pass 3 — score floor lowered to JURY.MIN_SCORE_FALLBACK", () => {
    const { JURY } = require(path.join(SHARED, "protocol-constants"));
    // All opted-in reviewers below REVIEWER.MIN_SCORE but ≥ JURY.MIN_SCORE_FALLBACK
    const lowScore = JURY.MIN_SCORE_FALLBACK + 10;
    const { dag, scoring } = _setup({
      seedScores: { [REV_A]: lowScore, [REV_B]: lowScore, [REV_C]: lowScore, [AUTHOR]: 900 },
    });
    const r = selectReviewer(dag, scoring, {
      reviewId: "rv_p3", ctid: CTID, round: 1, authorTipId: AUTHOR,
    });
    expect(r.reviewer).not.toBeNull();
    expect(r.pass).toBe(3);
  });

  test("cascade exhausted — every candidate below JURY.MIN_SCORE_FALLBACK → null", () => {
    const { JURY } = require(path.join(SHARED, "protocol-constants"));
    const tooLow = JURY.MIN_SCORE_FALLBACK - 1;
    const { dag, scoring } = _setup({
      seedScores: { [REV_A]: tooLow, [REV_B]: tooLow, [REV_C]: tooLow, [AUTHOR]: 900 },
    });
    const r = selectReviewer(dag, scoring, {
      reviewId: "rv_p_none", ctid: CTID, round: 1, authorTipId: AUTHOR,
    });
    expect(r.reviewer).toBeNull();
    expect(r.pass).toBe(0);
  });

  test("missing required input → throws", () => {
    const { dag, scoring } = _setup();
    expect(() => selectReviewer(dag, scoring, { ctid: CTID, round: 1 })).toThrow();
    expect(() => selectReviewer(dag, scoring, { reviewId: "x", round: 1 })).toThrow();
    expect(() => selectReviewer(dag, scoring, { reviewId: "x", ctid: CTID })).toThrow();
  });
});

// ─── helpers ──────────────────────────────────────────────────────────────────

let _adjCounter = 0;
function _seedAdjudicationVerdict(dag, ctid, verdict) {
  // Minimal ADJUDICATION_RESULT tx — getTxsByTypeAndCtid reads tx.data.verdict.
  // tx_id must be the canonical-hash of the tx body, so build the body first
  // then compute. A monotonic nonce keeps tx_ids unique across calls.
  const body = {
    tx_type: TX_TYPES.ADJUDICATION_RESULT,
    // 2026-01-01 UTC + N days. Monotonic counter for unique tx_ids.
    timestamp: 1767225600000 + (++_adjCounter) * 86_400_000,
    prev: [],
    data: { ctid, verdict, declared_origin: "OH" },
  };
  body.tx_id = computeTxId(body);
  dag.addTx(body);
}
