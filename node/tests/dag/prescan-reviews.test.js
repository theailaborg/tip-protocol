/**
 * @file tests/dag/prescan-reviews.test.js
 * @description DAG facade for the `prescan_reviews` table — the persistence
 * layer for the human-reviewing-AI-prescan-flag pipeline (Phase 2).
 *
 * Covers:
 *   - savePrescanReview round-trips all fields
 *   - INSERT OR REPLACE semantics (same review_id walks the state machine)
 *   - getOpenPrescanReviewByCtid filters by state ∈ {triggered, confirmed}
 *   - getOpenPrescanReviewByCtid returns null for closed reviews
 *   - getPrescanReviewsByCtid returns all reviews (sorted DESC by round)
 *   - getPrescanReviewsByReviewer filters correctly
 *   - state_merkle_root determinism — same rows in different insert orders
 *     produce identical canonical projection
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { PRESCAN_REVIEW_STATES } = require(path.join(SHARED, "constants"));

beforeAll(async () => { await initCrypto(); });

const CREATOR = "tip://id/US-aaaaaaaaaaaaaaaa";
const REVIEWER_1 = "tip://id/US-bbbbbbbbbbbbbbbb";
const REVIEWER_2 = "tip://id/US-cccccccccccccccc";
const CTID_1 = "tip://c/OH-1111111111111111-0001";
const CTID_2 = "tip://c/OH-2222222222222222-0002";

function _setup() {
  return initDAG({ dbPath: ":memory:" });
}

function _baseReview(overrides = {}) {
  return {
    review_id: "rv_001",
    ctid: CTID_1,
    creator_tip_id: CREATOR,
    assigned_reviewer: REVIEWER_1,
    triggered_at_round: 100,
    decided_at_round: null,
    confirmed_at_round: null,
    state: PRESCAN_REVIEW_STATES.TRIGGERED,
    decision_note: null,
    suggested_origin: null,
    ...overrides,
  };
}

describe("prescan_reviews — save + get round-trip", () => {

  test("savePrescanReview persists all fields; getPrescanReview returns them", () => {
    const dag = _setup();
    dag.savePrescanReview(_baseReview({
      review_id: "rv_a",
      decision_note: "Looks AI-y to me",
      suggested_origin: "AG",
    }));
    const got = dag.getPrescanReview("rv_a");
    expect(got).not.toBeNull();
    expect(got.review_id).toBe("rv_a");
    expect(got.ctid).toBe(CTID_1);
    expect(got.creator_tip_id).toBe(CREATOR);
    expect(got.assigned_reviewer).toBe(REVIEWER_1);
    expect(got.triggered_at_round).toBe(100);
    expect(got.state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
    expect(got.decision_note).toBe("Looks AI-y to me");
    expect(got.suggested_origin).toBe("AG");
  });

  test("getPrescanReview returns null for unknown review_id", () => {
    const dag = _setup();
    expect(dag.getPrescanReview("rv_nonexistent")).toBeNull();
  });

  test("INSERT OR REPLACE: state machine progression via successive saves", () => {
    const dag = _setup();
    // Start: triggered
    dag.savePrescanReview(_baseReview({ review_id: "rv_progress" }));
    expect(dag.getPrescanReview("rv_progress").state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);

    // Step 1: reviewer confirms
    dag.savePrescanReview(_baseReview({
      review_id: "rv_progress",
      state: PRESCAN_REVIEW_STATES.CONFIRMED,
      decided_at_round: 150,
      confirmed_at_round: 150,
      decision_note: "AI was right",
      suggested_origin: "AG",
    }));
    let row = dag.getPrescanReview("rv_progress");
    expect(row.state).toBe(PRESCAN_REVIEW_STATES.CONFIRMED);
    expect(row.decided_at_round).toBe(150);
    expect(row.suggested_origin).toBe("AG");

    // Step 2: creator accepts privately (skips dispute)
    dag.savePrescanReview(_baseReview({
      review_id: "rv_progress",
      state: PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE,
      decided_at_round: 150,
      confirmed_at_round: 150,
      decision_note: "AI was right",
      suggested_origin: "AG",
    }));
    row = dag.getPrescanReview("rv_progress");
    expect(row.state).toBe(PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE);
  });
});

describe("prescan_reviews — getOpenPrescanReviewByCtid", () => {

  test("returns the open review when state=triggered", () => {
    const dag = _setup();
    dag.savePrescanReview(_baseReview({ review_id: "rv_open1", ctid: CTID_1 }));
    const open = dag.getOpenPrescanReviewByCtid(CTID_1);
    expect(open).not.toBeNull();
    expect(open.review_id).toBe("rv_open1");
  });

  test("returns the open review when state=confirmed", () => {
    const dag = _setup();
    dag.savePrescanReview(_baseReview({
      review_id: "rv_open2",
      state: PRESCAN_REVIEW_STATES.CONFIRMED,
      decided_at_round: 200, confirmed_at_round: 200,
    }));
    const open = dag.getOpenPrescanReviewByCtid(CTID_1);
    expect(open).not.toBeNull();
    expect(open.state).toBe(PRESCAN_REVIEW_STATES.CONFIRMED);
  });

  test("returns null when only closed reviews exist", () => {
    const dag = _setup();
    for (const closedState of [
      PRESCAN_REVIEW_STATES.CLOSED_SELF_CORRECT,
      PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
      PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE,
      PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE,
      PRESCAN_REVIEW_STATES.RECUSED,
    ]) {
      const dag2 = _setup();
      dag2.savePrescanReview(_baseReview({
        review_id: `rv_closed_${closedState}`,
        state: closedState,
        decided_at_round: 200,
      }));
      expect(dag2.getOpenPrescanReviewByCtid(CTID_1)).toBeNull();
    }
  });

  test("returns null for unknown CTID", () => {
    const dag = _setup();
    dag.savePrescanReview(_baseReview({ review_id: "rv_other", ctid: CTID_2 }));
    expect(dag.getOpenPrescanReviewByCtid(CTID_1)).toBeNull();
  });
});

describe("prescan_reviews — getPrescanReviewsByCtid", () => {

  test("returns all reviews for a CTID sorted DESC by triggered_at_round", () => {
    const dag = _setup();
    dag.savePrescanReview(_baseReview({ review_id: "rv_a", ctid: CTID_1, triggered_at_round: 100 }));
    dag.savePrescanReview(_baseReview({ review_id: "rv_b", ctid: CTID_1, triggered_at_round: 200 }));
    dag.savePrescanReview(_baseReview({ review_id: "rv_c", ctid: CTID_1, triggered_at_round: 150 }));
    dag.savePrescanReview(_baseReview({ review_id: "rv_other", ctid: CTID_2, triggered_at_round: 175 }));

    const all = dag.getPrescanReviewsByCtid(CTID_1);
    expect(all.length).toBe(3);
    expect(all[0].review_id).toBe("rv_b");  // 200
    expect(all[1].review_id).toBe("rv_c");  // 150
    expect(all[2].review_id).toBe("rv_a");  // 100
  });

  test("returns empty array for CTID with no reviews", () => {
    const dag = _setup();
    expect(dag.getPrescanReviewsByCtid(CTID_1)).toEqual([]);
  });
});

describe("prescan_reviews — getPrescanReviewsByReviewer", () => {

  test("returns reviews assigned to a specific reviewer", () => {
    const dag = _setup();
    dag.savePrescanReview(_baseReview({ review_id: "rv_r1_a", assigned_reviewer: REVIEWER_1, triggered_at_round: 100 }));
    dag.savePrescanReview(_baseReview({ review_id: "rv_r2_b", assigned_reviewer: REVIEWER_2, triggered_at_round: 110 }));
    dag.savePrescanReview(_baseReview({ review_id: "rv_r1_c", assigned_reviewer: REVIEWER_1, triggered_at_round: 120 }));

    const r1Reviews = dag.getPrescanReviewsByReviewer(REVIEWER_1);
    expect(r1Reviews.length).toBe(2);
    expect(r1Reviews.map(r => r.review_id).sort()).toEqual(["rv_r1_a", "rv_r1_c"]);

    const r2Reviews = dag.getPrescanReviewsByReviewer(REVIEWER_2);
    expect(r2Reviews.length).toBe(1);
    expect(r2Reviews[0].review_id).toBe("rv_r2_b");
  });

  test("returns empty array for reviewer with no assignments", () => {
    const dag = _setup();
    expect(dag.getPrescanReviewsByReviewer("tip://id/US-nobody0000000000")).toEqual([]);
  });
});

describe("prescan_reviews — snapshot determinism", () => {

  test("two DAGs receiving same rows in different orders yield identical canonical output", () => {
    const dag1 = initDAG({ dbPath: ":memory:" });
    const dag2 = initDAG({ dbPath: ":memory:" });
    const rows = [
      _baseReview({ review_id: "rv_z", ctid: CTID_2, triggered_at_round: 300 }),
      _baseReview({ review_id: "rv_a", ctid: CTID_1, triggered_at_round: 100 }),
      _baseReview({ review_id: "rv_m", ctid: CTID_1, triggered_at_round: 200 }),
    ];

    // Insert in different orders
    for (const r of rows) dag1.savePrescanReview(r);
    for (const r of [...rows].reverse()) dag2.savePrescanReview(r);

    const yieldFromCanon = (dag) => {
      const out = [];
      for (const { table, row } of dag.iterateCanonicalState()) {
        if (table === "prescan_reviews") out.push(row);
      }
      return out;
    };

    const canon1 = yieldFromCanon(dag1);
    const canon2 = yieldFromCanon(dag2);
    expect(canon1).toEqual(canon2);
    expect(canon1.length).toBe(3);
    // Sorted by review_id (a → m → z)
    expect(canon1.map(r => r.review_id)).toEqual(["rv_a", "rv_m", "rv_z"]);
  });
});
