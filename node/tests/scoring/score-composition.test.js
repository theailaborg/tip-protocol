/**
 * @file tests/scoring/score-composition.test.js
 * @description Sub-score composition rules from the scoring spec
 * (TIP_Scoring_v2_Personal_Notes (2).md):
 *
 *   total_score = identity + content + reputation + longevity
 *   - Identity 0-530 (only sub-score that can decrease)
 *   - Content 0-350 (never decreases)
 *   - Reputation 0-50 (never decreases)
 *   - Longevity 0-70 (never decreases)
 *   - Total floor 0, ceiling 1000
 *   - INITIAL_IDENTITY = 500 (Verified tier on Day 1)
 *
 * The current scoring engine carries a single combined `score` (not four
 * sub-buckets) plus an offense counter — the sub-score split is a spec
 * goal, not a runtime structure today. These tests pin the implemented
 * surface (constants, init value, floor/ceiling) and document gaps for
 * the bucket-level work in progress.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { TX_TYPES } = require(SHARED + "/constants");
const { SCORE } = require(SHARED + "/protocol-constants");
const { applyScoreEffect, initialState } = require(path.join(SRC, "score-effects"));

describe("score composition — constants from genesis", () => {
  test("MAX_TOTAL = 1000 (spec)", () => {
    expect(SCORE.MAX_TOTAL).toBe(1000);
  });

  test("MAX_IDENTITY = 530 (500 base + 30 social cap)", () => {
    expect(SCORE.MAX_IDENTITY).toBe(530);
  });

  test("MAX_CONTENT = 350", () => {
    expect(SCORE.MAX_CONTENT).toBe(350);
  });

  test("MAX_REPUTATION = 50", () => {
    expect(SCORE.MAX_REPUTATION).toBe(50);
  });

  test("MAX_LONGEVITY = 70", () => {
    expect(SCORE.MAX_LONGEVITY).toBe(70);
  });

  test("INITIAL_IDENTITY = 500 (lands new users in Verified tier)", () => {
    expect(SCORE.INITIAL_IDENTITY).toBe(500);
  });

  test("Sub-bucket caps sum to MAX_TOTAL", () => {
    expect(
      SCORE.MAX_IDENTITY + SCORE.MAX_CONTENT + SCORE.MAX_REPUTATION + SCORE.MAX_LONGEVITY,
    ).toBe(SCORE.MAX_TOTAL);
  });
});

describe("score composition — initial state", () => {
  test("initialState() seeds a new tip_id at INITIAL_IDENTITY (500)", () => {
    const s = initialState();
    expect(s.score).toBe(SCORE.INITIAL_IDENTITY);
    expect(s.offense_count).toBe(0);
    expect(s.frozen).toBe(false);
  });

  test("REGISTER_IDENTITY does not change a fresh seed (delta 0)", () => {
    const tx = { tx_type: TX_TYPES.REGISTER_IDENTITY, data: { tip_id: "tip://id/x" } };
    const next = applyScoreEffect(tx, initialState());
    expect(next.score).toBe(SCORE.INITIAL_IDENTITY);
    expect(next.delta).toBe(0);
  });
});

describe("score composition — floor + ceiling clamps", () => {
  test("floor: a penalty larger than current score clamps to 0, never negative", () => {
    const tx = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: -10000 } };
    const next = applyScoreEffect(tx, { score: 500, offense_count: 0, frozen: false });
    expect(next.score).toBe(0);
  });

  test("floor: stacking penalties from 0 stays at 0", () => {
    const tx = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: -50 } };
    const next = applyScoreEffect(tx, { score: 0, offense_count: 0, frozen: false });
    expect(next.score).toBe(0);
  });

  test("ceiling: a positive delta past MAX_TOTAL clamps to 1000", () => {
    const tx = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: 9000 } };
    const next = applyScoreEffect(tx, { score: 990, offense_count: 0, frozen: false });
    expect(next.score).toBe(SCORE.MAX_TOTAL);
  });

  test("ceiling: at exactly MAX_TOTAL, further positive delta is a no-op clamp", () => {
    const tx = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: 1 } };
    const next = applyScoreEffect(tx, { score: SCORE.MAX_TOTAL, offense_count: 0, frozen: false });
    expect(next.score).toBe(SCORE.MAX_TOTAL);
  });

  test("at the ceiling, penalties still land (only Identity decreases per spec)", () => {
    const tx = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: -100 } };
    const next = applyScoreEffect(tx, { score: SCORE.MAX_TOTAL, offense_count: 0, frozen: false });
    expect(next.score).toBe(SCORE.MAX_TOTAL - 100);
  });
});

describe("score composition — frozen state preserves the bucket invariants", () => {
  test("after freeze, positive deltas zero out (Identity ceiling protected)", () => {
    const revoke = { tx_type: TX_TYPES.REVOKE_VOLUNTARY, data: { tip_id: "tip://id/x" } };
    const after = applyScoreEffect(revoke, { score: 500, offense_count: 0, frozen: false });
    expect(after.frozen).toBe(true);

    const bonus = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: 50 } };
    const next = applyScoreEffect(bonus, after);
    expect(next.score).toBe(500);
  });

  test("after freeze, negative deltas still apply (penalties don't get a free pass)", () => {
    const revoke = { tx_type: TX_TYPES.REVOKE_VOLUNTARY, data: { tip_id: "tip://id/x" } };
    const frozen = applyScoreEffect(revoke, { score: 500, offense_count: 0, frozen: false });

    const penalty = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: -100 } };
    const next = applyScoreEffect(penalty, frozen);
    expect(next.score).toBe(400);
    expect(next.frozen).toBe(true);
  });
});
