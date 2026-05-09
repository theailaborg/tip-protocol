/**
 * @file tests/scoring/longevity-score.test.js
 * @description Longevity Score (0-70) rules from TIP_Scoring_v2:
 *
 *   < 6 mo    →  0
 *   6-12 mo   → 15
 *   1-2 yr    → 30
 *   2-3 yr    → 45
 *   3-5 yr    → 60
 *   5+ yr     → 70
 *
 *   Cannot be gamed (time passes at the same rate for everyone).
 *   Longevity Score never decreases.
 *
 * Today's wiring:
 *   - The tier table lives in genesis.protocol_constants.longevity.tiers.
 *   - No production code reads or applies it. Longevity is a spec-forward
 *     bucket; the active scoring engine carries a single combined `score`
 *     and increments only via SCORE_UPDATE / REGISTER_IDENTITY paths.
 *
 * This file pins the genesis source-of-truth table (so a tier-shift in
 * the spec without a corresponding genesis update fails loudly), and
 * skip-marks the runtime computation tests for when the longevity engine
 * lands.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const { SCORE } = require(path.join(SHARED, "protocol-constants"));
const PROTO_CONSTANTS = require(path.resolve(__dirname, "../../../genesis-data/genesis.json")).protocol_constants;

// ─── Genesis source-of-truth ────────────────────────────────────────────────

describe("longevity — genesis tier table matches spec exactly", () => {
  test("MAX_LONGEVITY = 70", () => {
    expect(SCORE.MAX_LONGEVITY).toBe(70);
    expect(PROTO_CONSTANTS.score.max_longevity).toBe(70);
  });

  test("tier table has 5 thresholds: 6/12/24/36/60 months", () => {
    const tiers = PROTO_CONSTANTS.longevity.tiers;
    expect(tiers).toHaveLength(5);
    expect(tiers.map(t => t.months)).toEqual([6, 12, 24, 36, 60]);
  });

  test("tier points are 15/30/45/60/70 (matches spec table)", () => {
    const points = PROTO_CONSTANTS.longevity.tiers.map(t => t.points);
    expect(points).toEqual([15, 30, 45, 60, 70]);
  });

  test("the highest tier matches MAX_LONGEVITY (no gap or overshoot)", () => {
    const tiers = PROTO_CONSTANTS.longevity.tiers;
    const top = tiers[tiers.length - 1];
    expect(top.points).toBe(SCORE.MAX_LONGEVITY);
  });

  test("points are monotonically non-decreasing (older → not less)", () => {
    const points = PROTO_CONSTANTS.longevity.tiers.map(t => t.points);
    for (let i = 1; i < points.length; i++) {
      expect(points[i]).toBeGreaterThanOrEqual(points[i - 1]);
    }
  });
});

// ─── Spec-forward — engine not yet present ─────────────────────────────────

describe.skip("longevity — runtime computation (not yet implemented)", () => {
  test("brand-new identity (< 6 months): longevity = 0", () => {
    // No engine exists. When implemented, derive the bucket from
    //   floor((now - registered_at) / month_ms)
    // and pick the highest threshold whose months <= age. Today's score
    // engine doesn't track or surface a separate longevity bucket.
  });

  test.each([
    [6, 15],
    [12, 30],
    [24, 45],
    [36, 60],
    [60, 70],
    [120, 70],   // capped at MAX_LONGEVITY
  ])("age %i months → +%i longevity points", (_months, _expected) => {
    // Same shape as above. Each row is a boundary case from the spec.
  });

  test("identity refresh / re-issue does NOT reset longevity", () => {
    // Spec rationale: "Cannot be gamed. Time passes at the same rate for
    // everyone." If/when key-rotation flows exist, longevity should follow
    // the original registration timestamp, not the rotation event.
  });
});
