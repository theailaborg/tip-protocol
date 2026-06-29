/**
 * @file tests/consensus/bft-thresholds.test.js
 * @description Direct unit tests for the BFT primitives in certificate.js:
 *   - computeQuorum(n)        = ceil(2n/3)  (the ">2/3" quorum; NOT 2f+1)
 *   - bftHaltThreshold(n)     = max(floor((n-1)/3) + 1, 2), Infinity for n<=1
 *
 * Single source of truth tests — anti-entropy delegates to bftHaltThreshold,
 * narwhal/bullshark delegate to computeQuorum. If these formulas drift,
 * BFT correctness drifts with them, so they get focused coverage here.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const { computeQuorum, bftHaltThreshold } = require(path.join(SRC, "consensus", "certificate"));

describe("computeQuorum — ceil(2n/3) (smallest quorum guaranteeing honest overlap)", () => {
  // The unsafe 2f+1 shorthand would give n=5→3, n=6→3, n=8→5 here — too small at
  // non-3f+1 sizes. ceil(2n/3) is the tight, correct minimum.
  test.each([
    [1, 1], [2, 2], [3, 2], [4, 3], [5, 4], [6, 4], [7, 5], [8, 6], [9, 6], [10, 7], [100, 67],
  ])("n=%i → quorum=%i", (n, expected) => {
    expect(computeQuorum(n)).toBe(expected);
  });

  test("quorum is always a strict majority that guarantees honest overlap (2q > n+f)", () => {
    for (let n = 1; n <= 30; n++) {
      const q = computeQuorum(n);
      const f = Math.floor((n - 1) / 3);
      expect(2 * q - n).toBeGreaterThanOrEqual(f + 1); // two quorums share >= f+1 -> an honest node
    }
  });
});

describe("bftHaltThreshold — max(f+1, 2), Infinity for n<=1", () => {
  test("n<=1 → Infinity (no peers to compare)", () => {
    expect(bftHaltThreshold(0)).toBe(Infinity);
    expect(bftHaltThreshold(1)).toBe(Infinity);
    expect(bftHaltThreshold(-3)).toBe(Infinity);
  });

  test("n=2 → 2 (only 1 other peer; threshold unreachable; ack-filter handles)", () => {
    expect(bftHaltThreshold(2)).toBe(2);
  });

  test("n=3 → 2 (floor; both other peers must disagree before halt)", () => {
    // Formal f+1 = 1, but a single disagreer carries no signal in n=3.
    // Floor of 2 protects honest pair from being halted by one bad node.
    expect(bftHaltThreshold(3)).toBe(2);
  });

  test("n=4 → 2 (formal f+1; floor redundant since f+1>=2)", () => {
    expect(bftHaltThreshold(4)).toBe(2);
  });

  test("n=5 → 2 (formal f+1)", () => {
    expect(bftHaltThreshold(5)).toBe(2);
  });

  test("n=6 → 2 (formal f+1)", () => {
    expect(bftHaltThreshold(6)).toBe(2);
  });

  test("n=7 → 3 (formal f+1)", () => {
    expect(bftHaltThreshold(7)).toBe(3);
  });

  test("n=10 → 4 (formal f+1)", () => {
    expect(bftHaltThreshold(10)).toBe(4);
  });

  test("n=100 → 34 (formal f+1)", () => {
    // f = floor(99/3) = 33, threshold = 34
    expect(bftHaltThreshold(100)).toBe(34);
  });

  test("non-numeric / nullish input → Infinity (defensive)", () => {
    expect(bftHaltThreshold(null)).toBe(Infinity);
    expect(bftHaltThreshold(undefined)).toBe(Infinity);
    expect(bftHaltThreshold("nope")).toBe(Infinity);
  });

  test("threshold is always <= committee size for n>=2 (otherwise unreachable)", () => {
    for (let n = 2; n <= 20; n++) {
      const t = bftHaltThreshold(n);
      expect(t).toBeLessThanOrEqual(n);
    }
  });

  test("threshold is monotonically non-decreasing in n (for n>=2)", () => {
    let prev = bftHaltThreshold(2);
    for (let n = 3; n <= 30; n++) {
      const cur = bftHaltThreshold(n);
      expect(cur).toBeGreaterThanOrEqual(prev);
      prev = cur;
    }
  });
});
