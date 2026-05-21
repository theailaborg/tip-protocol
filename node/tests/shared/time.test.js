/**
 * @file tests/shared/time.test.js
 * @description Locks the contract of the timestamp single-source-of-truth.
 *
 * Every site that produces or converts a timestamp in the codebase routes
 * through these four helpers. If any of these tests fail, downstream
 * determinism (tx_id, state_merkle_root, BFT-Time arithmetic) is at risk.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const { nowMs, nowIso, nowPlusMs, toIso, fromIso, isValidMs, MS_FLOOR_2025_01_01_UTC } = require(path.join(SHARED, "time"));

describe("nowMs", () => {
  test("returns an integer in the plausible 2025+ range", () => {
    const v = nowMs();
    expect(Number.isInteger(v)).toBe(true);
    expect(v).toBeGreaterThanOrEqual(MS_FLOOR_2025_01_01_UTC);
  });
});

describe("nowPlusMs", () => {
  test("adds the offset to nowMs() and returns ms", () => {
    const before = nowMs();
    const deadline = nowPlusMs(3600000); // 1h
    const after = nowMs();
    expect(deadline).toBeGreaterThanOrEqual(before + 3600000);
    expect(deadline).toBeLessThanOrEqual(after + 3600000);
  });

  test("handles zero offset (deadline == nowMs)", () => {
    const before = nowMs();
    const d = nowPlusMs(0);
    const after = nowMs();
    expect(d).toBeGreaterThanOrEqual(before);
    expect(d).toBeLessThanOrEqual(after);
  });

  test("rejects non-finite offsets", () => {
    expect(() => nowPlusMs(NaN)).toThrow(TypeError);
    expect(() => nowPlusMs(Infinity)).toThrow(TypeError);
    expect(() => nowPlusMs("3600000")).toThrow(TypeError);
    expect(() => nowPlusMs(null)).toThrow(TypeError);
    expect(() => nowPlusMs(undefined)).toThrow(TypeError);
  });
});

describe("nowIso", () => {
  test("returns a parseable ISO string for the current instant", () => {
    const iso = nowIso();
    expect(typeof iso).toBe("string");
    expect(iso).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    const back = fromIso(iso);
    expect(back).toBeGreaterThanOrEqual(MS_FLOOR_2025_01_01_UTC);
  });
});

describe("toIso", () => {
  test("formats the 2025 floor", () => {
    expect(toIso(MS_FLOOR_2025_01_01_UTC)).toBe("2025-01-01T00:00:00.000Z");
  });

  test("round-trips a known instant", () => {
    const ms = 1773532800000; // 2026-03-15T00:00:00.000Z — TIP genesis
    expect(toIso(ms)).toBe("2026-03-15T00:00:00.000Z");
  });

  test("formats historical / pre-2025 ms without rejection (output is permissive)", () => {
    // Output conversion stays loose so test fixtures and legitimate historical
    // ms values format cleanly. The ingress floor lives on isValidMs.
    expect(toIso(0)).toBe("1970-01-01T00:00:00.000Z");
    expect(toIso(MS_FLOOR_2025_01_01_UTC - 1)).toBe("2024-12-31T23:59:59.999Z");
  });

  test("rejects non-finite / wrong-type inputs", () => {
    expect(() => toIso(NaN)).toThrow(TypeError);
    expect(() => toIso(Infinity)).toThrow(TypeError);
    expect(() => toIso("1773532800000")).toThrow(TypeError);
    expect(() => toIso(null)).toThrow(TypeError);
    expect(() => toIso(undefined)).toThrow(TypeError);
  });
});

describe("fromIso", () => {
  test("parses an ISO string to ms", () => {
    expect(fromIso("2026-03-15T00:00:00.000Z")).toBe(1773532800000);
  });

  test("round-trips toIso → fromIso losslessly", () => {
    const ms = 1773792000123;
    expect(fromIso(toIso(ms))).toBe(ms);
  });

  test("throws on malformed input", () => {
    expect(() => fromIso("not-an-iso-string")).toThrow(TypeError);
    expect(() => fromIso("")).toThrow(TypeError);
    expect(() => fromIso(null)).toThrow(TypeError);
    expect(() => fromIso(undefined)).toThrow(TypeError);
  });
});

describe("isValidMs", () => {
  test("accepts a current timestamp", () => {
    expect(isValidMs(nowMs())).toBe(true);
  });

  test("accepts the 2025 floor exactly", () => {
    expect(isValidMs(MS_FLOOR_2025_01_01_UTC)).toBe(true);
  });

  test("rejects pre-2025 timestamps as implausible", () => {
    expect(isValidMs(0)).toBe(false);                   // epoch zero
    expect(isValidMs(1)).toBe(false);                   // jan 1 1970 + 1ms
    expect(isValidMs(99999)).toBe(false);               // jan 1 1970 + 99s
    expect(isValidMs(MS_FLOOR_2025_01_01_UTC - 1)).toBe(false); // dec 31 2024
  });

  test("catches the seconds-as-ms unit mix-up", () => {
    // Math.floor(nowMs() / 1000) — a common Unix idiom — passed where
    // ms was expected. The 10-digit value is multiple orders of magnitude
    // below the 13-digit ms floor for 2025.
    expect(isValidMs(1750000000)).toBe(false);   // ~Jun 2025 in seconds
    expect(isValidMs(1773792000)).toBe(false);   // TIP genesis in seconds
  });

  test("rejects non-integers", () => {
    expect(isValidMs(1.5)).toBe(false);
    expect(isValidMs(NaN)).toBe(false);
    expect(isValidMs(Infinity)).toBe(false);
    expect(isValidMs("1735689600000")).toBe(false);
    expect(isValidMs(null)).toBe(false);
    expect(isValidMs(undefined)).toBe(false);
  });

  test("rejects values above MAX_SAFE_INTEGER", () => {
    expect(isValidMs(Number.MAX_SAFE_INTEGER + 1)).toBe(false);
  });
});
