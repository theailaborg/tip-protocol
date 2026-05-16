/**
 * @file tests/services/prescan-tier.test.js
 * @description Unit tests for the 4-tier prescan model.
 *
 * Covers:
 *   - computeRawTier(probability) — pure threshold mapping
 *   - adjustTier(rawTier, history) — creator-history calibration (Claim Group G)
 *   - preScanContent() — full pipeline returns probability + raw_tier + tier
 *
 * Calibration semantics:
 *   - LOW / ELEVATED never adjusted (already non-flagged)
 *   - Moderate (50+ verified_oh): HIGH → ELEVATED only
 *   - Veteran (200+ verified_oh): HIGH → ELEVATED, CRITICAL → HIGH
 *   - Never 2-tier shifts — prevents gaming at 0.98+
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");

const { PRESCAN_TIERS } = require(path.join(SHARED, "constants"));
const {
  preScanContent,
  computeRawTier,
  adjustTier,
  getTierThresholds,
} = require(path.join(SRC, "services", "helpers"));

describe("computeRawTier — probability → tier mapping (spec-pure)", () => {
  test("below elevated threshold → LOW", () => {
    expect(computeRawTier(0.0)).toBe(PRESCAN_TIERS.LOW);
    expect(computeRawTier(0.45)).toBe(PRESCAN_TIERS.LOW);
    expect(computeRawTier(0.69)).toBe(PRESCAN_TIERS.LOW);
  });

  test("[0.70, 0.90) → ELEVATED", () => {
    expect(computeRawTier(0.70)).toBe(PRESCAN_TIERS.ELEVATED);
    expect(computeRawTier(0.75)).toBe(PRESCAN_TIERS.ELEVATED);
    expect(computeRawTier(0.89)).toBe(PRESCAN_TIERS.ELEVATED);
  });

  test("[0.90, 0.98) → HIGH", () => {
    expect(computeRawTier(0.90)).toBe(PRESCAN_TIERS.HIGH);
    expect(computeRawTier(0.92)).toBe(PRESCAN_TIERS.HIGH);
    expect(computeRawTier(0.97)).toBe(PRESCAN_TIERS.HIGH);
  });

  test("[0.98, 1.0] → CRITICAL", () => {
    expect(computeRawTier(0.98)).toBe(PRESCAN_TIERS.CRITICAL);
    expect(computeRawTier(0.99)).toBe(PRESCAN_TIERS.CRITICAL);
    expect(computeRawTier(1.0)).toBe(PRESCAN_TIERS.CRITICAL);
  });

  test("contentType parameter accepted but ignored in v1", () => {
    // v2 hook — same probability returns same tier regardless of contentType
    expect(computeRawTier(0.92, "legal")).toBe(PRESCAN_TIERS.HIGH);
    expect(computeRawTier(0.92, "conversational")).toBe(PRESCAN_TIERS.HIGH);
    expect(computeRawTier(0.92, null)).toBe(PRESCAN_TIERS.HIGH);
  });
});

describe("getTierThresholds — content-type fusable hook", () => {
  test("returns spec defaults regardless of contentType in v1", () => {
    const def = getTierThresholds();
    expect(def.elevated).toBe(0.70);
    expect(def.high).toBe(0.90);
    expect(def.critical).toBe(0.98);

    // v2 hook: contentType is accepted but currently ignored
    expect(getTierThresholds("legal")).toEqual(def);
    expect(getTierThresholds("conversational")).toEqual(def);
  });
});

describe("adjustTier — creator-history calibration (Claim G)", () => {
  describe("LOW + ELEVATED never adjusted", () => {
    test.each([
      [{ verified_oh_count: 0 }],
      [{ verified_oh_count: 50 }],
      [{ verified_oh_count: 200 }],
      [{ verified_oh_count: 1000 }],
    ])("LOW stays LOW for any history (%j)", (history) => {
      expect(adjustTier(PRESCAN_TIERS.LOW, history)).toBe(PRESCAN_TIERS.LOW);
    });

    test.each([
      [{ verified_oh_count: 0 }],
      [{ verified_oh_count: 50 }],
      [{ verified_oh_count: 200 }],
      [{ verified_oh_count: 1000 }],
    ])("ELEVATED stays ELEVATED for any history (%j)", (history) => {
      expect(adjustTier(PRESCAN_TIERS.ELEVATED, history)).toBe(PRESCAN_TIERS.ELEVATED);
    });
  });

  describe("New creator (< 50 verified) — no shift", () => {
    test("HIGH stays HIGH", () => {
      expect(adjustTier(PRESCAN_TIERS.HIGH, { verified_oh_count: 0 })).toBe(PRESCAN_TIERS.HIGH);
      expect(adjustTier(PRESCAN_TIERS.HIGH, { verified_oh_count: 49 })).toBe(PRESCAN_TIERS.HIGH);
    });

    test("CRITICAL stays CRITICAL", () => {
      expect(adjustTier(PRESCAN_TIERS.CRITICAL, { verified_oh_count: 0 })).toBe(PRESCAN_TIERS.CRITICAL);
      expect(adjustTier(PRESCAN_TIERS.CRITICAL, { verified_oh_count: 49 })).toBe(PRESCAN_TIERS.CRITICAL);
    });
  });

  describe("Moderate creator (50-199 verified) — HIGH only demoted", () => {
    test("HIGH → ELEVATED", () => {
      expect(adjustTier(PRESCAN_TIERS.HIGH, { verified_oh_count: 50 })).toBe(PRESCAN_TIERS.ELEVATED);
      expect(adjustTier(PRESCAN_TIERS.HIGH, { verified_oh_count: 100 })).toBe(PRESCAN_TIERS.ELEVATED);
      expect(adjustTier(PRESCAN_TIERS.HIGH, { verified_oh_count: 199 })).toBe(PRESCAN_TIERS.ELEVATED);
    });

    test("CRITICAL stays CRITICAL (too suspicious to demote at 0.98+)", () => {
      expect(adjustTier(PRESCAN_TIERS.CRITICAL, { verified_oh_count: 50 })).toBe(PRESCAN_TIERS.CRITICAL);
      expect(adjustTier(PRESCAN_TIERS.CRITICAL, { verified_oh_count: 199 })).toBe(PRESCAN_TIERS.CRITICAL);
    });
  });

  describe("Veteran creator (200+ verified) — one-tier demotion at HIGH and CRITICAL", () => {
    test("HIGH → ELEVATED", () => {
      expect(adjustTier(PRESCAN_TIERS.HIGH, { verified_oh_count: 200 })).toBe(PRESCAN_TIERS.ELEVATED);
      expect(adjustTier(PRESCAN_TIERS.HIGH, { verified_oh_count: 500 })).toBe(PRESCAN_TIERS.ELEVATED);
    });

    test("CRITICAL → HIGH (never 2-tier shift to ELEVATED)", () => {
      expect(adjustTier(PRESCAN_TIERS.CRITICAL, { verified_oh_count: 200 })).toBe(PRESCAN_TIERS.HIGH);
      expect(adjustTier(PRESCAN_TIERS.CRITICAL, { verified_oh_count: 1000 })).toBe(PRESCAN_TIERS.HIGH);
    });
  });

  describe("Missing or malformed history defaults to new-creator", () => {
    test("null history → no shift", () => {
      expect(adjustTier(PRESCAN_TIERS.HIGH, null)).toBe(PRESCAN_TIERS.HIGH);
      expect(adjustTier(PRESCAN_TIERS.CRITICAL, null)).toBe(PRESCAN_TIERS.CRITICAL);
    });

    test("undefined history → no shift", () => {
      expect(adjustTier(PRESCAN_TIERS.HIGH, undefined)).toBe(PRESCAN_TIERS.HIGH);
    });

    test("history without verified_oh_count → no shift", () => {
      expect(adjustTier(PRESCAN_TIERS.HIGH, {})).toBe(PRESCAN_TIERS.HIGH);
    });
  });
});

describe("preScanContent — end-to-end pipeline", () => {
  // Content engineered to score high on the classifier features:
  // long words + low unique ratio + few sentences
  const HIGH_PROB_TEXT = "Furthermore furthermore furthermore furthermore furthermore "
    + "comprehensive comprehensive comprehensive comprehensive comprehensive "
    + "additionally additionally additionally additionally additionally "
    + "moreover moreover moreover moreover moreover";

  test("AG origin → skips prescan (already maximally discloses AI)", () => {
    const r = preScanContent(HIGH_PROB_TEXT, "AG", { verified_oh_count: 0 });
    expect(r.flagged).toBe(false);
    expect(r.probability).toBe(0);
    expect(r.tier).toBe(PRESCAN_TIERS.LOW);
    expect(r.raw_tier).toBe(PRESCAN_TIERS.LOW);
  });

  test("MX origin → skips prescan (already discloses mixed)", () => {
    const r = preScanContent(HIGH_PROB_TEXT, "MX", { verified_oh_count: 0 });
    expect(r.flagged).toBe(false);
    expect(r.probability).toBe(0);
    expect(r.tier).toBe(PRESCAN_TIERS.LOW);
    expect(r.raw_tier).toBe(PRESCAN_TIERS.LOW);
  });

  test("AA origin → runs prescan (catches AA→AG under-declaration)", () => {
    // AA claims human-primary with AI help; classifier flag means content
    // looks fully AI → creator should reconsider AG
    const ohResult = preScanContent(HIGH_PROB_TEXT, "OH", { verified_oh_count: 0 });
    const aaResult = preScanContent(HIGH_PROB_TEXT, "AA", { verified_oh_count: 0 });

    // Same content → same classifier output regardless of origin code
    expect(aaResult.probability).toBe(ohResult.probability);
    expect(aaResult.raw_tier).toBe(ohResult.raw_tier);
    expect(aaResult.tier).toBe(ohResult.tier);
  });

  test("short content (<20 words) → low tier without classifier", () => {
    const r = preScanContent("short text", "OH", { verified_oh_count: 0 });
    expect(r.flagged).toBe(false);
    expect(r.tier).toBe(PRESCAN_TIERS.LOW);
    expect(r.raw_tier).toBe(PRESCAN_TIERS.LOW);
  });

  test("returns both raw_tier and tier on every call", () => {
    const r = preScanContent(HIGH_PROB_TEXT, "OH", { verified_oh_count: 0 });
    expect(r).toHaveProperty("probability");
    expect(r).toHaveProperty("raw_tier");
    expect(r).toHaveProperty("tier");
    expect(r).toHaveProperty("flagged");
  });

  test("calibration applied: same content + same probability, veteran demoted vs new creator", () => {
    const newCreator = preScanContent(HIGH_PROB_TEXT, "OH", { verified_oh_count: 0 });
    const veteran = preScanContent(HIGH_PROB_TEXT, "OH", { verified_oh_count: 300 });

    // Same probability (same content, same feature extraction)
    expect(newCreator.probability).toBe(veteran.probability);

    // Same raw_tier (calibration doesn't affect raw)
    expect(newCreator.raw_tier).toBe(veteran.raw_tier);

    // If raw_tier ended up HIGH or CRITICAL, calibrated tier should differ
    if (newCreator.raw_tier === PRESCAN_TIERS.HIGH) {
      expect(newCreator.tier).toBe(PRESCAN_TIERS.HIGH);     // no shift for new
      expect(veteran.tier).toBe(PRESCAN_TIERS.ELEVATED);    // veteran demoted
    }
    if (newCreator.raw_tier === PRESCAN_TIERS.CRITICAL) {
      expect(newCreator.tier).toBe(PRESCAN_TIERS.CRITICAL); // no shift for new
      expect(veteran.tier).toBe(PRESCAN_TIERS.HIGH);        // veteran demoted
    }
  });

  test("legacy flagged boolean still computed for back-compat", () => {
    const r = preScanContent(HIGH_PROB_TEXT, "OH", { verified_oh_count: 0 });
    expect(typeof r.flagged).toBe("boolean");
    // flagged uses the legacy adaptive threshold (0.85 default for new creators)
  });
});

describe("Spec calibration table — 9 illustrative examples", () => {
  // Verifies the calibration matrix matches the design doc's example table.
  // Each row: rawTier (from probability) + history → calibrated tier.
  test.each([
    // probability proxy → raw_tier        creator history             expected calibrated tier
    [PRESCAN_TIERS.LOW, { verified_oh_count: 0 }, PRESCAN_TIERS.LOW],
    [PRESCAN_TIERS.ELEVATED, { verified_oh_count: 0 }, PRESCAN_TIERS.ELEVATED],
    [PRESCAN_TIERS.ELEVATED, { verified_oh_count: 500 }, PRESCAN_TIERS.ELEVATED],
    [PRESCAN_TIERS.HIGH, { verified_oh_count: 0 }, PRESCAN_TIERS.HIGH],
    [PRESCAN_TIERS.HIGH, { verified_oh_count: 60 }, PRESCAN_TIERS.ELEVATED],
    [PRESCAN_TIERS.HIGH, { verified_oh_count: 300 }, PRESCAN_TIERS.ELEVATED],
    [PRESCAN_TIERS.CRITICAL, { verified_oh_count: 0 }, PRESCAN_TIERS.CRITICAL],
    [PRESCAN_TIERS.CRITICAL, { verified_oh_count: 60 }, PRESCAN_TIERS.CRITICAL],
    [PRESCAN_TIERS.CRITICAL, { verified_oh_count: 300 }, PRESCAN_TIERS.HIGH],
  ])("%s + %j → %s", (rawTier, history, expected) => {
    expect(adjustTier(rawTier, history)).toBe(expected);
  });
});
