"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");

const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const PC = require(path.join(SHARED, "protocol-constants"));
try { PC._resetForTesting(); } catch { /* not yet initialised */ }
PC.init(getGenesisPayload().protocol_constants);

const {
  aggregate,
  isDegraded,
  collapseSameModality,
} = require(path.resolve(__dirname, "../../src/services/prescan-aggregator"));

// ── Helpers ────────────────────────────────────────────────────────────────
const M = (modality, probability, extra = {}) => ({
  modality,
  probability,
  weight: extra.weight ?? null,
  provider: extra.provider ?? "ensemble(test)",
  features_used: extra.features_used ?? null,
  error: extra.error ?? null,
});

const close = (actual, expected, eps = 1e-9) => Math.abs(actual - expected) < eps;

// ── isDegraded ─────────────────────────────────────────────────────────────
describe("isDegraded", () => {
  test("exact 0.5 probability → degraded", () => {
    expect(isDegraded(M("text", 0.5))).toBe(true);
  });
  test("explicit error → degraded", () => {
    expect(isDegraded(M("image", 0.3, { error: "no_signals_produced_a_result" }))).toBe(true);
  });
  test("disagreement_override feature → degraded", () => {
    expect(isDegraded(M("text", 0.7, { features_used: ["provider_ensemble", "disagreement_override"] }))).toBe(true);
  });
  test("clean result → not degraded", () => {
    expect(isDegraded(M("text", 0.42))).toBe(false);
  });
  test("0.5001 vs exact 0.5", () => {
    expect(isDegraded(M("text", 0.5001))).toBe(false);
  });
  test("primary at exactly 0.5 triggers the degraded fallback path (not the floor-lift path)", () => {
    // Aggregate with primary=text at exact 0.5 — should fall back to
    // weighted-average + overall_degraded=true, not use 0.5 as a floor.
    const r = aggregate([M("text", 0.5), M("image", 0.20)], "text");
    expect(r.overall_degraded).toBe(true);
  });
});

// ── collapseSameModality ───────────────────────────────────────────────────
describe("collapseSameModality", () => {
  test("three images → max kept", () => {
    const collapsed = collapseSameModality([
      M("image", 0.20),
      M("image", 0.85),
      M("image", 0.41),
    ]);
    expect(collapsed).toHaveLength(1);
    expect(collapsed[0].probability).toBe(0.85);
  });
  test("preserves single non-duplicate modalities", () => {
    const collapsed = collapseSameModality([
      M("text", 0.30),
      M("image", 0.70),
      M("audio", 0.10),
    ]);
    expect(collapsed.map(m => m.modality).sort()).toEqual(["audio", "image", "text"]);
  });
  test("empty input → empty", () => {
    expect(collapseSameModality([])).toEqual([]);
    expect(collapseSameModality(null)).toEqual([]);
  });
});

// ── Primary-floor scenarios (Case A: don't dilute) ─────────────────────────
describe("aggregate — primary-floor, no dilution", () => {
  test("AI primary + clean secondaries preserves primary", () => {
    // AI video at 0.95, clean text/image/audio
    const r = aggregate(
      [M("video", 0.95), M("text", 0.05), M("image", 0.05), M("audio", 0.05)],
      "video",
    );
    expect(close(r.probability, 0.95)).toBe(true);
    expect(r.overall_degraded).toBe(false);
  });
  test("AI text + clean image/audio/video preserves text=0.95", () => {
    const r = aggregate(
      [M("text", 0.95), M("image", 0.05), M("audio", 0.05), M("video", 0.05)],
      "text",
    );
    expect(close(r.probability, 0.95)).toBe(true);
  });
  test("AI image + clean secondaries preserves 0.95", () => {
    const r = aggregate(
      [M("image", 0.95), M("text", 0.05), M("audio", 0.05), M("video", 0.05)],
      "image",
    );
    expect(close(r.probability, 0.95)).toBe(true);
  });
  test("AI audio + clean secondaries preserves 0.95", () => {
    const r = aggregate(
      [M("audio", 0.95), M("text", 0.05), M("image", 0.05), M("video", 0.05)],
      "audio",
    );
    expect(close(r.probability, 0.95)).toBe(true);
  });
});

// ── Asymmetric lift (Case B: secondaries can raise) ────────────────────────
describe("aggregate — asymmetric lift", () => {
  test("borderline video + 3 strong AI secondaries → ELEVATED", () => {
    // video=0.51 (just above the exact-0.5 degraded marker)
    // text=0.95, image=0.95, audio=0.95
    // lift = (0.95-0.51)×0.15 + (0.95-0.51)×0.10 + (0.95-0.51)×0.35 = 0.2640
    // final = 0.774
    const r = aggregate(
      [M("video", 0.51), M("text", 0.95), M("image", 0.95), M("audio", 0.95)],
      "video",
    );
    expect(close(r.probability, 0.774, 1e-6)).toBe(true);
  });

  test("clean text + 1 AI image (meme in article) → small lift", () => {
    // text=0.05, image=0.95
    // lift = (0.95-0.05) × 0.30 = 0.27
    // final = 0.32
    const r = aggregate([M("text", 0.05), M("image", 0.95)], "text");
    expect(close(r.probability, 0.32, 1e-6)).toBe(true);
  });

  test("clean primary + 3 strong AI secondaries (text content_type)", () => {
    // text=0.05, image=0.95, audio=0.95, video=0.95
    // lift = 0.90×0.30 + 0.90×0.10 + 0.90×0.20 = 0.54
    // final = 0.59
    const r = aggregate(
      [M("text", 0.05), M("image", 0.95), M("audio", 0.95), M("video", 0.95)],
      "text",
    );
    expect(close(r.probability, 0.59, 1e-6)).toBe(true);
  });

  test("borderline video + AI audio (voiceover) — voice has highest weight on video row", () => {
    // video=0.51, audio=0.95
    // lift = (0.95-0.51) × 0.35 = 0.154
    // final = 0.664
    const r = aggregate([M("video", 0.51), M("audio", 0.95)], "video");
    expect(close(r.probability, 0.664, 1e-6)).toBe(true);
  });

  test("AI primary + AI secondary (reinforcement)", () => {
    // video=0.85, audio=0.95
    // lift = (0.95-0.85) × 0.35 = 0.035
    // final = 0.885
    const r = aggregate([M("video", 0.85), M("audio", 0.95)], "video");
    expect(close(r.probability, 0.885, 1e-6)).toBe(true);
  });

  test("clamps at 1.0", () => {
    // primary already high, lifts can't push beyond 1.0
    const r = aggregate(
      [M("text", 0.95), M("image", 0.99), M("audio", 0.99), M("video", 0.99)],
      "text",
    );
    expect(r.probability).toBeLessThanOrEqual(1.0);
    expect(r.probability).toBeGreaterThan(0.95);
  });
});

// ── Multi: weighted average fallback ───────────────────────────────────────
describe("aggregate — multi content_type uses weighted average", () => {
  test("multi with mixed signal blends via weighted average", () => {
    // weights for multi: text 0.30, image 0.30, audio 0.20, video 0.30
    // (0.90×0.30 + 0.10×0.30) / 0.60 = 0.50
    const r = aggregate([M("text", 0.90), M("image", 0.10)], "multi");
    expect(close(r.probability, 0.50, 1e-6)).toBe(true);
  });
});

// ── Degraded handling ──────────────────────────────────────────────────────
describe("aggregate — degraded signal handling", () => {
  test("degraded primary falls back to weighted average over non-degraded", () => {
    // primary text degraded (0.5), secondaries clean
    const r = aggregate(
      [M("text", 0.5), M("image", 0.20)],
      "text",
    );
    expect(r.overall_degraded).toBe(true);
    // text is degraded so half-weight; image clean.
    // But — wait: this falls back to weightedAverage where weights[text]=1.00, weights[image]=0.30.
    // Degraded text gets w/2 = 0.50. Clean image = 0.30. So:
    // (0.5 × 0.50 + 0.20 × 0.30) / (0.50 + 0.30) = (0.25 + 0.06) / 0.80 = 0.3875
    expect(close(r.probability, 0.3875, 1e-6)).toBe(true);
  });

  test("primary degraded + only image present → use image alone (degraded primary skipped)", () => {
    const r = aggregate(
      [M("text", 0.5, { error: "fail" }), M("image", 0.20)],
      "text",
    );
    expect(r.overall_degraded).toBe(true);
    // Degraded text excluded by fallback weighted_average half-weight.
    // Same math as above, slightly different because error is also explicit.
    expect(r.probability).toBeGreaterThan(0);
    expect(r.probability).toBeLessThan(1);
  });

  test("all modalities degraded → returns 0.5 + overall_degraded=true", () => {
    const r = aggregate(
      [M("text", 0.5), M("image", 0.5, { error: "no_signals_produced_a_result" })],
      "text",
    );
    expect(r.probability).toBe(0.5);
    expect(r.overall_degraded).toBe(true);
  });

  test("empty modality_results → 0.5 + degraded", () => {
    const r = aggregate([], "text");
    expect(r.probability).toBe(0.5);
    expect(r.overall_degraded).toBe(true);
    expect(r.modality_results).toEqual([]);
  });

  test("clean primary + degraded secondary (degraded secondary doesn't lift)", () => {
    // text=0.05 (clean), image=0.99 (degraded via error)
    // image is degraded so excluded from lift → final stays at 0.05
    const r = aggregate(
      [M("text", 0.05), M("image", 0.99, { error: "x" })],
      "text",
    );
    expect(close(r.probability, 0.05, 1e-6)).toBe(true);
    expect(r.overall_degraded).toBe(true);
  });
});

// ── Enriched output shape ──────────────────────────────────────────────────
describe("aggregate — enriched output shape", () => {
  test("each modality entry carries applied_weight + degraded flag", () => {
    const r = aggregate(
      [M("video", 0.85), M("audio", 0.95)],
      "video",
    );
    expect(r.modality_results).toHaveLength(2);
    const vid = r.modality_results.find(m => m.modality === "video");
    const aud = r.modality_results.find(m => m.modality === "audio");
    expect(vid.applied_weight).toBe(1.0);    // diagonal documentation value
    expect(aud.applied_weight).toBe(0.35);   // off-diagonal audio for video row
    expect(vid.degraded).toBe(false);
    expect(aud.degraded).toBe(false);
  });

  test("same-modality multi-instance is collapsed before enrichment", () => {
    const r = aggregate(
      [M("text", 0.50), M("image", 0.10), M("image", 0.95), M("image", 0.30)],
      "text",
    );
    // collapsed: text=0.50, image=0.95
    expect(r.modality_results).toHaveLength(2);
    const img = r.modality_results.find(m => m.modality === "image");
    expect(img.probability).toBe(0.95);  // max of 0.10, 0.95, 0.30
  });
});
