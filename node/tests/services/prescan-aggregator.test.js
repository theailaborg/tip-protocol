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
  isHardDegraded,
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
  test("non-finite probability (NaN) → degraded", () => {
    expect(isDegraded(M("text", NaN))).toBe(true);
  });
  test("undefined probability → degraded", () => {
    expect(isDegraded({ modality: "text" })).toBe(true);
  });
  test("Infinity probability → degraded (defensive)", () => {
    expect(isDegraded(M("text", Infinity))).toBe(true);
  });
});

// ── isHardDegraded ─────────────────────────────────────────────────────────
describe("isHardDegraded", () => {
  test("explicit error → hard-degraded", () => {
    expect(isHardDegraded(M("text", 0.3, { error: "fail" }))).toBe(true);
  });
  test("forced 0.5 neutral → hard-degraded", () => {
    expect(isHardDegraded(M("text", 0.5))).toBe(true);
  });
  test("non-finite probability → hard-degraded", () => {
    expect(isHardDegraded(M("text", NaN))).toBe(true);
    expect(isHardDegraded(M("text", Infinity))).toBe(true);
    expect(isHardDegraded({ modality: "text" })).toBe(true);
  });
  test("disagreement_override is soft-degraded, NOT hard-degraded", () => {
    const m = M("text", 0.21, { features_used: ["provider_ensemble", "disagreement_override"] });
    expect(isHardDegraded(m)).toBe(false);
    expect(isDegraded(m)).toBe(true);
  });
  test("clean result → not hard-degraded", () => {
    expect(isHardDegraded(M("text", 0.42))).toBe(false);
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
  test("leading undefined-prob entry doesn't block subsequent finite reading", () => {
    // Bug class: a first entry with prob=undefined would, under naive
    // `r.probability > prev.probability`, never be replaced because
    // `> undefined` is always false. The hardening treats non-finite as
    // -Infinity so the finite reading wins.
    const collapsed = collapseSameModality([
      { modality: "image" /* no probability */ },
      M("image", 0.80),
    ]);
    expect(collapsed).toHaveLength(1);
    expect(collapsed[0].probability).toBe(0.80);
  });
  test("leading NaN-prob entry doesn't block subsequent finite reading", () => {
    const collapsed = collapseSameModality([
      M("text", NaN),
      M("text", 0.42),
    ]);
    expect(collapsed).toHaveLength(1);
    expect(collapsed[0].probability).toBe(0.42);
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
  test("FIXED content type + hard-degraded primary (forced 0.5) → no-signal neutral, no secondary substitution", () => {
    // contentType=text, text=0.5 (forced neutral = hard-degraded), image=0.20.
    // Refined behavior: we don't substitute the image's verdict for the
    // missing text signal — the verdict is about the text, not the image.
    const r = aggregate(
      [M("text", 0.5), M("image", 0.20)],
      "text",
    );
    expect(r.probability).toBe(0.5);
    expect(r.overall_degraded).toBe(true);
    expect(r.overall_hard_degraded).toBe(true);
  });

  test("FIXED content type + hard-degraded primary (error) → no-signal neutral", () => {
    // contentType=text, text errored, image clean. Same refinement: image
    // is NOT a stand-in for the failed text scan.
    const r = aggregate(
      [M("text", 0.5, { error: "fail" }), M("image", 0.20)],
      "text",
    );
    expect(r.probability).toBe(0.5);
    expect(r.overall_degraded).toBe(true);
    expect(r.overall_hard_degraded).toBe(true);
  });

  test("FIXED content type=image + hard-degraded image + clean text caption → no-signal neutral (caption isn't a stand-in)", () => {
    // The motivating case: an Instagram-style post where the image fails
    // to scan but the caption text scans clean. We must NOT report the
    // caption's verdict as the post's verdict — the work is the image.
    const r = aggregate(
      [M("image", 0.5, { error: "model_crash" }), M("text", 0.05)],
      "image",
    );
    expect(r.probability).toBe(0.5);
    expect(r.overall_degraded).toBe(true);
    expect(r.overall_hard_degraded).toBe(true);
  });

  test("multi content_type + hard-degraded modality → still uses weighted_average (multi is intrinsically mixed)", () => {
    // multi differs from FIXED: blending across modalities IS the design
    // intent. Hard-degraded entries get half-weight via DEGRADED_MULTIPLIER.
    const r = aggregate(
      [M("text", 0.42), M("image", 0.5, { error: "fail" })],
      "multi",
    );
    expect(r.probability).not.toBe(0.5);
    expect(Number.isFinite(r.probability)).toBe(true);
    expect(r.overall_degraded).toBe(true);
    expect(r.overall_hard_degraded).toBe(true);
  });

  test("FIXED content type + SOFT-degraded primary (disagreement_override) → still uses fallback weighted_average", () => {
    // Soft-degraded primary means we DO have a real number from the
    // primary — just low confidence. Substituting/blending with
    // secondaries is fine (we're not pretending; the primary still
    // contributes). The hard-only short-circuit doesn't fire.
    const r = aggregate(
      [
        M("text", 0.30, { features_used: ["disagreement_override"] }),
        M("image", 0.20),
      ],
      "text",
    );
    expect(r.probability).not.toBe(0.5);
    expect(r.overall_degraded).toBe(true);
    expect(r.overall_hard_degraded).toBe(false);
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

  test("malformed primary (NaN probability) routes to no-signal neutral, not a fake 0 verdict", () => {
    // Without isDegraded's finite-probability check, NaN would propagate
    // through _weightedAverage and get masked to 0 by _clamp01 — a verdict
    // of "definitely human" that the classifier never produced.
    //
    // Under the FIXED-primary refinement, a hard-degraded primary doesn't
    // get its verdict substituted by secondaries — for content_type=text,
    // a NaN-probability text scan returns the no-signal neutral instead
    // of borrowing the image's clean number.
    const r = aggregate(
      [M("text", NaN), M("image", 0.85)],
      "text",
    );
    expect(r.overall_degraded).toBe(true);
    expect(r.overall_hard_degraded).toBe(true);
    expect(r.probability).toBe(0.5);
  });

  test("all modalities malformed (NaN) → 0.5 neutral, NOT 0", () => {
    // Previously _clamp01(NaN) returned 0; now non-finite final maps to
    // the no-signal neutral so downstream sees this as "unknown" rather
    // than "definitely human."
    const r = aggregate(
      [M("text", NaN), M("image", undefined)],
      "text",
    );
    expect(r.overall_degraded).toBe(true);
    expect(r.probability).toBe(0.5);
  });

  test("soft-only degraded (disagreement_override) ships through with real probability + overall_degraded=true", () => {
    // Live reproducer: classifier returns prob=0.2113 with
    // disagreement_override flagged because the statistical provider
    // skipped (text too short). The aggregator must NOT short-circuit
    // to 0.5 — the classifier's honest low-confidence answer is the
    // best we'll ever get for this input.
    const r = aggregate(
      [M("text", 0.2113, { features_used: ["provider_ensemble", "disagreement_override"] })],
      "text",
    );
    expect(close(r.probability, 0.2113, 1e-6)).toBe(true);
    expect(r.overall_degraded).toBe(true);
    expect(r.overall_hard_degraded).toBe(false);
  });

  test("overall_hard_degraded splits cleanly from overall_degraded", () => {
    // Soft only → degraded=true, hard_degraded=false
    const soft = aggregate(
      [M("text", 0.21, { features_used: ["disagreement_override"] })],
      "text",
    );
    expect(soft.overall_degraded).toBe(true);
    expect(soft.overall_hard_degraded).toBe(false);

    // Mixed (one hard + one clean) → both true
    const mixed = aggregate(
      [M("text", 0.5), M("image", 0.30)],
      "text",
    );
    expect(mixed.overall_degraded).toBe(true);
    expect(mixed.overall_hard_degraded).toBe(true);

    // All hard → both true, short-circuit
    const allHard = aggregate(
      [M("text", 0.5), M("image", 0.5, { error: "fail" })],
      "text",
    );
    expect(allHard.overall_degraded).toBe(true);
    expect(allHard.overall_hard_degraded).toBe(true);
    expect(allHard.probability).toBe(0.5);

    // Clean → both false
    const clean = aggregate([M("text", 0.42)], "text");
    expect(clean.overall_degraded).toBe(false);
    expect(clean.overall_hard_degraded).toBe(false);
  });

  test("enriched modality entries carry hard_degraded flag", () => {
    const r = aggregate(
      [
        M("text", 0.21, { features_used: ["disagreement_override"] }),
        M("image", 0.5, { error: "fail" }),
      ],
      "multi",
    );
    const text = r.modality_results.find(m => m.modality === "text");
    const image = r.modality_results.find(m => m.modality === "image");
    expect(text.degraded).toBe(true);
    expect(text.hard_degraded).toBe(false);
    expect(image.degraded).toBe(true);
    expect(image.hard_degraded).toBe(true);
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
