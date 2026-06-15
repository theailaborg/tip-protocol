/**
 * @file tests/services/classifier-local.test.js
 * @description Local fallback classifier — response shape parity with
 * the real client, heuristic text verdicts, stub media values, runtime
 * fallback wrapper semantics, and worker integration.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));
const {
  createLocalClassifierClient,
  createFallbackClassifierClient,
  MEDIA_STUB_PROBABILITY,
} = require(path.join(SRC, "services/classifier-local"));
const { isSkipped, isHeuristicOnly } = require(path.join(SRC, "services/classifier-client"));

beforeAll(() => {
  try { PC._resetForTesting(); } catch { /* not yet initialised */ }
  PC.init(getGenesisPayload().protocol_constants);
});

// A paragraph long enough to clear preScanContent's <20-word early-out
// so the heuristic actually runs.
const LONG_TEXT = Array.from({ length: 60 }, (_, i) => `word${i} flows naturally here and`).join(" ");

describe("local classifier — text", () => {
  test("OH text → heuristic-derived probability, provider local_fallback", async () => {
    const client = createLocalClassifierClient();
    const r = await client.prescan({ originCode: "OH", text: LONG_TEXT });

    expect(r.modality_results).toHaveLength(1);
    const m = r.modality_results[0];
    expect(m.modality).toBe("text");
    expect(typeof m.probability).toBe("number");
    expect(m.probability).toBeGreaterThanOrEqual(0);
    expect(m.probability).toBeLessThanOrEqual(1);
    expect(m.provider).toBe("local_fallback");
    expect(m.error).toBeNull();
    expect(r.provider_used).toBe("local_fallback");
  });

  test("not flagged as heuristic-only degraded, not flagged as skipped", async () => {
    // provider_used is "local_fallback", deliberately NOT "heuristic" —
    // the verdict should commit cleanly, with provenance on the
    // providers string, instead of burning the retry budget.
    const client = createLocalClassifierClient();
    const r = await client.prescan({ originCode: "OH", text: LONG_TEXT });
    expect(isHeuristicOnly(r)).toBe(false);
    expect(isSkipped(r)).toBe(false);
  });
});

describe("local classifier — media stubs", () => {
  test("image file → neutral 0.5 stub, modality image", async () => {
    const client = createLocalClassifierClient();
    const r = await client.prescan({
      originCode: "OH", text: "",
      file: { base64: "aGk=", mime: "image/png" },
    });
    expect(r.modality_results).toHaveLength(1);
    expect(r.modality_results[0].modality).toBe("image");
    expect(r.modality_results[0].probability).toBe(MEDIA_STUB_PROBABILITY);
    expect(r.modality_results[0].provider).toBe("local_fallback_stub");
  });

  test("audio mime maps to audio modality", async () => {
    const client = createLocalClassifierClient();
    const r = await client.prescan({
      originCode: "OH", text: "",
      file: { base64: "aGk=", mime: "audio/mpeg" },
    });
    expect(r.modality_results[0].modality).toBe("audio");
  });

  test("text + image together → both modalities in one response", async () => {
    const client = createLocalClassifierClient();
    const r = await client.prescan({
      originCode: "OH", text: LONG_TEXT,
      file: { base64: "aGk=", mime: "image/png" },
    });
    const kinds = r.modality_results.map(m => m.modality).sort();
    expect(kinds).toEqual(["image", "text"]);
  });
});

describe("local classifier — non-OH skip parity", () => {
  test("AG origin → locally_skipped, same contract as the real client", async () => {
    const client = createLocalClassifierClient();
    const r = await client.prescan({ originCode: "AG", text: LONG_TEXT });
    expect(isSkipped(r)).toBe(true);
    expect(r.modality_results).toEqual([]);
  });
});

describe("fallback wrapper", () => {
  test("network error from primary → warns and serves the local verdict", async () => {
    const primary = {
      prescan: async () => { const e = new Error("fetch failed"); throw e; },
      stage1: async () => ({}), providers: async () => ({}), health: async () => ({}),
    };
    const warnings = [];
    const wrapped = createFallbackClassifierClient({
      primary, log: { warn: (m) => warnings.push(m) },
    });
    const r = await wrapped.prescan({ originCode: "OH", text: LONG_TEXT });
    expect(r.provider_used).toBe("local_fallback");
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/LOCAL FALLBACK/);
  });

  test("ECONNREFUSED in error cause also triggers fallback", async () => {
    const err = new Error("request to http://classifier:8000 failed");
    err.cause = { code: "ECONNREFUSED" };
    const primary = {
      prescan: async () => { throw err; },
      stage1: async () => ({}), providers: async () => ({}), health: async () => ({}),
    };
    const wrapped = createFallbackClassifierClient({ primary, log: { warn: () => { } } });
    const r = await wrapped.prescan({ originCode: "OH", text: LONG_TEXT });
    expect(r.provider_used).toBe("local_fallback");
  });

  test("non-network error still throws (API contract problems stay loud)", async () => {
    const primary = {
      prescan: async () => { throw new Error("classifier rejected payload: video not supported"); },
      stage1: async () => ({}), providers: async () => ({}), health: async () => ({}),
    };
    const wrapped = createFallbackClassifierClient({ primary, log: { warn: () => { } } });
    await expect(wrapped.prescan({ originCode: "OH", text: LONG_TEXT }))
      .rejects.toThrow(/video not supported/);
  });

  test("healthy primary passes through untouched", async () => {
    const real = { probability: 0.42, provider_used: "ensemble", modality_results: [] };
    const primary = {
      prescan: async () => real,
      stage1: async () => ({}), providers: async () => ({}), health: async () => ({}),
    };
    const wrapped = createFallbackClassifierClient({ primary, log: { warn: () => { } } });
    expect(await wrapped.prescan({ originCode: "OH", text: LONG_TEXT })).toBe(real);
  });
});
