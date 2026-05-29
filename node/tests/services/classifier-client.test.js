"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");

const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const PC = require(path.join(SHARED, "protocol-constants"));
try { PC._resetForTesting(); } catch { /* not yet initialised */ }
PC.init(getGenesisPayload().protocol_constants);

const {
  createClassifierClient,
  isHeuristicOnly,
  isSkipped,
} = require(path.resolve(__dirname, "../../src/services/classifier-client"));

// ── Mock fetch helpers ─────────────────────────────────────────────────────
function mockFetch(responder) {
  const calls = [];
  async function fetchImpl(url, init) {
    calls.push({ url, init: init || {} });
    const result = typeof responder === "function" ? responder(url, init) : responder;
    const r = result instanceof Promise ? await result : result;
    return {
      status: r.status ?? 200,
      text: async () => typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {}),
    };
  }
  return Object.assign(fetchImpl, { calls });
}

function clientWith(responder, opts = {}) {
  const fetch = mockFetch(responder);
  const client = createClassifierClient({
    url: "http://classifier-test:6060",
    fetch,
    ...opts,
  });
  return { client, fetch };
}

// ── Configuration ──────────────────────────────────────────────────────────
describe("createClassifierClient — config", () => {
  test("throws when neither opts.url nor TIP_CLASSIFIER_URL is set", () => {
    const saved = process.env.TIP_CLASSIFIER_URL;
    delete process.env.TIP_CLASSIFIER_URL;
    try {
      expect(() => createClassifierClient({ fetch: () => ({}) }))
        .toThrow(/TIP_CLASSIFIER_URL env var is not set/);
    } finally {
      if (saved !== undefined) process.env.TIP_CLASSIFIER_URL = saved;
    }
  });

  test("reads URL from TIP_CLASSIFIER_URL when opts.url is absent", () => {
    const saved = process.env.TIP_CLASSIFIER_URL;
    process.env.TIP_CLASSIFIER_URL = "http://env-classifier:9999";
    try {
      const c = createClassifierClient({ fetch: () => ({ status: 200, text: async () => "{}" }) });
      expect(c).toBeDefined();
    } finally {
      if (saved === undefined) delete process.env.TIP_CLASSIFIER_URL;
      else process.env.TIP_CLASSIFIER_URL = saved;
    }
  });
});

// ── prescan — happy path ──────────────────────────────────────────────────
describe("prescan", () => {
  test("OH text content → POST /v1/prescan with required fields", async () => {
    const { client, fetch } = clientWith(() => ({
      body: { flagged: false, probability: 0.31, modality_results: [], modalities_analyzed: ["text"], provider_used: "ensemble(...)" },
    }));
    const r = await client.prescan({ originCode: "OH", text: "hello world" });
    expect(fetch.calls).toHaveLength(1);
    expect(fetch.calls[0].url).toBe("http://classifier-test:6060/v1/prescan");
    const body = JSON.parse(fetch.calls[0].init.body);
    expect(body.origin_code).toBe("OH");
    expect(body.text).toBe("hello world");
    expect(body.provider_preference).toBe("ensemble");
    expect(body.creator_cleared_count).toBe(0);
    expect(r.probability).toBe(0.31);
  });

  test("empty text + image file → text='' still sent (API requires the field)", async () => {
    const { client, fetch } = clientWith(() => ({
      body: { flagged: false, probability: 0.42, modalities_analyzed: ["image"], provider_used: "image_detector" },
    }));
    await client.prescan({
      originCode: "OH",
      file: { base64: "<<<b64>>>", mime: "image/png" },
    });
    const body = JSON.parse(fetch.calls[0].init.body);
    expect(body.text).toBe("");
    expect(body.file_base64).toBe("<<<b64>>>");
    expect(body.file_mime_type).toBe("image/png");
  });

  test("non-OH origin → locally skipped without round-trip", async () => {
    const { client, fetch } = clientWith(() => ({ body: { error: "should-not-be-called" } }));
    const r = await client.prescan({ originCode: "AG", text: "x" });
    expect(fetch.calls).toHaveLength(0);
    expect(r.flagged).toBe(false);
    expect(r.probability).toBe(0);
    expect(r.provider_used).toBe("skipped_locally");
    expect(r.locally_skipped).toBe(true);
  });

  test("invalid origin_code → throws before fetch", async () => {
    const { client, fetch } = clientWith(() => ({ body: { error: "x" } }));
    await expect(client.prescan({ originCode: "XX" })).rejects.toMatchObject({
      code: "invalid_origin_code",
    });
    expect(fetch.calls).toHaveLength(0);
  });

  test("video file → rejected before fetch (v1 block)", async () => {
    const { client, fetch } = clientWith(() => ({ body: { x: 1 } }));
    await expect(
      client.prescan({ originCode: "OH", file: { base64: "x", mime: "video/mp4" } })
    ).rejects.toMatchObject({
      code: "video_unsupported_v1",
      status: 415,
    });
    expect(fetch.calls).toHaveLength(0);
  });

  test("HTTP 500 from classifier → throws classifier_http_error", async () => {
    const { client } = clientWith(() => ({ status: 500, body: "Internal Server Error" }));
    await expect(client.prescan({ originCode: "OH", text: "x" })).rejects.toMatchObject({
      code: "classifier_http_error",
      status: 500,
    });
  });

  test("X-TIP-Classifier-Key header sent when key configured", async () => {
    const { client, fetch } = clientWith(
      () => ({ body: { probability: 0.1 } }),
      { key: "test-secret-key" },
    );
    await client.prescan({ originCode: "OH", text: "x" });
    expect(fetch.calls[0].init.headers["X-TIP-Classifier-Key"]).toBe("test-secret-key");
  });

  test("no auth header when key empty (dev mode)", async () => {
    const { client, fetch } = clientWith(() => ({ body: { probability: 0.1 } }));
    await client.prescan({ originCode: "OH", text: "x" });
    expect(fetch.calls[0].init.headers).not.toHaveProperty("X-TIP-Classifier-Key");
  });

  test("creatorClearedCount passes through", async () => {
    const { client, fetch } = clientWith(() => ({ body: { probability: 0.1 } }));
    await client.prescan({ originCode: "OH", text: "x", creatorClearedCount: 42 });
    expect(JSON.parse(fetch.calls[0].init.body).creator_cleared_count).toBe(42);
  });
});

// ── stage1 ─────────────────────────────────────────────────────────────────
describe("stage1", () => {
  test("POSTs to /v1/stage1 with declared_origin + dispute_reason", async () => {
    const { client, fetch } = clientWith(() => ({
      body: { outcome: "HUMAN_REVIEW", probability: 0.69, escalate_to_stage2: true },
    }));
    const r = await client.stage1({
      ctid: "tip://c/OH-...",
      declaredOrigin: "OH",
      text: "ai-style text",
    });
    expect(fetch.calls[0].url).toBe("http://classifier-test:6060/v1/stage1");
    const body = JSON.parse(fetch.calls[0].init.body);
    expect(body.declared_origin).toBe("OH");
    expect(body.dispute_reason).toBe("pre_scan_flag");
    expect(body.text).toBe("ai-style text");
    expect(r.outcome).toBe("HUMAN_REVIEW");
  });

  test("missing ctid → throws", async () => {
    const { client } = clientWith(() => ({ body: { x: 1 } }));
    await expect(client.stage1({ declaredOrigin: "OH" })).rejects.toMatchObject({
      code: "ctid_required",
    });
  });

  test("invalid declared_origin → throws", async () => {
    const { client } = clientWith(() => ({ body: { x: 1 } }));
    await expect(
      client.stage1({ ctid: "tip://c/x", declaredOrigin: "ZZ" })
    ).rejects.toMatchObject({ code: "invalid_origin_code" });
  });
});

// ── providers + health ────────────────────────────────────────────────────
describe("providers + health", () => {
  test("providers GETs /v1/providers", async () => {
    const { client, fetch } = clientWith(() => ({
      body: { providers: [{ name: "ollama", available: true }], active_count: 1 },
    }));
    const r = await client.providers();
    expect(fetch.calls[0].url).toBe("http://classifier-test:6060/v1/providers");
    expect(fetch.calls[0].init.method).toBe("GET");
    expect(r.active_count).toBe(1);
  });

  test("health GETs /health", async () => {
    const { client, fetch } = clientWith(() => ({
      body: { status: "ok", uptime_seconds: 100 },
    }));
    const r = await client.health();
    expect(fetch.calls[0].url).toBe("http://classifier-test:6060/health");
    expect(r.status).toBe("ok");
  });
});

// ── Quality gates ──────────────────────────────────────────────────────────
describe("isHeuristicOnly + isSkipped", () => {
  test("isHeuristicOnly true when only heuristic ran", () => {
    expect(isHeuristicOnly({ provider_used: "heuristic" })).toBe(true);
  });
  test("isHeuristicOnly false when ensemble ran", () => {
    expect(isHeuristicOnly({ provider_used: "ensemble(ollama,statistical,heuristic)" })).toBe(false);
  });
  test("isHeuristicOnly false on null/undefined", () => {
    expect(isHeuristicOnly(null)).toBe(false);
    expect(isHeuristicOnly(undefined)).toBe(false);
  });

  test("isSkipped recognises locally_skipped flag", () => {
    expect(isSkipped({ locally_skipped: true })).toBe(true);
  });
  test("isSkipped recognises classifier-side skipped", () => {
    expect(isSkipped({ provider_used: "skipped" })).toBe(true);
  });
  test("isSkipped false on real results", () => {
    expect(isSkipped({ provider_used: "ensemble(...)" })).toBe(false);
  });
});
