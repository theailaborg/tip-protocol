/**
 * @file tests/services/classifier-client-jobs.test.js
 * @description Classifier client side of async pre-scan jobs: client_ref and
 * callback_url on media requests, the 202 pending shape, a timed-out call as
 * classifier_timeout, and the job status call.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */
"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");

const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const PC = require(path.join(SHARED, "protocol-constants"));
try { PC._resetForTesting(); } catch { /* not yet initialised */ }
PC.init(getGenesisPayload().protocol_constants);

const { createClassifierClient } = require(path.resolve(__dirname, "../../src/services/classifier-client"));

const FILE = { media_id: "ab".repeat(32), mime: "image/png", url: "https://bucket.s3.amazonaws.com/x?sig" };
const VERDICT = { probability: 0.4, modalities_analyzed: ["image"], modality_results: [], provider_used: "ensemble" };

function _client(responder, opts = {}) {
  const calls = [];
  async function fetch(url, init) {
    calls.push({ url, init: init || {} });
    const r = await responder(url, init || {});
    return { status: r.status ?? 200, text: async () => typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {}) };
  }
  const client = createClassifierClient({
    url: "http://classifier-test:6060", fetch, callbackSecret: "", apiEndpoint: "", ...opts,
  });
  return { client, calls };
}

function _sentBody(calls, i = 0) {
  return JSON.parse(calls[i].init.body);
}

describe("prescan request body", () => {
  test("a media request carries client_ref, and no callback_url without a callback secret", async () => {
    const { client, calls } = _client(() => ({ body: VERDICT }));
    await client.prescan({ originCode: "OH", text: "", files: [FILE], clientRef: "pj_1" });
    const body = _sentBody(calls);
    expect(body.client_ref).toBe("pj_1");
    expect(body).not.toHaveProperty("callback_url");
  });

  test("callback_url is the node's own endpoint when a callback secret is set", async () => {
    const { client, calls } = _client(() => ({ body: VERDICT }), {
      callbackSecret: "wh_x", apiEndpoint: "https://node.example.org/",
    });
    await client.prescan({ originCode: "OH", text: "", files: [FILE], clientRef: "pj_1" });
    expect(_sentBody(calls).callback_url).toBe("https://node.example.org/v1/prescan/callback");
  });

  test("a text-only request carries no client_ref", async () => {
    const { client, calls } = _client(() => ({ body: VERDICT }));
    await client.prescan({ originCode: "OH", text: "hello", clientRef: "pj_1" });
    expect(_sentBody(calls)).not.toHaveProperty("client_ref");
  });
});

describe("prescan responses", () => {
  test("200 returns the verdict unchanged", async () => {
    const { client } = _client(() => ({ body: VERDICT }));
    await expect(client.prescan({ originCode: "OH", text: "", files: [FILE], clientRef: "pj_1" })).resolves.toEqual(VERDICT);
  });

  test("202 returns the pending job", async () => {
    const { client } = _client(() => ({ status: 202, body: { job_id: "cj_9", state: "queued", poll_after_ms: 30000 } }));
    await expect(client.prescan({ originCode: "OH", text: "", files: [FILE], clientRef: "pj_1" }))
      .resolves.toEqual({ pending: true, job_id: "cj_9", state: "queued", poll_after_ms: 30000 });
  });

  test("a call that outlives its timeout fails as classifier_timeout", async () => {
    const { client } = _client((url, init) => new Promise((resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
    }), { timeouts: { text: 20, file: 20 } });
    await expect(client.prescan({ originCode: "OH", text: "", files: [FILE], clientRef: "pj_1" }))
      .rejects.toEqual(expect.objectContaining({ code: "classifier_timeout" }));
  });
});

describe("prescanStatus", () => {
  test("GETs the encoded job id and returns the body", async () => {
    const { client, calls } = _client(() => ({ body: { job_id: "cj/1", state: "running" } }));
    await expect(client.prescanStatus("cj/1")).resolves.toEqual({ job_id: "cj/1", state: "running" });
    expect(calls[0].url).toBe("http://classifier-test:6060/v1/prescan/cj%2F1");
    expect(calls[0].init.method).toBe("GET");
  });

  test("404 means the classifier lost the job", async () => {
    const { client } = _client(() => ({ status: 404, body: { detail: "Job not found" } }));
    await expect(client.prescanStatus("cj_1")).resolves.toEqual({ job_id: "cj_1", state: "lost" });
  });

  test("any other failure throws classifier_http_error", async () => {
    const { client } = _client(() => ({ status: 500, body: "boom" }));
    await expect(client.prescanStatus("cj_1")).rejects.toEqual(expect.objectContaining({ code: "classifier_http_error", status: 500 }));
  });
});
