/**
 * @file tests/services/media-quota-client.test.js
 * @description Monthly media allowance client: opt-in, request shape, fail-open
 * with last-known fallback, and background record retries.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { createMediaQuotaClient } = require(path.resolve(__dirname, "../../src/services/media-quota-client"));

const TIP = "tip://id/US-0123456789abcdef";
const HASH = "a".repeat(64);
const quiet = { warn() {}, error() {} };

function _fetch(responses) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init, body: JSON.parse(init.body) });
    const r = responses.shift();
    if (r instanceof Error) throw r;
    return { ok: r.status < 400, status: r.status, text: async () => JSON.stringify(r.body) };
  };
  fn.calls = calls;
  return fn;
}

describe("media-quota-client", () => {
  test("disabled without a URL or key, and then answers null without calling out", async () => {
    const f = _fetch([]);
    for (const opts of [{ url: "", key: "k" }, { url: "https://vp.example", key: "" }]) {
      const c = createMediaQuotaClient({ ...opts, fetch: f, log: quiet });
      expect(c.enabled).toBe(false);
      expect(await c.check({ tip_id: TIP, content_hash: HASH, size: 1 })).toBeNull();
      expect(await c.record({ tip_id: TIP, content_hash: HASH, size: 1 })).toBe(false);
    }
    expect(f.calls).toEqual([]);
  });

  test("check posts to /api/media-quota/check with the key and returns the answer", async () => {
    const f = _fetch([{ status: 200, body: { allowed: false, remaining_bytes: 3 } }]);
    const c = createMediaQuotaClient({ url: "https://vp.example/", key: "secret-key", fetch: f, log: quiet });
    const out = await c.check({ tip_id: TIP, content_hash: HASH, size: 10 });
    expect(out).toEqual({ allowed: false, remaining_bytes: 3 });
    expect(f.calls[0].url).toBe("https://vp.example/api/media-quota/check");
    expect(f.calls[0].init.headers["X-TIP-Quota-Key"]).toBe("secret-key");
    expect(f.calls[0].init.headers["User-Agent"]).toBe("TIP-Node/1.0");
    expect(f.calls[0].body).toEqual({ tip_id: TIP, content_hash: HASH, size: 10 });
  });

  test("check forwards tip_id_type when given, and leaves it out when not", async () => {
    const f = _fetch([{ status: 200, body: { allowed: true } }, { status: 200, body: { allowed: true } }]);
    const c = createMediaQuotaClient({ url: "https://vp.example", key: "k", fetch: f, log: quiet });
    await c.check({ tip_id: TIP, content_hash: HASH, size: 1, tip_id_type: "organization" });
    await c.check({ tip_id: TIP, content_hash: HASH, size: 1 });
    expect(f.calls[0].body.tip_id_type).toBe("organization");
    expect("tip_id_type" in f.calls[1].body).toBe(false);
  });

  test("fails open: unreachable with nothing known lets the upload through", async () => {
    const f = _fetch([new Error("ECONNREFUSED")]);
    const c = createMediaQuotaClient({ url: "https://vp.example", key: "k", fetch: f, log: quiet });
    expect(await c.check({ tip_id: TIP, content_hash: HASH, size: 10 })).toBeNull();
  });

  test("an error status or a malformed answer counts as unreachable", async () => {
    const f = _fetch([{ status: 503, body: { detail: "x" } }, { status: 200, body: { nope: 1 } }]);
    const c = createMediaQuotaClient({ url: "https://vp.example", key: "k", fetch: f, log: quiet });
    expect(await c.check({ tip_id: TIP, content_hash: HASH, size: 10 })).toBeNull();
    expect(await c.check({ tip_id: TIP, content_hash: HASH, size: 10 })).toBeNull();
  });

  test("when unreachable later, the last known remaining allowance decides", async () => {
    const f = _fetch([{ status: 200, body: { allowed: true, remaining_bytes: 100 } }, new Error("down"), new Error("down")]);
    const c = createMediaQuotaClient({ url: "https://vp.example", key: "k", fetch: f, log: quiet });
    await c.check({ tip_id: TIP, content_hash: HASH, size: 10 });
    expect(await c.check({ tip_id: TIP, content_hash: HASH, size: 100 })).toMatchObject({ allowed: true, stale: true });
    expect(await c.check({ tip_id: TIP, content_hash: HASH, size: 101 })).toMatchObject({ allowed: false, stale: true });
  });

  test("no monthly limit (remaining_bytes null) never turns an outage into a refusal", async () => {
    const f = _fetch([{ status: 200, body: { allowed: true, remaining_bytes: null, allowance_bytes: null } }, new Error("down")]);
    const c = createMediaQuotaClient({ url: "https://vp.example", key: "k", fetch: f, log: quiet });
    expect(await c.check({ tip_id: TIP, content_hash: HASH, size: 10 })).toMatchObject({ allowed: true });
    expect(await c.check({ tip_id: TIP, content_hash: HASH, size: 10 ** 9 })).toBeNull();   // allowed through
  });

  test("record retries in the background and gives up without throwing", async () => {
    const slept = [];
    const sleep = async ms => { slept.push(ms); };
    const ok = _fetch([new Error("down"), { status: 200, body: { remaining_bytes: 5 } }]);
    const c1 = createMediaQuotaClient({ url: "https://vp.example", key: "k", fetch: ok, log: quiet, sleep });
    expect(await c1.record({ tip_id: TIP, content_hash: HASH, size: 7, media_id: HASH })).toBe(true);
    expect(ok.calls[1].body).toEqual({ tip_id: TIP, content_hash: HASH, size: 7, media_id: HASH });
    expect(ok.calls[1].url).toBe("https://vp.example/api/media-quota/record");

    const never = _fetch([new Error("1"), new Error("2"), new Error("3"), new Error("4")]);
    const c2 = createMediaQuotaClient({ url: "https://vp.example", key: "k", fetch: never, log: quiet, sleep });
    expect(await c2.record({ tip_id: TIP, content_hash: HASH, size: 7 })).toBe(false);
    expect(never.calls.length).toBe(4);
    expect(slept).toEqual([2000, 2000, 10000, 60000]);
  });
});
