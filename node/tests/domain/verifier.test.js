/**
 * @file tests/domain/verifier.test.js
 * @description Unit tests for DNS / HTTP verifier primitives.
 *
 * Uses dependency-injected resolveTxt / fetchJson stubs so the tests
 * don't actually touch the network. The contract under test is the
 * verifier's decision logic + structured error codes — actual DNS /
 * HTTP plumbing belongs to integration tests against a live test rig.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const verifier = require(path.join(SRC, "domain", "verifier"));

const DOMAIN = "example.com";
const TIP_ID = "tip://id/US-aaaaaaaaaaaaaaaa";
const PUBKEY = "deadbeef".repeat(8);

// ─── verifyDns ──────────────────────────────────────────────────────────────

describe("verifyDns", () => {
  test("matches tip-id= substring in any TXT record", async () => {
    const resolveTxt = jest.fn().mockResolvedValue([
      ["v=spf1 ~all"],
      ["v=tip1; tip-id=" + TIP_ID + "; verified=true"],
    ]);
    const r = await verifier.verifyDns(DOMAIN, TIP_ID, { resolveTxt });
    expect(r.verified).toBe(true);
    expect(r.method).toBe("dns");
    expect(r.evidence.txt[0]).toContain(TIP_ID);
    expect(resolveTxt).toHaveBeenCalledWith(`_tip-protocol.${DOMAIN}`);
  });

  test("multi-string TXT joins per RFC 7208", async () => {
    const resolveTxt = jest.fn().mockResolvedValue([
      ["tip-id=", TIP_ID],   // split across two strings — join must reconnect them
    ]);
    const r = await verifier.verifyDns(DOMAIN, TIP_ID, { resolveTxt });
    expect(r.verified).toBe(true);
  });

  test("case-insensitive match", async () => {
    const resolveTxt = jest.fn().mockResolvedValue([
      ["TIP-ID=" + TIP_ID.toUpperCase()],
    ]);
    const r = await verifier.verifyDns(DOMAIN, TIP_ID, { resolveTxt });
    expect(r.verified).toBe(true);
  });

  test("no TXT records → dns_no_record", async () => {
    const resolveTxt = jest.fn().mockResolvedValue([]);
    const r = await verifier.verifyDns(DOMAIN, TIP_ID, { resolveTxt });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("dns_no_record");
  });

  test("TXT records exist but none match → dns_no_match", async () => {
    const resolveTxt = jest.fn().mockResolvedValue([
      ["v=spf1 ~all"],
      ["v=tip1; tip-id=tip://id/US-other"],
    ]);
    const r = await verifier.verifyDns(DOMAIN, TIP_ID, { resolveTxt });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("dns_no_match");
  });

  test("resolver throws ENODATA → dns_no_record", async () => {
    const resolveTxt = jest.fn().mockRejectedValue(Object.assign(new Error("ENODATA"), { code: "ENODATA" }));
    const r = await verifier.verifyDns(DOMAIN, TIP_ID, { resolveTxt });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("dns_no_record");
  });

  test("resolver throws ENOTFOUND → dns_no_record", async () => {
    const resolveTxt = jest.fn().mockRejectedValue(Object.assign(new Error("not found"), { code: "ENOTFOUND" }));
    const r = await verifier.verifyDns(DOMAIN, TIP_ID, { resolveTxt });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("dns_no_record");
  });
});

// ─── verifyHttp ─────────────────────────────────────────────────────────────

describe("verifyHttp", () => {
  function fetcher(body, opts = {}) {
    return jest.fn().mockResolvedValue({ status: opts.status || 200, body });
  }

  test("happy path with matching domain + tip_id + public_key", async () => {
    const fetchJson = fetcher({
      protocol: "TIP", version: "2.0", domain: DOMAIN, tip_id: TIP_ID, public_key: PUBKEY,
    });
    const r = await verifier.verifyHttp(DOMAIN, TIP_ID, { fetchJson, expectedPublicKey: PUBKEY });
    expect(r.verified).toBe(true);
    expect(r.method).toBe("http");
    expect(r.evidence.url).toBe(`https://${DOMAIN}/.well-known/tip-protocol.json`);
  });

  test("missing tip_id → well_known_mismatch", async () => {
    const fetchJson = fetcher({ domain: DOMAIN });
    const r = await verifier.verifyHttp(DOMAIN, TIP_ID, { fetchJson });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("well_known_mismatch");
  });

  test("tip_id mismatch → well_known_mismatch", async () => {
    const fetchJson = fetcher({ domain: DOMAIN, tip_id: "tip://id/US-other" });
    const r = await verifier.verifyHttp(DOMAIN, TIP_ID, { fetchJson });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("well_known_mismatch");
  });

  test("domain mismatch (case-insensitive compare) → well_known_mismatch", async () => {
    const fetchJson = fetcher({ domain: "other.example", tip_id: TIP_ID });
    const r = await verifier.verifyHttp(DOMAIN, TIP_ID, { fetchJson });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("well_known_mismatch");
  });

  test("public_key mismatch against DAG identity → well_known_mismatch", async () => {
    const fetchJson = fetcher({ domain: DOMAIN, tip_id: TIP_ID, public_key: "wrong" });
    const r = await verifier.verifyHttp(DOMAIN, TIP_ID, { fetchJson, expectedPublicKey: PUBKEY });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("well_known_mismatch");
  });

  test("public_key cross-check skipped when expectedPublicKey not supplied", async () => {
    const fetchJson = fetcher({ domain: DOMAIN, tip_id: TIP_ID, public_key: "anything" });
    const r = await verifier.verifyHttp(DOMAIN, TIP_ID, { fetchJson });
    expect(r.verified).toBe(true);
  });

  test("non-object body → well_known_mismatch", async () => {
    const fetchJson = fetcher("not an object");
    const r = await verifier.verifyHttp(DOMAIN, TIP_ID, { fetchJson });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("well_known_mismatch");
  });

  test("fetch failure → well_known_unreachable, evidence carries URL", async () => {
    const fetchJson = jest.fn().mockRejectedValue(Object.assign(new Error("timeout"), { code: "well_known_unreachable" }));
    const r = await verifier.verifyHttp(DOMAIN, TIP_ID, { fetchJson });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("well_known_unreachable");
    expect(r.evidence.url).toBe(`https://${DOMAIN}/.well-known/tip-protocol.json`);
  });
});

// ─── verifyAuto ─────────────────────────────────────────────────────────────

describe("verifyAuto", () => {
  test("HTTP succeeds → returns http method, DNS not called", async () => {
    const fetchJson = jest.fn().mockResolvedValue({ status: 200, body: { domain: DOMAIN, tip_id: TIP_ID } });
    const resolveTxt = jest.fn();
    const r = await verifier.verifyAuto(DOMAIN, TIP_ID, { fetchJson, resolveTxt });
    expect(r.verified).toBe(true);
    expect(r.method).toBe("http");
    expect(resolveTxt).not.toHaveBeenCalled();
  });

  test("HTTP fails, DNS succeeds → returns dns method", async () => {
    const fetchJson = jest.fn().mockRejectedValue(Object.assign(new Error("404"), { code: "well_known_unreachable" }));
    const resolveTxt = jest.fn().mockResolvedValue([["tip-id=" + TIP_ID]]);
    const r = await verifier.verifyAuto(DOMAIN, TIP_ID, { fetchJson, resolveTxt });
    expect(r.verified).toBe(true);
    expect(r.method).toBe("dns");
  });

  test("both fail → DNS error preferred when TXT records exist", async () => {
    const fetchJson = jest.fn().mockRejectedValue(Object.assign(new Error("404"), { code: "well_known_unreachable" }));
    const resolveTxt = jest.fn().mockResolvedValue([["tip-id=tip://id/US-other"]]);
    const r = await verifier.verifyAuto(DOMAIN, TIP_ID, { fetchJson, resolveTxt });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("dns_no_match");
  });

  test("both fail with no DNS records → HTTP error returned", async () => {
    const fetchJson = jest.fn().mockRejectedValue(Object.assign(new Error("404"), { code: "well_known_unreachable" }));
    const resolveTxt = jest.fn().mockResolvedValue([]);
    const r = await verifier.verifyAuto(DOMAIN, TIP_ID, { fetchJson, resolveTxt });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("well_known_unreachable");
  });
});

// ─── dispatch ───────────────────────────────────────────────────────────────

describe("verify dispatch", () => {
  test("unknown method → method_invalid", async () => {
    const r = await verifier.verify("ftp", DOMAIN, TIP_ID);
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("method_invalid");
  });
});

// ─── Dev-mode localhost ─────────────────────────────────────────────────────

describe("dev-mode localhost", () => {
  const ORIGINAL_ENV = process.env.NODE_ENV;
  const ORIGINAL_FLAG = process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS;

  afterEach(() => {
    if (ORIGINAL_ENV === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = ORIGINAL_ENV;
    if (ORIGINAL_FLAG === undefined) delete process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS;
    else process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS = ORIGINAL_FLAG;
  });

  test("verifyHttp fetches over HTTP (not HTTPS) when flag set + loopback host", async () => {
    process.env.NODE_ENV = "development";
    process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS = "1";
    const fetchJson = jest.fn().mockResolvedValue({
      status: 200, body: { domain: "localhost:4000", tip_id: TIP_ID },
    });
    const r = await verifier.verifyHttp("localhost:4000", TIP_ID, { fetchJson });
    expect(r.verified).toBe(true);
    expect(fetchJson).toHaveBeenCalledWith(
      "http://localhost:4000/.well-known/tip-protocol.json",
      expect.objectContaining({ allowInsecure: true }),
    );
  });

  test("verifyHttp still uses HTTPS for non-loopback even with flag set", async () => {
    process.env.NODE_ENV = "development";
    process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS = "1";
    const fetchJson = jest.fn().mockResolvedValue({
      status: 200, body: { domain: "acmenews.com", tip_id: TIP_ID },
    });
    await verifier.verifyHttp("acmenews.com", TIP_ID, { fetchJson });
    const url = fetchJson.mock.calls[0][0];
    expect(url.startsWith("https://")).toBe(true);
  });

  test("verifyHttp uses HTTPS in production even when flag set", async () => {
    process.env.NODE_ENV = "production";
    process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS = "1";
    const fetchJson = jest.fn().mockResolvedValue({
      status: 200, body: { domain: "localhost", tip_id: TIP_ID },
    });
    await verifier.verifyHttp("localhost", TIP_ID, { fetchJson });
    const url = fetchJson.mock.calls[0][0];
    expect(url.startsWith("https://")).toBe(true);
  });

  test("verifyDns short-circuits to dns_no_record for loopback (no real resolver call)", async () => {
    process.env.NODE_ENV = "development";
    process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS = "1";
    const resolveTxt = jest.fn();
    const r = await verifier.verifyDns("localhost", TIP_ID, { resolveTxt });
    expect(r.verified).toBe(false);
    expect(r.error.code).toBe("dns_no_record");
    expect(resolveTxt).not.toHaveBeenCalled();
  });

  test("verifyAuto on loopback in dev mode: DNS short-circuits, HTTP succeeds", async () => {
    process.env.NODE_ENV = "development";
    process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS = "1";
    const fetchJson = jest.fn().mockResolvedValue({
      status: 200, body: { domain: "localhost", tip_id: TIP_ID },
    });
    const resolveTxt = jest.fn();
    const r = await verifier.verifyAuto("localhost", TIP_ID, { fetchJson, resolveTxt });
    expect(r.verified).toBe(true);
    expect(r.method).toBe("http");
    expect(resolveTxt).not.toHaveBeenCalled();
  });
});
