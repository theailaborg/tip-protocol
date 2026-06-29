/**
 * @file tests/process-error-handler.test.js
 * @description Process-level error capture/classification + safeTimer routing.
 *
 * Covers:
 *   1. classify() flags fatal severity from driver CODES only; peer-controllable
 *      message text is never fatal (DoS-vector guard).
 *   2. captureError() returns a structured record and counts by origin+category.
 *   3. A fatal-severity capture is counted but NEVER calls process.exit
 *      (observe-only: this boundary doesn't halt the node).
 *   4. safeSetTimeout/safeSetInterval route a thrown error AND a rejected
 *      promise through captureError without propagating, and return a clearable
 *      native handle.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../src");
const pe = require(path.join(SRC, "process-error-handler"));
const { safeSetTimeout, safeSetInterval } = require(path.join(SRC, "safe-timer"));

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

describe("classify", () => {
  test.each([
    [{ code: "SQLITE_CORRUPT" }, "store_corruption", true],
    [{ code: "SQLITE_NOTADB" }, "store_corruption", true],
    [{ code: "ERR_WORKER_OUT_OF_MEMORY", message: "worker oom" }, "oom", false],
    [{ code: "SQLITE_BUSY", message: "database is busy" }, "store_contention", false],
    [new Error("read ECONNRESET"), "network", false],
    [new Error("protobuf decode failed: invalid wire type"), "decode", false],
    [new Error("something nobody expected"), "unknown", false],
    // DoS-vector guard: peer-controllable MESSAGE text must NEVER be fatal.
    [new Error("certificate is malformed"), "unknown", false],
    [new Error("ArrayBuffer allocation failed"), "unknown", false],
    [new Error("database disk image is malformed"), "unknown", false],
  ])("%o -> %s (fatal=%s)", (err, category, fatal) => {
    const c = pe.classify(err);
    expect(c.category).toBe(category);
    expect(c.fatal).toBe(fatal);
  });
});

describe("captureError", () => {
  test("returns a structured record and counts by origin+category", () => {
    const before = pe.getMetrics().uncaught.network || 0;
    const rec = pe.captureError(new Error("read ECONNRESET"), { origin: "uncaughtException", module: "test" });
    expect(rec.error_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(rec.category).toBe("network");
    expect(rec.fatal).toBe(false);
    expect(rec.module).toBe("test");
    expect(rec.stack).toBeTruthy();
    expect(pe.getMetrics().uncaught.network).toBe(before + 1);
  });

  test("unhandledRejection origin counts separately from uncaught", () => {
    const before = pe.getMetrics().unhandled.unknown || 0;
    pe.captureError(new Error("weird"), { origin: "unhandledRejection" });
    expect(pe.getMetrics().unhandled.unknown).toBe(before + 1);
  });
});

describe("fatal severity (observe-only)", () => {
  test("a store-corruption CODE is flagged fatal and counted", () => {
    const before = pe.getMetrics().fatal.store_corruption || 0;
    const rec = pe.captureError({ code: "SQLITE_CORRUPT", message: "disk image malformed" }, { origin: "uncaughtException" });
    expect(rec.fatal).toBe(true);
    expect(pe.getMetrics().fatal.store_corruption).toBe(before + 1);
  });

  test("a fatal capture NEVER calls process.exit", () => {
    const spy = jest.spyOn(process, "exit").mockImplementation(() => { throw new Error("process.exit called"); });
    try {
      const rec = pe.captureError({ code: "SQLITE_CORRUPT" }, { origin: "uncaughtException" });
      expect(rec.fatal).toBe(true);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });
});

describe("safe-timer", () => {
  test("a thrown error is captured, not propagated, and counted by label", async () => {
    const before = pe.getMetrics().timer["t.sync"] || 0;
    safeSetTimeout(() => { throw new Error("boom"); }, 1, "t.sync");
    await wait(15);
    expect(pe.getMetrics().timer["t.sync"]).toBe(before + 1);
  });

  test("a rejected promise from an async callback is captured", async () => {
    const before = pe.getMetrics().timer["t.async"] || 0;
    safeSetTimeout(async () => { throw new Error("boom-async"); }, 1, "t.async");
    await wait(15);
    expect(pe.getMetrics().timer["t.async"]).toBe(before + 1);
  });

  test("returns a native handle that clearTimeout cancels", async () => {
    let fired = false;
    const h = safeSetTimeout(() => { fired = true; }, 20, "t.clear");
    clearTimeout(h);
    await wait(40);
    expect(fired).toBe(false);
  });

  test("a healthy interval callback runs normally and is clearable", async () => {
    let n = 0;
    const h = safeSetInterval(() => { n++; }, 5, "t.ok");
    await wait(18);
    clearInterval(h);
    const seen = n;
    expect(seen).toBeGreaterThan(0);
    await wait(15);
    expect(n).toBe(seen); // no further ticks after clear
  });
});
