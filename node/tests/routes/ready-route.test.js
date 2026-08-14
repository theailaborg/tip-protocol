/**
 * @file tests/routes/ready-route.test.js
 * @description Tests for GET /ready (LB readiness probe).
 *
 * Covers:
 *   - 200 only when db readable + consensus not halted + joinState "ready"
 *   - 503 while syncing / catching_up (drained from LB rotation)
 *   - 503 on consensus halt and on DB read failure
 *   - Fail-closed: a throwing halt check reports not-ready
 *   - /health stays 200 while catching up (Docker liveness unaffected)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const express = require("express");
const request = require("supertest");

const SRC = path.resolve(__dirname, "../../src");
const healthRoutes = require(path.join(SRC, "routes", "health"));

function makeApp({ dag, consensus, network } = {}) {
  const app = express();
  const config = {
    nodeId: "tip://node/self",
    nodeRegisteredId: "tip://node/self",
    nodeType: "full",
    nodeVersion: "2.0.0",
  };
  app.use(healthRoutes.createRouter({
    dag: dag || { count: () => 42, getTxsByType: () => [], getAllNodes: () => [], getNode: () => null },
    scoring: {},
    config,
    consensus: consensus ?? { current: null },
    network: network ?? { current: null },
  }));
  return app;
}

function consensusWith({ joinState = "ready", halted = false } = {}) {
  return {
    current: {
      stats: () => ({ narwhal: { joinState } }),
      isConsensusHalted: () => ({ halted, reason: halted ? "sub-quorum" : "healthy" }),
    },
  };
}

describe("GET /ready", () => {
  test("200 ready when db ok, not halted, joinState ready", async () => {
    const res = await request(makeApp({ consensus: consensusWith() })).get("/ready");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ready: true, db_ok: true, halted: false, join_state: "ready" });
  });

  test.each(["syncing", "catching_up"])("503 while joinState is %s", async (joinState) => {
    const res = await request(makeApp({ consensus: consensusWith({ joinState }) })).get("/ready");
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ ready: false, join_state: joinState });
  });

  test("503 when consensus is halted", async () => {
    const res = await request(makeApp({ consensus: consensusWith({ halted: true }) })).get("/ready");
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ ready: false, halted: true });
  });

  test("503 when DB read throws", async () => {
    const dag = { count: () => { throw new Error("db gone"); }, getTxsByType: () => [], getAllNodes: () => [], getNode: () => null };
    const res = await request(makeApp({ dag, consensus: consensusWith() })).get("/ready");
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ ready: false, db_ok: false });
  });

  test("503 when consensus is absent", async () => {
    const res = await request(makeApp({ consensus: { current: null } })).get("/ready");
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ ready: false, join_state: null });
  });

  test("fail-closed: throwing halt check reports not-ready", async () => {
    const consensus = {
      current: {
        stats: () => ({ narwhal: { joinState: "ready" } }),
        isConsensusHalted: () => { throw new Error("halt check broke"); },
      },
    };
    const res = await request(makeApp({ consensus })).get("/ready");
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ ready: false, halted: true });
  });

  test("/health stays 200 while catching up (liveness vs readiness split)", async () => {
    const app = makeApp({ consensus: consensusWith({ joinState: "catching_up" }) });
    const health = await request(app).get("/health");
    const ready = await request(app).get("/ready");
    expect(health.status).toBe(200);
    expect(ready.status).toBe(503);
  });
});
