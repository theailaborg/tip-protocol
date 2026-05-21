/**
 * @file tests/routes/sync-status-route.test.js
 * @description §28 REST surface test — GET /v1/sync-status.
 *
 * The `getSyncStatus()` helper is covered directly in
 * tests/consensus/anti-entropy.test.js. This file exercises the
 * express-level wiring in `routes/stats.js` so a refactor that breaks
 * the HTTP path (missing router mount, wrong consensus ref shape,
 * bad error handling) fails here.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../../../shared/time");

const path = require("path");
const express = require("express");
const request = require("supertest");

const SRC = path.resolve(__dirname, "../../src");
const statsRoutes = require(path.join(SRC, "routes", "stats"));

function makeApp({ consensus, network } = {}) {
  const app = express();
  const config = {
    nodeId: "tip://node/self",
    nodeRegisteredId: "tip://node/self",
    nodeType: "full",
    nodeVersion: "2.0.0",
  };
  const dag = { count: () => 0 };
  app.use("/v1", statsRoutes.createRouter({
    dag, config,
    consensus: consensus ?? { current: null },
    network: network ?? { current: null },
  }));
  return app;
}

describe("GET /v1/sync-status", () => {
  test("200 with {self, peers, in_sync, timestamp} when consensus is running", async () => {
    const syncStatus = {
      self: {
        node_id: "tip://node/self",
        round: 10,
        committed_round: 10,
        consensus_index: 5,
        state_merkle_root: "aabbcc",
      },
      peers: [
        { node_id: "tip://node/A", round: 10, committed_round: 10, state_merkle_root: "aabbcc", in_sync: true, checked_at: nowMs() },
        { node_id: "tip://node/B", round: 10, committed_round: 10, state_merkle_root: "aabbcc", in_sync: true, checked_at: nowMs() },
      ],
      in_sync: true,
      timestamp: nowMs(),
    };
    const app = makeApp({ consensus: { current: { getSyncStatus: () => syncStatus } } });

    const res = await request(app).get("/v1/sync-status");
    expect(res.status).toBe(200);
    expect(res.body).toEqual(syncStatus);
  });

  test("503 when consensus.current is null (not running)", async () => {
    const app = makeApp({ consensus: { current: null } });
    const res = await request(app).get("/v1/sync-status");
    expect(res.status).toBe(503);
    expect(res.body).toHaveProperty("error");
    expect(res.body.sync_status).toBeNull();
  });

  test("503 when consensus doesn't expose getSyncStatus (older build)", async () => {
    const app = makeApp({ consensus: { current: { stats: () => ({}) } } });  // no getSyncStatus
    const res = await request(app).get("/v1/sync-status");
    expect(res.status).toBe(503);
    expect(res.body).toHaveProperty("error");
  });

  test("500 when getSyncStatus throws", async () => {
    const app = makeApp({
      consensus: {
        current: { getSyncStatus: () => { throw new Error("internal failure"); } },
      },
    });
    const res = await request(app).get("/v1/sync-status");
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/sync-status failed/);
  });

  test("reflects in_sync=false when any peer diverges", async () => {
    const syncStatus = {
      self: { node_id: "tip://node/self", round: 10, committed_round: 10, consensus_index: 5, state_merkle_root: "aabbcc" },
      peers: [
        { node_id: "tip://node/A", round: 10, committed_round: 10, state_merkle_root: "aabbcc", in_sync: true, checked_at: nowMs() },
        { node_id: "tip://node/B", round: 10, committed_round: 10, state_merkle_root: "ffffff", in_sync: false, checked_at: nowMs() },
      ],
      in_sync: false,
      timestamp: nowMs(),
    };
    const app = makeApp({ consensus: { current: { getSyncStatus: () => syncStatus } } });

    const res = await request(app).get("/v1/sync-status");
    expect(res.status).toBe(200);
    expect(res.body.in_sync).toBe(false);
    expect(res.body.peers.find(p => p.node_id === "tip://node/B").in_sync).toBe(false);
  });

  test("empty peers list returns 200 with in_sync=false (no peers to verify against)", async () => {
    const syncStatus = {
      self: { node_id: "tip://node/self", round: 0, committed_round: 0, consensus_index: 0, state_merkle_root: "" },
      peers: [],
      in_sync: false,
      timestamp: nowMs(),
    };
    const app = makeApp({ consensus: { current: { getSyncStatus: () => syncStatus } } });

    const res = await request(app).get("/v1/sync-status");
    expect(res.status).toBe(200);
    expect(res.body.peers).toEqual([]);
    expect(res.body.in_sync).toBe(false);
  });
});
