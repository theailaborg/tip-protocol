/**
 * @file tests/consensus/halt-gate.test.js
 * @description Consensus-halt gate tests — #30 "halt honestly" behavior.
 *
 * Layered coverage:
 *   1. `computeHaltStatus` — pure decision function, exercised against
 *      the REAL code (no duplicate). Tests each branch plus transitions:
 *      healthy → halted → healthy.
 *   2. `createConsensusGate` middleware — HTTP behavior (GET passes,
 *      writes 503 when halted, missing-ref pass-through).
 *   3. Narwhal wire — verifies `start()` sets `lastRoundAdvanceAt` and
 *      `stats()` / the `lastRoundAdvanceAt()` getter expose it so the
 *      halt gate has a real signal to read.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const express = require("express");
const request = require("supertest");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createConsensusGate } = require(path.join(SRC, "middleware", "consensus-gate"));
const { computeHaltStatus } = require(path.join(SRC, "consensus", "halt-status"));
const { createNarwhal } = require(path.join(SRC, "consensus", "narwhal"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

// ═══════════════════════════════════════════════════════════════════════════
// 1. computeHaltStatus — pure function, REAL code (no duplicate).
// ═══════════════════════════════════════════════════════════════════════════
describe("computeHaltStatus (pure)", () => {
  const ROUND_TIMEOUT_MS = 2000;   // threshold = 6000ms

  test("narwhal not started → not halted", () => {
    const r = computeHaltStatus({ running: false }, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: () => 1000 });
    expect(r.halted).toBe(false);
    expect(r.reason).toBe("narwhal_not_started");
  });

  test("narwhal syncing → not halted (transient boot state)", () => {
    const r = computeHaltStatus(
      { running: true, joinState: "syncing", lastRoundAdvanceAt: 0 },
      { roundTimeoutMs: ROUND_TIMEOUT_MS, now: () => 100_000 }
    );
    expect(r.halted).toBe(false);
    expect(r.reason).toBe("join_state_syncing");
  });

  test("running + ready but no activity yet → not halted (grace)", () => {
    const r = computeHaltStatus(
      { running: true, joinState: "ready", lastRoundAdvanceAt: 0 },
      { roundTimeoutMs: ROUND_TIMEOUT_MS, now: () => 100_000 }
    );
    expect(r.halted).toBe(false);
    expect(r.reason).toBe("no_activity_yet");
  });

  test("recent round advance → healthy", () => {
    const now = 1_000_000;
    const r = computeHaltStatus(
      { running: true, joinState: "ready", lastRoundAdvanceAt: now - 1000 },
      { roundTimeoutMs: ROUND_TIMEOUT_MS, now: () => now }
    );
    expect(r.halted).toBe(false);
    expect(r.reason).toBe("healthy");
  });

  test("no advance for > 3× round timeout → halted (sub_quorum)", () => {
    const now = 1_000_000;
    const r = computeHaltStatus(
      {
        running: true, joinState: "ready", lastRoundAdvanceAt: now - 10_000,
        round: 42, certificatesThisRound: 1, quorum: 2
      },
      { roundTimeoutMs: ROUND_TIMEOUT_MS, now: () => now }
    );
    expect(r.halted).toBe(true);
    expect(r.reason).toBe("sub_quorum");
    expect(r.staleMs).toBe(10_000);
    // Message carries the round + quorum so operators see the exact state
    expect(r.message).toMatch(/round 42/);
    expect(r.message).toMatch(/1\/2 certs/);
  });

  test("boundary: exactly at 3× threshold → not halted (strict > check)", () => {
    const now = 1_000_000;
    const r = computeHaltStatus(
      { running: true, joinState: "ready", lastRoundAdvanceAt: now - 6000 },
      { roundTimeoutMs: ROUND_TIMEOUT_MS, now: () => now }   // 6000 === 3×2000
    );
    expect(r.halted).toBe(false);   // not > 6000
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 1b. Transitions — walk a simulated node through healthy → halted → healthy.
//     This is the whole point of the gate; if transitions don't fire, the
//     rest is meaningless.
// ═══════════════════════════════════════════════════════════════════════════
describe("computeHaltStatus transitions", () => {
  const ROUND_TIMEOUT_MS = 2000;

  // Mutable clock so we can drive time forward deterministically.
  function mkClock(startMs) {
    let t = startMs;
    return { now: () => t, advance: (ms) => { t += ms; } };
  }

  test("healthy → halted when rounds stop advancing past threshold", () => {
    const clock = mkClock(1_000_000);
    const stats = {
      running: true, joinState: "ready", lastRoundAdvanceAt: clock.now(),
      round: 10, certificatesThisRound: 1, quorum: 2
    };

    // T+0: just advanced → healthy
    let r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(false);

    // T+3s: still healthy (within 6s threshold)
    clock.advance(3000);
    r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(false);
    expect(r.staleMs).toBe(3000);

    // T+6001ms total: crosses threshold → halted
    clock.advance(3001);
    r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(true);
    expect(r.reason).toBe("sub_quorum");
  });

  test("halted → healthy when a round finally advances", () => {
    const clock = mkClock(1_000_000);
    const stats = {
      running: true, joinState: "ready", lastRoundAdvanceAt: clock.now() - 20_000,
      round: 10, certificatesThisRound: 1, quorum: 2
    };

    // Start in halted state (no advance for 20s)
    let r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(true);

    // Peer comes back, round advances → narwhal updates lastRoundAdvanceAt
    clock.advance(100);
    stats.lastRoundAdvanceAt = clock.now();

    r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(false);
    expect(r.reason).toBe("healthy");
    expect(r.staleMs).toBe(0);
  });

  test("joining node (syncing) within threshold is not halted", () => {
    const clock = mkClock(1_000_000);
    // syncEnteredAt = "now" — within threshold, expected boot state.
    const stats = {
      running: true, joinState: "syncing", lastRoundAdvanceAt: 0,
      syncEnteredAt: clock.now(),
    };

    // Advance just below the threshold (3× round timeout).
    clock.advance(ROUND_TIMEOUT_MS * 3 - 1);
    const r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(false);
    expect(r.reason).toBe("join_state_syncing");
  });

  // #78: a node pinned in `_joinState=syncing` due to repeated sync
  // failures (#66 fingerprint) was previously hidden from the halt
  // detector. Now flagged as `stuck_syncing` so Grafana points operators
  // at the right node — the one ignoring all peer batches and causing the
  // federation halt — instead of the honest-but-blocked nodes.
  test("#78: joining node stuck > threshold → halted (stuck_syncing)", () => {
    const t0 = 1_000_000;
    const clock = mkClock(t0);
    const stats = {
      running: true, joinState: "syncing", lastRoundAdvanceAt: 0,
      syncEnteredAt: t0,
    };

    // Advance past the threshold (3× round timeout).
    clock.advance(ROUND_TIMEOUT_MS * 3 + 1);
    const r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(true);
    expect(r.reason).toBe("stuck_syncing");
    expect(r.staleMs).toBeGreaterThan(ROUND_TIMEOUT_MS * 3);
    expect(r.message).toMatch(/Stuck in sync mode/);
  });

  test("#78: legacy stats without syncEnteredAt → not flagged (backward compat)", () => {
    // Older builds didn't surface syncEnteredAt — keep their behavior
    // (joining is never halted) so a partial deploy doesn't false-flag
    // healthy nodes whose stats schema lags this change.
    const clock = mkClock(1_000_000);
    const stats = { running: true, joinState: "syncing", lastRoundAdvanceAt: 0 };
    clock.advance(ROUND_TIMEOUT_MS * 100);  // way past threshold
    const r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(false);
    expect(r.reason).toBe("join_state_syncing");
  });

  // ── catching_up coverage. Mirrors stuck_syncing but with a 10× threshold.

  test("catching_up within threshold → not halted (healthy tail closure)", () => {
    const t0 = 1_000_000;
    const clock = mkClock(t0);
    const stats = {
      running: true, joinState: "catching_up", lastRoundAdvanceAt: 0,
      catchingUpEnteredAt: t0, catchUpTarget: 5000, round: 4500,
    };
    // Just below 10× round timeout — bandwidth-bound tail closure
    // legitimately takes longer than initial install.
    clock.advance(ROUND_TIMEOUT_MS * 10 - 1);
    const r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(false);
    expect(r.reason).toBe("join_state_catching_up");
  });

  test("catching_up past threshold → halted (stuck_catching_up)", () => {
    const t0 = 1_000_000;
    const clock = mkClock(t0);
    const stats = {
      running: true, joinState: "catching_up", lastRoundAdvanceAt: 0,
      catchingUpEnteredAt: t0, catchUpTarget: 5000, round: 4500,
    };
    clock.advance(ROUND_TIMEOUT_MS * 10 + 1);
    const r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(true);
    expect(r.reason).toBe("stuck_catching_up");
    expect(r.staleMs).toBeGreaterThan(ROUND_TIMEOUT_MS * 10);
    expect(r.message).toMatch(/Stuck closing cert tail/);
    expect(r.message).toMatch(/target=5000/);
    expect(r.message).toMatch(/current=4500/);
  });

  test("catching_up without catchingUpEnteredAt → not flagged (backward compat)", () => {
    const clock = mkClock(1_000_000);
    const stats = { running: true, joinState: "catching_up", lastRoundAdvanceAt: 0 };
    clock.advance(ROUND_TIMEOUT_MS * 100);
    const r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(false);
    expect(r.reason).toBe("join_state_catching_up");
  });

  test("catching_up uses 10× threshold, not 3× (must not false-flag at sync threshold)", () => {
    const t0 = 1_000_000;
    const clock = mkClock(t0);
    const stats = {
      running: true, joinState: "catching_up", lastRoundAdvanceAt: 0,
      catchingUpEnteredAt: t0, catchUpTarget: 5000, round: 4500,
    };
    // Past the 3× syncing threshold but well within 10× catching_up window
    clock.advance(ROUND_TIMEOUT_MS * 5);
    const r = computeHaltStatus(stats, { roundTimeoutMs: ROUND_TIMEOUT_MS, now: clock.now });
    expect(r.halted).toBe(false);
    expect(r.reason).toBe("join_state_catching_up");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Middleware — HTTP behavior. Uses a stubbed consensus.isConsensusHalted
//    (we're testing the middleware's response handling, not the decision
//    logic — that's tested above against the real function).
// ═══════════════════════════════════════════════════════════════════════════
describe("consensus-gate middleware", () => {
  function stubConsensus(haltResult) {
    return { current: { isConsensusHalted: () => haltResult } };
  }
  function buildApp(consensusRef) {
    const app = express();
    app.use(express.json());
    app.use(createConsensusGate({ consensusRef }));
    app.get("/ping", (req, res) => res.json({ ok: true, method: "GET" }));
    app.post("/ping", (req, res) => res.json({ ok: true, method: "POST" }));
    app.put("/ping", (req, res) => res.json({ ok: true, method: "PUT" }));
    app.delete("/ping", (req, res) => res.json({ ok: true, method: "DELETE" }));
    return app;
  }

  test("GET always passes through — reads stay open during halt", async () => {
    const app = buildApp(stubConsensus({ halted: true, reason: "sub_quorum", staleMs: 20000, lastAdvanceAt: 0 }));
    const res = await request(app).get("/ping");
    expect(res.status).toBe(200);
    expect(res.body.method).toBe("GET");
  });

  test("POST is 503'd when consensus is halted, with structured error", async () => {
    const app = buildApp(stubConsensus({
      halted: true, reason: "sub_quorum", staleMs: 20000, lastAdvanceAt: 1700000000000,
      message: "quorum unreachable",
    }));
    const res = await request(app).post("/ping").send({});
    expect(res.status).toBe(503);
    expect(res.body.ok).toBe(false);
    expect(res.body.error.code).toBe("CONSENSUS_HALTED");
    expect(res.body.error.reason).toBe("sub_quorum");
    expect(res.body.error.stale_ms).toBe(20000);
    expect(res.body.error.last_advance_at).toBe(1700000000000);
  });

  test("PUT and DELETE are gated the same as POST", async () => {
    const app = buildApp(stubConsensus({ halted: true, reason: "sub_quorum", staleMs: 5000 }));
    expect((await request(app).put("/ping").send({})).status).toBe(503);
    expect((await request(app).delete("/ping")).status).toBe(503);
  });

  test("writes pass through when consensus is healthy", async () => {
    const app = buildApp(stubConsensus({ halted: false, reason: "healthy", staleMs: 500 }));
    const res = await request(app).post("/ping").send({});
    expect(res.status).toBe(200);
  });

  test("writes pass through when consensus is joining/syncing", async () => {
    const app = buildApp(stubConsensus({ halted: false, reason: "join_state_syncing", staleMs: 0 }));
    const res = await request(app).post("/ping").send({});
    expect(res.status).toBe(200);
  });

  test("missing consensus ref → pass-through (backwards-compat)", async () => {
    const res = await request(buildApp(null)).post("/ping").send({});
    expect(res.status).toBe(200);
  });

  test("consensus ref without isConsensusHalted → pass-through", async () => {
    const res = await request(buildApp({ current: { stats: () => ({}) } })).post("/ping").send({});
    expect(res.status).toBe(200);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Narwhal wire — minimal-stub integration: create a real narwhal, call
//    start(), verify the halt-signal plumbing is wired correctly. This
//    catches regressions where someone removes the `_lastRoundAdvanceAt`
//    assignment or the stats field.
// ═══════════════════════════════════════════════════════════════════════════
describe("narwhal lastRoundAdvanceAt wire", () => {
  function buildNarwhal() {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);
    const kp = generateMLDSAKeypair();
    const config = {
      nodeId: "TEST_NODE",
      nodeRegisteredId: "TEST_NODE",
      nodePrivateKey: kp.privateKey,
      nodePublicKey: kp.publicKey,
    };
    // Minimal network stub — narwhal only calls publish() on broadcasts;
    // tests here don't exercise broadcast paths.
    const network = {
      publish: async () => { },
      topics: {},
    };
    const narwhal = createNarwhal({
      dag, mempool, network, config,
      getNodeKey: () => kp.publicKey,
      getNodeCount: () => 1,
      getCommittee: () => ["TEST_NODE"],
      onCommit: () => { },
      onCertSaved: () => { },
    });
    return { narwhal, dag };
  }

  test("before start(): lastRoundAdvanceAt is 0 (grace signal)", () => {
    const { narwhal } = buildNarwhal();
    expect(narwhal.lastRoundAdvanceAt()).toBe(0);
    expect(narwhal.stats().lastRoundAdvanceAt).toBe(0);
  });

  test("after start(): lastRoundAdvanceAt is set to ~now (starts the grace window)", () => {
    const { narwhal } = buildNarwhal();
    const before = Date.now();
    narwhal.start();
    try {
      const got = narwhal.lastRoundAdvanceAt();
      expect(got).toBeGreaterThanOrEqual(before);
      expect(got).toBeLessThanOrEqual(Date.now());
      expect(narwhal.stats().lastRoundAdvanceAt).toBe(got);
    } finally {
      narwhal.stop();
    }
  });

  test("freshly-started narwhal feeds computeHaltStatus with a healthy answer", () => {
    const { narwhal } = buildNarwhal();
    narwhal.start();
    try {
      const status = computeHaltStatus(narwhal.stats(), { roundTimeoutMs: 2000, now: Date.now });
      expect(status.halted).toBe(false);
      expect(["healthy", "join_state_ready"]).toContain(status.reason);
    } finally {
      narwhal.stop();
    }
  });

  test("computeHaltStatus flips to halted when simulated time jumps past threshold", () => {
    const { narwhal } = buildNarwhal();
    narwhal.start();
    try {
      const startedAt = narwhal.lastRoundAdvanceAt();
      // "20 seconds later, no rounds have advanced"
      const fakeNow = () => startedAt + 20_000;
      const status = computeHaltStatus(narwhal.stats(), { roundTimeoutMs: 2000, now: fakeNow });
      expect(status.halted).toBe(true);
      expect(status.reason).toBe("sub_quorum");
    } finally {
      narwhal.stop();
    }
  });
});
