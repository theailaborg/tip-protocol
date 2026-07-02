/**
 * @file tests/routes/metrics-route.test.js
 * @description Tests for GET /metrics (Prometheus exposition — §29).
 *
 * Covers:
 *   - Response is text/plain v0.0.4 (Prometheus format)
 *   - Every emitted metric has a `# HELP` and `# TYPE` line
 *   - Counter and gauge lines format correctly (with and without labels)
 *   - Missing consensus still yields a valid response with
 *     `tip_consensus_halted = 1` so operators can see the outage
 *   - Counter values reflect the underlying stats()
 *   - The CRITICAL divergence counter is always present (alert target)
 *   - Halt gauge flips correctly
 *   - Metrics endpoint is scrapable even when halt-gate trips
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const express = require("express");
const request = require("supertest");

const SRC = path.resolve(__dirname, "../../src");
const metricsRoutes = require(path.join(SRC, "routes", "metrics"));

function makeApp({ consensus, network, dag } = {}) {
  const app = express();
  const config = {
    nodeId: "tip://node/self",
    nodeRegisteredId: "tip://node/self",
    nodeType: "full",
    nodeVersion: "2.0.0",
  };
  const defaultDag = { count: () => 0, certificateCount: () => 0 };
  app.use(metricsRoutes.createRouter({
    dag: dag || defaultDag,
    config,
    consensus: consensus ?? { current: null },
    network: network ?? { current: null },
  }));
  return app;
}

function fakeStats(overrides = {}) {
  return {
    narwhal: {
      round: 42,
      certificatesThisRound: 3,
      batchesThisRound: 3,
      pendingCerts: 0,
      quorum: 3,
      activeParticipants: 4,
      registeredNodes: 4,
      mempoolSize: 7,
      metrics: {
        rounds_advanced: 41,
        batches_received: 120,
        certs_received: 120,
        certs_parked: 2,
        certs_unblocked: 2,
        pending_certs_pruned: 0,
        equivocation_refused: 0,
        fast_forwards: 1,
        retries: 5,
      },
    },
    bullshark: {
      lastCommittedRound: 40,
      orderedCertificates: 160,
      consensusIndex: 20,
      metrics: {
        anchors_committed: 20,
        anchors_no_support: 1,
        txs_committed: 150,
        certs_pruned: 0,
        gc_runs: 2,
        gc_failures: 0,
      },
    },
    mempool: { size: 7, capacity: 10000 },
    antiEntropy: {
      last_status_size: 3,
      metrics: {
        loops_run: 100,
        checks_total: 300,
        peers_queried: 300,
        peer_rpc_failures: 2,
        peer_rpc_timeouts: 1,
        peer_identity_mismatch: 0,
        peer_unauthorized_query: 0,
        peer_unauthorized_inbound: 0,
        gaps_pulled: 3,
        consensus_divergence_total: 0,
      },
    },
    merkleRoot: "aabbccddeeff00112233445566778899",
    ...overrides,
  };
}

describe("GET /metrics — Prometheus exposition format", () => {
  test("200 OK with text/plain content-type (v0.0.4)", async () => {
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy", staleMs: 0 }) } },
    });
    const res = await request(app).get("/metrics");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/^text\/plain/);
    expect(res.headers["content-type"]).toMatch(/version=0\.0\.4/);
  });

  test("every emitted metric has # HELP and # TYPE lines", async () => {
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
    });
    const res = await request(app).get("/metrics");
    const body = res.text;

    // Pull every metric name (strip labels) and verify each has a HELP + TYPE
    // immediately preceding its value line.
    const lines = body.split("\n");
    const metricsWithValues = new Set();
    for (const line of lines) {
      if (line.startsWith("#")) continue;
      if (!line.trim()) continue;
      const name = line.split(/[{\s]/)[0];
      if (name.startsWith("tip_")) metricsWithValues.add(name);
    }

    for (const name of metricsWithValues) {
      expect(body).toMatch(new RegExp(`^# HELP ${name.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")} `, "m"));
      expect(body).toMatch(new RegExp(`^# TYPE ${name.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")} (counter|gauge)`, "m"));
    }

    // Spot-check a few expected metrics.
    expect(metricsWithValues.has("tip_narwhal_current_round")).toBe(true);
    expect(metricsWithValues.has("tip_bullshark_anchors_committed_total")).toBe(true);
    expect(metricsWithValues.has("tip_consensus_divergence_total")).toBe(true);
    expect(metricsWithValues.has("tip_consensus_halted")).toBe(true);
  });

  test("counter values reflect underlying stats()", async () => {
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
    });
    const res = await request(app).get("/metrics");
    // All metrics carry an injected `node` label (TIP node identity, short
    // hex form). With config.nodeId="tip://node/self", nodeShort="self".
    expect(res.text).toMatch(/^tip_bullshark_anchors_committed_total\{node="tip:\/\/node\/self"\} 20$/m);
    expect(res.text).toMatch(/^tip_bullshark_txs_committed_total\{node="tip:\/\/node\/self"\} 150$/m);
    expect(res.text).toMatch(/^tip_narwhal_rounds_advanced_total\{node="tip:\/\/node\/self"\} 41$/m);
  });

  test("gauge values reflect underlying stats()", async () => {
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
    });
    const res = await request(app).get("/metrics");
    expect(res.text).toMatch(/^tip_narwhal_current_round\{node="tip:\/\/node\/self"\} 42$/m);
    expect(res.text).toMatch(/^tip_bullshark_last_committed_round\{node="tip:\/\/node\/self"\} 40$/m);
    expect(res.text).toMatch(/^tip_narwhal_mempool_size\{node="tip:\/\/node\/self"\} 7$/m);
  });

  test("labels are properly formatted (node_id, version, node)", async () => {
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
    });
    const res = await request(app).get("/metrics");
    // Uptime has node_id + version + injected node label.
    expect(res.text).toMatch(/^tip_process_uptime_seconds\{node_id="tip:\/\/node\/self",version="2\.0\.0",node="tip:\/\/node\/self"\} \d+$/m);
  });

  test("consensus_divergence_total is ALWAYS present and zero when healthy", async () => {
    // This is the critical alert metric — operators write rules like
    // `rate(tip_consensus_divergence_total[5m]) > 0`. It MUST be present
    // in every scrape even if consensus is halted, else rate alerts break.
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
    });
    const res = await request(app).get("/metrics");
    expect(res.text).toMatch(/^tip_consensus_divergence_total\{node="tip:\/\/node\/self"\} 0$/m);
    expect(res.text).toMatch(/^# HELP tip_consensus_divergence_total BYZANTINE EVENT/m);
  });

  test("halt gauge flips to 1 when halt-gate is halted", async () => {
    const app = makeApp({
      consensus: {
        current: {
          stats: () => fakeStats(),
          isConsensusHalted: () => ({ halted: true, reason: "sub_quorum", staleMs: 8000 }),
        },
      },
    });
    const res = await request(app).get("/metrics");
    // Halt is a single label-free gauge (no churn on reason change). The
    // reason rides on a separate info metric. Both carry the injected
    // `node` label so dashboards group by real identity.
    expect(res.text).toMatch(/^tip_consensus_halted\{node="tip:\/\/node\/self"\} 1$/m);
    expect(res.text).toMatch(/^tip_consensus_halt_reason\{reason="sub_quorum",node="tip:\/\/node\/self"\} 1$/m);
    expect(res.text).toMatch(/^tip_consensus_stale_ms\{node="tip:\/\/node\/self"\} 8000$/m);
  });

  test("metrics endpoint scrapable even when consensus is null (node not running consensus)", async () => {
    const app = makeApp({ consensus: { current: null } });
    const res = await request(app).get("/metrics");
    expect(res.status).toBe(200);
    // Halt gauge is 1 with reason=consensus_not_running — operators see the outage.
    expect(res.text).toMatch(/^tip_consensus_halted\{node="tip:\/\/node\/self"\} 1$/m);
    expect(res.text).toMatch(/^tip_consensus_halt_reason\{reason="consensus_not_running",node="tip:\/\/node\/self"\} 1$/m);
    // Process + DAG metrics still emit.
    expect(res.text).toMatch(/^tip_process_uptime_seconds/m);
    expect(res.text).toMatch(/^tip_dag_tx_count/m);
  });

  test("network metrics appear when network is running", async () => {
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
      network: {
        current: {
          peerCount: () => 3,
          directPeers: () => ["peer-A", "peer-B", "peer-C"],
        },
      },
    });
    const res = await request(app).get("/metrics");
    expect(res.text).toMatch(/^tip_network_peers_authorized\{node="tip:\/\/node\/self"\} 3$/m);
    expect(res.text).toMatch(/^tip_network_direct_peers\{node="tip:\/\/node\/self"\} 3$/m);
  });

  test("per-peer channel-health + force-redial metrics appear", async () => {
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
      network: {
        current: {
          peerCount: () => 2,
          directPeers: () => ["a", "b"],
          metrics: () => ({ connects: 5, disconnects: 1, conn_closes: 1, handshakes_initiated: 2, rehandshakes: 0, fast_reauths: 1, force_redials: 3 }),
          channelHealth: () => [
            { peerId: "p1", tipNodeId: "tip://node/feedface1234", sendOk: 10, sendFail: 4, consecutiveFail: 2, lastOkAgeMs: 5000 },
          ],
        },
      },
    });
    const res = await request(app).get("/metrics");
    expect(res.text).toMatch(/^tip_network_force_redials_total\{node="tip:\/\/node\/self"\} 3$/m);
    expect(res.text).toMatch(/tip_network_peer_send_failures_total\{[^}]*peer="feedface1234"[^}]*\} 4/);
    expect(res.text).toMatch(/tip_network_peer_send_consecutive_failures\{[^}]*peer="feedface1234"[^}]*\} 2/);
    expect(res.text).toMatch(/tip_network_peer_last_send_ok_age_ms\{[^}]*peer="feedface1234"[^}]*\} 5000/);
  });

  test("per-peer heartbeat consecutive-misses (send/receive direction matrix) appears", async () => {
    const app = makeApp({
      consensus: {
        current: {
          stats: () => fakeStats({
            heartbeat: { peers: {
              p1: { consecutiveMisses: 3, tipNodeId: "tip://node/deadbeef0001" },
              p2: { consecutiveMisses: 0, tipNodeId: "tip://node/deadbeef0002" },
            } },
          }),
          isConsensusHalted: () => ({ halted: false, reason: "healthy" }),
        },
      },
    });
    const res = await request(app).get("/metrics");
    expect(res.text).toMatch(/tip_heartbeat_peer_consecutive_misses\{[^}]*peer="deadbeef0001"[^}]*\} 3/);
    expect(res.text).toMatch(/tip_heartbeat_peer_consecutive_misses\{[^}]*peer="deadbeef0002"[^}]*\} 0/);
  });

  test("mempool capacity emitted when available", async () => {
    const app = makeApp({
      consensus: {
        current: {
          stats: () => fakeStats({ mempool: { size: 5, capacity: 10000 } }),
          isConsensusHalted: () => ({ halted: false, reason: "healthy" }),
        },
      },
    });
    const res = await request(app).get("/metrics");
    expect(res.text).toMatch(/^tip_mempool_size\{node="tip:\/\/node\/self"\} 5$/m);
    expect(res.text).toMatch(/^tip_mempool_capacity\{node="tip:\/\/node\/self"\} 10000$/m);
  });

  test("merkle root emitted as info-style metric with label", async () => {
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
    });
    const res = await request(app).get("/metrics");
    expect(res.text).toMatch(/^tip_cert_merkle_root_info\{root="[a-f0-9]{16}",node="tip:\/\/node\/self"\} 1$/m);
  });

  test("body ends with a trailing newline (Prometheus format requirement)", async () => {
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
    });
    const res = await request(app).get("/metrics");
    expect(res.text.endsWith("\n")).toBe(true);
  });

  test("divergence counter increments are visible in the metric", async () => {
    // Simulate a divergence event having happened.
    const stats = fakeStats();
    stats.antiEntropy.metrics.consensus_divergence_total = 3;
    const app = makeApp({
      consensus: { current: { stats: () => stats, isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
    });
    const res = await request(app).get("/metrics");
    expect(res.text).toMatch(/^tip_consensus_divergence_total\{node="tip:\/\/node\/self"\} 3$/m);
  });

  test("non-numeric / missing counter values default to 0", async () => {
    // If a new metric is added upstream but stats hasn't been updated yet,
    // the line should still be emitted as 0 rather than "NaN" (which
    // Prometheus would reject).
    const stats = fakeStats();
    delete stats.bullshark.metrics.certs_pruned;  // simulate missing field
    const app = makeApp({
      consensus: { current: { stats: () => stats, isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
    });
    const res = await request(app).get("/metrics");
    expect(res.text).toMatch(/^tip_bullshark_certs_pruned_total\{node="tip:\/\/node\/self"\} 0$/m);
  });

  test("does NOT get wrapped in {ok, data} JSON envelope", async () => {
    // The app's global response wrapper applies to JSON only. Metrics
    // returns plain text via res.type + res.send — scrapers would
    // reject anything with JSON wrapping.
    const app = makeApp({
      consensus: { current: { stats: () => fakeStats(), isConsensusHalted: () => ({ halted: false, reason: "healthy" }) } },
    });
    const res = await request(app).get("/metrics");
    expect(res.text).not.toMatch(/^\{"ok":/);
    expect(res.text.startsWith("# HELP")).toBe(true);
  });
});
