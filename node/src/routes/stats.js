/**
 * @file @tip-protocol/node/src/routes/stats.js
 * @description Observability endpoints — detailed node/consensus stats for
 *              dashboards and operators.
 *
 * Split from /health (which stays minimal for load-balancer liveness probes)
 * so that hitting these richer endpoints doesn't compete with high-frequency
 * health checks. Counters populated by narwhal/bullshark's internal _metrics
 * object accumulate for the lifetime of the process; callers can compute
 * rates by snapshotting two consecutive responses.
 *
 * Endpoints:
 *   GET /v1/stats             — full snapshot (node + network + consensus)
 *   GET /v1/stats/consensus   — consensus subset only (narwhal + bullshark)
 *   GET /v1/sync-status       — §28 anti-entropy cluster sync view
 *   GET /v1/debug/committee   — committee derivation reasoning at a given round
 *                               (cross-node diffable; flushes the gossip-lag /
 *                                snapshot-asymmetry classes of bug)
 *
 * For Prometheus-compatible /metrics see issue #29.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ dag, config, consensus, network }) {
  const router = express.Router();

  function _snapshot() {
    const net = network?.current;
    const cons = consensus?.current;
    const mem = process.memoryUsage();

    return {
      node: {
        node_id: config.nodeRegisteredId || config.nodeId,
        node_type: config.nodeType,
        version: config.nodeVersion,
        uptime_seconds: Math.floor(process.uptime()),
      },
      network: net ? {
        peer_id: net.peerId,
        peers_connected: net.peerCount(),
        peer_ids: net.peers().map(p => p.toString()),
      } : null,
      consensus: cons ? cons.stats() : null,
      dag: {
        tx_count: (() => { try { return dag.count(); } catch { return null; } })(),
      },
      memory_mb: {
        rss: Math.round(mem.rss / 1048576),
        heap_used: Math.round(mem.heapUsed / 1048576),
        heap_total: Math.round(mem.heapTotal / 1048576),
      },
      timestamp: new Date().toISOString(),
    };
  }

  router.get("/stats", (_req, res) => {
    res.json(_snapshot());
  });

  router.get("/stats/consensus", (_req, res) => {
    const cons = consensus?.current;
    if (!cons) {
      res.status(503).json({ error: "Consensus not running", consensus: null });
      return;
    }
    res.json({
      node_id: config.nodeRegisteredId || config.nodeId,
      consensus: cons.stats(),
      timestamp: new Date().toISOString(),
    });
  });

  // Diagnostic: full committee derivation reasoning at any round.
  // Surfaces inputs (registered set, producers in window with their
  // per-author earliest+last-in-window) and the derivation result. Two
  // nodes can hit this endpoint at the same round and diff the JSON to
  // spot exactly where their views diverged — gossip-lag asymmetry,
  // missing certs, registration mismatches, etc.
  //
  //   curl 'http://node1:4000/v1/debug/committee?round=300'
  //   curl 'http://node2:4000/v1/debug/committee?round=300'
  //   diff <(curl ...) <(curl ...)
  router.get("/debug/committee", asyncHandler((req, res) => {
    const cons = consensus?.current;
    if (!cons) throw { status: 503, error: "Consensus not running" };

    const round = Number(req.query.round);
    if (!Number.isFinite(round) || round < 1) {
      throw { status: 400, error: "Query parameter 'round' must be a positive integer" };
    }

    const { CONSENSUS } = require("../../../shared/protocol-constants");
    const K = Number(req.query.K) || CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS;
    const wave = Math.floor((round - 1) / 2);
    const waveStartRound = wave * 2 + 1;

    const registered = [];
    for (const n of dag.getAllNodes()) {
      if (n.status === "active" && !dag.isRevoked(n.node_id)) {
        registered.push(n.node_id);
      }
    }

    const fromRound = Math.max(1, waveStartRound - K);
    const toRound = waveStartRound - 1;
    // authorId → { earliest, lastInWindow, certCountInWindow }
    const producers = {};
    for (let r = fromRound; r <= toRound; r++) {
      try {
        const certs = dag.getCertificatesByRound(r);
        for (const cert of certs) {
          const id = cert.author_node_id;
          if (!producers[id]) {
            const earliest = typeof dag.getEarliestCertRoundForAuthor === "function"
              ? dag.getEarliestCertRoundForAuthor(id) : 0;
            producers[id] = { earliest, lastInWindow: r, certCountInWindow: 0 };
          }
          producers[id].lastInWindow = r;
          producers[id].certCountInWindow++;
        }
      } catch { /* ignore */ }
    }

    const proven = [];
    const notProven = [];
    for (const [id, info] of Object.entries(producers)) {
      if (!registered.includes(id)) continue;
      const span = info.lastInWindow - info.earliest;
      if (info.earliest > 0 && span >= K) {
        proven.push({ id, span, ...info });
      } else {
        notProven.push({ id, span, reason: span < K ? `span ${span} < K=${K}` : "earliest=0", ...info });
      }
    }

    const liveProducers = Object.keys(producers).filter(id => registered.includes(id));

    let activeCommittee;
    let fallbackPath;
    if (proven.length > 0) {
      activeCommittee = proven.map(p => p.id).sort();
      fallbackPath = "proven";
    } else if (liveProducers.length > 0) {
      activeCommittee = [...liveProducers].sort();
      fallbackPath = "cold-start_liveProducers";
    } else {
      activeCommittee = [...registered].sort();
      fallbackPath = "cold-start_registered";
    }

    res.json({
      node_id: config.nodeRegisteredId || config.nodeId,
      query: { round, K, waveStartRound, kWindow: [fromRound, toRound] },
      registered: registered.sort(),
      producers,
      proven,
      notProven,
      fallback_path: fallbackPath,
      active_committee: activeCommittee,
      active_committee_size: activeCommittee.length,
      quorum: Math.ceil((2 * activeCommittee.length) / 3),
      timestamp: new Date().toISOString(),
    });
  }));

  // §28: cluster-wide sync state. Returns self + every authorized peer
  // we've successfully probed via /tip/sync-status/1.0.0, with an
  // in_sync flag (same committed_round + same state_merkle_root) and
  // the top-level `in_sync` = all peers match. Ops dashboards use this
  // to verify N-node convergence at a glance.
  router.get("/sync-status", (_req, res) => {
    const cons = consensus?.current;
    if (!cons || typeof cons.getSyncStatus !== "function") {
      res.status(503).json({ error: "Consensus not running", sync_status: null });
      return;
    }
    try {
      res.json(cons.getSyncStatus());
    } catch (err) {
      res.status(500).json({ error: `sync-status failed: ${err.message}` });
    }
  });

  return router;
}

module.exports = { createRouter };
