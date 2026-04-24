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
 *
 * For Prometheus-compatible /metrics see issue #29.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const express = require("express");

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
