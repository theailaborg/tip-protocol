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
const { nowIso } = require("../../../shared/time");

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
      timestamp: nowIso(),
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
      timestamp: nowIso(),
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

    // #75: under the rotation-period model, committee derivation is a
    // pure lookup against committee_history (no per-round span check).
    // This endpoint exposes (a) the committee in effect at the queried
    // round, (b) the rotation that put it there, (c) the participation
    // tally for the latest rotation in progress — useful for ops to
    // diff across nodes and verify deterministic agreement.
    const { CONSENSUS } = require("../../../shared/protocol-constants");
    const intervalCommits = CONSENSUS.COMMITTEE_ROTATION_INTERVAL_COMMITS;
    const minPct = CONSENSUS.COMMITTEE_ROTATION_PARTICIPATION_PCT_OF_INTERVAL;
    const threshold = Math.ceil((intervalCommits * minPct) / 100);

    const registered = [];
    for (const n of dag.getAllNodes()) {
      if (n.status === "active" && !dag.isRevoked(n.node_id)) {
        registered.push(n.node_id);
      }
    }

    const rotationAtRound = (typeof dag.getCommitteeAtRound === "function")
      ? dag.getCommitteeAtRound(round) : null;
    const latestRotation = (typeof dag.getLatestRotation === "function")
      ? dag.getLatestRotation() : null;

    // Latest rotation's in-progress participation tally — what the next
    // boundary will use to compute the next committee.
    const latestRotationNumber = latestRotation ? latestRotation.rotation_number : -1;
    const inProgressRotation = latestRotationNumber + 1;
    const participation = (typeof dag.getRotationParticipation === "function")
      ? dag.getRotationParticipation(inProgressRotation) : [];

    const activeCommittee = rotationAtRound
      ? rotationAtRound.committee.map(m => m.node_id).filter(id => registered.includes(id)).sort()
      : registered.sort();

    res.json({
      node_id: config.nodeRegisteredId || config.nodeId,
      query: { round },
      rotation_model: {
        interval_commits: intervalCommits,
        min_participation_pct: minPct,
        threshold,
      },
      active_at_round: rotationAtRound ? {
        rotation_number: rotationAtRound.rotation_number,
        effective_round: rotationAtRound.effective_round,
        committee: rotationAtRound.committee.map(m => m.node_id).sort(),
      } : null,
      latest_rotation: latestRotation ? {
        rotation_number: latestRotation.rotation_number,
        effective_round: latestRotation.effective_round,
        committee: latestRotation.committee.map(m => m.node_id).sort(),
      } : null,
      in_progress_rotation: {
        rotation_number: inProgressRotation,
        participation: participation.sort((a, b) => a.node_id.localeCompare(b.node_id)),
      },
      registered: registered.sort(),
      active_committee: activeCommittee,
      active_committee_size: activeCommittee.length,
      quorum: Math.ceil((2 * activeCommittee.length) / 3),
      timestamp: nowIso(),
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
