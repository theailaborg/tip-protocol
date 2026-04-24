/**
 * @file @tip-protocol/node/src/routes/metrics.js
 * @description Prometheus exposition endpoint — GET /metrics (§29 in issues.md).
 *
 * Walks the counters already accumulated by narwhal, bullshark, mempool,
 * sync-handler, and anti-entropy (plus process + halt-gate state) and
 * emits them in Prometheus text format so scrapers, Grafana, and
 * Alertmanager can consume directly.
 *
 * Wire format (Prometheus text exposition v0.0.4):
 *   # HELP metric_name description
 *   # TYPE metric_name counter|gauge
 *   metric_name{label="value"} numeric_value
 *
 * Naming conventions honored (Prometheus best practices):
 *   - Prefix all metrics with `tip_` (namespace)
 *   - Counters end with `_total`
 *   - Gauges are bare names
 *   - Byte values end with `_bytes`
 *   - Time values end with `_seconds` or `_ms`
 *   - Use snake_case throughout
 *
 * Deliberate choices:
 *   - Mounted at top-level `/metrics` (not `/v1/metrics`) — matches
 *     Prometheus client convention and existing scraper configs
 *   - text/plain response; does NOT pass through the `{ok,data}` JSON
 *     wrapper middleware (uses res.type + res.send)
 *   - 200 OK even when consensus is halted or null — metrics should
 *     ALWAYS be scrapable so operators can see the halt via the
 *     `tip_consensus_halted` gauge
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const express = require("express");

/**
 * Build a Prometheus-format metrics line.
 * @param {string} name        metric name (already prefixed with tip_)
 * @param {number|string} value numeric value (NaN/null → 0)
 * @param {Object} [labels]    optional label map
 * @returns {string}           single line (no trailing newline)
 */
function _line(name, value, labels) {
  const num = Number.isFinite(Number(value)) ? Number(value) : 0;
  if (labels && Object.keys(labels).length > 0) {
    const labelStr = Object.entries(labels)
      .map(([k, v]) => `${k}="${String(v).replace(/"/g, '\\"')}"`)
      .join(",");
    return `${name}{${labelStr}} ${num}`;
  }
  return `${name} ${num}`;
}

function _block(name, type, help, value, labels) {
  return [
    `# HELP ${name} ${help}`,
    `# TYPE ${name} ${type}`,
    _line(name, value, labels),
  ].join("\n");
}

function createRouter({ dag, config, consensus, network }) {
  const router = express.Router();

  router.get("/metrics", (_req, res) => {
    const lines = [];

    // ── Process + node identity ──────────────────────────────────────────
    const mem = process.memoryUsage();
    const nodeLabels = {
      node_id: config.nodeRegisteredId || config.nodeId || "unknown",
      version: config.nodeVersion || "0.0.0",
    };

    lines.push(_block(
      "tip_process_uptime_seconds",
      "gauge",
      "Seconds since this node process started",
      Math.floor(process.uptime()),
      nodeLabels,
    ));
    lines.push(_block(
      "tip_process_memory_rss_bytes",
      "gauge",
      "Resident Set Size of the node process",
      mem.rss,
    ));
    lines.push(_block(
      "tip_process_memory_heap_used_bytes",
      "gauge",
      "Node heap bytes currently allocated",
      mem.heapUsed,
    ));
    lines.push(_block(
      "tip_process_memory_heap_total_bytes",
      "gauge",
      "Node heap capacity",
      mem.heapTotal,
    ));

    // ── DAG state ────────────────────────────────────────────────────────
    let txCount = 0;
    try { txCount = dag.count ? dag.count() : 0; } catch { /* ignore */ }
    lines.push(_block(
      "tip_dag_tx_count",
      "gauge",
      "Total transactions committed to the DAG",
      txCount,
    ));

    let certCount = 0;
    try { certCount = dag.certificateCount ? dag.certificateCount() : 0; } catch { /* ignore */ }
    lines.push(_block(
      "tip_dag_cert_count",
      "gauge",
      "Certificates currently in the DAG (bounded by cert GC)",
      certCount,
    ));

    // ── Network (libp2p peers) ───────────────────────────────────────────
    const net = network?.current;
    if (net) {
      lines.push(_block(
        "tip_network_peers_authorized",
        "gauge",
        "Count of peers that completed TIP handshake and are currently connected",
        net.peerCount ? net.peerCount() : 0,
      ));
      lines.push(_block(
        "tip_network_direct_peers",
        "gauge",
        "Count of peers in gossipsub DirectPeers mesh (bypass random mesh selection)",
        net.directPeers ? (net.directPeers().length || 0) : 0,
      ));
    }

    // ── Consensus ────────────────────────────────────────────────────────
    const cons = consensus?.current;
    if (cons && typeof cons.stats === "function") {
      const s = cons.stats();

      // Narwhal
      const n = s.narwhal || {};
      const nm = n.metrics || {};
      lines.push(_block("tip_narwhal_current_round",           "gauge",   "Current consensus round Narwhal is working on", n.round));
      lines.push(_block("tip_narwhal_certificates_this_round", "gauge",   "Certificates collected for current round", n.certificatesThisRound));
      lines.push(_block("tip_narwhal_batches_this_round",      "gauge",   "Batches received for current round (incl. self)", n.batchesThisRound));
      lines.push(_block("tip_narwhal_pending_certs",           "gauge",   "Cert waiters parked because parents missing from DAG", n.pendingCerts));
      lines.push(_block("tip_narwhal_quorum",                  "gauge",   "Current quorum threshold (2f+1 of active committee)", n.quorum));
      lines.push(_block("tip_narwhal_active_participants",     "gauge",   "Active committee size (DAG-derived)", n.activeParticipants));
      lines.push(_block("tip_narwhal_registered_nodes",        "gauge",   "Total registered nodes (includes inactive)", n.registeredNodes));
      lines.push(_block("tip_narwhal_mempool_size",            "gauge",   "Pending txs in mempool", n.mempoolSize));
      lines.push(_block("tip_narwhal_rounds_advanced_total",     "counter", "Total consensus rounds advanced since process start", nm.rounds_advanced));
      lines.push(_block("tip_narwhal_batches_received_total",    "counter", "Total batches received (own + peer)", nm.batches_received));
      lines.push(_block("tip_narwhal_certs_received_total",      "counter", "Total certificates received from peers", nm.certs_received));
      lines.push(_block("tip_narwhal_certs_parked_total",        "counter", "Certs parked on missing-parent waiter", nm.certs_parked));
      lines.push(_block("tip_narwhal_certs_unblocked_total",     "counter", "Parked certs unblocked when parents arrived", nm.certs_unblocked));
      lines.push(_block("tip_narwhal_pending_certs_pruned_total", "counter", "Stale parked certs dropped by §2 GC on round advance", nm.pending_certs_pruned));
      lines.push(_block("tip_narwhal_equivocation_refused_total", "counter", "§1 equivocation attempts refused (vote-digest mismatch)", nm.equivocation_refused));
      lines.push(_block("tip_narwhal_fast_forwards_total",       "counter", "Round fast-forwards triggered by higher-round batch", nm.fast_forwards));
      lines.push(_block("tip_narwhal_retries_total",             "counter", "Retry broadcasts of own batch/cert while stuck", nm.retries));

      // Bullshark
      const b = s.bullshark || {};
      const bm = b.metrics || {};
      lines.push(_block("tip_bullshark_last_committed_round",  "gauge",   "Last round where an anchor was committed", b.lastCommittedRound));
      lines.push(_block("tip_bullshark_ordered_certificates",  "gauge",   "Certs marked ordered (bounded cache, see ORDERED_HASH_CACHE_SIZE)", b.orderedCertificates));
      lines.push(_block("tip_bullshark_consensus_index",       "gauge",   "Monotonic commit counter (§15) — advances on every real activity-commit", b.consensusIndex));
      lines.push(_block("tip_bullshark_anchors_committed_total",   "counter", "Total anchor certs committed by Bullshark", bm.anchors_committed));
      lines.push(_block("tip_bullshark_anchors_no_support_total",  "counter", "Anchor candidates that failed the 2f+1 support check", bm.anchors_no_support));
      lines.push(_block("tip_bullshark_txs_committed_total",       "counter", "Transactions committed to derived state", bm.txs_committed));
      lines.push(_block("tip_bullshark_certs_pruned_total",        "counter", "Certs pruned from SQLite by §2 GC", bm.certs_pruned));
      lines.push(_block("tip_bullshark_gc_runs_total",             "counter", "Successful §2 GC runs", bm.gc_runs));
      lines.push(_block("tip_bullshark_gc_failures_total",         "counter", "GC attempts that threw (SQLite error, etc.)", bm.gc_failures));
      lines.push(_block("tip_bullshark_gc_skipped_disabled_total", "counter", "GC ticks skipped because TIP_GC_DISABLED=1", bm.gc_skipped_disabled));

      // Mempool
      const m = s.mempool || {};
      lines.push(_block("tip_mempool_size",          "gauge", "Pending tx count in mempool", m.size));
      if (m.capacity != null) {
        lines.push(_block("tip_mempool_capacity",    "gauge", "Maximum mempool size", m.capacity));
      }

      // Anti-entropy
      const ae = s.antiEntropy || {};
      const aem = ae.metrics || {};
      lines.push(_block("tip_antientropy_last_status_size",              "gauge",   "Peers currently tracked in the anti-entropy status cache", ae.last_status_size));
      lines.push(_block("tip_antientropy_loops_run_total",               "counter", "Completed anti-entropy reconciliation cycles", aem.loops_run));
      lines.push(_block("tip_antientropy_checks_total",                  "counter", "Per-peer checks attempted across all cycles", aem.checks_total));
      lines.push(_block("tip_antientropy_peers_queried_total",           "counter", "Sync-status RPCs issued to peers", aem.peers_queried));
      lines.push(_block("tip_antientropy_peer_rpc_failures_total",       "counter", "Sync-status RPCs that failed (open/send/decode)", aem.peer_rpc_failures));
      lines.push(_block("tip_antientropy_peer_rpc_timeouts_total",       "counter", "Sync-status RPCs that timed out", aem.peer_rpc_timeouts));
      lines.push(_block("tip_antientropy_peer_identity_mismatch_total",  "counter", "Peer claimed different node_id than authorized (spoofing guard)", aem.peer_identity_mismatch));
      lines.push(_block("tip_antientropy_peer_unauthorized_query_total", "counter", "queryPeer rejected — peer missing from authorized map", aem.peer_unauthorized_query));
      lines.push(_block("tip_antientropy_peer_unauthorized_inbound_total", "counter", "Incoming sync-status from unauthorized peer rejected", aem.peer_unauthorized_inbound));
      lines.push(_block("tip_antientropy_gaps_pulled_total",             "counter", "Times self-was-behind triggered a cert gap pull", aem.gaps_pulled));
      // Divergence counter — the CRITICAL alert signal. Named per Prometheus
      // convention so Alertmanager rules like `rate(tip_consensus_divergence_total[5m]) > 0`
      // work out of the box.
      lines.push(_block(
        "tip_consensus_divergence_total",
        "counter",
        "BYZANTINE EVENT: equal committed_round but different state_merkle_root across peers. Should always be 0; any increase requires immediate ops attention.",
        aem.consensus_divergence_total,
      ));

      // Merkle root — exposed as an info-style metric with the hex in a label
      // so Prometheus can detect changes via label churn (cardinality is
      // bounded because old roots are forgotten as soon as a new one is emitted).
      if (s.merkleRoot) {
        lines.push(`# HELP tip_cert_merkle_root_info Current certificate-DAG Merkle root (hex, short). Label-based info metric.`);
        lines.push(`# TYPE tip_cert_merkle_root_info gauge`);
        lines.push(_line("tip_cert_merkle_root_info", 1, { root: String(s.merkleRoot).slice(0, 16) }));
      }
    }

    // ── Halt gate (§30 halt-honestly) ────────────────────────────────────
    if (cons && typeof cons.isConsensusHalted === "function") {
      try {
        const halt = cons.isConsensusHalted();
        lines.push(_block(
          "tip_consensus_halted",
          "gauge",
          "1 if halt-gate is tripping (sub-quorum, stale rounds); 0 if healthy. 503 on /v1/* writes when this is 1.",
          halt.halted ? 1 : 0,
          { reason: halt.reason || "unknown" },
        ));
        if (halt.staleMs != null) {
          lines.push(_block(
            "tip_consensus_stale_ms",
            "gauge",
            "Milliseconds since the last Narwhal round advance",
            halt.staleMs,
          ));
        }
      } catch { /* ignore */ }
    } else {
      // Even without a running consensus we emit the halt gauge as 1 so
      // scrapers see the outage.
      lines.push(_block(
        "tip_consensus_halted",
        "gauge",
        "1 if halt-gate is tripping; 0 if healthy. Emitted as 1 when consensus module isn't running.",
        1,
        { reason: "consensus_not_running" },
      ));
    }

    // Prometheus requires a trailing newline after the last metric.
    const body = lines.join("\n") + "\n";
    res.type("text/plain; version=0.0.4").send(body);
  });

  return router;
}

module.exports = { createRouter };
