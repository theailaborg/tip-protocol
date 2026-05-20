/**
 * @file @tip-protocol/node/src/services/metrics-service.js
 * @description Builds the Prometheus exposition body for /metrics (§29).
 *
 * Walks consensus + network + DAG state and emits the Prometheus text
 * exposition format (v0.0.4). The route module just calls
 * `metricsService.buildBody()` and writes the string back as text/plain.
 *
 * Layout (section functions are small + named so each metric class is easy
 * to find / extend / remove):
 *
 *   processSection         — uptime, memory, node identity
 *   dagSection             — tx + cert counts
 *   registrySection        — federation roster (one row per registered node)
 *   networkSection         — libp2p peer counts (only when network is up)
 *   narwhalSection         — round, mempool, sync state, per-event counters
 *   bullsharkSection       — anchor commits, ordering, GC counters
 *   mempoolSection         — pending tx count + capacity
 *   antiEntropySection     — reconciliation + the divergence canary
 *   merkleRootSection      — current cert-DAG Merkle root (info metric)
 *   haltSection            — halt gauge + reason (split so the gauge is a
 *                            single label-free time series; reason rides on
 *                            a separate info metric, no churn on transitions)
 *
 * Final pass: `injectNodeLabel` adds a `node="<tip://node/...>"` label to
 * every metric row so dashboards group by real identity. Lines that already
 * have a `node="..."` label (e.g. `tip_node_registry_info` carries the
 * REGISTERED identity, not the emitter's) are skipped.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// Pure Prometheus text-format helpers live in lib/ — they're reusable
// from any emitter and don't belong in a TIP-specific service file.
const { line, gauge, counter } = require("../lib/prom-format");

// ── Section builders ──────────────────────────────────────────────────────
//
// Each returns either a single block string or an array of block strings.
// They take only what they need so they're easy to test or reuse.

function processSection(config) {
  const mem = process.memoryUsage();
  const idLabels = {
    node_id: config.nodeRegisteredId || config.nodeId || "unknown",
    version: config.nodeVersion || "0.0.0",
  };
  return [
    gauge("tip_process_uptime_seconds", "Seconds since this node process started", Math.floor(process.uptime()), idLabels),
    gauge("tip_process_memory_rss_bytes", "Resident Set Size of the node process", mem.rss),
    gauge("tip_process_memory_heap_used_bytes", "Node heap bytes currently allocated", mem.heapUsed),
    gauge("tip_process_memory_heap_total_bytes", "Node heap capacity", mem.heapTotal),
  ].join("\n");
}

function dagSection(dag) {
  let txCount = 0, certCount = 0;
  try { txCount = dag.count?.() ?? 0; } catch { /* ignore */ }
  try { certCount = dag.certificateCount?.() ?? 0; } catch { /* ignore */ }
  return [
    gauge("tip_dag_tx_count", "Total transactions committed to the DAG", txCount),
    gauge("tip_dag_cert_count", "Certificates currently in the DAG (bounded by cert GC)", certCount),
  ].join("\n");
}

/**
 * Federation roster — one row per registered node from THIS emitter's DAG
 * view. Lets dashboards show offline-but-registered nodes alongside live
 * ones. The `node` label here is the REGISTERED identity, distinct from
 * the emitter — `injectNodeLabel` knows to leave these rows alone.
 */
function registrySection(dag) {
  let allNodes = [];
  try { allNodes = (dag.getAllNodes && dag.getAllNodes()) || []; } catch { /* ignore */ }

  const out = [];
  if (allNodes.length > 0) {
    out.push(`# HELP tip_node_registry_info Federation roster from this node's DAG. One line per registered node, value 1. The 'node' label is the REGISTERED identity, not the emitter.`);
    out.push(`# TYPE tip_node_registry_info gauge`);
    for (const n of allNodes) {
      out.push(line("tip_node_registry_info", 1, {
        node: n.node_id || "",
        name: n.name || "",
        status: n.status || "unknown",
      }));
    }
  }
  out.push(gauge("tip_dag_registered_nodes", "Total nodes in the DAG registry (active + inactive)", allNodes.length));
  return out.join("\n");
}

function networkSection(network, dag) {
  const net = network?.current;
  if (!net) return "";

  const out = [
    gauge("tip_network_peers_authorized", "Count of peers that completed TIP handshake and are currently connected", net.peerCount?.() ?? 0),
    gauge("tip_network_direct_peers", "Count of peers in gossipsub DirectPeers mesh (bypass random mesh selection)", (net.directPeers?.() || []).length),
  ];

  const authorized = net.authorizedPeers ? net.authorizedPeers() : {};
  const peerTipIds = Object.values(authorized).filter(Boolean);

  // Resolve TIP IDs → human-readable names via the local registry. Falls
  // back to the short TIP ID for peers whose registry row hasn't replicated
  // yet (boot ordering: the libp2p connection authorizes faster than the
  // DAG row propagates on a cold join). The lookup is cheap — registry is
  // an in-memory map keyed by TIP ID.
  function resolveName(tipId) {
    try {
      const node = dag?.getNode?.(tipId);
      if (node?.name) return node.name;
    } catch { /* fall through */ }
    return tipId.slice(0, 16);
  }
  const peerNames = peerTipIds.map(resolveName).sort();

  // Per-peer connectivity, two views of the same data:
  //
  // (1) tip_network_peer_connection — one line per (self, peer) directed
  //     edge. The `peer` label is the canonical TIP ID — best for
  //     diagnosing asymmetric drops (A→B exists but B→A doesn't) where
  //     identity stability matters. Use when you need the raw graph.
  //
  // (2) tip_network_peer_list — single line per emitter with all peer
  //     NAMES pre-joined into a comma-separated label, sorted alphabetically.
  //     Best for at-a-glance dashboards: "node X is connected to: A, B, C"
  //     in one row. Names are stable across reconnects (tied to registered
  //     identity, not libp2p peer ID) so the label value churns less
  //     than a TIP-ID-based encoding would.
  //
  // (1) is canonical (one time series per edge), (2) is a convenience
  // view optimised for human readability.
  if (peerTipIds.length > 0) {
    out.push(`# HELP tip_network_peer_connection Directed edge: emitter (node label) is currently connected to (peer label, canonical TIP ID). Value is always 1; the labels carry the topology.`);
    out.push(`# TYPE tip_network_peer_connection gauge`);
    for (const tipPeerId of peerTipIds.slice().sort()) {
      out.push(line("tip_network_peer_connection", 1, { peer: tipPeerId }));
    }
  }
  out.push(`# HELP tip_network_peer_list Comma-separated NAMES of peers this emitter is currently connected to (sorted alphabetically; falls back to short TIP ID for peers whose registry row hasn't replicated yet). Value is the peer count.`);
  out.push(`# TYPE tip_network_peer_list gauge`);
  out.push(line("tip_network_peer_list", peerTipIds.length, { peers: peerNames.join(",") }));

  return out.join("\n");
}

function narwhalSection(s) {
  const n = s.narwhal || {};
  const nm = n.metrics || {};
  return [
    gauge("tip_narwhal_current_round", "Current consensus round Narwhal is working on", n.round),
    gauge("tip_narwhal_syncing", "1 if Narwhal is in sync mode (round production suppressed while catching up); 0 if ready", n.joinState === "syncing" ? 1 : 0),
    // Tri-state join FSM exposed as three indicator gauges. Dashboards can
    // mux these into one column or chart the timeline of transitions.
    gauge("tip_narwhal_join_state_ready",       "1 when Narwhal is ready (cert production active)",                  n.joinState === "ready" ? 1 : 0),
    gauge("tip_narwhal_join_state_catching_up", "1 when Narwhal is catching_up (cert tail closing, no production)", n.joinState === "catching_up" ? 1 : 0),
    gauge("tip_narwhal_join_state_syncing",     "1 when Narwhal is syncing (snapshot installing)",                   n.joinState === "syncing" ? 1 : 0),
    gauge("tip_narwhal_sync_duration_seconds", "Seconds since the node entered syncing; 0 when not syncing. Sustained > 3× round timeout means sync attempts are looping",
      n.joinState === "syncing" && n.syncEnteredAt ? Math.floor((Date.now() - n.syncEnteredAt) / 1000) : 0),
    gauge("tip_narwhal_catching_up_duration_seconds", "Seconds since the node entered catching_up; 0 when not catching_up. Sustained > 10× round timeout flips back to syncing for a fresher snapshot",
      n.joinState === "catching_up" && n.catchingUpEnteredAt ? Math.floor((Date.now() - n.catchingUpEnteredAt) / 1000) : 0),
    gauge("tip_narwhal_catch_up_target", "Round the cert tail must reach for catching_up to promote to ready; 0 when not catching up",
      n.catchUpTarget || 0),
    gauge("tip_narwhal_certificates_this_round", "Certificates collected for current round", n.certificatesThisRound),
    gauge("tip_narwhal_batches_this_round", "Batches received for current round (incl. self)", n.batchesThisRound),
    gauge("tip_narwhal_pending_certs", "Cert waiters parked because parents missing from DAG", n.pendingCerts),
    gauge("tip_narwhal_quorum", "Current quorum threshold (2f+1 of active committee)", n.quorum),
    gauge("tip_narwhal_active_participants", "Active committee size (DAG-derived)", n.activeParticipants),
    gauge("tip_narwhal_registered_nodes", "Total registered nodes (includes inactive)", n.registeredNodes),
    gauge("tip_narwhal_mempool_size", "Pending txs in mempool", n.mempoolSize),
    counter("tip_narwhal_rounds_advanced_total", "Total consensus rounds advanced since process start", nm.rounds_advanced),
    counter("tip_narwhal_batches_received_total", "Total batches received (own + peer)", nm.batches_received),
    counter("tip_narwhal_certs_received_total", "Total certificates received from peers", nm.certs_received),
    counter("tip_narwhal_certs_parked_total", "Certs parked on missing-parent waiter", nm.certs_parked),
    counter("tip_narwhal_certs_unblocked_total", "Parked certs unblocked when parents arrived", nm.certs_unblocked),
    counter("tip_narwhal_pending_certs_pruned_total", "Stale parked certs dropped by §2 GC on round advance", nm.pending_certs_pruned),
    counter("tip_narwhal_equivocation_refused_total", "§1 equivocation attempts refused (vote-digest mismatch)", nm.equivocation_refused),
    counter("tip_narwhal_fast_forwards_total", "Round fast-forwards triggered by higher-round batch", nm.fast_forwards),
    counter("tip_narwhal_retries_total", "Retry broadcasts of own batch/cert while stuck", nm.retries),
    counter("tip_narwhal_acks_rebroadcast_total", "Cached acks re-broadcast on duplicate batch arrival (dropped-ack recovery)", nm.acks_rebroadcast),
    counter("tip_narwhal_acks_sent_direct_total", "BatchAcks delivered via direct libp2p stream (#46 structural fix)", nm.acks_sent_direct),
    counter("tip_narwhal_acks_sent_fallback_total", "BatchAcks that fell back to gossipsub after direct-stream failure", nm.acks_sent_fallback),
  ].join("\n");
}

function bullsharkSection(s) {
  const b = s.bullshark || {};
  const bm = b.metrics || {};
  return [
    gauge("tip_bullshark_last_committed_round", "Last round where an anchor was committed", b.lastCommittedRound),
    gauge("tip_bullshark_ordered_certificates", "Certs marked ordered (bounded cache, see ORDERED_HASH_CACHE_SIZE)", b.orderedCertificates),
    gauge("tip_bullshark_consensus_index", "Monotonic commit counter (§15) — advances on every real activity-commit", b.consensusIndex),
    counter("tip_bullshark_anchors_committed_total", "Total anchor certs committed by Bullshark", bm.anchors_committed),
    counter("tip_bullshark_anchors_no_support_total", "Anchor candidates that failed the 2f+1 support check", bm.anchors_no_support),
    counter("tip_bullshark_txs_committed_total", "Transactions committed to derived state", bm.txs_committed),
    counter("tip_bullshark_certs_pruned_total", "Certs pruned from SQLite by §2 GC", bm.certs_pruned),
    counter("tip_bullshark_gc_runs_total", "Successful §2 GC runs", bm.gc_runs),
    counter("tip_bullshark_gc_failures_total", "GC attempts that threw (SQLite error, etc.)", bm.gc_failures),
    counter("tip_bullshark_gc_skipped_disabled_total", "GC ticks skipped because TIP_GC_DISABLED=1", bm.gc_skipped_disabled),
  ].join("\n");
}

function mempoolSection(s) {
  const m = s.mempool || {};
  const c = m.counters || {};
  const out = [
    gauge("tip_mempool_size", "Pending tx count in mempool (gauge — may miss transients on busy networks; pair with tip_mempool_received_total)", m.size),
    // Cumulative counters — never miss transient tx flow that gauges
    // can sample-through. rate(tip_mempool_received_total[1m]) = submit
    // rate; rate(tip_mempool_drained_total[1m]) = batched-into-cert rate.
    counter("tip_mempool_received_total", "Cumulative txs accepted into the mempool since process start", c.received_total),
    counter("tip_mempool_drained_total", "Cumulative txs drained from the mempool into Narwhal batches", c.drained_total),
    counter("tip_mempool_evicted_total", "Cumulative txs evicted from the mempool for exceeding TTL", c.evicted_total),
    counter("tip_mempool_rejected_total", "Cumulative submit attempts rejected (full / duplicate / malformed)", c.rejected_total),
  ];
  if (m.capacity != null) out.push(gauge("tip_mempool_capacity", "Maximum mempool size", m.capacity));
  return out.join("\n");
}

/**
 * §4 + #34 — chain-of-trust committee rotation metrics.
 *
 * Five metrics surfacing rotation health:
 *   - current_rotation_number: which rotation are we in (gauge from DAG)
 *   - rotation_proposals_total: leader has tried to propose (bullshark counter)
 *   - rotation_committed_total: rotation tx committed (derived from
 *     committee_history row count, excluding genesis bootstrap)
 *   - rotation_failures_total: rotation tx rejected at commit time
 *     (derived from tx_rejections rows where tx_type='COMMITTEE_ROTATION')
 *   - chain_walk_failures_total: snapshot import rejected for chain-of-trust
 *     break (snapshot-handler counter)
 */
function committeeSection(s, dag) {
  let currentRotation = 0;
  let totalRotations = 0;
  let committedTotal = 0;
  let failuresTotal = 0;

  try {
    const latest = dag.getLatestRotation && dag.getLatestRotation();
    currentRotation = latest ? latest.rotation_number : 0;
  } catch { /* ignore */ }

  try {
    if (typeof dag.getRotationsFromGenesis === "function") {
      // Cheap on a tiny table (~50 rows over years).
      let n = 0;
      for (const _ of dag.getRotationsFromGenesis()) n++;
      totalRotations = n;
      // Genesis (rotation 0) is bootstrap, not a "committed rotation".
      committedTotal = Math.max(0, n - 1);
    }
  } catch { /* ignore */ }

  try {
    if (typeof dag.getTxRejectionsByReason === "function") {
      // tx_rejections doesn't directly index by tx_type, but
      // REVALIDATION_FAILED is the only reason that hits a
      // COMMITTEE_ROTATION tx (signature/quorum check). Count rows
      // where reason_detail mentions rotation + tx_type column matches.
      // Using the existing accessor avoids adding a new index.
      const rows = dag.getTxRejectionsByReason("revalidation_failed", { limit: 10000 }) || [];
      failuresTotal = rows.filter(r => r.tx_type === "COMMITTEE_ROTATION").length;
    }
  } catch { /* ignore */ }

  const proposals = (s.bullshark?.metrics?.committee_rotation_proposals) || 0;
  const chainWalkFailures = (s.snapshotHandler?.metrics?.chain_walk_failures) || 0;

  return [
    gauge("tip_committee_current_rotation_number", "Latest rotation_number in committee_history (0 = genesis bootstrap, no rotation has fired yet)", currentRotation),
    gauge("tip_committee_history_size", "Total rows in committee_history (includes rotation 0 bootstrap)", totalRotations),
    counter("tip_committee_rotation_proposals_total", "Total COMMITTEE_ROTATION txs the bullshark proposer has attempted to submit (regardless of downstream success)", proposals),
    counter("tip_committee_rotation_committed_total", "Total rotation events that landed in committee_history (excludes the genesis bootstrap row)", committedTotal),
    counter("tip_committee_rotation_failures_total", "COMMITTEE_ROTATION txs rejected at commit-handler (insufficient sigs, gap, payload mismatch, etc.)", failuresTotal),
    counter("tip_snapshot_chain_walk_failures_total", "Snapshot imports rejected because the rotation chain failed cryptographic verification (synthetic-snapshot attack class)", chainWalkFailures),
  ].join("\n");
}

function antiEntropySection(s) {
  const ae = s.antiEntropy || {};
  const aem = ae.metrics || {};
  return [
    gauge("tip_antientropy_last_status_size", "Peers currently tracked in the anti-entropy status cache", ae.last_status_size),
    counter("tip_antientropy_loops_run_total", "Completed anti-entropy reconciliation cycles", aem.loops_run),
    counter("tip_antientropy_checks_total", "Per-peer checks attempted across all cycles", aem.checks_total),
    counter("tip_antientropy_peers_queried_total", "Sync-status RPCs issued to peers", aem.peers_queried),
    counter("tip_antientropy_peer_rpc_failures_total", "Sync-status RPCs that failed (open/send/decode)", aem.peer_rpc_failures),
    counter("tip_antientropy_peer_rpc_timeouts_total", "Sync-status RPCs that timed out", aem.peer_rpc_timeouts),
    counter("tip_antientropy_peer_identity_mismatch_total", "Peer claimed different node_id than authorized (spoofing guard)", aem.peer_identity_mismatch),
    counter("tip_antientropy_peer_unauthorized_query_total", "queryPeer rejected — peer missing from authorized map", aem.peer_unauthorized_query),
    counter("tip_antientropy_peer_unauthorized_inbound_total", "Incoming sync-status from unauthorized peer rejected", aem.peer_unauthorized_inbound),
    counter("tip_antientropy_gaps_pulled_total", "Times self-was-behind triggered a cert gap pull", aem.gaps_pulled),
    // The byzantine-fork canary. Alertmanager rule:
    //   rate(tip_consensus_divergence_total[5m]) > 0
    counter(
      "tip_consensus_divergence_total",
      "BYZANTINE EVENT: equal committed_round but different state_merkle_root across peers. Should always be 0; any increase requires immediate ops attention.",
      aem.consensus_divergence_total,
    ),
  ].join("\n");
}

function merkleRootSection(s) {
  if (!s.merkleRoot) return "";
  // Info-style metric: value is always 1; the hex root is the label.
  // Cardinality is bounded — old roots are forgotten when new ones emit.
  return [
    `# HELP tip_cert_merkle_root_info Current certificate-DAG Merkle root (hex, short). Label-based info metric.`,
    `# TYPE tip_cert_merkle_root_info gauge`,
    line("tip_cert_merkle_root_info", 1, { root: String(s.merkleRoot).slice(0, 16) }),
  ].join("\n");
}

/**
 * Halt gate is split into TWO metrics so the gauge stays a single label-free
 * time series (no churn when the reason changes between scrapes), and the
 * reason rides on a separate info metric. Standard Prometheus pattern.
 */
function haltSection(consensus) {
  const cons = consensus?.current;
  const lines = [];

  let halted = true;
  let reason = "consensus_not_running";
  let staleMs = null;

  if (cons && typeof cons.isConsensusHalted === "function") {
    try {
      const halt = cons.isConsensusHalted();
      halted = !!halt.halted;
      reason = halted ? (halt.reason || "unknown") : "ok";
      staleMs = halt.staleMs;
    } catch { /* keep defaults */ }
  }

  lines.push(gauge(
    "tip_consensus_halted",
    "1 if halt-gate is tripping (sub-quorum, stale rounds); 0 if healthy. 503 on /v1/* writes when this is 1.",
    halted ? 1 : 0,
  ));
  lines.push(`# HELP tip_consensus_halt_reason Current halt reason as a label. Always emits value 1; value carries no meaning, the reason label does.`);
  lines.push(`# TYPE tip_consensus_halt_reason gauge`);
  lines.push(line("tip_consensus_halt_reason", 1, { reason }));
  if (staleMs != null) {
    lines.push(gauge("tip_consensus_stale_ms", "Milliseconds since the last Narwhal round advance", staleMs));
  }
  return lines.join("\n");
}

// ── Post-process: stamp every row with the running node's identity ───────

const _METRIC_LINE = /^([a-zA-Z_][a-zA-Z0-9_]*)(\{[^}]*\})?\s+(.+)$/;
const _HAS_NODE_LBL = /(^|,)\s*node="/;

/**
 * Append `node="<emitter id>"` to every metric row so dashboards can group
 * by real identity. Comment / blank rows are left alone. Rows whose label
 * set already includes `node="..."` are also left alone (registry rows
 * carry the REGISTERED identity, not the emitter's).
 *
 * `_block` produces multi-line entries (HELP + TYPE + metric joined by \n)
 * so we flatten to per-line first; otherwise the regex would only see the
 * first line of each entry (always a # HELP comment) and skip everything.
 */
function injectNodeLabel(body, nodeId) {
  const flat = body.split("\n");
  for (let i = 0; i < flat.length; i++) {
    const m = flat[i].match(_METRIC_LINE);
    if (!m) continue;
    const [, name, labelStr, rest] = m;
    const inner = labelStr ? labelStr.slice(1, -1) : "";
    if (_HAS_NODE_LBL.test(inner)) continue;
    flat[i] = `${name}{${inner}${inner ? "," : ""}node="${nodeId}"} ${rest}`;
  }
  return flat.join("\n");
}

// ── Public API ────────────────────────────────────────────────────────────

function createMetricsService({ dag, config, consensus, network }) {
  /**
   * Build the full Prometheus exposition body.
   * Always returns a string (never throws — failures inside any section
   * fall back to zero-value metrics so scrapers always succeed).
   */
  function buildBody() {
    const sections = [];
    sections.push(processSection(config));
    sections.push(dagSection(dag));
    sections.push(registrySection(dag));

    const networkBlock = networkSection(network, dag);
    if (networkBlock) sections.push(networkBlock);

    const cons = consensus?.current;
    if (cons && typeof cons.stats === "function") {
      const stats = cons.stats();
      sections.push(narwhalSection(stats));
      sections.push(bullsharkSection(stats));
      sections.push(mempoolSection(stats));
      sections.push(antiEntropySection(stats));
      sections.push(committeeSection(stats, dag));   // §4 + #34
      const merkleBlock = merkleRootSection(stats);
      if (merkleBlock) sections.push(merkleBlock);
    }

    sections.push(haltSection(consensus));

    const nodeId = config.nodeRegisteredId || config.nodeId || "unknown";
    const body = injectNodeLabel(sections.join("\n"), nodeId);

    // Prometheus format requires a trailing newline after the last row.
    return body + "\n";
  }

  return { buildBody };
}

module.exports = { createMetricsService };
