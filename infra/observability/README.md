# TIP Federation observability stack (local dev)

Local Prometheus + Grafana for the TIP dev federation. Scrapes each
node's `/metrics` endpoint and provisions six dashboards out of the box
(`tip-home` is the landing page). See the
[Dashboards & panels reference](#dashboards--panels-reference) below for what
every panel means.

## Run

```bash
cd infra/observability
cp .env.example .env       # then edit .env if you want non-default credentials or node list
docker compose up -d
```

- Grafana → http://localhost:3030  (creds from `.env`, defaults `admin` / `admin`)
- Prometheus → http://localhost:9090  (`Status > Targets` shows scrape health)

Stop with `docker compose down`. Add `-v` to wipe stored time series.

## Configuration (`.env`)

Defaults are fine for loopback. Override these in `.env` before exposing
the stack on any non-loopback interface:

| Variable | Default | Purpose |
|---|---|---|
| `GF_ADMIN_USER` | `admin` | Grafana admin username |
| `GF_ADMIN_PASSWORD` | `admin` | Grafana admin password (change this) |
| `GF_ANON_ENABLED` | `true` | Anonymous viewer; set `false` for prod |
| `GF_HTTP_PORT` | `3030` | Host port Grafana binds to |
| `PROM_HTTP_PORT` | `9090` | Host port Prometheus binds to |
| `PROM_RETENTION` | `7d` | Prometheus TSDB retention |
| `TIP_NODE_TARGETS` | 5 nodes on `host.docker.internal:4000-4400` | Comma-separated `host:port` list of TIP nodes to scrape |

`.env` is git-ignored. `.env.example` is the committed template.

## Prometheus targets

Targets are driven by `TIP_NODE_TARGETS` in `.env`, no need to edit
`prometheus.yml`. On container startup the entrypoint converts the
comma-separated list into a `file_sd_configs` JSON file that Prometheus
re-reads every 30s.

To add or remove a node:

```bash
# 1. Edit .env, change TIP_NODE_TARGETS (e.g. add a 6th node)
TIP_NODE_TARGETS=host.docker.internal:4000,host.docker.internal:4100,host.docker.internal:4200,host.docker.internal:4300,host.docker.internal:4400,host.docker.internal:4500

# 2. Restart only the prometheus container
docker compose up -d --force-recreate prometheus
```

`host.docker.internal` resolves to the host machine from inside the
prom container on Linux/Mac/Windows (via the `extra_hosts` mapping in
`docker-compose.yml`). For TIP nodes on a different host or network,
substitute the actual reachable address.

The `node` label on metrics comes from each TIP node's `/metrics`
output (its real registered TIP node id, not the port), so dashboards
group by node identity regardless of `host:port` rewiring.

## Adding a dashboard

Drop a Grafana JSON export into `grafana/dashboards/`. The provisioning
config (`grafana/provisioning/`) auto-loads everything in that
directory on Grafana startup, no UI import step needed.

## Quick access & navigation

All TIP dashboards are provisioned into a `TIP` folder, and `tip-home` is the
default home page. There are two ways to jump between them:

**Top-bar dropdown (works anonymously).** Every dashboard carries a provisioned
`TIP dashboards` dropdown in its top-right link bar (a tag-based `links` entry on
each dashboard JSON). One click hops to any of the six, no login required. This
is the durable, no-setup path.

**Left sidebar "Starred" (logged-in users).** To pin every dashboard to
Grafana's left sidebar as a direct link, run:

```bash
./grafana/star-dashboards.sh
```

Stars are per-user runtime state (in Grafana's DB, not provisioned), so re-run
this after `docker compose down -v`. It defaults to `admin:admin` on
`http://localhost:3030`; override with `GF_AUTH` / `GF_URL`. Note: anonymous
viewers cannot hold stars (a Grafana limitation), so the Starred sidebar only
shows once you log in as admin; use the top-bar dropdown otherwise.

## Dashboards & panels reference

The stack provisions **six dashboards** from `grafana/dashboards/`, auto-loaded
on Grafana startup. `tip-home` is the default landing page. Every panel also
carries its own description in Grafana (hover the `i` in the panel header); the
tables below mirror those so you can scan the whole fleet without clicking in.

**Reading order:** start on **TIP Overview**. If anything there is non-green,
drill into the matching specialized dashboard below.

**On the red canaries:** a panel goes red only for a *present-tense* fault.
`Halted nodes` and `Byzantine fork (active)` read live gauges
(`tip_consensus_halted`, `tip_consensus_byzantine_fork_halted`), not lifetime
counters, so a fault that has since recovered does not leave them stuck red.
Transient state-root mismatches during catch-up/rejoin are auto-healed by resync
and surface only as the informational `Divergence detections (15m)` rate on
Consensus Health, never as the active-fork emergency.

| Dashboard | uid | Go here for |
|---|---|---|
| TIP Overview | `tip-home` | One-screen fleet health; the landing page |
| TIP Consensus Health | `tip-consensus-health` | Commits stalled or a node halted; consensus internals |
| TIP Federation | `tip-federation` | Who is registered vs online, committee/quorum, DAG totals |
| TIP Networking | `tip-networking` | Nodes flapping or one-directional send/receive faults |
| TIP Rotation Health | `tip-rotation` | A committee rotation boundary wedged |
| TIP Snapshot & Recovery | `tip-snapshot` | A node catching up via state-snapshot install |

The "Key metric" column lists the primary series each panel reads (some panels
join several); `up (scrape)` means the panel is derived from Prometheus scrape
state, not a TIP-emitted metric.

### TIP Overview (`tip-home`)

The landing page (set as Grafana default home). Six headline health stats plus a links list. Read this first: all-green here means the fleet is healthy; click through for detail.

| Panel | What it shows | Key metric |
|---|---|---|
| Halted nodes | Nodes that have halted consensus. 0 is healthy. | `tip_consensus_halted` |
| Nodes online | Nodes currently in the registry. | `tip_node_registry_info` |
| Byzantine fork (active) | 1 if ANY node is currently fork-halted (active byzantine fork) - red is a real, present-tense emergency. 0 is healthy. (more in-panel) | `tip_consensus_byzantine_fork_halted` |
| Quorum margin (min) | Active participants beyond quorum on the weakest node. 0 = one drop halts. | `tip_consensus_quorum_margin` |
| Committed round (max) | Highest committed round across the fleet. | `tip_bullshark_last_committed_round` |
| Rotation number | Current committee rotation number. | `tip_committee_current_rotation_number` |
| All TIP dashboards | navigation list (links to the other dashboards) | `n/a` |

### TIP Consensus Health (`tip-consensus-health`)

The deep consensus view. Liveness (commits, rounds, quorum margin), safety (halt reason, byzantine fork, divergence), the mempool tx funnel, and the event-loop / GC internals that starve consensus. Go here when commits stall or a node halts.

| Panel | What it shows | Key metric |
|---|---|---|
| Halted nodes | Nodes whose consensus halt-gate is tripped (stale rounds / sub-quorum / fork). | `tip_consensus_halted` |
| Divergence detections (15m, auto-healed) | Rate of state-root divergences anti-entropy *detected and auto-healed* in the last 15m (`tip_consensus_divergence_total` is a lifetime counter; this is its windowed increase). | `tip_consensus_divergence_total` |
| Nodes online | Nodes whose /metrics responded to the last scrape. | `up (scrape)` |
| Quorum margin (min) | Smallest (active participants minus quorum) across the federation. | `tip_consensus_quorum_margin` |
| Quorum threshold | The 2f+1 majority needed for Bullshark to commit an anchor, derived from the active committee size. For N nodes: quorum = floor(2N/3) + 1. | `tip_narwhal_quorum` |
| Worst event-loop stall | Longest single event-loop block in the federation (last 1s window). | `tip_process_event_loop_lag_max_ms` |
| Suspect peers | Peers any node currently can't reach via heartbeat. | `tip_heartbeat_suspect_peers` |
| Commit rate | Anchors committed per minute across the federation. | `tip_bullshark_anchors_committed_total` |
| Committed round per node | The last round each node finalized. | `tip_bullshark_last_committed_round, tip_node_registry_info` |
| Commit spread: leader minus laggard | How many rounds the most-behind node trails the leader. | `tip_bullshark_last_committed_round` |
| Consensus index (anchor commits since genesis) - per node | Network-wide count of anchor commits. Persisted via `consensus_meta` (#44) so it survives restart on idle networks; joining nodes adopt the cluster's value at snapshot install time (more in-panel) | `tip_bullshark_consensus_index, tip_node_registry_info` |
| Consensus advance rate (anchors/min) - per node | Rate at which Bullshark commits anchor certs, per minute, over a 5-minute window. (more in-panel) | `tip_bullshark_anchors_committed_total, tip_node_registry_info` |
| Narwhal current round | The round Narwhal is currently producing batches at. Always 1-2 rounds ahead of `last_committed_round` since Bullshark needs the next wave's votes before finalizing. | `tip_narwhal_current_round, tip_node_registry_info` |
| Bullshark commits / 5s | Rate of anchor commits in 5-second windows. | `tip_bullshark_anchors_committed_total, tip_node_registry_info` |
| Quorum margin per node | active participants minus quorum, per node. | `tip_consensus_quorum_margin, tip_node_registry_info` |
| Event-loop stall per node (ms) | Longest thread block per node, per 1s window. The two lines mark warn (250ms) and act (1s). | `tip_process_event_loop_lag_max_ms, tip_node_registry_info` |
| Nodes online over time | Per-node scrape success (1 = online). | `up (scrape)` |
| Pending / parked certs | Certs parked waiting on missing parents before an anchor can commit. | `tip_narwhal_pending_certs, tip_node_registry_info` |
| Producer-pause stuck duration (rotation boundary) | Milliseconds a node has been producer-paused at a rotation boundary with no tx to carve. Sustained > 0 means a stuck boundary; pull-repair runs and the pause is never bypassed. | `tip_consensus_producer_paused_ms, tip_node_registry_info` |
| Anti-entropy: peers queried / gaps pulled | Anti-entropy: peers queried / gaps pulled - Anti-entropy is the pull-side safety net (#28) that runs every 4s, querying every authorized peer's sync-status and pulling missing cert (more in-panel) | `tip_antientropy_peers_queried_total, tip_node_registry_info` |
| Cert GC (rounds pruned) | Cumulative count of certificate rows pruned by Bullshark's GC trigger (every `gc_interval_commits`, prunes certs older than `gc_depth` rounds). | `tip_bullshark_gc_runs_total, tip_node_registry_info` |
| Offered vs committed tx rate (/min) | Federation tx funnel: offered (into mempool), batched, committed (finalized). | `tip_mempool_received_total, tip_mempool_drained_total` |
| Mempool backlog per node (the knee detector) | Pending txs not yet committed, per node. | `tip_narwhal_mempool_size, tip_node_registry_info` |
| Mempool throughput (submit / drain rate) | Cumulative-counter rate of txs entering and leaving the mempool, per second. | `tip_mempool_received_total, tip_node_registry_info` |
| Mempool size over time | Per-node pending-tx queue size, time series. | `tip_mempool_size, tip_node_registry_info` |
| Halt reason per node | Current halt reason carried as a label. 'ok' = healthy. Tells you WHY a node halted (sub-quorum / stale / fork), not just that it did. | `tip_consensus_halt_reason, tip_node_registry_info` |
| Byzantine fork (halted / detection round) | Per node: 1 when this node halted on a state-divergence fork, plus the round it was detected. The node emitting 1 is the forked one. | `tip_consensus_byzantine_fork_halted, tip_node_registry_info` |
| Time since last round advance (stale) | Milliseconds since this node's last Narwhal round advance. A climbing line that never resets is a stuck node before the halt gate trips. | `tip_consensus_stale_ms, tip_node_registry_info` |
| Cert parking (parked / unblocked / pruned, /min) | Certs held on a missing parent (parked), released when the parent arrives (unblocked), or dropped by GC (pruned). Parked climbing faster than unblocked = a propagation leak. | `tip_narwhal_certs_parked_total, tip_node_registry_info` |
| Batch-ack delivery (direct / fallback / rebroadcast, /min) | BatchAcks sent on the direct stream vs fallen back to gossipsub vs re-broadcast on duplicate. A rising fallback share is the early signal of a broken direct push. | `tip_narwhal_acks_sent_direct_total, tip_narwhal_acks_sent_fallback_total` |
| Byzantine defenses & stalls (/min) | Equivocations refused (vote-digest mismatch), round fast-forwards, and own-batch retries while stuck. A retry storm with no fast-forwards is a one-sided stall. | `tip_narwhal_equivocation_refused_total, tip_narwhal_fast_forwards_total` |
| Event-loop lag (max / p99 / mean) | Per-node event-loop delay. max catches rare spikes; p99/mean catch chronic stalls (sync ML-DSA verify, big merkle rebuilds) that starve consensus. | `tip_process_event_loop_lag_max_ms, tip_node_registry_info` |
| Bullshark GC (runs / failures / skipped, /min) | DAG garbage collection. Failures > 0 = SQLite errors; skipped > 0 = TIP_GC_DISABLED left on, which leaks the cert table. | `tip_bullshark_gc_runs_total, tip_bullshark_gc_failures_total` |
| Mempool rejections / evictions (/min) | Submits rejected (full / duplicate / malformed) and txs evicted on TTL. A spike in rejections is a load or DOS signature. | `tip_mempool_rejected_total, tip_node_registry_info` |

### TIP Federation (`tip-federation`)

Fleet overview: registry vs online state, committee size and quorum, per-node consensus index / round / uptime / RSS, DAG totals, and the cert-DAG merkle-root cross-check. The is-everyone-here-and-agreeing view.

| Panel | What it shows | Key metric |
|---|---|---|
| Registered nodes | Total count of nodes registered in the DAG `nodes` table, regardless of their current online state. | `tip_node_registry_info` |
| Online (scrapeable) | Count of nodes currently emitting metrics - `up{job="tip-federation"} == 1`. (more in-panel) | `up (scrape)` |
| Active committee (max) | Largest active-committee value reported across all online nodes. Should be identical across all nodes since the committee is deterministically derived from DAG state. | `tip_narwhal_active_participants` |
| Quorum threshold | The 2f+1 majority needed for Bullshark to commit an anchor, derived from the active committee size. For N nodes: quorum = floor(2N/3) + 1. | `tip_narwhal_quorum` |
| Consensus index - federation max | Federation-wide max - what all healthy nodes converge to. Per-node breakdown is in the panel to the right. | `tip_bullshark_consensus_index` |
| Anchor rate - federation max (anchors/min) | Federation-wide max - what all healthy nodes converge to. Per-node breakdown is in the panel to the right. | `tip_bullshark_anchors_committed_total` |
| Byzantine fork active (any node halted) | 1 if ANY node is currently fork-halted (`tip_consensus_byzantine_fork_halted`). This is the present-tense emergency gauge: red means a fork is happening right now. | `tip_consensus_byzantine_fork_halted` |
| Federation status - registered nodes, online state, join state, connections | One row per TIP node in the DAG registry. Status = registered status from the DAG. Online = whether the node is currently emitting metrics. (more in-panel) | `tip_node_registry_info, tip_process_uptime_seconds` |
| Peers connected | Number of TIP-handshake-authorized peers this node currently sees. | `tip_network_peers_authorized, tip_node_registry_info` |
| Halt status | 0 = consensus advancing normally; 1 = halted (no new commits for > 3× round timeout, default ~6s). | `tip_consensus_halted, tip_node_registry_info` |
| Mempool depth | Number of pending transactions waiting to be committed via Bullshark. | `tip_mempool_size, tip_node_registry_info` |
| Active committee size (per node) | Number of nodes in the currently-derived consensus committee on each node. (more in-panel) | `tip_narwhal_active_participants, tip_node_registry_info` |
| Last committed round | The highest round at which Bullshark has finalized an anchor commit. Tracked in-memory by Bullshark, ticks every successful anchor (~2s on healthy network). | `tip_bullshark_last_committed_round, tip_node_registry_info` |
| Node uptime | Seconds since this node's process started (`tip_process_uptime_seconds`). Resets on process restart. | `tip_process_uptime_seconds, tip_node_registry_info` |
| Process memory (RSS) | Resident Set Size of each node's Node.js process (`tip_process_memory_rss_bytes`). Includes V8 heap, libp2p buffers, SQLite page cache, and native modules. | `tip_process_memory_rss_bytes, tip_node_registry_info` |
| Consensus index (anchor commits since genesis) - per node | Network-wide count of anchor commits. Persisted via `consensus_meta` (#44) so it survives restart on idle networks; joining nodes adopt the cluster's value at snapshot install time (more in-panel) | `tip_bullshark_consensus_index, tip_node_registry_info` |
| Consensus advance rate (anchors/min) - per node | Rate at which Bullshark commits anchor certs, per minute, over a 5-minute window. (more in-panel) | `tip_bullshark_anchors_committed_total, tip_node_registry_info` |
| DAG transactions | Total transactions committed to the DAG (fleet max). | `tip_dag_tx_count` |
| DAG certificates | Certificates currently in the DAG, bounded by cert GC (fleet max). | `tip_dag_cert_count` |
| Registered nodes (DAG) | Nodes in the DAG registry, active + inactive (fleet max). | `tip_dag_registered_nodes` |
| Cert-DAG merkle root per node | Current certificate-DAG merkle root per node. All nodes should show the SAME root; a divergent root is a fork before anti-entropy flags it. | `tip_cert_merkle_root_info, tip_node_registry_info` |
| Mempool size vs capacity | Per-node mempool depth against its capacity ceiling. Size approaching capacity is back-pressure. | `tip_mempool_size, tip_node_registry_info` |
| Producer-pause per node (rotation boundary) | Milliseconds each node has been producer-paused at a rotation boundary. Sustained > 0 is a stuck boundary. | `tip_consensus_producer_paused_ms, tip_node_registry_info` |
| Nodes online over time | Per-node scrape success (1 = online). | `up (scrape)` |
| Narwhal current round | The round Narwhal is currently producing batches at. Always 1-2 rounds ahead of `last_committed_round` since Bullshark needs the next wave's votes before finalizing. | `tip_narwhal_current_round, tip_node_registry_info` |
| Txs committed (cumulative) | Running total of transactions ordered through Bullshark since this process started. | `tip_bullshark_txs_committed_total, tip_node_registry_info` |

### TIP Networking (`tip-networking`)

The mesh and transport layer. Connectivity completeness, connect/disconnect flap, re-handshakes, per-peer outbound-send health, and the comms-direction matrix that localizes one-directional (send-vs-receive) faults. Go here when nodes seem to randomly drop.

| Panel | What it shows | Key metric |
|---|---|---|
| Under-connected nodes | Nodes not at full mesh (connectivity_complete = 0). 0 is healthy; anything else means a node is missing peer connections. | `tip_network_connectivity_complete` |
| Full-mesh nodes | Nodes currently at full mesh connectivity. | `tip_network_connectivity_complete` |
| Suspect peers | Heartbeat-suspect peers across the fleet. 0 is healthy. | `tip_heartbeat_suspect_peers` |
| Disconnect flap (/min) | Fleet-wide peer disconnect rate. Sustained > 0 is the flap that reads as 'nodes randomly drop'. | `tip_network_peer_disconnects_total` |
| Re-handshakes (/min) | Fleet-wide re-handshakes of connected-but-unauthorized peers (auth-window recovery). | `tip_network_rehandshakes_total` |
| Auto-heals fired (/min) | Force-close + re-dial events that rebuild a half-dead connection. > 0 means the transport auto-heal fired (needs this branch deployed to emit). | `tip_network_force_redials_total` |
| Per-node connectivity | Per-node mesh view: authorized vs connected peers, full-mesh flag, who each node is connected to, and churn counters. | `tip_node_registry_info, tip_network_peers_authorized` |
| Comms direction matrix (row can't reach column) | Consecutive heartbeat misses; rows = observing node, columns = peer. A row that is all-red while its own column stays green = that node can receive but not send (broken outbound di (more in-panel) | `tip_heartbeat_peer_consecutive_misses, tip_node_registry_info` |
| Consecutive send failures per peer | Current consecutive outbound-send failures to a peer (resets on success or auto-heal). The first thing to climb when a node goes one-directionally deaf. | `tip_network_peer_send_consecutive_failures` |
| Authorized peers per node | Connected + handshaked committee peers. | `tip_network_peers_authorized, tip_node_registry_info` |
| Connectivity complete (1 = full mesh) | 1 when a node is connected to every active committee member. | `tip_network_connectivity_complete, tip_node_registry_info` |
| Connects per node (/min) | libp2p peer:connect rate. Paired with disconnects, this is the flap that reads as 'node goes offline randomly'. | `tip_network_peer_connects_total, tip_node_registry_info` |
| Disconnects per node (/min) | Rate of libp2p peer disconnects. | `tip_network_peer_disconnects_total, tip_node_registry_info` |
| Connection closes per node (/min) | libp2p connection:close rate (incl. pre-auth) - the rawest flap signal. | `tip_network_connection_closes_total, tip_node_registry_info` |
| Fast re-auths per node (/min) | Reconnects restored within the 15s grace window (no full handshake). | `tip_network_fast_reauths_total, tip_node_registry_info` |
| Re-handshakes per node (/min) | Re-handshakes of connected-but-unauthorized peers (recovery of a stale auth window). | `tip_network_rehandshakes_total, tip_node_registry_info` |
| Heartbeat suspect peers | Peers each node currently marks suspect (missed heartbeats). | `tip_heartbeat_suspect_peers, tip_node_registry_info` |
| Outbound send failures per peer (/min) | Direct-stream send failures from a node to a peer. A line that climbs while the peer stays connected is a silent one-directional partition (the rotation-halt root cause). | `tip_network_peer_send_failures_total` |
| Time since last successful send (per peer) | Milliseconds since the last successful outbound send to a peer. High while connected = a broken outbound push. | `tip_network_peer_last_send_ok_age_ms` |
| Transport auto-heals (/min) | Force-close + re-dial events that rebuild a half-dead connection after sustained one-directional send failures. Spikes mean the auto-heal fired. | `tip_network_force_redials_total, tip_node_registry_info` |
| Heartbeat health (tracked / with-misses / suspect) | Per node: peers tracked, peers with >=1 miss (early churn), and peers at the suspect threshold. with-misses rising before suspect is the leading indicator. | `tip_heartbeat_tracked_peers, tip_node_registry_info` |
| GossipSub mesh peers (fallback detector) | Random-mesh peer count per topic. TIP pins committee members via DirectPeers, so this should sit at ~0; a non-trivial value means cert propagation has fallen back to the gossip mes (more in-panel) | `tip_network_gossip_mesh_peers, tip_node_registry_info` |
| Anti-entropy RPC health (/min) | Sync-status RPC failures and timeouts. If these climb, gaps_pulled never fires and divergence goes undetected (fail-open). | `tip_antientropy_peer_rpc_failures_total, tip_antientropy_peer_rpc_timeouts_total` |
| Authorization violations (/min) | Spoofing-guard trips: a peer claiming a different node_id than authorized, and unauthorized query/inbound attempts. Sustained > 0 warrants investigation. | `tip_antientropy_peer_identity_mismatch_total, tip_antientropy_peer_unauthorized_query_total` |

### TIP Rotation Health (`tip-rotation`)

Committee rotation. Current rotation number (fleet and per node), committee_history growth, the proposal-vs-commit funnel, and producer-pause stuck duration at boundaries. Go here when a rotation boundary wedges.

| Panel | What it shows | Key metric |
|---|---|---|
| Current rotation number | Latest committee rotation_number in committee_history (0 = genesis). | `tip_committee_current_rotation_number` |
| Committee history size | Total rows in committee_history (includes the rotation-0 bootstrap). | `tip_committee_history_size` |
| Rotation failures (/min) | Genuine rotation rejections per minute (insufficient sigs / payload mismatch; benign re-broadcast duplicates excluded). 0 is healthy. Real health = the rotation number advancing. | `tip_committee_rotation_failures_total` |
| Rotation proposals / commits / failures (/min) | Proposer attempts vs rotations that landed in committee_history vs commit-handler rejections. Proposals with no commits = a stuck rotation boundary. | `tip_committee_rotation_proposals_total, tip_committee_rotation_committed_total` |
| Current rotation number per node | Each node's view of the current rotation_number. A node lagging the others has not applied the latest rotation. | `tip_committee_current_rotation_number, tip_node_registry_info` |
| Producer-pause stuck duration per node | Milliseconds producer-paused at the boundary with no tx to carve. Sustained > 0 = the boundary is stuck; pull-repair runs without bypassing the pause. | `tip_consensus_producer_paused_ms, tip_node_registry_info` |

### TIP Snapshot & Recovery (`tip-snapshot`)

State-snapshot fast-sync and recovery. Installs in progress / completed, per-node install progress and size, and chain-walk (rotation chain-of-trust) rejections. Go here when a node is catching up via snapshot.

| Panel | What it shows | Key metric |
|---|---|---|
| Installs in progress | Nodes currently installing a state snapshot. Sustained > 0 may be a snapshot loop. | `tip_snapshot_install_in_progress` |
| Installs completed (total) | State-snapshot installs that completed successfully across the fleet. | `tip_snapshot_installs_completed_total` |
| Chain-walk failures (total) | Snapshot imports rejected for failing rotation chain-of-trust verification. > 0 = a rejected (possibly malicious) snapshot. | `tip_snapshot_chain_walk_failures_total` |
| Install progress (rows installed / total) | For an in-progress snapshot: rows installed so far vs total. A flat 'installed' below 'total' is a stalled install. | `tip_snapshot_install_progress_rows, tip_node_registry_info` |
| Install in progress (per node) | 1 while a node is installing a snapshot, 0 idle. Flapping = repeated install attempts. | `tip_snapshot_install_in_progress, tip_node_registry_info` |
| Last completed install size | Download size in bytes of each node's most recent completed snapshot install. | `tip_snapshot_last_install_bytes, tip_node_registry_info` |

## Metrics reference

Each TIP node exposes Prometheus-format metrics on `GET /metrics` over
its REST port (the same one in `TIP_NODE_TARGETS`). Use Prometheus's
`/graph` UI to explore available series, or query directly via the HTTP
API.

## NOT production-ready

This stack is local-dev tooling. Before exposing any of it on a
non-loopback interface:

- Replace `GF_SECURITY_ADMIN_PASSWORD=admin` with a strong secret.
- Disable `GF_AUTH_ANONYMOUS_ENABLED`.
- Put Prometheus on a private network; it has no auth.
- Decide whether each node's `/metrics` should be reachable publicly
  (BFT default is yes; firewall/reverse-proxy if not).
