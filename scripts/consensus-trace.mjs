#!/usr/bin/env node
/**
 * Live consensus tracer. Polls every federation node's /metrics endpoint each
 * tick and prints one correlated table so transient jitter is visible: which
 * node stalls, and whether the stall trails an event-loop spike, a connection
 * close storm, a gossip mesh drop, or a sync-mode flip.
 *
 * Counters (closes/disc/conn/reauth, rounds) are shown as per-second rates
 * derived from the delta between ticks; gauges (round, committed, stale, peers,
 * mesh, loop lag) are shown raw. Anomalies are flagged with `!`.
 *
 * Usage:
 *   node scripts/consensus-trace.mjs [--interval=1] [--hosts=localhost:4000,localhost:4100,...]
 *
 * Default hosts target the local repro cluster (node1..node5 on :4000..:4400).
 */

"use strict";

import http from "node:http";

const arg = (k, d) => {
  const hit = process.argv.find((a) => a.startsWith(`--${k}=`));
  return hit ? hit.slice(k.length + 3) : d;
};

const INTERVAL_MS = Math.max(250, Number(arg("interval", "1")) * 1000);
const HOSTS = arg("hosts", "localhost:4000,localhost:4100,localhost:4200,localhost:4300,localhost:4400")
  .split(",").map((s) => s.trim()).filter(Boolean);

const LOOP_LAG_WARN_MS = 250;

function fetchMetrics(hostport) {
  return new Promise((resolve) => {
    const [host, port] = hostport.split(":");
    const req = http.get({ host, port: Number(port), path: "/metrics", timeout: 2000 }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve(body));
    });
    req.on("error", () => resolve(null));
    req.on("timeout", () => { req.destroy(); resolve(null); });
  });
}

// Parse the Prometheus text body into { metricName: number } (last value wins;
// one series per node since each node stamps its own `node` label). Mesh is
// summed across topics.
function parse(body) {
  if (!body) return null;
  const m = {};
  let meshSum = 0;
  for (const raw of body.split("\n")) {
    if (!raw || raw[0] === "#") continue;
    const sp = raw.lastIndexOf(" ");
    if (sp < 0) continue;
    const val = Number(raw.slice(sp + 1));
    if (!Number.isFinite(val)) continue;
    const head = raw.slice(0, sp);
    const name = head.includes("{") ? head.slice(0, head.indexOf("{")) : head;
    if (name === "tip_network_mesh_peers") meshSum += val;
    else m[name] = val;
  }
  m._mesh = meshSum;
  return m;
}

const NAME = (m, key, d = 0) => (m && Number.isFinite(m[key]) ? m[key] : d);

let _prev = new Map();   // hostport -> { m, t }

function rate(cur, prev, dt) {
  if (prev == null || dt <= 0) return 0;
  const r = (cur - prev) / dt;
  return r > 0 ? r : 0;
}

const pad = (s, n) => String(s).padEnd(n).slice(0, n);
const padL = (s, n) => String(s).padStart(n).slice(0, n);

function syncState(m) {
  if (NAME(m, "tip_narwhal_join_state_syncing")) return "sync";
  if (NAME(m, "tip_narwhal_join_state_catching_up")) return "catch";
  if (NAME(m, "tip_narwhal_join_state_ready")) return "ready";
  return "?";
}

async function tick() {
  const now = Date.now();
  const bodies = await Promise.all(HOSTS.map(fetchMetrics));

  const rows = [];
  for (let i = 0; i < HOSTS.length; i++) {
    const hp = HOSTS[i];
    const m = parse(bodies[i]);
    const prev = _prev.get(hp);
    const dt = prev ? (now - prev.t) / 1000 : 0;

    if (!m) { rows.push({ name: `n${i + 1}`, down: true }); _prev.set(hp, { m: null, t: now }); continue; }

    const loopMax = Math.round(NAME(m, "tip_process_event_loop_lag_max_ms"));
    const row = {
      name: `n${i + 1}`,
      round: NAME(m, "tip_narwhal_current_round"),
      committed: NAME(m, "tip_bullshark_last_committed_round"),
      stale: Math.round(NAME(m, "tip_consensus_stale_ms")),
      peers: NAME(m, "tip_network_peers_authorized"),
      mesh: NAME(m, "_mesh"),
      loop: loopMax,
      closes: rate(NAME(m, "tip_network_connection_closes_total"), prev && prev.m && NAME(prev.m, "tip_network_connection_closes_total"), dt),
      disc: rate(NAME(m, "tip_network_peer_disconnects_total"), prev && prev.m && NAME(prev.m, "tip_network_peer_disconnects_total"), dt),
      reauth: rate(NAME(m, "tip_network_fast_reauths_total"), prev && prev.m && NAME(prev.m, "tip_network_fast_reauths_total"), dt),
      rounds: rate(NAME(m, "tip_narwhal_rounds_advanced_total"), prev && prev.m && NAME(prev.m, "tip_narwhal_rounds_advanced_total"), dt),
      sync: syncState(m),
      halt: NAME(m, "tip_consensus_halted") ? "HALT" : "-",
      mempool: NAME(m, "tip_narwhal_mempool_size"),
    };
    rows.push(row);
    _prev.set(hp, { m, t: now });
  }

  const flag = (v, bad) => (bad ? `${v}!` : `${v}`);
  const f1 = (x) => x.toFixed(1);

  const lines = [];
  lines.push(`\x1b[2J\x1b[H consensus trace  ${new Date(now).toISOString()}  every ${INTERVAL_MS / 1000}s`);
  lines.push(
    " " + pad("node", 5) + padL("round", 8) + padL("commit", 8) + padL("stale", 7) +
    padL("peer", 5) + padL("mesh", 5) + padL("loopMx", 8) + padL("clos/s", 7) +
    padL("disc/s", 7) + padL("reau/s", 7) + padL("rnd/s", 7) + padL("mpool", 7) + "  " + pad("sync", 6) + "halt",
  );
  for (const r of rows) {
    if (r.down) { lines.push(" " + pad(r.name, 5) + "  DOWN / unreachable"); continue; }
    lines.push(
      " " + pad(r.name, 5) +
      padL(r.round, 8) + padL(r.committed, 8) +
      padL(flag(r.stale, r.stale > 8000), 7) +
      padL(r.peers, 5) + padL(r.mesh, 5) +
      padL(flag(r.loop, r.loop >= LOOP_LAG_WARN_MS), 8) +
      padL(flag(f1(r.closes), r.closes > 0), 7) +
      padL(flag(f1(r.disc), r.disc > 0), 7) +
      padL(f1(r.reauth), 7) +
      padL(f1(r.rounds), 7) +
      padL(r.mempool, 7) + "  " +
      pad(r.sync, 6) + (r.halt === "HALT" ? "\x1b[31mHALT\x1b[0m" : "-"),
    );
  }
  lines.push("");
  lines.push(" ! = anomaly: stale>8s, loopMx>=250ms, any closes/disconnects this tick");
  process.stdout.write(lines.join("\n") + "\n");
}

console.log(`Tracing ${HOSTS.length} nodes: ${HOSTS.join(", ")}`);
await tick();
const timer = setInterval(tick, INTERVAL_MS);
process.on("SIGINT", () => { clearInterval(timer); process.stdout.write("\n"); process.exit(0); });
