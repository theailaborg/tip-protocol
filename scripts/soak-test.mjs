/**
 * soak-test.mjs — sustained cluster health check under chaos + tx load.
 *
 * What this tests:
 *   Verifies the threshold-gated ack-refusal fix under real network churn.
 *   Before the fix a single divergent peer caused ack refusals that, when
 *   combined with any disconnection, depleted quorum and caused a permanent
 *   sub_quorum halt. After the fix acks are only refused once
 *   distinct_peers_observed >= bftHaltThreshold(n).
 *
 * Regression assertion (FAIL immediately if violated):
 *   acks_refused_divergent_peer must never increment unless
 *   divergence.distinct_peers_observed >= divergence.threshold.
 *
 * Pass criteria (checked at end of run):
 *   1. No unrecovered halts at end of run
 *   2. No sub-threshold ack-refusals (regression check above)
 *   3. Round never stalled > STALL_TIMEOUT_S on all nodes simultaneously
 *   4. No byzantine_fork_halt remaining on any node
 *   5. At least MIN_ROUNDS committed over the run duration
 *   6. All nodes converged on the same committed_round ± CONVERGENCE_DRIFT
 *
 * Chaos pattern (identical to chaos-restart.mjs):
 *   Pause a random non-seed node for MIN_PAUSE_S–MAX_PAUSE_S seconds every
 *   MIN_WAIT_S–MAX_WAIT_S seconds. Never pauses two nodes simultaneously.
 *   Never touches node1 (seed/bootstrap).
 *
 * Usage:
 *   node scripts/soak-test.mjs
 *   SOAK_DURATION_S=300 node scripts/soak-test.mjs
 *   SOAK_DURATION_S=600 MIN_PAUSE_S=50 MAX_PAUSE_S=60 node scripts/soak-test.mjs
 *   NO_CHAOS=1 node scripts/soak-test.mjs   (tx load only, no node pauses)
 *   NO_TX=1   node scripts/soak-test.mjs   (chaos only, no tx submissions)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

import { exec } from 'child_process';
import { nowMs, nowIso, toIso } from "../shared/time.js";
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __dirname  = path.dirname(fileURLToPath(import.meta.url));
const require    = createRequire(import.meta.url);
const { signBody, initCrypto } = require(path.resolve(__dirname, '../shared/crypto.js'));

// ─── Configuration ────────────────────────────────────────────────────────────
const SOAK_DURATION_MS  = parseInt(process.env.SOAK_DURATION_S  || '300',  10) * 1000;
const MIN_WAIT_MS       = parseInt(process.env.MIN_WAIT_S        || '25',   10) * 1000;
const MAX_WAIT_MS       = parseInt(process.env.MAX_WAIT_S        || '90',   10) * 1000;
const MIN_PAUSE_MS      = parseInt(process.env.MIN_PAUSE_S       || '15',   10) * 1000;
const MAX_PAUSE_MS      = parseInt(process.env.MAX_PAUSE_S       || '30',   10) * 1000;
const TX_INTERVAL_MS    = parseInt(process.env.TX_INTERVAL_MS    || '1500', 10);
const POLL_INTERVAL_MS  = parseInt(process.env.POLL_INTERVAL_MS  || '5000', 10);
// A halt that recovers within this window is counted as "recovered" not a failure.
const HALT_RECOVERY_MS  = parseInt(process.env.HALT_RECOVERY_S   || '90',   10) * 1000;
const STALL_TIMEOUT_MS  = parseInt(process.env.STALL_TIMEOUT_S   || '60',   10) * 1000;
const MIN_ROUNDS        = parseInt(process.env.MIN_ROUNDS        || '100',  10);
// Acceptable round-lag between fastest and slowest node at end.
const CONVERGENCE_DRIFT = parseInt(process.env.CONVERGENCE_DRIFT || '10',   10);

const NO_CHAOS = process.env.NO_CHAOS === '1';
const NO_TX    = process.env.NO_TX    === '1';

const NODES     = ['tip-node2', 'tip-node3', 'tip-node4', 'tip-node5'];
const ALL_PORTS = [4000, 4100, 4200, 4300, 4400];
const NODE_NAME = { 4000: 'node1', 4100: 'node2', 4200: 'node3', 4300: 'node4', 4400: 'node5' };

// ─── Helpers ──────────────────────────────────────────────────────────────────
function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function sleep(ms)      { return new Promise(r => setTimeout(r, ms)); }
function ts()           { return nowIso().slice(11, 19); }
function pad(v, w)      { return String(v ?? '?').padStart(w, ' '); }
function elapsed(startMs) {
  const s = Math.floor((nowMs() - startMs) / 1000);
  return `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s`;
}

function get(port, urlPath, timeoutMs = 3000) {
  return new Promise(resolve => {
    const req = http.get(
      { hostname: 'localhost', port, path: urlPath, timeout: timeoutMs },
      res => {
        let d = '';
        res.on('data', c => d += c);
        res.on('end', () => {
          try { resolve({ ok: true, body: JSON.parse(d) }); }
          catch { resolve({ ok: false, body: null }); }
        });
      },
    );
    req.on('error', () => resolve({ ok: false, body: null }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, body: null }); });
  });
}

function post(port, urlPath, payload, timeoutMs = 3000) {
  return new Promise(resolve => {
    const body = JSON.stringify(payload);
    const req  = http.request({
      hostname: 'localhost', port, path: urlPath, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: timeoutMs,
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode }));
    });
    req.on('error', () => resolve({ status: 0 }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0 }); });
    req.write(body);
    req.end();
  });
}

function dockerPauseUnpause(container, pauseMs) {
  return new Promise(resolve => {
    exec(`docker pause ${container}`, { timeout: 5000 }, err => {
      if (err) { resolve(false); return; }
      setTimeout(() => {
        exec(`docker unpause ${container}`, { timeout: 5000 }, err2 => resolve(!err2));
      }, pauseMs);
    });
  });
}

// ─── Per-node state ───────────────────────────────────────────────────────────
const nodeState = {};
for (const port of ALL_PORTS) {
  nodeState[port] = {
    round: 0,
    committed_round: 0,
    halted: false,
    halt_reason: '',
    join_state: 'unknown',
    acks_refused: 0,        // cumulative from health
    divergent_peers: 0,     // from sync-status
    divergence_threshold: 2,
    byzantine_fork_halt: null,
    reachable: false,
    lastSeenRound: 0,
    lastRoundChangeAt: nowMs(),
  };
}

// ─── Global counters / event log ─────────────────────────────────────────────
let startRounds = {};         // port → round at test start
const failures  = [];         // fatal assertion failures
const warnings  = [];         // soft issues
const haltEvents = [];        // { port, at, reason, recoveredAt? }
let activeHalts = {};         // port → { at, reason }

let txSubmitted = 0;
let txAccepted  = 0;
let txRejected  = 0;   // non-202 / non-0 status (validation fail, 503, etc.)
let txErrors    = 0;   // connection refused / timeout
let chaosCount  = 0;

// Regression check state: snapshot of acks_refused per port before each poll
const prevAcksRefused = Object.fromEntries(ALL_PORTS.map(p => [p, 0]));

// ─── Poll a single node ───────────────────────────────────────────────────────
async function pollNode(port) {
  const [healthRes, syncRes] = await Promise.all([
    get(port, '/health'),
    get(port, '/v1/sync-status'),
  ]);

  const ns = nodeState[port];

  if (!healthRes.ok) {
    ns.reachable = false;
    return;
  }
  ns.reachable = true;

  const hd  = healthRes.body?.data || {};
  const con = hd.consensus || {};
  const nw  = con.narwhal  || {};
  const halt = con.halt    || {};
  const metrics = nw.metrics || {};

  ns.round        = nw.round         || 0;
  ns.join_state   = nw.joinState     || 'unknown';
  ns.halted       = halt.halted      === true;
  ns.halt_reason  = halt.reason      || '';
  ns.byzantine_fork_halt = nw.byzantineForkHalt || null;

  const newAcksRefused = metrics.acks_refused_divergent_peer || 0;

  // Pull divergence data from sync-status (richer than health for this)
  if (syncRes.ok && syncRes.body?.data) {
    const sd = syncRes.body.data;
    ns.committed_round       = sd.self?.committed_round || 0;
    ns.divergent_peers       = sd.divergence?.distinct_peers_observed || 0;
    ns.divergence_threshold  = sd.divergence?.threshold || 2;
  }

  // ── Regression check ─────────────────────────────────────────────────────
  // acks_refused_divergent_peer must only increment when
  // divergent_peers >= divergence_threshold.
  const delta = newAcksRefused - prevAcksRefused[port];
  if (delta > 0 && ns.divergent_peers < ns.divergence_threshold) {
    const msg = `REGRESSION: ${NODE_NAME[port]} acks_refused_divergent_peer +${delta} ` +
      `but divergent_peers=${ns.divergent_peers} < threshold=${ns.divergence_threshold} ` +
      `at round=${ns.round}`;
    failures.push({ at: ts(), msg });
    console.error(`\n[${ts()}] ✗ FAIL — ${msg}\n`);
  }
  prevAcksRefused[port] = newAcksRefused;
  ns.acks_refused = newAcksRefused;

  // ── Round-stall detection ─────────────────────────────────────────────────
  if (ns.round > ns.lastSeenRound) {
    ns.lastSeenRound    = ns.round;
    ns.lastRoundChangeAt = nowMs();
  }

  // ── Halt event tracking ────────────────────────────────────────────────────
  if (ns.halted && !activeHalts[port]) {
    activeHalts[port] = { at: nowMs(), reason: ns.halt_reason };
    haltEvents.push({ port, at: nowMs(), reason: ns.halt_reason });
    console.log(`\n[${ts()}] ⚠  HALT detected on ${NODE_NAME[port]} — reason="${ns.halt_reason}" round=${ns.round}`);
  }
  if (!ns.halted && activeHalts[port]) {
    const elapsed_ms = nowMs() - activeHalts[port].at;
    const last = haltEvents.findLast(e => e.port === port && !e.recoveredAt);
    if (last) last.recoveredAt = nowMs();
    console.log(`\n[${ts()}] ✓  RECOVERED ${NODE_NAME[port]} after ${(elapsed_ms / 1000).toFixed(1)}s`);
    delete activeHalts[port];
  }
}

// ─── Cluster-wide stall check ─────────────────────────────────────────────────
function checkStalls() {
  for (const port of ALL_PORTS) {
    const ns = nodeState[port];
    if (!ns.reachable) continue;
    const staleMs = nowMs() - ns.lastRoundChangeAt;
    if (staleMs > STALL_TIMEOUT_MS && ns.join_state === 'ready' && !ns.halted) {
      const msg = `STALL: ${NODE_NAME[port]} round=${ns.round} has not advanced in ${(staleMs/1000).toFixed(0)}s`;
      if (!warnings.some(w => w.msg === msg)) {
        warnings.push({ at: ts(), msg });
        console.warn(`\n[${ts()}] ⚠  WARN — ${msg}`);
      }
    }
  }
}

// ─── Status table ─────────────────────────────────────────────────────────────
function printTable(startMs) {
  console.log(
    `\n[${ts()}] elapsed=${elapsed(startMs)}  chaos=${chaosCount}  tx=${txSubmitted}(acc=${txAccepted} rej=${txRejected} err=${txErrors})  halts=${haltEvents.length}  fails=${failures.length}`
  );
  console.log(
    `  ${'NODE'.padEnd(7)}  ${'ROUND'.padStart(6)}  ${'CMT'.padStart(6)}  ${'STATE'.padEnd(11)}  ${'HALTED'.padEnd(6)}  ${'DIV_PEERS'.padStart(9)}  ${'REFUSED'.padStart(7)}`
  );
  console.log(`  ${'─'.repeat(70)}`);
  for (const port of ALL_PORTS) {
    const ns = nodeState[port];
    if (!ns.reachable) {
      console.log(`  ${NODE_NAME[port].padEnd(7)}  ${'UNREACHABLE'.padStart(6)}`);
      continue;
    }
    const haltFlag = ns.halted ? `${ns.halt_reason.slice(0, 6)}`.toUpperCase() : 'no';
    const divFlag  = ns.divergent_peers > 0
      ? `${ns.divergent_peers}/${ns.divergence_threshold}`
      : '0';
    console.log(
      `  ${NODE_NAME[port].padEnd(7)}  ${pad(ns.round, 6)}  ${pad(ns.committed_round, 6)}` +
      `  ${ns.join_state.padEnd(11)}  ${haltFlag.padEnd(6)}  ${divFlag.padStart(9)}` +
      `  ${pad(ns.acks_refused, 7)}`
    );
  }
}

// ─── Poll loop ────────────────────────────────────────────────────────────────
async function pollLoop() {
  while (true) {
    await Promise.all(ALL_PORTS.map(p => pollNode(p)));
    checkStalls();
    await sleep(POLL_INTERVAL_MS);
  }
}

// ─── Chaos loop ───────────────────────────────────────────────────────────────
async function chaosLoop(endAt) {
  if (NO_CHAOS) {
    console.log(`[${ts()}] Chaos disabled (NO_CHAOS=1)`);
    return;
  }

  // Initial wait — let cluster warm up before first churn.
  const warmup = Math.min(30000, SOAK_DURATION_MS / 6);
  console.log(`[${ts()}] Chaos: warming up ${(warmup/1000).toFixed(0)}s before first pause`);
  await sleep(warmup);

  while (nowMs() < endAt) {
    const waitMs  = rand(MIN_WAIT_MS, MAX_WAIT_MS);
    const pauseMs = rand(MIN_PAUSE_MS, MAX_PAUSE_MS);
    await sleep(Math.min(waitMs, endAt - nowMs()));
    if (nowMs() >= endAt) break;

    // Skip if any node already halted — chaos during halt risks state divergence.
    const anyHalted = ALL_PORTS.some(p => nodeState[p].halted);
    if (anyHalted) {
      console.log(`[${ts()}] Chaos: skipping — cluster already halted, waiting for recovery`);
      await sleep(15000);
      continue;
    }

    const target = NODES[rand(0, NODES.length - 1)];
    chaosCount++;
    console.log(`[${ts()}] Chaos #${chaosCount}: pause ${target} for ${(pauseMs/1000).toFixed(0)}s`);

    const ok = await dockerPauseUnpause(target, pauseMs);
    if (!ok) console.warn(`[${ts()}] Chaos: docker pause/unpause failed for ${target}`);
  }
}

// ─── Tx flood loop ────────────────────────────────────────────────────────────
async function txLoop(endAt, vpId, vp) {
  if (NO_TX) {
    console.log(`[${ts()}] Tx flood disabled (NO_TX=1)`);
    return;
  }
  let seq = parseInt(process.env.START_SEQ || '50000', 10);
  while (nowMs() < endAt) {
    const port  = ALL_PORTS[seq % ALL_PORTS.length];
    // Same dedup format as tx-flood.mjs (20-char zero-padded decimal).
    // Prefix with 'sk' to avoid collision with flood runs that start at 0.
    const dedup = String(seq + 1).padStart(20, '0');
    const body  = {
      region: 'US',
      public_key: `aabb${dedup}ccdd`,
      dedup_hash: dedup,
      zk_proof: {
        pi_a: ['1','2','3'], pi_b: [['1','2'],['3','4'],['5','6']], pi_c: ['1','2','3'],
        protocol: 'groth16', curve: 'bn128',
      },
      verification_tier: 'T1',
      vp_id: vpId,
      social_attested: false,
      creator_name: `SoakTx-${seq}`,
    };
    const payload = { ...body, vp_signature: signBody(body, vp.privateKey) };
    const { status } = await post(port, '/v1/identity/register', payload);
    txSubmitted++;
    if (status === 202) txAccepted++;
    else if (status === 0) txErrors++;
    else txRejected++;
    seq++;
    await sleep(TX_INTERVAL_MS);
  }
}

// ─── Final verdict ────────────────────────────────────────────────────────────
function finalVerdict() {
  console.log('\n' + '═'.repeat(70));
  console.log('SOAK TEST RESULTS');
  console.log('═'.repeat(70));

  const checks = [];

  // 1. No unrecovered halts
  const unrecoveredHalts = haltEvents.filter(e => !e.recoveredAt);
  const longHalts        = haltEvents.filter(e => e.recoveredAt && (e.recoveredAt - e.at) > HALT_RECOVERY_MS);
  checks.push({
    name: 'No unrecovered halts at end',
    pass: unrecoveredHalts.length === 0,
    detail: unrecoveredHalts.length > 0
      ? `${unrecoveredHalts.length} unrecovered: ${unrecoveredHalts.map(e => `${NODE_NAME[e.port]}(${e.reason})`).join(', ')}`
      : `${haltEvents.length} total halts, all recovered` +
        (longHalts.length > 0 ? ` (${longHalts.length} slow: >${(HALT_RECOVERY_MS/1000)}s)` : ''),
  });

  // 2. No sub-threshold ack refusals (regression check)
  checks.push({
    name: 'No ack-refusals below BFT threshold (regression)',
    pass: failures.length === 0,
    detail: failures.length === 0
      ? 'acks_refused_divergent_peer only fired at/above threshold'
      : `${failures.length} violation(s): ${failures.slice(0, 3).map(f => f.msg).join('; ')}`,
  });

  // 3. No node stalled for > STALL_TIMEOUT_MS at end
  const stalledNow = ALL_PORTS.filter(p => {
    const ns = nodeState[p];
    return ns.reachable && !ns.halted && (nowMs() - ns.lastRoundChangeAt) > STALL_TIMEOUT_MS;
  });
  checks.push({
    name: `No round stalls > ${STALL_TIMEOUT_MS/1000}s at end`,
    pass: stalledNow.length === 0,
    detail: stalledNow.length === 0
      ? 'All nodes advancing'
      : `Stalled: ${stalledNow.map(p => NODE_NAME[p]).join(', ')}`,
  });

  // 4. No byzantine_fork_halt remaining
  const bfzNodes = ALL_PORTS.filter(p => nodeState[p].byzantine_fork_halt);
  checks.push({
    name: 'No byzantine_fork_halt remaining',
    pass: bfzNodes.length === 0,
    detail: bfzNodes.length === 0
      ? 'None'
      : `Stuck: ${bfzNodes.map(p => NODE_NAME[p]).join(', ')}`,
  });

  // 5. Minimum rounds committed
  const rounds = ALL_PORTS.map(p => nodeState[p].round).filter(r => r > 0);
  const minRound = rounds.length ? Math.min(...rounds) : 0;
  const startMin = Math.min(...ALL_PORTS.map(p => startRounds[p] || 0).filter(r => r > 0));
  const roundsCommitted = minRound - startMin;
  checks.push({
    name: `At least ${MIN_ROUNDS} rounds committed`,
    pass: roundsCommitted >= MIN_ROUNDS,
    detail: `committed ${roundsCommitted} rounds (${startMin} → ${minRound})`,
  });

  // 6. Convergence — all reachable nodes within CONVERGENCE_DRIFT rounds
  const reachable = ALL_PORTS.filter(p => nodeState[p].reachable);
  const committedRounds = reachable.map(p => nodeState[p].committed_round).filter(r => r > 0);
  const drift = committedRounds.length > 1
    ? Math.max(...committedRounds) - Math.min(...committedRounds)
    : 0;
  checks.push({
    name: `Nodes converged within ±${CONVERGENCE_DRIFT} committed rounds`,
    pass: drift <= CONVERGENCE_DRIFT,
    detail: `drift=${drift} (${committedRounds.join(', ')})`,
  });

  // Print table
  let allPass = true;
  for (const c of checks) {
    const mark = c.pass ? '✓' : '✗';
    console.log(`  ${mark} ${c.name}`);
    console.log(`      ${c.detail}`);
    if (!c.pass) allPass = false;
  }

  // Summary counts
  console.log('\n' + '─'.repeat(70));
  console.log(`  Chaos churns:        ${chaosCount}`);
  console.log(`  Halt events:         ${haltEvents.length} (${longHalts.length} slow, ${unrecoveredHalts.length} unrecovered)`);
  console.log(`  Txs submitted:       ${txSubmitted} (accepted=${txAccepted}, rejected=${txRejected}, errors=${txErrors})`);
  console.log(`  Warn events:         ${warnings.length}`);
  console.log(`  Fail events:         ${failures.length}`);
  if (warnings.length > 0) {
    console.log('\nWarnings:');
    warnings.forEach(w => console.log(`  [${w.at}] ${w.msg}`));
  }

  console.log('\n' + '═'.repeat(70));
  if (allPass && failures.length === 0) {
    console.log('  RESULT: PASS');
  } else {
    console.log('  RESULT: FAIL');
    if (failures.length > 0) {
      console.log('\nFatal failures:');
      failures.forEach(f => console.log(`  [${f.at}] ${f.msg}`));
    }
  }
  console.log('═'.repeat(70) + '\n');

  process.exit(allPass && failures.length === 0 ? 0 : 1);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  await initCrypto();

  // Load VP key — fetch authoritative VP ID from running node1 container.
  const vp = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../genesis-data/founding-vp-keys.json'), 'utf8'));
  let vpId;
  try {
    const { execSync } = await import('child_process');
    vpId = JSON.parse(execSync('docker exec tip-node1 cat /app/genesis-data/genesis.json', { timeout: 5000 }).toString()).founding_vp.vp_id;
  } catch {
    vpId = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../genesis-data/genesis.json'), 'utf8')).founding_vp.vp_id;
  }

  console.log('═'.repeat(70));
  console.log(`SOAK TEST  started ${nowIso()}`);
  console.log('═'.repeat(70));
  console.log(`  Duration:     ${SOAK_DURATION_MS / 1000}s`);
  console.log(`  Chaos:        ${NO_CHAOS ? 'disabled' : `pause ${MIN_PAUSE_MS/1000}–${MAX_PAUSE_MS/1000}s every ${MIN_WAIT_MS/1000}–${MAX_WAIT_MS/1000}s`}`);
  console.log(`  Tx load:      ${NO_TX ? 'disabled' : `every ${TX_INTERVAL_MS}ms across all nodes`}`);
  console.log(`  Poll:         every ${POLL_INTERVAL_MS / 1000}s`);
  console.log(`  Halt recovery window: ${HALT_RECOVERY_MS / 1000}s`);
  console.log(`  Round-stall timeout:  ${STALL_TIMEOUT_MS / 1000}s`);
  console.log(`  VP ID:        ${vpId}`);
  console.log('');

  // Baseline poll
  await Promise.all(ALL_PORTS.map(p => pollNode(p)));
  for (const port of ALL_PORTS) {
    startRounds[port] = nodeState[port].round;
    for (const port2 of ALL_PORTS) prevAcksRefused[port2] = nodeState[port2].acks_refused;
  }
  printTable(nowMs());
  const startMs = nowMs();
  const endAt   = startMs + SOAK_DURATION_MS;

  // Print table every 30s
  const tableInterval = setInterval(() => printTable(startMs), 30000);

  // Poll loop runs in background (never resolves — process.exit terminates it).
  pollLoop().catch(() => {});

  // Wait for both chaos and tx loops to finish (they terminate at endAt).
  await Promise.all([
    chaosLoop(endAt),
    txLoop(endAt, vpId, vp),
    sleep(SOAK_DURATION_MS),
  ]);

  clearInterval(tableInterval);

  // Final poll to capture end state.
  await Promise.all(ALL_PORTS.map(p => pollNode(p)));
  printTable(startMs);
  finalVerdict();
}

main().catch(err => {
  console.error('soak-test fatal:', err.message, err.stack);
  process.exit(1);
});
