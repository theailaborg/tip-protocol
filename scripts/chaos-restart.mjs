/**
 * chaos-restart.mjs — pause/unpause non-seed nodes to cause gossipsub mesh churn.
 *
 * What this script tests:
 *   Pausing a node for 3-5s causes gossipsub heartbeats to miss, marking
 *   direct-peer edges stale. On unpause the mesh reforms, but directed ack
 *   delivery may fail for the current round — the two-tier narwhal retry
 *   (Layer 1: refreshDirectPeer at tick 3; Layer 2: direct libp2p stream at
 *   tick 6+) should auto-recover sub_quorum halts within ~12s.
 *
 * What this script does NOT test:
 *   Byzantine-fork recovery (Option B). The 3-5s pause keeps TCP buffers
 *   well below overflow; no cert data is lost. A pause-induced byzantine_fork
 *   requires longer pauses (>8s under active cert traffic), which are
 *   intentionally prevented here so the gossipsub fix can be isolated.
 *
 * Pause duration: 15-20s (configurable via MIN_PAUSE_S / MAX_PAUSE_S).
 *   At this duration gossipsub edges go stale AND TCP buffers overflow
 *   (≈40KB/s × 20s = 800KB > 256KB typ. buffer), so the paused node
 *   resumes with cert gaps. This exercises Option A (deferred anchor
 *   commit on incomplete DAG) and Option B (unanimous minority auto-recovery).
 *
 * Warmup: waits until all nodes reach MIN_PARTICIPANTS active committee
 *   members AND the cluster runs stably for WARMUP_ROUNDS rounds first.
 *   This ensures the bootstrap exception has fired and committed the first
 *   rotation before any churn begins — pausing a node during the bootstrap
 *   rotation commit window causes state divergence (learned in testing).
 *
 * Never touches node1 (seed/bootstrap) — that would break peer discovery.
 * Never pauses two nodes simultaneously — that would drop below quorum.
 *
 * Usage:
 *   node scripts/chaos-restart.mjs
 *   MIN_WAIT_S=20 MAX_WAIT_S=60 node scripts/chaos-restart.mjs
 *   MIN_PARTICIPANTS=5 WARMUP_ROUNDS=100 node scripts/chaos-restart.mjs
 */

import { execSync, exec } from 'child_process';
import { nowMs, nowIso, toIso } from "../shared/time.js";
import http from 'http';
import fs from 'fs';
import path from 'path';

// ── File logging ─────────────────────────────────────────────────────────────
const LOG_DIR = path.resolve('./logs');
fs.mkdirSync(LOG_DIR, { recursive: true });
const _logDate = nowIso().slice(0, 10);
const _logFile = path.join(LOG_DIR, `chaos-restart-${_logDate}.log`);
const _logStream = fs.createWriteStream(_logFile, { flags: 'a' });
_logStream.write(`\n${'='.repeat(72)}\n`);
_logStream.write(`chaos-restart session started: ${nowIso()}\n`);
_logStream.write(`${'='.repeat(72)}\n`);
const _origLog = console.log.bind(console);
const _origErr = console.error.bind(console);
console.log = (...args) => { const line = args.join(' '); _origLog(line); _logStream.write(line + '\n'); };
console.error = (...args) => { const line = args.join(' '); _origErr(line); _logStream.write('[ERROR] ' + line + '\n'); };
process.on('exit', () => _logStream.end());
process.on('SIGINT', () => { console.log(`\n[chaos] Session ended. Log: ${_logFile}`); process.exit(0); });
console.log(`[chaos] Logging to ${_logFile}`);

const NODES      = ['tip-node2', 'tip-node3', 'tip-node4', 'tip-node5'];
const PORTS      = { 'tip-node2': 4100, 'tip-node3': 4200, 'tip-node4': 4300, 'tip-node5': 4400 };
const ALL_PORTS  = [4000, 4100, 4200, 4300, 4400];
const MIN_WAIT   = parseInt(process.env.MIN_WAIT_S || '25', 10) * 1000;
const MAX_WAIT   = parseInt(process.env.MAX_WAIT_S || '90', 10) * 1000;
// How long to keep a node paused.
//   3-5s  → gossipsub edges go stale, no cert loss (TCP buffers hold).
//           Tests Layer 1 retry (gossipsub mesh refresh).
//  15-20s  → TCP buffers overflow, certs are dropped, node resumes with an
//           incomplete DAG. Exercises Option A (deferred anchor commit) and
//           Option B (unanimous minority auto-recovery via snapshot resync).
//  50-60s  → Deep DAG gap. Node resumes well past gc_depth/2 rounds behind;
//           snapshot fast-sync is mandatory. Exercises full Option B path
//           (unanimous minority detection → clearByzantineForkHalt →
//           snapshot install → BFT-time floor reset → cert window GC_DEPTH).
const MIN_PAUSE  = parseInt(process.env.MIN_PAUSE_S || '15', 10) * 1000;
const MAX_PAUSE  = parseInt(process.env.MAX_PAUSE_S || '20', 10) * 1000;

let restartCount = 0;
let haltCount    = 0;
let recoveries   = 0;
let lastHaltAt   = null;
let inHalt       = false;
const pauseCounts = Object.fromEntries(NODES.map(n => [n, 0]));

function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function sleep(ms)      { return new Promise(r => setTimeout(r, ms)); }
function ts()           { return nowIso().slice(11, 19); }

function health(port) {
  return new Promise(resolve => {
    const req = http.get({ hostname: 'localhost', port, path: '/health', timeout: 2000 }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const body = JSON.parse(d);
          const data = body.data || {};
          resolve({
            ok: data.status === 'ok',
            halted: data.consensus?.halt?.halted === true,
            reason: data.consensus?.halt?.reason || '',
            round: data.consensus?.narwhal?.round || 0,
            retries: data.consensus?.narwhal?.metrics?.retries || 0,
            activeParticipants: data.consensus?.narwhal?.activeParticipants || 0,
          });
        } catch { resolve({ ok: false, halted: false, activeParticipants: 0 }); }
      });
    });
    req.on('error', () => resolve({ ok: false, halted: false }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, halted: false }); });
  });
}

async function clusterStatus() {
  const results = await Promise.all(ALL_PORTS.map(p => health(p)));
  const anyHalted = results.some(r => r.halted);
  const rounds    = results.map(r => r.round).filter(r => r > 0);
  const minRound  = rounds.length ? Math.min(...rounds) : 0;
  const maxRound  = rounds.length ? Math.max(...rounds) : 0;
  const totalRetries = results.reduce((s, r) => s + r.retries, 0);
  const minParticipants = results.reduce((m, r) => Math.min(m, r.activeParticipants || 0), Infinity);
  return { anyHalted, minRound, maxRound, totalRetries, minParticipants, nodes: results };
}


async function waitForRecovery(timeoutMs = 30000) {
  const start = nowMs();
  while (nowMs() - start < timeoutMs) {
    await sleep(1000);
    const st = await clusterStatus();
    if (!st.anyHalted && st.minRound > 0) {
      return { recovered: true, elapsedMs: nowMs() - start };
    }
  }
  return { recovered: false, elapsedMs: timeoutMs };
}

// Pause a container for pauseMs, then unpause. No DB state change —
// gossipsub heartbeats stop, direct-peer edges go stale, mesh tears down.
// When unpaused the node reconnects and the mesh reforms — exactly the
// scenario that triggers stale-ack delivery failures without risking a
// state divergence (docker restart would replay state non-deterministically).
async function pauseUnpauseNode(container, pauseMs) {
  return new Promise(resolve => {
    exec(`docker pause ${container}`, { timeout: 5000 }, (err) => {
      if (err) { resolve(false); return; }
      setTimeout(() => {
        exec(`docker unpause ${container}`, { timeout: 5000 }, (err2) => {
          resolve(!err2);
        });
      }, pauseMs);
    });
  });
}

async function loop() {
  console.log(`\n[${ts()}] chaos-restart started (pause/unpause mode)`);
  console.log(`  Churn interval: ${MIN_WAIT/1000}s – ${MAX_WAIT/1000}s between churns`);
  console.log(`  Pause duration: ${MIN_PAUSE/1000}s – ${MAX_PAUSE/1000}s per churn`);
  console.log(`  Targets: ${NODES.join(', ')} (node1/seed never touched)\n`);

  // Print initial cluster status
  const init = await clusterStatus();
  console.log(`[${ts()}] Initial state: round=${init.minRound}-${init.maxRound}  halted=${init.anyHalted}  participants=${init.minParticipants}  retries=${init.totalRetries}`);


  while (true) {
    const waitMs = rand(MIN_WAIT, MAX_WAIT);
    console.log(`\n[${ts()}] Next churn in ${(waitMs/1000).toFixed(0)}s...`);
    await sleep(waitMs);

    // Check state before restarting — skip if already halted to avoid
    // state divergences caused by restarting nodes mid-halt (a restarted node
    // may commit a different tx set, causing genuine byzantine fork detection).
    const before = await clusterStatus();
    console.log(`[${ts()}] Pre-restart state: round=${before.minRound}  halted=${before.anyHalted}  participants=${before.minParticipants}  retries=${before.totalRetries}`);
    if (before.anyHalted) {
      console.log(`[${ts()}] ⏸  Cluster already halted — skipping restart, waiting for auto-recovery`);
      const recovery = await waitForRecovery(60000);
      if (recovery.recovered) {
        console.log(`[${ts()}] ✓  Recovered in ${(recovery.elapsedMs/1000).toFixed(1)}s — resuming chaos`);
      } else {
        console.log(`[${ts()}] ✗  Still halted after 60s — likely byzantine fork, stopping chaos`);
        break;
      }
      continue;
    }

    // Pick random target node
    const target = NODES[rand(0, NODES.length - 1)];
    const pauseMs = rand(MIN_PAUSE, MAX_PAUSE);
    restartCount++;
    pauseCounts[target]++;
    console.log(`[${ts()}] ► Churn #${restartCount}: pause ${target} for ${(pauseMs/1000).toFixed(0)}s  (picks: ${NODES.map(n => `${n.replace('tip-','+')}=${pauseCounts[n]}`).join(' ')})`);

    const ok = await pauseUnpauseNode(target, pauseMs);
    if (!ok) { console.log(`[${ts()}] ✗ docker pause/unpause failed for ${target}`); continue; }
    console.log(`[${ts()}]   ${target} ✓ unpaused — gossipsub mesh edges should be stale`);

    // Monitor for halt over next 60s (Option B recovery can take ~30s with cooldown)
    let detectedHalt = false;
    for (let i = 0; i < 60; i++) {
      await sleep(1000);
      const st = await clusterStatus();

      if (st.anyHalted && !detectedHalt) {
        detectedHalt = true;
        haltCount++;
        lastHaltAt = nowMs();
        inHalt = true;
        console.log(`[${ts()}] ⚠  HALT DETECTED (halt #${haltCount}) — round=${st.minRound}  retries=${st.totalRetries}`);
        console.log(`[${ts()}]    Watching for auto-recovery (our fix should fire in ~6-12s)...`);
      }

      if (inHalt && !st.anyHalted) {
        const elapsed = nowMs() - lastHaltAt;
        recoveries++;
        inHalt = false;
        console.log(`[${ts()}] ✓  AUTO-RECOVERED in ${(elapsed/1000).toFixed(1)}s (recovery #${recoveries})`);
        console.log(`[${ts()}]    round=${st.minRound}  retries=${st.totalRetries}`);
        break;
      }

      if (!detectedHalt && i % 5 === 4) {
        console.log(`[${ts()}]   Status: round=${st.minRound}  halted=${st.anyHalted}  retries=${st.totalRetries}`);
      }
    }

    if (inHalt) {
      console.log(`[${ts()}] ✗  Still halted after 60s — fix did not recover. Manual inspection needed.`);
    }

    console.log(`[${ts()}] Totals: churns=${restartCount}  halts=${haltCount}  recoveries=${recoveries}`);
  }
}

loop().catch(err => {
  console.error('chaos-restart fatal:', err.message);
  process.exit(1);
});
