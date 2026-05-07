/**
 * chaos-restart.mjs — randomly restart non-seed nodes to cause gossipsub mesh churn.
 *
 * Reproduces the directed gossipsub delivery failure that halted the federation:
 *   1. Restart a non-seed node → mesh edges tear down and reform
 *   2. After several churns, some directed edges go stale
 *   3. With committee=5 / quorum=4, two certs losing >1 ack → halt
 *   4. Our narwhal retry fix should auto-recover within ~12s (no manual restart)
 *
 * Never restarts node1 (seed/bootstrap) — that would break peer discovery.
 * Never restarts two nodes simultaneously — that would drop below quorum.
 *
 * Usage:
 *   node scripts/chaos-restart.mjs
 *   MIN_WAIT_S=20 MAX_WAIT_S=60 node scripts/chaos-restart.mjs
 */

import { execSync, exec } from 'child_process';
import http from 'http';

const NODES      = ['tip-node2', 'tip-node3', 'tip-node4', 'tip-node5'];
const PORTS      = { 'tip-node2': 4100, 'tip-node3': 4200, 'tip-node4': 4300, 'tip-node5': 4400 };
const ALL_PORTS  = [4000, 4100, 4200, 4300, 4400];
const MIN_WAIT   = parseInt(process.env.MIN_WAIT_S || '25', 10) * 1000;
const MAX_WAIT   = parseInt(process.env.MAX_WAIT_S || '90', 10) * 1000;

let restartCount = 0;
let haltCount    = 0;
let recoveries   = 0;
let lastHaltAt   = null;
let inHalt       = false;

function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function sleep(ms)      { return new Promise(r => setTimeout(r, ms)); }
function ts()           { return new Date().toISOString().slice(11, 19); }

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
          });
        } catch { resolve({ ok: false, halted: false }); }
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
  return { anyHalted, minRound, maxRound, totalRetries, nodes: results };
}

async function waitForRecovery(timeoutMs = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    await sleep(1000);
    const st = await clusterStatus();
    if (!st.anyHalted && st.minRound > 0) {
      return { recovered: true, elapsedMs: Date.now() - start };
    }
  }
  return { recovered: false, elapsedMs: timeoutMs };
}

async function restartNode(container) {
  return new Promise(resolve => {
    exec(`docker restart ${container}`, { timeout: 15000 }, (err) => {
      resolve(!err);
    });
  });
}

async function waitNodeUp(container, timeoutMs = 20000) {
  const port  = PORTS[container];
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    await sleep(1500);
    const h = await health(port);
    if (h.ok) return true;
  }
  return false;
}

async function loop() {
  console.log(`\n[${ts()}] chaos-restart started`);
  console.log(`  Restart window: ${MIN_WAIT/1000}s – ${MAX_WAIT/1000}s between churns`);
  console.log(`  Targets: ${NODES.join(', ')} (node1/seed never touched)\n`);

  // Print initial cluster status
  const init = await clusterStatus();
  console.log(`[${ts()}] Initial state: round=${init.minRound}-${init.maxRound}  halted=${init.anyHalted}  retries=${init.totalRetries}`);

  while (true) {
    const waitMs = rand(MIN_WAIT, MAX_WAIT);
    console.log(`\n[${ts()}] Next churn in ${(waitMs/1000).toFixed(0)}s...`);
    await sleep(waitMs);

    // Check state before restarting
    const before = await clusterStatus();
    console.log(`[${ts()}] Pre-restart state: round=${before.minRound}  halted=${before.anyHalted}  retries=${before.totalRetries}`);

    // Pick random target node
    const target = NODES[rand(0, NODES.length - 1)];
    restartCount++;
    console.log(`[${ts()}] ► Restart #${restartCount}: ${target}`);

    const ok = await restartNode(target);
    if (!ok) { console.log(`[${ts()}] ✗ docker restart failed for ${target}`); continue; }

    // Wait for the restarted node to come back
    const up = await waitNodeUp(target);
    console.log(`[${ts()}]   ${target} ${up ? '✓ back up' : '✗ did not come up in time'}`);

    // Monitor for halt over next 20s
    let detectedHalt = false;
    for (let i = 0; i < 20; i++) {
      await sleep(1000);
      const st = await clusterStatus();

      if (st.anyHalted && !detectedHalt) {
        detectedHalt = true;
        haltCount++;
        lastHaltAt = Date.now();
        inHalt = true;
        console.log(`[${ts()}] ⚠  HALT DETECTED (halt #${haltCount}) — round=${st.minRound}  retries=${st.totalRetries}`);
        console.log(`[${ts()}]    Watching for auto-recovery (our fix should fire in ~6-12s)...`);
      }

      if (inHalt && !st.anyHalted) {
        const elapsed = Date.now() - lastHaltAt;
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
      console.log(`[${ts()}] ✗  Still halted after 20s — fix did not recover. Manual inspection needed.`);
    }

    console.log(`[${ts()}] Totals: restarts=${restartCount}  halts=${haltCount}  recoveries=${recoveries}`);
  }
}

loop().catch(err => {
  console.error('chaos-restart fatal:', err.message);
  process.exit(1);
});
