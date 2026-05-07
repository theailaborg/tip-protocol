/**
 * tx-flood.mjs — continuously submit identity transactions to all 5 nodes.
 *
 * Rotates submissions across nodes 1-5, one every INTERVAL_MS.
 * Prints running totals: submitted, accepted (202), rejected, and per-node
 * mempool drain rate from Prometheus metrics.
 *
 * Usage:
 *   node scripts/tx-flood.mjs
 *   INTERVAL_MS=500 node scripts/tx-flood.mjs
 */

import { createRequire } from 'module';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { signBody, initCrypto } = require(path.resolve(__dirname, '../shared/crypto.js'));

const PORTS     = [4000, 4100, 4200, 4300, 4400];
const INTERVAL  = parseInt(process.env.INTERVAL_MS || '1500', 10);

await initCrypto();

const vp = JSON.parse(fs.readFileSync('./genesis-data/founding-vp-keys.json', 'utf8'));

// Fetch the authoritative VP ID from the running node1 container — the local
// genesis-data/genesis.json may be out of sync after node re-registration.
let vpId;
try {
  const raw = execSync('docker exec tip-node1 cat /app/genesis-data/genesis.json', { timeout: 5000 }).toString();
  vpId = JSON.parse(raw).founding_vp.vp_id;
  console.log(`VP ID (from container): ${vpId}`);
} catch {
  vpId = JSON.parse(fs.readFileSync('./genesis-data/genesis.json', 'utf8')).founding_vp.vp_id;
  console.log(`VP ID (from local genesis.json): ${vpId}`);
}

let seq       = 0;
let accepted  = 0;
let rejected  = 0;
let errors    = 0;
const perNode = {};
for (const p of PORTS) perNode[p] = { sent: 0, ok: 0 };

function pad(n, w) { return String(n).padStart(w, ' '); }

function post(port, payload) {
  return new Promise(resolve => {
    const body = JSON.stringify(payload);
    const req  = http.request({
      hostname: 'localhost', port,
      path: '/v1/identity/register', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 3000,
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.on('error', err => resolve({ status: 0, body: err.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: 'timeout' }); });
    req.write(body);
    req.end();
  });
}

function metrics(port) {
  return new Promise(resolve => {
    http.get({ hostname: 'localhost', port, path: '/metrics', timeout: 2000 }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve(d));
    }).on('error', () => resolve(''));
  });
}

async function printStats() {
  process.stdout.write('\n');
  for (const port of PORTS) {
    const raw  = await metrics(port);
    // Metrics use labels: tip_narwhal_current_round{node="..."} 42
    const round = (raw.match(/^tip_narwhal_current_round\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';
    const halted= (raw.match(/^tip_consensus_halted\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';
    const recv  = (raw.match(/^tip_mempool_received_total\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';
    const drain = (raw.match(/^tip_mempool_drained_total\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';
    const retry = (raw.match(/^tip_narwhal_retries_total\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';
    const haltFlag = halted === '1' ? ' ⚠ HALTED' : '';
    console.log(`  :${port}  round=${pad(round,5)}  halted=${halted}${haltFlag}  mempool recv=${pad(recv,4)} drained=${pad(drain,4)}  retries=${retry}`);
  }
  console.log(`  flood: seq=${seq}  accepted=${accepted}  rejected=${rejected}  errors=${errors}`);
}

setInterval(async () => {
  const port = PORTS[seq % PORTS.length];

  // unique dedup_hash per submission (20-char zero-padded decimal)
  const dedup = String(seq + 1).padStart(20, '0');
  const body  = {
    region: 'US',
    public_key: `aabb${dedup}ccdd`,
    dedup_hash: dedup,
    zk_proof: {
      pi_a: ['1', '2', '3'],
      pi_b: [['1','2'],['3','4'],['5','6']],
      pi_c: ['1', '2', '3'],
      protocol: 'groth16', curve: 'bn128',
    },
    verification_tier: 'T1',
    vp_id: vpId,
    social_attested: false,
    creator_name: `FloodTx-${seq}`,
  };

  const payload = { ...body, vp_signature: signBody(body, vp.privateKey) };
  const { status } = await post(port, payload);

  perNode[port].sent++;
  if (status === 202) { accepted++; perNode[port].ok++; }
  else if (status === 0) errors++;
  else rejected++;

  process.stdout.write(`\r  tx #${pad(seq,5)}  :${port}  status=${status}  acc=${accepted}  rej=${rejected}  err=${errors}   `);
  seq++;
}, INTERVAL);

// Print full stats every 15s
setInterval(printStats, 15000);

console.log(`tx-flood started — submitting every ${INTERVAL}ms across nodes ${PORTS.join(',')}`);
console.log('Press Ctrl+C to stop.\n');
