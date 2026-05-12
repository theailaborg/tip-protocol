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

// ── File logging ─────────────────────────────────────────────────────────────
const LOG_DIR = path.resolve('./logs');
fs.mkdirSync(LOG_DIR, { recursive: true });
const _logDate = new Date().toISOString().slice(0, 10);
const _logFile = path.join(LOG_DIR, `tx-flood-${_logDate}.log`);
const _logStream = fs.createWriteStream(_logFile, { flags: 'a' });
_logStream.write(`\n${'='.repeat(72)}\n`);
_logStream.write(`tx-flood session started: ${new Date().toISOString()}\n`);
_logStream.write(`${'='.repeat(72)}\n`);
const _origLog = console.log.bind(console);
const _origErr = console.error.bind(console);
console.log = (...args) => { const line = args.join(' '); _origLog(line); _logStream.write(line + '\n'); };
console.error = (...args) => { const line = args.join(' '); _origErr(line); _logStream.write('[ERROR] ' + line + '\n'); };
process.on('exit', () => _logStream.end());
process.on('SIGINT', () => { console.log(`\n[flood] Session ended. Log: ${_logFile}`); process.exit(0); });

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { signBody, initCrypto } = require(path.resolve(__dirname, '../shared/crypto.js'));

const PORTS     = [4000, 4100, 4200, 4300, 4400];
const INTERVAL  = parseInt(process.env.INTERVAL_MS || '1500', 10);

await initCrypto();

const _vpFile = JSON.parse(fs.readFileSync('./genesis-data/founding-vp-keys.json', 'utf8'));
// Support both the legacy flat format { privateKey, publicKey }
// and the new envelope format { entries: [{ private_key, public_key, id }] }.
const _vpEntry = _vpFile.entries ? _vpFile.entries[0] : _vpFile;
const vp = {
  privateKey: _vpEntry.private_key ?? _vpEntry.privateKey,
  publicKey:  _vpEntry.public_key  ?? _vpEntry.publicKey,
};
const _vpIdFromFile = _vpEntry.id ?? null;

// Prefer the VP ID embedded in the keys file (always in sync after re-seed).
// Fall back to reading the container/local genesis.json.
let vpId = _vpIdFromFile;
if (!vpId) {
  try {
    const raw = execSync('docker exec tip-node1 cat /app/genesis-data/genesis.json', { timeout: 5000 }).toString();
    vpId = JSON.parse(raw).founding_vp.vp_id;
    console.log(`VP ID (from container): ${vpId}`);
  } catch {
    vpId = JSON.parse(fs.readFileSync('./genesis-data/genesis.json', 'utf8')).founding_vp.vp_id;
    console.log(`VP ID (from local genesis.json): ${vpId}`);
  }
} else {
  console.log(`VP ID (from keys file): ${vpId}`);
}

let seq       = parseInt(process.env.START_SEQ || '0', 10);
let accepted  = 0;
let rejected  = 0;
let errors    = 0;
const perNode = {};
for (const p of PORTS) perNode[p] = { sent: 0, ok: 0, err: 0 };

// Track drained totals from the previous stats print to compute throughput delta.
const prevDrained = {};
for (const p of PORTS) prevDrained[p] = 0;

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
  let totalDrainDelta = 0;
  for (const port of PORTS) {
    const raw   = await metrics(port);
    const round = (raw.match(/^tip_narwhal_current_round\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';
    const halted= (raw.match(/^tip_consensus_halted\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';
    const recv  = (raw.match(/^tip_mempool_received_total\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';
    const drain = (raw.match(/^tip_mempool_drained_total\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';
    const retry = (raw.match(/^tip_narwhal_retries_total\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';
    const committed = (raw.match(/^tip_bullshark_txs_committed_total\{[^}]*\}\s+(\d+)/m) || [])[1] || '?';

    // How many txs were drained (batch-included by narwhal) since last print.
    const drainNum   = parseInt(drain, 10);
    const drainDelta = isNaN(drainNum) ? 0 : drainNum - (prevDrained[port] || 0);
    if (!isNaN(drainNum)) { prevDrained[port] = drainNum; totalDrainDelta += drainDelta; }

    const haltFlag  = halted === '1' ? ' ⚠ HALTED' : '';
    const drainTag  = drainDelta > 0 ? `+${drainDelta}` : (raw ? `+0` : 'DOWN');
    const nodeErr   = perNode[port].err;
    const errTag    = nodeErr > 0 ? `  err=${nodeErr}` : '';
    console.log(
      `  :${port}  round=${pad(round,5)}  halted=${halted}${haltFlag}` +
      `  recv=${pad(recv,4)} drained=${pad(drain,4)}(${pad(drainTag,4)}/15s)` +
      `  committed=${pad(committed,5)}  retries=${retry}${errTag}`
    );
  }
  console.log(`  flood: seq=${seq}  accepted=${accepted}  rejected=${rejected}  errors=${errors}  drain/15s=${totalDrainDelta}`);
  // Warn if the whole cluster stopped draining txs — sign of consensus stall.
  if (totalDrainDelta === 0 && seq > 10) {
    console.log(`  *** WARNING: no txs drained in the last 15s — chain may be stalled ***`);
  }
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
    tip_id_type: 'personal',
  };

  // Sign the canonical payload matching registerIdentitySchema.buildSigningPayload —
  // the server verifies against that exact field set (tip_id_type was added in d2da883).
  const canonicalPayload = {
    creator_name: body.creator_name,
    dedup_hash:   body.dedup_hash,
    public_key:   body.public_key,
    region:       body.region.toUpperCase(),
    social_attested: !!body.social_attested,
    tip_id_type:  body.tip_id_type,
    verification_tier: body.verification_tier,
    vp_id:        body.vp_id,
    zk_proof:     body.zk_proof,
  };
  const payload = { ...body, vp_signature: signBody(canonicalPayload, vp.privateKey) };
  const { status } = await post(port, payload);

  perNode[port].sent++;
  if (status === 202) { accepted++; perNode[port].ok++; }
  else if (status === 0) { errors++; perNode[port].err++; }
  else rejected++;

  process.stdout.write(`\r  tx #${pad(seq,5)}  :${port}  status=${status}  acc=${accepted}  rej=${rejected}  err=${errors}   `);
  seq++;
}, INTERVAL);

// Print full stats every 15s
setInterval(printStats, 15000);

console.log(`tx-flood started — submitting every ${INTERVAL}ms across nodes ${PORTS.join(',')}`);
console.log('Press Ctrl+C to stop.\n');
