
/**
 * concurrent-content-register.mjs — register content on node1 (:4000) and
 * node2 (:4100) at the same time and watch how consensus handles it.
 *
 * Fires three waves with Promise.all so the POSTs hit both nodes concurrently:
 *   1. distinct content to each node (2 independent txs)
 *   2. same content to BOTH nodes at once (dedup collision: must converge to 1 ctid)
 *   3. a small burst of distinct content split across both nodes
 * Then polls both nodes' /v1/content/:ctid until every ctid resolves on BOTH,
 * proving the DAG converged.
 *
 *   node scripts/concurrent-content-register.mjs
 */
import { createRequire } from 'module';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const ROOT = path.resolve(__dirname, '..');
const SHARED = path.join(ROOT, 'shared');

const { initCrypto, shake256, tipNormalize } = require(path.join(SHARED, 'crypto'));
const contentRegisterSchema = require(path.join(ROOT, 'node/src/schemas/content-register'));
const PC = require(path.join(SHARED, 'protocol-constants'));
const { nowMs } = require(path.join(SHARED, 'time'));
const { getGenesisPayload } = require(path.join(ROOT, 'node/src/genesis'));

const SIGNER = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'genesis-data', 'backups', 'tip-id-US-02debc7b60b07301.tip.json'), 'utf8'));

const N1 = 'http://localhost:4000';
const N2 = 'http://localhost:4100';

await initCrypto();
try { PC._resetForTesting(); } catch { /* not yet init */ }
PC.init(getGenesisPayload().protocol_constants);

function signContent(text, urls) {
  const body = {
    signer_tip_id: SIGNER.tip_id,
    origin_code: 'OH',
    content: text,
    media_canonical_hash: null,
    content_type_hint: null,
    cna_version: '2.2',
    attribution_mode: 'self',
    authors: [{ tip_id: SIGNER.tip_id, tip_id_type: SIGNER.tip_id_type, contribution_role: 'creator' }],
    extras: {},
    registered_urls: urls,
  };
  const contentHash = shake256(tipNormalize(text));
  const canonical = contentRegisterSchema.buildSigningPayload(body, contentHash);
  body.signature = contentRegisterSchema.sign(canonical, SIGNER.private_key);
  return body;
}

async function register(nodeUrl, text, urls) {
  const body = signContent(text, urls || [`https://example.com/c/${encodeURIComponent(text)}`]);
  const t0 = performance.now();
  let status, json;
  try {
    const resp = await fetch(`${nodeUrl}/v1/content/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    status = resp.status;
    const t = await resp.text();
    try { json = JSON.parse(t); } catch { json = { raw: t }; }
  } catch (e) {
    status = 'ERR'; json = { error: e.message };
  }
  const ms = Math.round(performance.now() - t0);
  const ctid = json.ctid || json.content_id || json.tip_ctid || (json.data && json.data.ctid) || null;
  return { node: nodeUrl.endsWith('4000') ? 'node1' : 'node2', status, ms, ctid, json };
}

async function resolves(nodeUrl, ctid) {
  try {
    const r = await fetch(`${nodeUrl}/v1/content/${encodeURIComponent(ctid)}`);
    return r.status === 200;
  } catch { return false; }
}

async function waitConverge(ctids, timeoutMs = 30000) {
  const start = performance.now();
  const pending = new Set(ctids);
  while (pending.size && performance.now() - start < timeoutMs) {
    for (const ctid of [...pending]) {
      const [a, b] = await Promise.all([resolves(N1, ctid), resolves(N2, ctid)]);
      if (a && b) pending.delete(ctid);
    }
    if (pending.size) await new Promise(r => setTimeout(r, 1000));
  }
  return pending; // empty == fully converged on both nodes
}

const stamp = nowMs();
const line = (r) => `  ${r.node} <- "${r.label}"  status=${r.status} ${r.ms}ms ctid=${r.ctid || '(none) ' + JSON.stringify(r.json).slice(0, 160)}`;

console.log(`signer: ${SIGNER.tip_id}\n`);

// Wave 1: distinct content, one to each node, fired together.
console.log('Wave 1: distinct content to each node concurrently');
const w1 = await Promise.all([
  register(N1, `concurrent A ${stamp}`).then(r => (r.label = 'A', r)),
  register(N2, `concurrent B ${stamp}`).then(r => (r.label = 'B', r)),
]);
w1.forEach(r => console.log(line(r)));

// Wave 2: SAME content to both nodes at the exact same time -> dedup collision.
console.log('\nWave 2: identical content to BOTH nodes at once (dedup collision)');
const collide = `collision ${stamp}`;
const w2 = await Promise.all([
  register(N1, collide).then(r => (r.label = 'collide', r)),
  register(N2, collide).then(r => (r.label = 'collide', r)),
]);
w2.forEach(r => console.log(line(r)));
const w2ctids = [...new Set(w2.map(r => r.ctid).filter(Boolean))];
console.log(`  -> distinct ctids produced: ${w2ctids.length} (expect 1 — same content_hash)`);

// Wave 3: burst of distinct content split across both nodes, all concurrent.
console.log('\nWave 3: burst of 8 distinct, split across both nodes, all at once');
const burst = await Promise.all(
  Array.from({ length: 8 }, (_, i) =>
    register(i % 2 === 0 ? N1 : N2, `burst ${i} ${stamp}`).then(r => (r.label = `burst${i}`, r))),
);
const ok = burst.filter(r => r.status === 202 || r.status === 200).length;
console.log(`  accepted: ${ok}/8 (statuses: ${burst.map(r => r.status).join(',')})`);

// Convergence: every accepted ctid must resolve on BOTH nodes.
const allCtids = [...new Set([...w1, ...w2, ...burst].map(r => r.ctid).filter(Boolean))];
console.log(`\nConvergence: waiting for ${allCtids.length} ctids to resolve on BOTH nodes...`);
const stillPending = await waitConverge(allCtids);
if (stillPending.size === 0) {
  console.log(`  CONVERGED — all ${allCtids.length} ctids present on node1 AND node2`);
} else {
  console.log(`  NOT converged — ${stillPending.size} ctid(s) missing on a node: ${[...stillPending].join(', ')}`);
}
process.exit(stillPending.size === 0 ? 0 : 1);
