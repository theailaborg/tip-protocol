/**
 * bench-content-register.mjs , throughput driver for the content-register path.
 *
 * Fires signed REGISTER_CONTENT requests at a target rate, spread round-robin
 * across the given nodes, and measures:
 *   - submit latency (POST -> 202) p50/p95/p99
 *   - commit latency (202 -> readable on a DIFFERENT node), sampled
 *   - acceptance/rejection breakdown by status code
 *
 * Usage:
 *   node scripts/bench-content-register.mjs \
 *     --rate 1 --duration 60 \
 *     --nodes https://node1.theailab.org,https://node2.theailab.org,https://node3.theailab.org
 *
 * Requires genesis-data/temp-users/temp-users-latest.json (seed-temp-users.js).
 */

import { createRequire } from "module";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { initCrypto, shake256, tipNormalize, mldsaSign, mldsaVerify, generateMLDSAKeypair } =
  require(path.join(ROOT, "shared/crypto"));
const { nowMs } = require(path.join(ROOT, "shared/time"));
const schema = require(path.join(ROOT, "node/src/schemas/content-register"));

function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : dflt;
}
const RATE = Number(arg("rate", "1"));
const DURATION = Number(arg("duration", "60"));
const NODES = arg("nodes",
  "https://node1.theailab.org,https://node2.theailab.org,https://node3.theailab.org").split(",");
const USERS_FILE = arg("users", path.join(ROOT, "genesis-data/temp-users/temp-users-latest.json"));
const COMMIT_SAMPLE = Number(arg("commit-sample", "5"));   // poll every Nth tx
const RUN_ID = `${nowMs().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;

function pct(sorted, p) {
  if (!sorted.length) return null;
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

async function microbench() {
  const kp = generateMLDSAKeypair();
  const msg = "bench-" + RUN_ID;
  let t0 = performance.now();
  const N = 20;
  const sigs = [];
  for (let i = 0; i < N; i++) sigs.push(mldsaSign(msg + i, kp.privateKey));
  const signMs = (performance.now() - t0) / N;
  t0 = performance.now();
  for (let i = 0; i < N; i++) mldsaVerify(msg + i, sigs[i], kp.publicKey);
  const verifyMs = (performance.now() - t0) / N;
  console.log(`ML-DSA-65 on this driver machine: sign ${signMs.toFixed(1)}ms, verify ${verifyMs.toFixed(1)}ms per op`);
}

function buildTx(user, seq) {
  const text = `bench ${RUN_ID} seq ${seq} from ${user.tip_id}`;
  const body = {
    creator_tip_id: user.tip_id,
    signer_tip_id: user.tip_id,
    origin_code: "OH",
    title: `bench ${RUN_ID}/${seq}`,
    content: text,
    content_type_hint: null,
    cna_version: "2.2",
    attribution_mode: "self",
    authors: [{ tip_id: user.tip_id, tip_id_type: user.tip_id_type || "personal", contribution_role: "creator" }],
    extras: {},
    registered_urls: [`https://bench.example.org/${RUN_ID}/${seq}`],
  };
  const contentHash = shake256(tipNormalize(text));
  body.signature = schema.sign(schema.buildSigningPayload(body, contentHash), user.private_key);
  return body;
}

async function pollCommitted(ctid, nodeUrl, timeoutMs = 90000) {
  const t0 = performance.now();
  const url = `${nodeUrl}/v1/content/${encodeURIComponent(ctid)}`;
  while (performance.now() - t0 < timeoutMs) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
      if (r.status === 200) return performance.now() - t0;
    } catch { /* retry */ }
    await new Promise(r => setTimeout(r, 1000));
  }
  return null;
}

async function main() {
  await initCrypto();
  await microbench();

  const doc = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  const users = (doc.users || doc).filter(u => u.private_key);
  if (!users.length) throw new Error("no users with private keys in " + USERS_FILE);
  console.log(`rate=${RATE}/s duration=${DURATION}s nodes=${NODES.length} users=${users.length} run=${RUN_ID}\n`);

  // Pre-sign the whole corpus so the timed window measures the CLUSTER,
  // not this machine's ~16ms/signature.
  const corpusSize = Math.ceil(RATE * DURATION * 1.05);
  console.log(`pre-signing ${corpusSize} payloads...`);
  const corpus = [];
  for (let i = 0; i < corpusSize; i++) {
    corpus.push(buildTx(users[i % users.length], i));
    if (i % 500 === 499) console.log(`  ${i + 1}/${corpusSize}`);
  }
  console.log("corpus ready; firing.\n");

  const submitLat = [];
  const commitLat = [];
  const statuses = {};
  const commitPolls = [];
  let seq = 0, sent = 0;

  const intervalMs = 1000 / RATE;
  const endAt = performance.now() + DURATION * 1000;

  while (performance.now() < endAt && seq < corpus.length) {
    const tickStart = performance.now();
    const mySeq = seq++;
    const node = NODES[mySeq % NODES.length];
    const body = corpus[mySeq];

    (async () => {
      const t0 = performance.now();
      try {
        const r = await fetch(`${node}/v1/content/register`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(15000),
        });
        const ms = performance.now() - t0;
        statuses[r.status] = (statuses[r.status] || 0) + 1;
        if (r.status === 202) {
          submitLat.push(ms);
          if (mySeq % COMMIT_SAMPLE === 0) {
            const j = await r.json();
            const otherNode = NODES[(mySeq + 1) % NODES.length];
            commitPolls.push(pollCommitted(j.data.ctid, otherNode).then(v => { if (v != null) commitLat.push(v); }));
          }
        } else if ((statuses[r.status] || 0) <= 3) {
          const t = await r.text();
          console.log(`  [${r.status}] ${t.slice(0, 140)}`);
        }
      } catch (e) {
        statuses.ERR = (statuses.ERR || 0) + 1;
        if (statuses.ERR <= 3) console.log(`  [ERR] ${e.message}`);
      }
      sent++;
    })();

    const elapsed = performance.now() - tickStart;
    await new Promise(r => setTimeout(r, Math.max(0, intervalMs - elapsed)));
  }

  // let in-flight submits land, then wait for sampled commit polls
  await new Promise(r => setTimeout(r, 5000));
  await Promise.all(commitPolls);

  submitLat.sort((a, b) => a - b);
  commitLat.sort((a, b) => a - b);
  const ok = statuses[202] || 0;
  console.log("\n══ RESULTS ══");
  console.log(`offered:   ${seq} tx over ${DURATION}s  (${RATE}/s target)`);
  console.log(`accepted:  ${ok} (${(ok / DURATION).toFixed(2)}/s)  statuses: ${JSON.stringify(statuses)}`);
  console.log(`submit ms: p50=${pct(submitLat, 50)?.toFixed(0)} p95=${pct(submitLat, 95)?.toFixed(0)} p99=${pct(submitLat, 99)?.toFixed(0)}`);
  console.log(`commit ms: p50=${pct(commitLat, 50)?.toFixed(0)} p95=${pct(commitLat, 95)?.toFixed(0)} (n=${commitLat.length} sampled, cross-node)`);
}

main().then(() => process.exit(0)).catch(e => { console.error("BENCH FAILED:", e.message); process.exit(1); });
