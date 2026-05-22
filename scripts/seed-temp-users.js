#!/usr/bin/env node
/**
 * @file scripts/seed-temp-users.js
 * @description DEV-ONLY: Register N temporary identities with a configurable
 * score distribution so dispute jury selection has a real pool to draw from.
 *
 * Why this exists separately from scripts/seed.js:
 *   - seed.js bootstraps GENESIS state — keys persist forever, signed into
 *     the genesis block, used as the cryptographic root of the network.
 *     Genesis output goes in genesis-data/founder-keys.json + genesis.json.
 *   - This script seeds DEV-ONLY playthrough identities — they're noise for
 *     local testing, not part of network history. Keys go in
 *     genesis-data/temp-users/ which is gitignored and safe to wipe.
 *
 * Run order:
 *   1. scripts/seed.js                     # genesis bootstrap (once)
 *   2. start nodes                         # wait for healthy quorum
 *   3. scripts/seed-temp-users.js          # this script — registers N temp users
 *   4. restart nodes                       # mirror re-hydrates with bumped scores
 *
 * Score distribution:
 *   New identities default to SCORE.INITIAL_IDENTITY (500). The protocol has
 *   no admin path to bump scores — they grow only from real activity, which
 *   takes too long for local testing (per-day verify caps make 500 → 700
 *   take ~20 days of cluster time). This script SQL-UPDATEs the `scores`
 *   table on every node DB to a configurable random value, then asks you to
 *   restart so the in-memory mirror re-hydrates. **Test environments only.**
 *
 * Defaults: 70% of users at 700-1000 (jury-eligible), 30% at 500-699 (below
 * jury threshold, can dispute, can't sit on jury). Scores randomized within
 * each band so tests cover the range.
 *
 * Safety:
 *   - Refuses to run if NODE_ENV=production unless --force-prod is passed.
 *   - Refuses to run if the target node is consensus-halted — submitting txs
 *     during a halt is what caused the state divergence we hit during the
 *     first iteration of this script.
 *   - Idempotent: if a tip_id is already registered (e.g. a prior run timed
 *     out client-side but committed server-side), the script skips registration
 *     and continues. Re-running is safe.
 *
 * Usage:
 *   node scripts/seed-temp-users.js
 *   node scripts/seed-temp-users.js --count 50 --high-pct 70
 *   node scripts/seed-temp-users.js --node-url http://localhost:4000
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../shared/time");

const fs = require("fs");
const path = require("path");
const http = require("http");
const { execSync } = require("child_process");
const crypto = require("crypto");

const { initCrypto, generateMLDSAKeypair } = require("../shared/crypto");
const registerIdentitySchema = require("../node/src/schemas/register-identity");
const { generateDedupProof } = require("../shared/zk");

const REPO_ROOT = path.resolve(__dirname, "..");
const GENESIS_DIR = path.join(REPO_ROOT, "genesis-data");
const VP_KEYS_FILE = path.join(GENESIS_DIR, "founding-vp-keys.json");
const SEED_OUT_FILE = path.join(GENESIS_DIR, "seed-output.json");
const TEMP_USERS_DIR = path.join(GENESIS_DIR, "temp-users");
const TEMP_USERS_KEYS_DIR = path.join(TEMP_USERS_DIR, "keys");
const OUT_LATEST = path.join(TEMP_USERS_DIR, "temp-users-latest.json");

// HTTP endpoints + their corresponding postgres DBs. These must be kept in
// sync with the node-N.env files; if you reshape the dev cluster, update both.
const NODES = [
  { url: "http://localhost:4000", db: "tip_protocol" },
  { url: "http://localhost:4100", db: "tip_node2" },
  { url: "http://localhost:4200", db: "tip_node3" },
  { url: "http://localhost:4300", db: "tip_node4" },
  { url: "http://localhost:4400", db: "tip_node5" },
];
const PG_CONTAINER = "tip-postgres";

// ─── CLI ─────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  // Default region pool. Each new user gets a region picked uniformly at
  // random from this list — without this, every temp user lands in "US"
  // and the jury-selection geographic-diversity cap (jury_max_same_country)
  // limits the realisable jury pool to <max_per_country> regardless of
  // how many score-eligible identities exist. Override via --regions.
  const DEFAULT_REGIONS = ["US", "BR", "DE", "JP", "IN", "GB", "FR", "AU", "CA", "MX"];

  const args = {
    count: 50,
    nodeUrl: NODES[0].url,
    highPct: 70,
    highMin: 700, highMax: 1000,
    lowMin: 500, lowMax: 699,
    regions: DEFAULT_REGIONS,
    namePrefix: "TempUser",  // creator_name = `${namePrefix}-${001..N}` — easy to spot in identity lists
    skipScoreBump: false,
    forceProd: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--count") args.count = Number(argv[++i]);
    else if (a === "--node-url") args.nodeUrl = argv[++i];
    else if (a === "--high-pct") args.highPct = Number(argv[++i]);
    else if (a === "--high-min") args.highMin = Number(argv[++i]);
    else if (a === "--high-max") args.highMax = Number(argv[++i]);
    else if (a === "--low-min") args.lowMin = Number(argv[++i]);
    else if (a === "--low-max") args.lowMax = Number(argv[++i]);
    else if (a === "--region") args.regions = [argv[++i]];                         // single-region back-compat
    else if (a === "--regions") args.regions = argv[++i].split(",").map(s => s.trim()).filter(Boolean);
    else if (a === "--name-prefix") args.namePrefix = argv[++i];
    else if (a === "--no-score-bump") args.skipScoreBump = true;
    else if (a === "--force-prod") args.forceProd = true;
    else if (a === "--help" || a === "-h") {
      console.log("usage: seed-temp-users.js [opts]");
      console.log("  --count N           number of temp users to create (default 50)");
      console.log("  --node-url URL      submission target (default http://localhost:4000)");
      console.log("  --high-pct N        % of users at jury-eligible scores (default 70)");
      console.log("  --high-min/max N    jury-eligible band (default 700-1000)");
      console.log("  --low-min/max N     below-threshold band (default 500-699)");
      console.log("  --region XX         single region (back-compat; equivalent to --regions XX)");
      console.log("  --regions A,B,C     pool of regions; each user picks uniformly at random");
      console.log("                      (default: US,BR,DE,JP,IN,GB,FR,AU,CA,MX — wide enough to clear");
      console.log("                       jury_max_same_country cap with default count)");
      console.log("  --name-prefix STR   creator_name prefix; final name = STR-NNN (default TempUser)");
      console.log("  --no-score-bump     skip the SQL score UPDATE step");
      console.log("  --force-prod        bypass the NODE_ENV=production guard (you better mean it)");
      process.exit(0);
    } else throw new Error(`unknown arg: ${a}`);
  }
  if (args.count < 1) throw new Error("--count must be >= 1");
  if (args.highPct < 0 || args.highPct > 100) throw new Error("--high-pct must be 0..100");
  if (args.highMin > args.highMax || args.lowMin > args.lowMax) throw new Error("score min must be <= max");
  return args;
}

// ─── HTTP ───────────────────────────────────────────────────────────────────
function httpRequest(url, { method = "GET", body = null, timeoutMs = 60000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = body ? JSON.stringify(body) : null;
    const headers = { "Accept": "application/json" };
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }
    const req = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname + (u.search || ""),
      method, headers, timeout: timeoutMs,
    }, (res) => {
      let data = ""; res.on("data", c => data += c);
      res.on("end", () => {
        let parsed = null;
        try { parsed = JSON.parse(data); } catch { /* leave null */ }
        resolve({ status: res.statusCode, body: parsed, raw: data });
      });
    });
    req.on("timeout", () => { req.destroy(new Error(`timeout after ${timeoutMs}ms`)); });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function postJson(url, body, timeoutMs) {
  const r = await httpRequest(url, { method: "POST", body, timeoutMs });
  if (r.status >= 200 && r.status < 300) return r.body;
  const msg = r.body?.error?.message || r.body?.error || `HTTP ${r.status}`;
  const err = new Error(msg);
  err.status = r.status; err.body = r.body;
  throw err;
}

async function getJson(url, timeoutMs = 5000) {
  const r = await httpRequest(url, { method: "GET", timeoutMs });
  return r;
}

async function waitFor(predicate, { intervalMs = 500, timeoutMs = 60000 } = {}) {
  const deadline = nowMs() + timeoutMs;
  while (nowMs() < deadline) {
    if (await predicate()) return true;
    await new Promise(r => setTimeout(r, intervalMs));
  }
  return false;
}

// ─── Pre-flight ─────────────────────────────────────────────────────────────
//
// Hard requirement: the submission target itself must be healthy + at
// quorum. Submitting to a node that's mid-snapshot-recovery is what
// caused the divergent-tx-during-recovery issue we saw earlier — a tx
// that admits on a recovering node but never commits there.
//
// Soft check: peers in nodeUrls that are unreachable are reported as
// "best-effort". A deliberately-stopped node is fine; it'll catch up via
// anti-entropy when it boots, same as a normal new-node-join. We only
// refuse if ZERO peers are reachable (sole online node = no quorum).
async function preflightHealth(submissionUrl, peerUrls) {
  async function probe(url) {
    try {
      const r = await getJson(`${url}/health`, 3000);
      if (r.status !== 200) return { url, ok: false, reason: `health http ${r.status}` };
      const c = r.body?.data?.consensus;
      const halted = c?.halt?.halted;
      if (halted) return { url, ok: false, reason: `halted: ${c.halt.reason}` };
      return { url, ok: true, round: c?.narwhal?.round };
    } catch (e) {
      // Network errors don't always carry a meaningful .message — surface the
      // error code (ECONNREFUSED / ETIMEDOUT / etc.) so "node down" doesn't
      // print as a blank reason.
      const reason = e.code || e.message || (typeof e === "string" ? e : "unreachable");
      return { url, ok: false, reason };
    }
  }

  // Hard check on the submission target.
  const target = await probe(submissionUrl);
  if (!target.ok) {
    throw new Error(`Submission target ${submissionUrl} not healthy: ${target.reason}\n` +
      `Start it (or pick a different --node-url) before re-running.`);
  }
  console.log(`✓ Submission target healthy: ${submissionUrl} (round ~${target.round})`);

  // Soft check on peers (everything in NODES other than the submission target).
  const otherUrls = peerUrls.filter(u => u !== submissionUrl);
  if (otherUrls.length === 0) return [submissionUrl];

  const peers = await Promise.all(otherUrls.map(probe));
  const reachable = peers.filter(p => p.ok);
  const unreachable = peers.filter(p => !p.ok);

  if (reachable.length > 0) {
    const rounds = reachable.map(p => p.round).filter(r => r !== undefined);
    const roundRange = rounds.length ? `round ~${Math.min(...rounds)}–${Math.max(...rounds)}` : "round unknown";
    console.log(`✓ ${reachable.length}/${otherUrls.length} peer node(s) reachable (${roundRange})`);
  }
  if (unreachable.length > 0) {
    console.log(`⚠ ${unreachable.length} peer node(s) unreachable (will catch up on boot via anti-entropy):`);
    for (const u of unreachable) console.log(`    ${u.url} — ${u.reason}`);
  }

  // Return list of URLs we'll poll for tx propagation.
  return [submissionUrl, ...reachable.map(p => p.url)];
}

// ─── Registration ───────────────────────────────────────────────────────────
async function registerOne({ kp, region, vpKp, vpId, nodeUrl, creatorName }) {
  const govId = `DEV-${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
  const dob = "1990-01-01";
  const { dedup_hash, proof: zk_proof } = await generateDedupProof(govId, dob, region);

  // VP signs the canonical 9-field payload (schemas/register-identity).
  // Temp users are always `tip_id_type: "personal"` — dev fixtures
  // representing individual humans.
  const idFields = {
    region, public_key: kp.publicKey, dedup_hash, zk_proof,
    verification_tier: "T1", vp_id: vpId, social_attested: false,
    tip_id_type: "personal",
    ...(creatorName ? { creator_name: creatorName } : {}),
  };
  const canonicalPayload = registerIdentitySchema.buildSigningPayload(idFields);
  const vp_signature = registerIdentitySchema.sign(canonicalPayload, vpKp.privateKey);

  // 60s timeout: ZK verify + consensus admission can be slow on a busy local
  // cluster. The prior 10s timeout caused the divergent-tx-during-recovery
  // problem (client gave up; server still committed).
  const res = await postJson(`${nodeUrl}/v1/identity/register`, { ...idFields, vp_signature }, 60000);
  const tipId = res.data?.tip_id;
  if (!tipId) throw new Error(`register response missing tip_id: ${JSON.stringify(res).slice(0, 300)}`);
  return { tip_id: tipId, dedup_hash, creator_name: creatorName || null };
}

async function existsOnNode(tipId, nodeUrl) {
  const r = await getJson(`${nodeUrl}/v1/identity/${encodeURIComponent(tipId)}`, 3000);
  return r.status === 200;
}

// Wait for the new identity to appear on each *reachable* node. Nodes that
// were offline at preflight time aren't polled — they'll pick up the tx via
// anti-entropy / sync when they boot, just like any normal new-node-join.
async function confirmOnReachableNodes(tipId, reachableUrls) {
  return waitFor(async () => {
    const probes = await Promise.all(reachableUrls.map(u => existsOnNode(tipId, u).catch(() => false)));
    return probes.every(Boolean);
  }, { timeoutMs: 90000 });
}

// ─── Score distribution ────────────────────────────────────────────────────
function pickScore(args, isHigh) {
  const min = isHigh ? args.highMin : args.lowMin;
  const max = isHigh ? args.highMax : args.lowMax;
  return min + Math.floor(Math.random() * (max - min + 1));
}

function bumpScoresInAllDBs(rows) {
  // rows: [{ tip_id, score }, ...]
  if (rows.length === 0) return;
  // `scores.last_updated` is a bigint epoch-ms column (declared
  // t.bigInteger in db/knex-adapter.js). Pre-migration this script
  // wrote `nowIso()` here which only worked when the schema was TEXT;
  // now produces "invalid input syntax for type bigint" against the
  // migrated column. Match the on-chain shape: integer ms throughout.
  const now = nowMs();
  // Pipe SQL via stdin rather than -c '...'. The -c path required JSON.stringify
  // to shell-escape, which converted real newlines into literal backslash-n
  // characters and broke psql's parser. Stdin avoids all quoting/escaping
  // headaches: -i keeps the docker exec stdin attached, psql reads SQL until EOF.
  const valuesSql = rows.map(r => `('${r.tip_id}', ${r.score}, 0, ${now})`).join(",\n");
  const sql = `INSERT INTO scores (tip_id, score, offense_count, last_updated)
VALUES ${valuesSql}
ON CONFLICT (tip_id) DO UPDATE SET score = EXCLUDED.score, last_updated = EXCLUDED.last_updated;`;
  let bumped = 0, skipped = 0;
  for (const { db } of NODES) {
    try {
      execSync(`docker exec -i ${PG_CONTAINER} psql -U tip -d ${db} -v ON_ERROR_STOP=1`, {
        input: sql,
        stdio: ["pipe", "pipe", "pipe"],
      });
      console.log(`  ✓ bumped ${rows.length} score(s) in ${db}`);
      bumped++;
    } catch (e) {
      const stderr = e.stderr?.toString() || e.message;
      const firstLine = stderr.split("\n").filter(Boolean)[0] || stderr;
      // Schema-not-yet-migrated is benign — that node has never booted, so its
      // postgres has the empty database but no tables. When it boots later, it
      // runs the schema migration + hydrates from DAG, then re-running this
      // bump (or the next seed-temp-users run) will succeed.
      if (/relation "scores" does not exist|database .* does not exist/.test(stderr)) {
        console.log(`  ⚠ ${db}: skipped (${/database/.test(stderr) ? "DB missing" : "schema not migrated"} — boot the node, then re-bump)`);
        skipped++;
        continue;
      }
      console.error(`  ✗ ${db}: ${firstLine}`);
      throw e;
    }
  }
  if (skipped > 0) {
    console.log(`  → ${bumped} bumped, ${skipped} skipped. Re-run seed-temp-users (or just the bump) after booting the skipped nodes.`);
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv);

  if (process.env.NODE_ENV === "production" && !args.forceProd) {
    throw new Error("Refusing to run with NODE_ENV=production. This script writes test-only state. Pass --force-prod to override.");
  }

  if (!fs.existsSync(VP_KEYS_FILE)) {
    throw new Error(`founding-vp-keys.json not found at ${VP_KEYS_FILE} — run scripts/seed.js first`);
  }
  if (!fs.existsSync(SEED_OUT_FILE)) {
    throw new Error(`seed-output.json not found at ${SEED_OUT_FILE} — run scripts/seed.js first`);
  }

  fs.mkdirSync(TEMP_USERS_DIR, { recursive: true });

  // Read from the v1 multi-entry envelope. founding-vp-keys.json carries
  // an `entries: [{tag, public_key, private_key, ...}]` array; we look up
  // the primary VP by tag.
  const vpFile = JSON.parse(fs.readFileSync(VP_KEYS_FILE, "utf8"));
  const vpEntry = vpFile?.entries?.find(e => e.tag === "primary-vp");
  if (!vpEntry?.public_key || !vpEntry?.private_key) {
    throw new Error(`founding-vp-keys.json missing primary-vp entry — re-run scripts/seed.js`);
  }
  const vpKp = { publicKey: vpEntry.public_key, privateKey: vpEntry.private_key };

  const seedOut = JSON.parse(fs.readFileSync(SEED_OUT_FILE, "utf8"));
  const vpSummary = seedOut?.founding_vps?.find(v => v.tag === "primary-vp");
  if (!vpSummary?.vp_id) {
    throw new Error(`seed-output.json missing founding_vps[primary-vp].vp_id — re-run scripts/seed.js`);
  }
  const vpId = vpSummary.vp_id;

  console.log(`▸ Pre-flight: checking submission target + peers...`);
  const reachableUrls = await preflightHealth(args.nodeUrl, NODES.map(n => n.url));

  console.log(`▸ Initializing crypto + ZK circuits...`);
  await initCrypto();

  const nHigh = Math.round(args.count * (args.highPct / 100));
  const nLow = args.count - nHigh;
  console.log(`▸ Plan: ${args.count} users — ${nHigh} jury-eligible (${args.highMin}-${args.highMax}), ${nLow} below threshold (${args.lowMin}-${args.lowMax})`);

  // Zero-pad the index so list sorts lexicographically by name later.
  // 50 users → "01..50", 500 users → "001..500".
  const idxWidth = String(args.count).length;
  const padIdx = (i) => String(i + 1).padStart(idxWidth, "0");

  const pickRegion = () => args.regions[Math.floor(Math.random() * args.regions.length)];

  const users = [];
  for (let i = 0; i < args.count; i++) {
    const isHigh = i < nHigh;
    const kp = generateMLDSAKeypair();
    const creatorName = `${args.namePrefix}-${padIdx(i)}`;
    const region = pickRegion();
    process.stdout.write(`  [${String(i + 1).padStart(2, " ")}/${args.count}] ${isHigh ? "high" : "low "} ${region} ${creatorName} `);
    let result;
    try {
      result = await registerOne({ kp, region, vpKp, vpId, nodeUrl: args.nodeUrl, creatorName });
    } catch (e) {
      // If the request timed out client-side but a previous attempt may have
      // landed, we have no way to recover the tip_id (it's deterministic on
      // the public_key, but each call generates a fresh keypair). Bail loudly
      // rather than continue and produce a half-applied state.
      console.log(`✗ FAILED: ${e.message}`);
      throw new Error(`Registration failed for user ${i + 1}. Aborting to avoid leaving partial state.`);
    }
    const score = pickScore(args, isHigh);
    users.push({
      tip_id: result.tip_id,
      tip_id_type: "personal",
      creator_name: creatorName,
      region,
      public_key: kp.publicKey,
      private_key: kp.privateKey,
      dedup_hash: result.dedup_hash,
      target_score: score,
      jury_eligible: isHigh,
    });
    console.log(`✓ ${result.tip_id}  → score ${score}`);
  }

  console.log(`▸ Waiting for consensus to commit + propagate to ${reachableUrls.length} reachable node(s)...`);
  for (const u of users) {
    process.stdout.write(`  ${u.tip_id} `);
    const ok = await confirmOnReachableNodes(u.tip_id, reachableUrls);
    if (!ok) throw new Error(`identity ${u.tip_id} did not appear on reachable nodes within 90s`);
    console.log("✓");
  }

  const outFile = path.join(TEMP_USERS_DIR, `temp-users-${nowIso().replace(/[:.]/g, "-")}.json`);
  const payload = {
    created_at: nowIso(),
    vp_id: vpId,
    regions: args.regions,
    note: "DEV-ONLY temp users. Private keys included — never commit. Wipe genesis-data/temp-users/ before sharing.",
    config: { count: args.count, highPct: args.highPct, highBand: [args.highMin, args.highMax], lowBand: [args.lowMin, args.lowMax], regions: args.regions },
    users,
  };
  fs.writeFileSync(outFile, JSON.stringify(payload, null, 2));
  fs.writeFileSync(OUT_LATEST, JSON.stringify(payload, null, 2));
  console.log(`▸ Wrote ${outFile} (${users.length} keypairs)`);
  console.log(`▸ Wrote ${OUT_LATEST} (latest pointer)`);

  // Per-user .tip.json backups — same format as genesis-data/backups/
  // (the VP app's identity-export format). Kept in temp-users/keys/ rather
  // than the genesis backups/ directory so the genesis ring stays clearly
  // separated from dev-fixture identities. Filename mirrors the existing
  // pattern: tip-id-<region>-<hex>.tip.json.
  fs.mkdirSync(TEMP_USERS_KEYS_DIR, { recursive: true });
  const toFileName = (id) => id.replace(/[^a-zA-Z0-9-]/g, "-").replace(/-+/g, "-") + ".tip.json";
  for (const u of users) {
    const tipBackup = {
      v: 1,
      type: "identity",
      name: u.creator_name || `Temp user ${u.tip_id.slice(-8)}`,
      tip_id: u.tip_id,
      tip_id_type: u.tip_id_type || "personal",
      ...(u.creator_name ? { creator_name: u.creator_name } : {}),
      public_key: u.public_key,
      private_key: u.private_key,
      created: payload.created_at,
    };
    fs.writeFileSync(
      path.join(TEMP_USERS_KEYS_DIR, toFileName(u.tip_id)),
      JSON.stringify(tipBackup, null, 2),
      { mode: 0o600 },
    );
  }
  console.log(`▸ Wrote ${users.length} per-user .tip.json files to ${TEMP_USERS_KEYS_DIR}/`);

  if (!args.skipScoreBump) {
    console.log(`▸ Bumping scores in all ${NODES.length} postgres DBs (test-only path)...`);
    bumpScoresInAllDBs(users.map(u => ({ tip_id: u.tip_id, score: u.target_score })));
    console.log("");
    console.log("⚠ Restart all nodes so the in-memory mirror re-hydrates from DB:");
    console.log("    docker restart tip-node");
    console.log("    # plus restart local node-2..5 processes");
    console.log("");
    console.log(`After restart: ${nHigh} jury-eligible identities will be available + ${nLow} below-threshold for negative-test coverage.`);
  } else {
    console.log("");
    console.log(`Done — ${users.length} identities registered at score 500 (INITIAL_IDENTITY).`);
    console.log("Re-run without --no-score-bump to apply the score distribution.");
  }
}

// snarkjs (used by generateDedupProof) leaves background WASM workers /
// file-descriptor handles open after groth16.fullProve finishes, so node
// won't auto-exit when main() resolves — it just sits at an idle event
// loop until you Ctrl+C. Force-exit on completion to avoid that.
main()
  .then(() => process.exit(0))
  .catch(err => { console.error("FAILED:", err.message); process.exit(1); });
