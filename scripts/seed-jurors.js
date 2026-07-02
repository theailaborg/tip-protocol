#!/usr/bin/env node
/**
 * @file scripts/seed-jurors.js
 * @description DEV-ONLY: Register a batch of temp-user key files as
 * juror-eligible personal identities on the local dev cluster.
 *
 * Prerequisites
 * ─────────────
 *   • genesis-data/founding-vp-keys.json + seed-output.json must exist.
 *   • Key files must be in genesis-data/temp-users/keys/.
 *
 * What it does
 * ────────────
 *   1. Registers each key file as a personal identity (real Groth16 proof).
 *   2. Enables juror_consent=true via become-juror endpoint.
 *   3. SQL-bumps scores to 750 across all 5 node DBs (above JURY.MIN_SCORE=700).
 *   4. After this script: restart all 5 nodes to reload the mirror.
 *
 * Usage
 * ─────
 *   node scripts/seed-jurors.js
 *   node scripts/seed-jurors.js --count 7   (default 7)
 *   node scripts/seed-jurors.js --node-url http://localhost:4000
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const { execSync } = require("child_process");
const fs   = require("fs");
const http = require("http");
const path = require("path");

const { initCrypto } = require("../shared/crypto");
const { nowMs }      = require("../shared/time");
const registerIdentitySchema = require("../node/src/schemas/register-identity");
const { generateDedupProof } = require("../shared/zk");
const updateProfileSchema    = require("../node/src/schemas/update-profile");

const REPO_ROOT    = path.resolve(__dirname, "..");
const KEYS_DIR     = path.join(REPO_ROOT, "genesis-data", "temp-users", "keys");
const VP_KEYS_FILE = path.join(REPO_ROOT, "genesis-data", "founding-vp-keys.json");
const SEED_OUT     = path.join(REPO_ROOT, "genesis-data", "seed-output.json");

const NODES_DBS  = ["tip_node1", "tip_node2", "tip_node3", "tip_node4", "tip_node5"];
const PG_CONTAINER = "tip-postgres";
const PG_USER      = "tipuser";
const PG_PASSWORD  = "Tip_Password_2025";


// ─── HTTP helpers ────────────────────────────────────────────────────────────
function httpReq(url, { method = "GET", body = null, timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = body ? JSON.stringify(body) : null;
    const headers = { Accept: "application/json" };
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + (u.search || ""), method, headers, timeout: timeoutMs },
      (res) => {
        let data = "";
        res.on("data", c => (data += c));
        res.on("end", () => {
          let parsed = null;
          try { parsed = JSON.parse(data); } catch { /* ignore */ }
          resolve({ status: res.statusCode, body: parsed });
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function get(url) { return httpReq(url, { method: "GET" }); }
async function post(url, body) { return httpReq(url, { method: "POST", body }); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── SQL helper ──────────────────────────────────────────────────────────────
function runSql(db, sql) {
  try {
    execSync(
      `docker exec -i -e PGPASSWORD=${PG_PASSWORD} ${PG_CONTAINER} psql -U ${PG_USER} -d ${db} -v ON_ERROR_STOP=1`,
      { input: sql, stdio: ["pipe", "pipe", "pipe"] }
    );
    return true;
  } catch (e) {
    const msg = e.stderr?.toString().split("\n")[0] || e.message;
    console.error(`  ✗ ${db}: ${msg}`);
    return false;
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  // ── CLI ──
  let count = 7;
  let nodeUrl = "http://localhost:4000";
  for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i];
    if (a === "--count")    count   = Number(process.argv[++i]);
    if (a === "--node-url") nodeUrl = process.argv[++i];
  }

  await initCrypto();

  // ── Load VP keys ──
  if (!fs.existsSync(VP_KEYS_FILE)) throw new Error("founding-vp-keys.json missing — run seed.js first");
  if (!fs.existsSync(SEED_OUT))     throw new Error("seed-output.json missing — run seed.js first");

  const vpFile  = JSON.parse(fs.readFileSync(VP_KEYS_FILE, "utf8"));
  const vpEntry = vpFile?.entries?.find(e => e.tag === "primary-vp");
  if (!vpEntry) throw new Error("primary-vp entry not found in founding-vp-keys.json");
  const vpKp = { publicKey: vpEntry.public_key, privateKey: vpEntry.private_key };

  const seedOut = JSON.parse(fs.readFileSync(SEED_OUT, "utf8"));
  const vpId    = seedOut?.founding_vps?.find(v => v.tag === "primary-vp")?.vp_id;
  if (!vpId) throw new Error("primary-vp vp_id not found in seed-output.json");

  // ── Pick key files ──
  const allKeyFiles = fs.readdirSync(KEYS_DIR)
    .filter(f => f.endsWith(".tip.json"))
    .slice(0, count);

  if (allKeyFiles.length === 0) throw new Error(`No .tip.json files found in ${KEYS_DIR}`);
  console.log(`\nSeed jurors: registering up to ${count} identities from ${KEYS_DIR}`);
  console.log(`Node: ${nodeUrl}\n`);

  // ── Poll until identity is confirmed in the DAG ──
  async function waitForIdentity(tipId, timeoutMs = 60000) {
    const deadline = nowMs() + timeoutMs;
    while (nowMs() < deadline) {
      const r = await get(`${nodeUrl}/v1/identity/${encodeURIComponent(tipId)}`);
      if (r.status === 200) return true;
      await sleep(1000);
    }
    return false;
  }

  // ── Register each identity ──
  const registered = [];

  for (let idx = 0; idx < allKeyFiles.length; idx++) {
    const fname = allKeyFiles[idx];
    const kf    = JSON.parse(fs.readFileSync(path.join(KEYS_DIR, fname), "utf8"));
    const tipId = kf.tip_id;

    // Extract region from tip_id: "tip://id/IN-c4cff70f4719d3e1" → "IN"
    const region = tipId.replace("tip://id/", "").split("-")[0] || "US";

    // Check if already registered and confirmed in DAG
    const check = await get(`${nodeUrl}/v1/identity/${encodeURIComponent(tipId)}`);
    if (check.status === 200) {
      console.log(`  ↳ ${tipId} — already confirmed, skipping registration`);
      registered.push(kf);
      continue;
    }

    // Real Groth16 proof; gov id derives from the pubkey so re-runs are
    // idempotent (same identity, same dedup_hash).
    const { dedup_hash, proof: zk_proof } =
      await generateDedupProof(`GOV-JUROR-${kf.public_key.slice(0, 24)}`, "1990-01-01", region);
    const idFields = {
      region,
      public_key:        kf.public_key,
      dedup_hash,
      zk_proof,
      verification_tier: "T1",
      vp_id:             vpId,
      social_attested:   false,
      tip_id_type:       "personal",
      creator_name:      `Juror-${region}-${tipId.slice(-6)}`,
    };

    const canonicalPayload = registerIdentitySchema.buildSigningPayload(idFields);
    const vp_signature     = registerIdentitySchema.sign(canonicalPayload, vpKp.privateKey);

    const res = await post(`${nodeUrl}/v1/identity/register`, { ...idFields, vp_signature });
    if (res.status >= 200 && res.status < 300) {
      const assignedId = res.body?.data?.tip_id || tipId;
      process.stdout.write(`  ✓ submitted ${assignedId} — waiting for DAG commit...`);
      const confirmed = await waitForIdentity(assignedId);
      if (confirmed) {
        console.log(" confirmed");
        registered.push({ ...kf, tip_id: assignedId });
      } else {
        console.log(" TIMEOUT — identity not in DAG after 60s");
      }
    } else {
      const errMsg = res.body?.error?.message || JSON.stringify(res.body).slice(0, 150);
      // "already registered" → tx committed in a prior run, just add to queue
      if (/already registered/i.test(errMsg)) {
        process.stdout.write(`  ↳ ${tipId} — tx already committed, waiting for DAG...`);
        const confirmed = await waitForIdentity(tipId);
        if (confirmed) { console.log(" confirmed"); registered.push(kf); }
        else console.log(" TIMEOUT");
      } else {
        console.error(`  ✗ ${tipId}: ${errMsg}`);
      }
    }
  }

  if (registered.length === 0) {
    console.error("\nNo identities confirmed in DAG. Check node health.");
    process.exit(1);
  }

  // ── Enable juror_consent for each ──
  console.log(`\nEnabling juror_consent...`);
  for (const kf of registered) {
    const tipId = kf.tip_id;

    const profileFields = { tip_id: tipId, juror_consent: true };
    const payload       = updateProfileSchema.buildSigningPayload(profileFields);
    const signature     = updateProfileSchema.sign(payload, kf.private_key);

    const res = await post(
      `${nodeUrl}/v1/identity/${encodeURIComponent(tipId)}/become-juror`,
      { signature }
    );

    if (res.status >= 200 && res.status < 300) {
      console.log(`  ✓ juror_consent=true → ${tipId}`);
    } else {
      const errMsg = res.body?.error?.message || JSON.stringify(res.body).slice(0, 150);
      console.error(`  ✗ become-juror failed for ${tipId}: ${errMsg}`);
    }

    await sleep(500);
  }

  // ── Boost scores via SQL (above JURY.MIN_SCORE=700) ──
  console.log(`\nBoosting scores to 750 across all 5 node DBs...`);
  const now = nowMs();
  const vals = registered.map(kf => `('${kf.tip_id.replace(/'/g, "''")}', 750, 0, ${now})`).join(",\n");
  const sql = `INSERT INTO scores (tip_id, score, offense_count, last_updated)
VALUES ${vals}
ON CONFLICT (tip_id) DO UPDATE SET score = EXCLUDED.score, last_updated = EXCLUDED.last_updated;`;

  for (const db of NODES_DBS) {
    if (runSql(db, sql)) console.log(`  ✓ ${db}`);
  }

  // ── Summary ──
  console.log(`\n✓ Done. ${registered.length} juror(s) seeded.`);
  console.log(`\nNext steps:`);
  console.log(`  1. Restart all nodes to reload the mirror:`);
  console.log(`       docker restart tip-node1 tip-node2 tip-node3 tip-node4 tip-node5`);
  console.log(`  2. Verify pool:`);
  console.log(`       curl -s ${nodeUrl}/v1/reviewers/pool | python3 -m json.tool`);
  console.log(`  3. Then: creator disputes → jury summoned → vote via VP + drive-jury.js`);
}

main().catch(err => {
  console.error("FATAL:", err.message || err);
  process.exit(1);
});
