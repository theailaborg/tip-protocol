#!/usr/bin/env node
/**
 * @file scripts/register-node.js
 * @description Register a new node in the TIP network via the API.
 *
 * Generates a fresh ML-DSA-65 keypair, signs the registration with the
 * founding VP key, calls the node registration endpoint, and saves the
 * node credentials to a .tip.json backup file + .env file.
 *
 * Usage:
 *   node --experimental-vm-modules scripts/register-node.js [options]
 *
 * Options:
 *   --name "My Node"           Node name (default: "TIP Node {N}")
 *   --node-url http://host:4000  API endpoint (default: http://localhost:4000)
 *   --out-dir ./node2            Output directory for .env and .tip.json
 *
 * Prerequisites:
 *   - genesis-data/founding-vp-keys.json must exist (from seed script)
 *   - Target node must be running and healthy
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

try { require("dotenv").config(); } catch { /* dotenv optional */ }

const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");

const {
  initCrypto,
  generateMLDSAKeypair,
  generateNodeId,
  signBody,
} = require("../shared/crypto");

// ─── Terminal colors ──────────────────────────────────────────────────────────
const T = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m",
  yellow: "\x1b[33m",
};
const ok = (m) => console.log(`${T.green}  ✓${T.reset} ${m}`);
const fail = (m) => console.log(`${T.red}  ✗${T.reset} ${m}`);
const info = (m) => console.log(`${T.cyan}  ℹ${T.reset} ${m}`);
const label = (k, v) => console.log(`    ${T.dim}${k.padEnd(24)}${T.reset}${v}`);

// ─── CLI args ─────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
function getArg(name, fallback) {
  const idx = args.indexOf(name);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
}

const nodeName = getArg("--name", null); // auto-generated if not provided
const nodeUrl = getArg("--node-url", "http://localhost:4000");
const outDir = path.resolve(getArg("--out-dir", "./node2"));

// ─── HTTP helper ──────────────────────────────────────────────────────────────
function post(url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === "https:" ? https : http;
    const payload = JSON.stringify(body);
    const req = lib.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
    }, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(parsed);
          else reject(Object.assign(new Error(parsed.error || `HTTP ${res.statusCode}`), { status: res.statusCode, data: parsed }));
        } catch { reject(new Error(`Non-JSON response: ${data.slice(0, 200)}`)); }
      });
    });
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function get(url) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === "https:" ? https : http;
    lib.get(url, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error(`Non-JSON response: ${data.slice(0, 200)}`)); }
      });
    }).on("error", reject);
  });
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log();
  console.log(`${T.bold}  TIP Protocol — Register New Node${T.reset}`);
  console.log();

  // 1. Load founding VP keys (needed to sign the council_signature)
  const vpKeysFile = path.resolve(__dirname, "../genesis-data/founding-vp-keys.json");
  if (!fs.existsSync(vpKeysFile)) {
    fail("founding-vp-keys.json not found — run seed script first");
    process.exit(1);
  }
  const vpKeys = JSON.parse(fs.readFileSync(vpKeysFile, "utf8"));
  ok("Founding VP keys loaded");

  // 2. Check target node is healthy
  info(`Target node: ${nodeUrl}`);
  let health;
  try {
    health = await get(`${nodeUrl}/health`);
    const healthData = health.data || health;
    if (healthData.status !== "ok") throw new Error(`Node unhealthy: ${healthData.status}`);
    ok(`Node healthy — DAG: ${healthData.dag_count} txs`);
  } catch (err) {
    fail(`Cannot reach node: ${err.message}`);
    process.exit(1);
  }

  // 3. Get founding VP ID from genesis
  const { getFoundingVP } = require("../node/src/genesis");
  const foundingVpId = getFoundingVP().vp_id;
  if (!foundingVpId) {
    fail("Founding VP ID not found in genesis");
    process.exit(1);
  }
  ok(`Founding VP: ${foundingVpId}`);

  // 4. Initialize crypto and generate keypair
  await initCrypto();
  const keypair = generateMLDSAKeypair();
  const nodeId = generateNodeId(keypair.publicKey);
  const name = nodeName || `TIP Node ${nodeId.slice(-8)}`;
  ok(`Keypair generated: ${nodeId}`);

  // 5. Sign registration with founding VP key
  const registrationFields = {
    name,
    public_key: keypair.publicKey,
    approving_vp_id: foundingVpId,
  };
  const councilSignature = signBody(registrationFields, vpKeys.privateKey);
  ok("Council signature created");

  // 6. Register via API
  info("Registering node...");
  let result;
  try {
    const response = await post(`${nodeUrl}/v1/node/register`, {
      ...registrationFields,
      council_signature: councilSignature,
    });
    result = response.data || response;
    ok(`Node registered: ${result.node_id}`);
    label("Name", result.name);
    label("Confirmation", result.confirmation || "registered");
  } catch (err) {
    fail(`Registration failed: ${err.message}`);
    if (err.data) console.error("  ", JSON.stringify(err.data, null, 2));
    process.exit(1);
  }

  // 7. Save credentials
  fs.mkdirSync(outDir, { recursive: true });

  // .tip.json backup
  const tipJson = JSON.stringify({
    v: 1,
    type: "node",
    name,
    node_id: result.node_id,
    public_key: keypair.publicKey,
    private_key: keypair.privateKey,
    registered_at: result.registered_at,
    registered_on: nodeUrl,
  }, null, 2);
  const tipFileName = result.node_id.replace(/[^a-zA-Z0-9-]/g, "-").replace(/-+/g, "-") + ".tip.json";
  fs.writeFileSync(path.join(outDir, tipFileName), tipJson, { mode: 0o600 });
  ok(`Backup: ${outDir}/${tipFileName}`);

  // .env for the new node
  const envContent = [
    `# TIP Protocol — ${name}`,
    `# Generated by register-node.js on ${new Date().toISOString()}`,
    `# Copy this to the new node's .env file`,
    ``,
    `NODE_ENV=development`,
    `PORT=4000`,
    `HOST=0.0.0.0`,
    `TIP_NODE_TYPE=full`,
    `TIP_REGION=US`,
    `TIP_DATA_DIR=./data`,
    `TIP_DB_PATH=./data/tip.db`,
    `TIP_CORS_ORIGINS=*`,
    `TIP_LOG_LEVEL=info`,
    ``,
    `# ─── Node Identity ─────────────────────────────────────────────────────────`,
    `TIP_NODE_ID=${result.node_id}`,
    ``,
    `# ─── Node Keys (ML-DSA-65) ─────────────────────────────────────────────────`,
    `TIP_NODE_PRIVATE_KEY=${keypair.privateKey}`,
    `TIP_NODE_PUBLIC_KEY=${keypair.publicKey}`,
    ``,
  ].join("\n");
  fs.writeFileSync(path.join(outDir, ".env"), envContent, { mode: 0o600 });
  ok(`Env file: ${outDir}/.env`);

  // 8. Print setup instructions
  console.log();
  console.log(`${T.bold}  Setup instructions for the new node:${T.reset}`);
  console.log();
  console.log(`  1. Copy the project to the second laptop`);
  console.log(`  2. Copy ${T.cyan}${outDir}/.env${T.reset} → project root ${T.cyan}.env${T.reset}`);
  console.log(`  3. Copy ${T.cyan}data/tip.db${T.reset} from Node 1 → ${T.cyan}data/tip.db${T.reset} on Node 2`);
  console.log(`     (Node 2 needs the same DAG state including its own registration)`);
  console.log(`  4. Run: ${T.cyan}npm start${T.reset} (or docker compose up)`);
  console.log(`  5. mDNS auto-discovers Node 1 on the same WiFi`);
  console.log();
  label("Node ID", result.node_id);
  label("Name", name);
  label("Output dir", outDir);
  console.log();
}

main().catch(err => {
  fail(`FAILED: ${err.message}`);
  if (process.env.TIP_LOG_LEVEL === "debug") console.error(err.stack);
  process.exit(1);
});
