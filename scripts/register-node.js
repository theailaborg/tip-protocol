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
 *   --name "My Node"             Node name (default: "TIP Node {N}")
 *   --node-url http://host:4000  API endpoint to register against (default: http://localhost:4000)
 *   --out-dir ./path             Override output directory
 *                                (default: ./generated_nodes/<slug>-<short-tip-id>/)
 *   --port 4100                  API port for the new node (default: 4100)
 *   --p2p-port 4101              libp2p port for the new node (default: api-port + 1)
 *   --public-ip 127.0.0.1        Publicly-reachable IP (default: 127.0.0.1)
 *   --db-name tip_node2          Per-node DB name override (optional; defaults to DB_NAME from env)
 *   --db-user tip_node2          Per-node DB user override (optional; Oracle nodes need tip_node2/3/4)
 *
 * Output layout:
 *   generated_nodes/<slug>-<short-tip-id>/
 *     ├── <slug>.env             Drop-in env file (use with --env-file=); no inline keys
 *     ├── <node-id>.tip.json     Keypair (mode 0600); node reads it via TIP_NODE_CREDENTIALS_FILE
 *     └── data/                  Per-node data dir (created on first run)
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

const { nowIso } = require("../shared/time");

const {
  initCrypto,
  generateMLDSAKeypair,
  generateNodeId,
  signBody,
} = require("../shared/crypto");

const { renderEnvFromExample } = require("./node-env-template");

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
// Accept both `--flag value` (space-separated) and `--flag=value` forms.
// The `=` form is what most users reach for and was being silently
// dropped by the previous space-only parser.
function getArg(name, fallback) {
  const eqHit = args.find(a => a.startsWith(`${name}=`));
  if (eqHit) return eqHit.slice(name.length + 1);
  const idx = args.indexOf(name);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
}

const nodeName = getArg("--name", null); // auto-generated if not provided
const nodeUrl = getArg("--node-url", "http://localhost:4000");
// Out-dir is resolved AFTER registration so the path can include the
// auto-generated tip-id suffix. `--out-dir` is now an explicit override
// for operators who want a specific path; otherwise it lands under
// generated_nodes/<slug>-<short-id>/.
const outDirOverride = getArg("--out-dir", null);
const apiPort = parseInt(getArg("--port", "4100"), 10);   // API port for the new node
const p2pPort = parseInt(getArg("--p2p-port", String(apiPort + 1)), 10);   // libp2p port; convention is API+1
const publicIp = getArg("--public-ip", "127.0.0.1");      // override for prod / cloud deployments
const dbNameOverride = getArg("--db-name", null);         // per-node DB name (optional)
const dbUserOverride = getArg("--db-user", null);         // per-node DB user (optional; needed for Oracle)
const forceHalted = args.includes("--force");              // allow registration against a halted node

/** Slugify a display name into a filesystem-safe identifier. */
function slugify(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "node";
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────
function post(url, body, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === "https:" ? https : http;
    const payload = JSON.stringify(body);
    const req = lib.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload), ...extraHeaders },
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
  // founding-vp-keys.json uses the multi-entry envelope: { v:1, type, entries:[{tag, public_key, private_key, ...}] }.
  // Look up the primary VP entry by tag rather than reading flat top-level fields.
  const vpKeysFile = path.resolve(__dirname, "../genesis-data/founding-vp-keys.json");
  if (!fs.existsSync(vpKeysFile)) {
    fail("founding-vp-keys.json not found — run seed script first");
    process.exit(1);
  }
  const vpKeysFile_parsed = JSON.parse(fs.readFileSync(vpKeysFile, "utf8"));
  const vpEntry = vpKeysFile_parsed?.entries?.find(e => e.tag === "primary-vp");
  if (!vpEntry?.public_key || !vpEntry?.private_key) {
    fail("founding-vp-keys.json missing primary-vp entry — re-run seed script");
    process.exit(1);
  }
  // Map the envelope's snake_case fields to the camelCase shape the rest of the
  // script expects (vpKeys.publicKey / vpKeys.privateKey).
  const vpKeys = { publicKey: vpEntry.public_key, privateKey: vpEntry.private_key };
  ok("Founding VP keys loaded");

  // 2. Check target node is healthy
  info(`Target node: ${nodeUrl}`);
  let health;
  try {
    health = await get(`${nodeUrl}/health`);
    const healthData = health.data || health;
    if (healthData.status !== "ok") {
      if (forceHalted && healthData.status === "halted") {
        info(`Node halted (--force) — tx will queue until peers join. DAG: ${healthData.dag_count} txs`);
      } else {
        throw new Error(`Node unhealthy: ${healthData.status}`);
      }
    } else {
      ok(`Node healthy — DAG: ${healthData.dag_count} txs`);
    }
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
    algorithm: "ml-dsa-65",
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
    const postHeaders = forceHalted ? { "x-bootstrap-force": "1" } : {};
    const response = await post(`${nodeUrl}/v1/node/register`, {
      ...registrationFields,
      council_signature: councilSignature,
    }, postHeaders);
    result = response.data || response;
    ok(`Node registered: ${result.node_id}`);
    label("Name", result.name);
    label("Confirmation", result.confirmation || "registered");
  } catch (err) {
    fail(`Registration failed: ${err.message}`);
    if (err.data) console.error("  ", JSON.stringify(err.data, null, 2));
    process.exit(1);
  }

  // 7. Resolve output directory now that we have a tip-id.
  // Default layout: ./generated_nodes/<slug>-<short-id>/  — keeps every
  // generated node in one place and stops fresh runs from clobbering each
  // other when the operator forgets to pass --out-dir.
  const slug = slugify(name);
  const shortId = String(result.node_id || "")
    .replace(/^tip:\/\/node\//, "")
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(0, 12) || "unknown";
  const outDir = path.resolve(outDirOverride || `./generated_nodes/${slug}-${shortId}`);
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
  // The node reads both keys from this .tip.json via TIP_NODE_CREDENTIALS_FILE,
  // so the generated .env never inlines the secret.
  const tipFileRel = path.relative(process.cwd(), path.join(outDir, tipFileName));

  // Pull the target node's bootstrap multiaddr so the new node can dial it
  // immediately on startup. Falls back to a placeholder if /health didn't
  // include one (e.g. node started without TIP_PUBLIC_IP set on a pre-#48
  // build) — operator has to fill it in by hand in that case.
  const bootstrapAddr =
    (health && health.data && health.data.p2p && health.data.p2p.bootstrap_addr) ||
    (health && health.p2p && health.p2p.bootstrap_addr) ||
    "";
  if (bootstrapAddr) ok(`Bootstrap multiaddr: ${bootstrapAddr}`);
  else fail(`Could not read bootstrap_addr from ${nodeUrl}/health — set TIP_BOOTSTRAP_PEERS manually after generation`);

  // Per-node data dir lives inside the generated node directory so each
  // generated node keeps its DB + keystore self-contained. The path is
  // recorded relative to the project root because that's where the node
  // is meant to be launched from.
  const dataDirRel = `./${path.relative(process.cwd(), path.join(outDir, "data"))}`;
  // Per-node log dir at the top-level `./logs/<slug>-<short-id>` — matches
  // the existing convention used by docker-compose (`./logs/node-1`) and
  // by the founding `.env`. Without an explicit TIP_LOG_DIR, the logger
  // defaults to `node/logs/` which every generated node would share,
  // clobbering each other's per-process log streams. Each node's own
  // sub-directory keeps debug.log / info.log / error.log unambiguous.
  const logDirRel = `./logs/${slug}-${shortId}`;
  const envFileName = `${slug}.env`;
  const envPath = path.join(outDir, envFileName);
  const envRelForLaunch = path.relative(process.cwd(), envPath);

  // Collect DB settings from the current environment (loaded by dotenv above).
  // DB_NAME may be overridden per-node via --db-name; all other settings are
  // inherited from the seed node's environment so the new node uses the same DB.
  const dbDriver = process.env.DB_DRIVER || "";
  const dbHost = process.env.DB_HOST || "";
  const dbPort = process.env.DB_PORT || "";
  const dbName = dbNameOverride || process.env.DB_NAME || "";
  const dbUser = dbUserOverride || process.env.DB_USER || "";
  const dbPassword = process.env.DB_PASSWORD || "";
  const dbSsl = process.env.DB_SSL || "";
  const dbSslRejectUnauthorized = process.env.DB_SSL_REJECT_UNAUTHORIZED || "";
  const dbPoolMin = process.env.DB_POOL_MIN || "";
  const dbPoolMax = process.env.DB_POOL_MAX || "";

  // Operational config carried from the seed node's env (media, classifier,
  // prescan, rate-limit, dev) so a new node matches it. Not consensus-critical.
  const mediaBackend = process.env.TIP_MEDIA_BACKEND || "";
  const mediaFsPath = process.env.TIP_MEDIA_FS_PATH || "";
  const mediaPresignTtl = process.env.TIP_MEDIA_PRESIGN_TTL_SEC || "";
  const mediaS3Bucket = process.env.TIP_MEDIA_S3_BUCKET || "";
  const mediaS3Region = process.env.TIP_MEDIA_S3_REGION || "";
  const mediaS3Kms = process.env.TIP_MEDIA_S3_KMS_KEY_ID || "";
  const classifierUrl = process.env.TIP_CLASSIFIER_URL || "";
  const classifierFb = process.env.TIP_CLASSIFIER_FALLBACK || "";
  const prescanConc = process.env.TIP_PRESCAN_CONCURRENCY || "";
  const rateLimitMax = process.env.TIP_RATE_LIMIT_MAX || "";
  const devForceTier = process.env.TIP_DEV_FORCE_PRESCAN_TIER || "";
  const vpId = process.env.TIP_VP_ID || "";
  const databaseUrl = process.env.DATABASE_URL || "";
  const cryptoPool = process.env.TIP_CRYPTO_POOL_SIZE || "";
  const classifierKey = process.env.TIP_CLASSIFIER_KEY || "";
  const classifierScan = process.env.TIP_CLASSIFIER_SCAN_NON_OH || "";
  const prescanWorker = process.env.TIP_PRESCAN_WORKER_COUNT || "";
  const rateLimitWin = process.env.TIP_RATE_LIMIT_WINDOW_MS || "";
  const apiEndpoint = process.env.TIP_API_ENDPOINT || "";

  // Drop-in .env from .env.example + the values we know. Blank carried values
  // (u -> undefined) keep the example default. See node-env-template.js.
  const u = (x) => (x === "" || x === undefined || x === null ? undefined : x);
  const envContent = renderEnvFromExample({
    TIP_NODE_ID: result.node_id,
    PORT: apiPort,
    TIP_P2P_PORT: p2pPort,
    TIP_PUBLIC_IP: publicIp,
    TIP_BOOTSTRAP_PEERS: u(bootstrapAddr),
    TIP_ENABLE_MDNS: "false",
    TIP_DATA_DIR: dataDirRel,
    TIP_DB_PATH: `${dataDirRel}/tip.db`,
    TIP_LOG_DIR: logDirRel,
    TIP_PUBLIC_URL: `http://localhost:${apiPort}`,
    TIP_NODE_CREDENTIALS_FILE: tipFileRel,
    DB_DRIVER: u(dbDriver) || "postgres",
    DB_HOST: u(dbHost) || "postgres",
    DB_PORT: u(dbPort) || "5432",
    DB_NAME: u(dbName) || "tip_protocol",
    DB_USER: u(dbUser) || "tip",
    DB_PASSWORD: u(dbPassword) || "secret",
    DB_SSL: u(dbSsl), DB_SSL_REJECT_UNAUTHORIZED: u(dbSslRejectUnauthorized),
    DB_POOL_MIN: u(dbPoolMin), DB_POOL_MAX: u(dbPoolMax),
    TIP_VP_ID: u(vpId), DATABASE_URL: u(databaseUrl), TIP_CRYPTO_POOL_SIZE: u(cryptoPool),
    TIP_MEDIA_BACKEND: u(mediaBackend), TIP_MEDIA_FS_PATH: u(mediaFsPath),
    TIP_MEDIA_PRESIGN_TTL_SEC: u(mediaPresignTtl), TIP_MEDIA_S3_BUCKET: u(mediaS3Bucket),
    TIP_MEDIA_S3_REGION: u(mediaS3Region), TIP_MEDIA_S3_KMS_KEY_ID: u(mediaS3Kms),
    TIP_CLASSIFIER_URL: u(classifierUrl), TIP_CLASSIFIER_KEY: u(classifierKey),
    TIP_CLASSIFIER_FALLBACK: u(classifierFb), TIP_CLASSIFIER_SCAN_NON_OH: u(classifierScan),
    TIP_PRESCAN_CONCURRENCY: u(prescanConc), TIP_PRESCAN_WORKER_COUNT: u(prescanWorker),
    TIP_RATE_LIMIT_MAX: u(rateLimitMax), TIP_RATE_LIMIT_WINDOW_MS: u(rateLimitWin),
    TIP_API_ENDPOINT: u(apiEndpoint),
    TIP_DEV_FORCE_PRESCAN_TIER: u(devForceTier),
  }, {
    headerNotes: [
      `${name}`,
      `Generated by register-node.js on ${nowIso()}`,
      `Drop-in usable: node --env-file=${envRelForLaunch} node/src/index.js`,
    ],
  });
  fs.writeFileSync(envPath, envContent, { mode: 0o600 });
  ok(`Env file: ${outDir}/${envFileName}`);

  // 8. Print setup instructions
  const envRel = envRelForLaunch;
  const dataRel = path.relative(process.cwd(), path.join(outDir, "data"));
  console.log();
  console.log(`${T.bold}  Setup for the new node:${T.reset}`);
  console.log();
  console.log(`  1. ${T.bold}Seed the data dir${T.reset} from a known-good peer:`);
  console.log(`       ${T.cyan}rm -rf ${dataRel} && cp -r data ${dataRel}${T.reset}`);
  console.log(`     (a fresh node can't auto-sync the registry yet)`);
  console.log();
  console.log(`  2. ${T.bold}Start the node${T.reset} from the project root:`);
  console.log(`       ${T.cyan}node --env-file=${envRel} node/src/index.js${T.reset}`);
  console.log();
  console.log(`  3. ${T.bold}Verify${T.reset} it joined the federation:`);
  console.log(`       ${T.cyan}curl -s http://localhost:${apiPort}/health | jq '.data.peers'${T.reset}`);
  console.log(`     Should show ${T.cyan}peer_count >= 1${T.reset} once the bootstrap dial completes (~5s).`);
  console.log();
  label("Node ID", result.node_id);
  label("Name", name);
  label("API port", apiPort);
  label("P2P port", p2pPort);
  label("Bootstrap", bootstrapAddr || "(none — fill in TIP_BOOTSTRAP_PEERS manually)");
  label("Output dir", outDir);
  console.log();
}

main().catch(err => {
  fail(`FAILED: ${err.message}`);
  if (process.env.TIP_LOG_LEVEL === "debug") console.error(err.stack);
  process.exit(1);
});
