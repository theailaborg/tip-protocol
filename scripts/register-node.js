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
 *                                (default: ./generated/<partner|slug-short-id>/node/)
 *   --partner SLUG               Partner folder shared with the org registration
 *   --port 4100                  API port for the new node (default: 4100)
 *   --p2p-port 4101              libp2p port for the new node (default: api-port + 1)
 *   --public-ip 127.0.0.1        Publicly-reachable IP (default: 127.0.0.1)
 *   --vp-file PATH               Founding VP .tip.json. Defaults to the VP in
 *                                genesis-data/backups (the LOCAL/TEST VP);
 *                                pass the mainnet VP explicitly for mainnet.
 *   --db-name tip_node2          Per-node DB name (default: tip_protocol)
 *   --db-user tip_node2          Per-node DB user (default: tip; Oracle nodes need tip_node2/3/4)
 *   --db-host postgres           DB host (default: postgres)
 *   --db-port 5432               DB port (default: 5432)
 *   --db-password ...            DB password (default: secret, the local-compose value)
 *   --public-url https://...     Public URL of the new node (default: http://localhost:<port>)
 *   --api-endpoint https://...   Endpoint the node announces on chain (default: unset)
 *   --classifier-url https://... Classifier base URL (default: the .env.example value)
 *   --cors-origins a,b           Allowed origins (default: the .env.example value)
 *   --production                 NODE_ENV=production and force an explicit CORS origin list
 *   --operated-by tip://id/...   Identity responsible for this node (optional)
 *   --operator-key-file ./x.json That identity's .tip.json; required with --operated-by,
 *                                since the operator must cosign the registration
 *
 * The generated .env is built from .env.example plus the flags above and
 * nothing else. It deliberately inherits no value from the operator's own
 * environment: this file is handed to other node operators, so an inherited
 * credential, bucket or tuning value would travel with it. Secrets
 * (TIP_CLASSIFIER_KEY, TIP_METRICS_TOKEN, DATABASE_URL, AWS_*) are set by hand
 * on the target host; node-env-template.js refuses to write them.
 *
 * Output layout:
 *   generated/<partner>/node/
 *     ├── <slug>.env             Drop-in env file (use with --env-file=); no inline keys
 *     ├── <node-id>.tip.json     Keypair (mode 0600); node reads it via TIP_NODE_CREDENTIALS_FILE
 *     └── data/                  Per-node data dir (created on first run)
 *
 * Prerequisites:
 *   - genesis-data/backups/ must hold the VP .tip.json (from seed script)
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
const { loadVpBackup } = require("./genesis-backups");

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
// See register-org.js: --partner groups this node run into the same
// generated/<partner>/ folder as the org it belongs to.
const partnerSlug = getArg("--partner", null);
// The identity responsible for this node. Naming one is a claim about a third
// party, so its keyfile is required too: the node registers only if that
// identity cosigns the same bytes the founding VP signs.
const operatedBy = getArg("--operated-by", null);
const operatorKeyFile = getArg("--operator-key-file", null);
const vpFile = getArg("--vp-file", null);
const apiPort = parseInt(getArg("--port", "4100"), 10);   // API port for the new node
const p2pPort = parseInt(getArg("--p2p-port", String(apiPort + 1)), 10);   // libp2p port; convention is API+1
const publicIp = getArg("--public-ip", "127.0.0.1");      // override for prod / cloud deployments
const dbNameOverride = getArg("--db-name", null);         // per-node DB name (optional)
const dbUserOverride = getArg("--db-user", null);         // per-node DB user (optional; needed for Oracle)
const forceHalted = args.includes("--force");              // allow registration against a halted node

// The generated .env is a function of .env.example plus these flags and nothing
// else. It reads nothing from the operator's own environment: this file is
// handed to other node operators, so anything inherited here travels with it,
// and a value that is right for our box is usually wrong or unsafe on theirs.
const dbHost = getArg("--db-host", "postgres");
const dbPort = getArg("--db-port", "5432");
const dbPassword = getArg("--db-password", "secret");
const classifierUrl = getArg("--classifier-url", null);
// Announced on chain by init-endpoint-announce, so it must never be inherited:
// a generated node would publish the generating machine's endpoint as its own.
const apiEndpoint = getArg("--api-endpoint", null);
const publicUrl = getArg("--public-url", null);
const corsOrigins = getArg("--cors-origins", null);
const isProduction = args.includes("--production");

/** Slugify a display name into a filesystem-safe identifier. */
function slugify(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "node";
}

// One README at the partner root explaining every credential type it may hold.
// Overwritten on each run so it always reflects the current layout.
function writePartnerReadme(partnerRoot) {
  const text = `# Partner credentials , handling rules

Everything for one partner lives under this directory.

## org/  (organization identity)
The .tip.json here IS the organization on the network: it signs content as them.
It is NOT needed to run a node. Keep it OFF the node host, with company signing
material. Mode 0600, never committed, never emailed in the clear.

## node/  (node identity + env)
The .tip.json here runs the node: it lives on the node host, read at boot
(mode 0600, owned by the container user). The .env is the node configuration ,
secrets (classifier key, metrics token) are filled by hand at bundle time, never
generated here.

## vp/  (verification provider , rarely present)
A VP key approves registrations. If one exists here, it is the most sensitive
file in this tree; it never leaves the registration machine.

Delivery: docs/REGISTRATION_AND_KEY_DISTRIBUTION.md section 5 , one AES-256 zip
via scripts/make-secure-bundle.sh, password over a separate channel.
`;
  fs.writeFileSync(path.join(partnerRoot, "README.md"), text);
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

  // 1. Load the founding VP keypair (signs the council_signature). Defaults to
  // genesis-data/backups, which on a dev machine is the LOCAL/TEST VP: mainnet
  // runs must pass --vp-file explicitly, same as register-org.js.
  let vpEntry;
  if (vpFile) {
    try { vpEntry = JSON.parse(fs.readFileSync(path.resolve(vpFile), "utf8")); }
    catch (e) { fail(`cannot read ${vpFile}: ${e.message}`); process.exit(1); }
    if (!vpEntry.private_key || !vpEntry.public_key) { fail(`${vpFile} is not a VP keypair file`); process.exit(1); }
  } else {
    try { vpEntry = loadVpBackup(); }
    catch (e) { fail(e.message); process.exit(1); }
    info("no --vp-file given, using the VP in genesis-data/backups (local/test VP)");
  }
  const vpKeys = { publicKey: vpEntry.public_key, privateKey: vpEntry.private_key };
  ok(`Founding VP keys loaded: ${vpEntry.vp_id || "(no vp_id field)"}`);

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
  // The council signature only verifies if the loaded key IS the chain's
  // founding VP; a mismatch would 403 server-side after signing, so stop here.
  if (vpEntry.vp_id && vpEntry.vp_id !== foundingVpId) {
    fail(`loaded VP key is ${vpEntry.vp_id} but the chain's founding VP is ${foundingVpId} , pass the right --vp-file`);
    process.exit(1);
  }

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
    ...(operatedBy ? { operated_by: operatedBy } : {}),
  };
  const councilSignature = signBody(registrationFields, vpKeys.privateKey);
  ok("Council signature created");

  // The operator signs the SAME fields as the VP, so the two attestations
  // cover identical bytes and the server can verify both against one payload.
  let operatorSignature = null;
  if (operatedBy) {
    if (!operatorKeyFile) {
      fail("--operated-by requires --operator-key-file (the operating identity's .tip.json)");
      process.exit(1);
    }
    const opKeys = JSON.parse(fs.readFileSync(path.resolve(operatorKeyFile), "utf8"));
    if (opKeys.tip_id && opKeys.tip_id !== operatedBy) {
      fail(`--operator-key-file is for ${opKeys.tip_id}, not ${operatedBy}`);
      process.exit(1);
    }
    operatorSignature = signBody(registrationFields, opKeys.private_key);
    ok(`Operator cosignature created: ${operatedBy}`);
  }

  // 6. Register via API
  info("Registering node...");
  let result;
  try {
    const postHeaders = forceHalted ? { "x-bootstrap-force": "1" } : {};
    const response = await post(`${nodeUrl}/v1/node/register`, {
      ...registrationFields,
      council_signature: councilSignature,
      ...(operatorSignature ? { operator_signature: operatorSignature } : {}),
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
  const partnerRoot = path.resolve(`./generated/${partnerSlug || `${slug}-${shortId}`}`);
  const outDir = path.resolve(outDirOverride || path.join(partnerRoot, "node"));
  fs.mkdirSync(outDir, { recursive: true });
  if (!outDirOverride) writePartnerReadme(partnerRoot);

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

  // Drop-in .env from .env.example + the values we know. Anything omitted here
  // keeps its .env.example default. See node-env-template.js.
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
    TIP_PUBLIC_URL: u(publicUrl) || `http://localhost:${apiPort}`,
    TIP_NODE_CREDENTIALS_FILE: tipFileRel,
    DB_DRIVER: "postgres",
    DB_HOST: dbHost,
    DB_PORT: dbPort,
    DB_NAME: dbNameOverride || "tip_protocol",
    DB_USER: dbUserOverride || "tip",
    DB_PASSWORD: dbPassword,
    TIP_CLASSIFIER_URL: u(classifierUrl),
    TIP_API_ENDPOINT: u(apiEndpoint),
    NODE_ENV: isProduction ? "production" : undefined,
    TIP_CORS_ORIGINS: u(corsOrigins)
      || (isProduction ? "CHANGE_ME_YOUR_CLIENT_ORIGINS_COMMA_SEPARATED" : undefined),
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
