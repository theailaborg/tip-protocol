#!/usr/bin/env node
/**
 * @file tip-protocol/scripts/seed.js
 * @description Production Seed Script — End-to-End Genesis Block and DAG Bootstrap
 *
 * This script:
 *   1. Generates founding VP keypair + member keypairs, embeds in genesis
 *   2. Mints and signs the Genesis Block (signed by founding VP)
 *   3. Registers The AI Lab as the founding Verification Provider
 *   3b. Registers the seed node in the DAG + writes keys to .env
 *   4. Registers founding identities (Genesis Ring)
 *   5. Registers sample content (dev only, skipped in production)
 *   6. Verifies the full DAG state
 *   7. Writes seed output files
 *
 * USAGE:
 *   # Full seed (generates everything from scratch):
 *   node --experimental-vm-modules scripts/seed.js
 *
 *   # Skip sample content:
 *   node --experimental-vm-modules scripts/seed.js --no-sample-content
 *
 *   # Seed against a running node via REST API:
 *   node --experimental-vm-modules scripts/seed.js --node-url http://localhost:4000
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
  mldsaSign,
  shake256,
  shake256Multi,
  generateTIPID,
  generateVPId,
  generateNodeId,
  generateCTID,
  hashContent,
  perceptualHashText,
  signBody,
  computeTxId,
  canonicalTx,
  canonicalJson,
} = require("../shared/crypto");

const { TX_TYPES, ORIGIN, ORIGIN_LABELS, PROTOCOL } = require("../shared/constants");
const PC = require("../shared/protocol-constants");
const {
  GENESIS_TX_ID,
  GENESIS_TIMESTAMP,
  GENESIS_CHAIN_ID,
  buildGenesisBlock,
  computeGenesisHash,
  GENESIS_PAYLOAD,
  getGenesisPayload,
} = require("../node/src/genesis");
// Init protocol constants before any module that uses backward-compat
// accessors (initDAG → scoring → ...) is required.
PC.init(getGenesisPayload().protocol_constants);
const { getTier } = PC;
const { initDAG } = require("../node/src/dag");
const { initScoring } = require("../node/src/scoring");
const { loadConfig } = require("../node/src/config");
const registerIdentitySchema = require("../node/src/schemas/register-identity");

// ─── Terminal colors ──────────────────────────────────────────────────────────
const T = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", blue: "\x1b[34m", yellow: "\x1b[33m",
  red: "\x1b[31m", cyan: "\x1b[36m", gold: "\x1b[33m", grey: "\x1b[90m",
  bgNavy: "\x1b[44m", white: "\x1b[37m",
};

const ok = (m) => console.log(`${T.green}  ✓${T.reset} ${m}`);
const warn = (m) => console.log(`${T.yellow}  ⚠${T.reset} ${m}`);
const info = (m) => console.log(`${T.cyan}  ℹ${T.reset} ${m}`);
const label = (k, v) => console.log(`    ${T.dim}${k.padEnd(28)}${T.reset}${v}`);
const sep = () => console.log(`${T.dim}  ${"─".repeat(62)}${T.reset}`);
const head = (t) => { sep(); console.log(`  ${T.bold}${T.gold}${t}${T.reset}`); sep(); };

// ─── CLI args ─────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const skipSampleContent = args.includes("--no-sample-content") || process.env.NODE_ENV === "production";
const nodeUrl = args.find(a => a.startsWith("--node-url="))?.split("=")[1] || "http://localhost:4000";
const useDirectMode = args.includes("--direct") || !args.includes("--node-url");

const DATA_DIR = path.resolve(__dirname, "../genesis-data");
const GENESIS_FILE = path.join(DATA_DIR, "genesis.json");
const SEED_FILE = path.join(DATA_DIR, "seed-output.json");

// ─── Cached-entries envelope ────────────────────────────────────────────────
// All dev-only keys files (founding-vp-keys.json, founding-node-keys.json,
// founder-keys.json) use the same multi-entry envelope so n=1 today and
// n=N tomorrow share one code path. seed-output.json adopts the same plural
// arrays + `v` field for forward compat. genesis.json stays on its current
// shape — see issues.md "Protocol/Shared #16" for the deferred refactor.
//
// Envelope shape:
//   { v: 1, type: "<kind>", created_at, security_notice, entries: [{tag, ...}] }
//
// Each entry is keyed by `tag` (stable handle, e.g. "primary-vp", "founder",
// "cofounder-tushar"). Cross-references between files use the tag (e.g. a
// founding-node entry's `approving_vp_tag` points at a founding-vp entry).
const ENVELOPE_VERSION = 1;
const KEYS_FILE_TYPES = Object.freeze({
  VPS: "founding-vps",
  NODES: "founding-nodes",
  IDENTITIES: "founding-identities",
});

function loadCachedEntries(filePath, expectedType) {
  if (!fs.existsSync(filePath)) return null;
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(filePath, "utf8")); }
  catch (e) {
    warn(`${path.basename(filePath)} present but unreadable (${e.message}) — regenerating`);
    return null;
  }
  if (parsed.v !== ENVELOPE_VERSION || parsed.type !== expectedType) {
    warn(`${path.basename(filePath)} has unexpected shape (v=${parsed.v}, type=${parsed.type}) — regenerating`);
    return null;
  }
  if (!Array.isArray(parsed.entries)) {
    warn(`${path.basename(filePath)} missing entries[] — regenerating`);
    return null;
  }
  return new Map(parsed.entries.map(e => [e.tag, e]));
}

function writeCachedEntries(filePath, type, entries) {
  const envelope = {
    v: ENVELOPE_VERSION,
    type,
    created_at: new Date().toISOString(),
    security_notice: "HIGHLY SENSITIVE. Keep offline. Never commit to version control.",
    entries,
  };
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(envelope, null, 2), { mode: 0o600 });
}

// ─── HTTP helper (wraps Node.js http/https) ────────────────────────────────────
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
        } catch { reject(new Error(`Non-JSON response: ${data.slice(0, 100)}`)); }
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
        catch { reject(new Error(`Non-JSON response: ${data.slice(0, 100)}`)); }
      });
    }).on("error", reject);
  });
}

// ─── Founding members definition ─────────────────────────────────────────────
// `tip_id_type` is signed into the genesis_ring_keys VP signature so the
// type is cryptographically attested at bootstrap, not just inferred.
// `tag` is the stable lookup key for founder-keys.json — adding a new
// member with a fresh tag generates a fresh keypair on next seed; existing
// tags reuse cached keypairs so tip_ids stay stable across re-seeds.
const FOUNDING_MEMBERS = [
  { name: "The AI Lab Intelligence Unobscured, Inc.", role: "Founding Organization", region: "US", tag: "ai-lab", tip_id_type: "organization" },
  { name: "Dinesh Mendhe — Founder",   role: "Founder & Sole Inventor",     region: "US", tag: "founder",         tip_id_type: "personal" },
  { name: "Tushar Bhendarkar — Co-Founder", role: "Co-Founder & Core Engineer", region: "US", tag: "cofounder-tushar", tip_id_type: "personal" },
  { name: "Vishal — Co-Founder",       role: "Co-Founder & Core Engineer",  region: "US", tag: "cofounder-vishal", tip_id_type: "personal" },
];

// Keypairs generated in Step 2, used in Step 5
let _foundingKeypairs = []; // [{ member, keypair, tipId }]

// ─── Step 1: Generate founding VP + member keypairs and embed in genesis ─────
async function embedFoundingVPKey() {
  head("STEP 1: Founding VP & Member Keypairs → Genesis Payload");

  const vpKeysFile = path.join(DATA_DIR, "founding-vp-keys.json");
  const VP_TAG = "primary-vp";

  let vpKeypair;
  const cachedVps = loadCachedEntries(vpKeysFile, KEYS_FILE_TYPES.VPS);
  const cachedVp = cachedVps?.get(VP_TAG);
  if (cachedVp?.public_key && cachedVp?.private_key) {
    warn(`founding-vp-keys.json already exists — reusing keypair for tag "${VP_TAG}"`);
    vpKeypair = {
      algorithm: "ML-DSA-65",
      publicKey: cachedVp.public_key,
      privateKey: cachedVp.private_key,
    };
    label("Public key (first 32 chars)", vpKeypair.publicKey.slice(0, 32) + "...");
  } else {
    info("Generating ML-DSA-65 keypair for founding VP...");
    vpKeypair = generateMLDSAKeypair();
    writeCachedEntries(vpKeysFile, KEYS_FILE_TYPES.VPS, [{
      tag: VP_TAG,
      name: "The AI Lab Intelligence Unobscured, Inc.",
      region: "US",
      id: generateVPId("US", vpKeypair.publicKey),
      public_key: vpKeypair.publicKey,
      private_key: vpKeypair.privateKey,
      created_at: new Date().toISOString(),
    }]);
    ok("Founding VP keypair generated and saved");
    warn("SECURITY: founding-vp-keys.json is chmod 600. NEVER commit to git.");
  }

  // Embed public key into genesis.js and genesis.py source files
  const genesisJsFile = path.resolve(__dirname, "../node/src/genesis.js");
  const genesisPyFile = path.resolve(__dirname, "../python/tip_node/genesis.py");

  for (const file of [genesisJsFile, genesisPyFile]) {
    let src = fs.readFileSync(file, "utf8");
    if (src.includes(vpKeypair.publicKey)) {
      info(`${path.basename(file)} already has the correct VP public key`);
    } else {
      // Replace placeholder or any existing key (hex string in quotes after public_key)
      src = src.replace(
        /(public_key['":\s]+)["']([a-f0-9]+|GENESIS_VP_PUBLIC_KEY_PLACEHOLDER)["']/,
        `$1"${vpKeypair.publicKey}"`
      );
      fs.writeFileSync(file, src);
      ok(`Embedded VP public key in ${path.basename(file)}`);
    }
  }

  // Compute and embed founding VP ID from public key
  const vpId = generateVPId("US", vpKeypair.publicKey);
  for (const file of [genesisJsFile, genesisPyFile]) {
    let src = fs.readFileSync(file, "utf8");
    // Replace any existing vp_id value (hardcoded or previously generated)
    src = src.replace(
      /(vp_id['":\s]+)["'][^"']+["']/,
      `$1"${vpId}"`
    );
    fs.writeFileSync(file, src);
  }
  ok(`Embedded VP ID: ${vpId}`);

  // Generate (or reuse) founding member keypairs and compute TIP-IDs for
  // genesis_ring. Cache file (founder-keys.json) uses the multi-entry
  // envelope (see ENVELOPE_VERSION + KEYS_FILE_TYPES near top of file).
  // Lookup is by `tag` so adding a member to FOUNDING_MEMBERS later only
  // generates a fresh key for that one tag; existing tags stay stable.
  const founderKeysFile = path.join(DATA_DIR, "founder-keys.json");
  const cachedFounders = loadCachedEntries(founderKeysFile, KEYS_FILE_TYPES.IDENTITIES);
  if (!cachedFounders) info("Generating founding member keypairs...");
  else warn(`founder-keys.json already exists — reusing ${cachedFounders.size} keypair(s) by tag`);

  _foundingKeypairs = FOUNDING_MEMBERS.map(member => {
    const cached = cachedFounders?.get(member.tag);
    let keypair;
    if (cached?.private_key && cached?.public_key) {
      keypair = { algorithm: "ML-DSA-65", privateKey: cached.private_key, publicKey: cached.public_key };
    } else {
      if (cachedFounders) info(`  ↳ no cached key for tag "${member.tag}" — generating fresh`);
      keypair = generateMLDSAKeypair();
    }
    const tipId = generateTIPID(member.region, keypair.publicKey);
    return { member, keypair, tipId };
  });
  const genesisRing = _foundingKeypairs.map(fk => fk.tipId);
  ok(`${cachedFounders ? "Loaded" : "Generated"} ${genesisRing.length} founding member keypairs`);

  // Embed genesis_ring (TIP-IDs) into genesis source files
  const ringJson = JSON.stringify(genesisRing);
  // JS: genesis_ring: [...]
  let jsSrc = fs.readFileSync(genesisJsFile, "utf8");
  jsSrc = jsSrc.replace(/genesis_ring:\s*\[.*?\]/s, `genesis_ring: ${ringJson}`);
  fs.writeFileSync(genesisJsFile, jsSrc);
  // Python: "genesis_ring": [...]
  let pySrc = fs.readFileSync(genesisPyFile, "utf8");
  pySrc = pySrc.replace(/"genesis_ring":\s*\[.*?\]/s, `"genesis_ring": ${ringJson}`);
  fs.writeFileSync(genesisPyFile, pySrc);
  ok("Embedded genesis_ring (founding TIP-IDs) in genesis source files");

  // Embed genesis_ring_keys (public keys + dedup hashes + VP signatures for initDAG)
  const ringKeys = _foundingKeypairs.map(({ member, keypair, tipId }) => {
    const dedupHash = shake256Multi("seed", member.name, member.region).replace(/[^0-9]/g, "").slice(0, 20) || "12345678901234567890";
    const tipIdType = member.tip_id_type || "personal";
    // creator_name attested for organizations (so the VP-vouched display
    // name persists on the identity row). Personal members keep null.
    const creatorName = tipIdType === "organization" ? member.name : null;
    const idFields = {
      region: member.region, public_key: keypair.publicKey, dedup_hash: dedupHash,
      zk_proof: { pi_a: ["1", "2", "3"], pi_b: [["1", "2"], ["3", "4"], ["5", "6"]], pi_c: ["1", "2", "3"], protocol: "groth16", curve: "bn128" },
      verification_tier: "T1", vp_id: vpId, social_attested: true,
      tip_id_type: tipIdType,
      ...(creatorName ? { creator_name: creatorName } : {}),
    };
    // Sign via the canonical-payload schema — same model as the API and
    // commit-handler use, so the embedded signature would re-verify
    // identically if any future path checks it. Deterministic so re-seeds
    // produce byte-identical bytes → genesis_ring_keys hash stays stable
    // → GENESIS_HASH stays stable.
    const canonicalPayload = registerIdentitySchema.buildSigningPayload(idFields);
    const vpSignature = registerIdentitySchema.sign(canonicalPayload, vpKeypair.privateKey, { deterministic: true });
    return {
      tip_id: tipId,
      region: member.region.toUpperCase(),
      public_key: keypair.publicKey,
      dedup_hash: dedupHash,
      tip_id_type: tipIdType,
      ...(creatorName ? { creator_name: creatorName } : {}),
      vp_signature: vpSignature,
    };
  });
  jsSrc = fs.readFileSync(genesisJsFile, "utf8");
  jsSrc = jsSrc.replace(/genesis_ring_keys:\s*\[.*?\]/s, `genesis_ring_keys: ${JSON.stringify(ringKeys)}`);
  fs.writeFileSync(genesisJsFile, jsSrc);
  ok("Embedded genesis_ring_keys (public keys + VP signatures) in genesis.js");

  // Clear Node.js require cache so genesis.js is re-read with updated key + ring
  const genesisModule = require.resolve("../node/src/genesis");
  delete require.cache[genesisModule];
  Object.keys(require.cache).forEach(key => {
    if (key.includes("genesis")) delete require.cache[key];
  });

  // Compute and embed bootstrap tx signatures (founding VP signs both)
  // Re-read genesis module with the updated VP key + genesis_ring
  const freshGenesis = require("../node/src/genesis");

  // Bootstrap tx signatures are embedded in genesis.js source (GENESIS_TX_SIGNATURE
  // / GENESIS_VP_TX_SIGNATURE) — they're consumed at every node boot when the DAG
  // re-plays the bootstrap txs. Deterministic so re-seeds produce byte-identical
  // signatures and don't drift from the genesis hash baked at network birth.
  const SIG_DET = { deterministic: true };
  const genesisTxSig = mldsaSign(canonicalTx(freshGenesis.GENESIS_TX), vpKeypair.privateKey, SIG_DET);
  // Sign VP registration tx (same structure as initDAG builds)
  const vpTxBody = {
    tx_type: "VP_REGISTERED",
    timestamp: freshGenesis.GENESIS_TIMESTAMP,
    prev: [freshGenesis.GENESIS_TX_ID, freshGenesis.GENESIS_TX_ID],
    data: {
      vp_id: freshGenesis.GENESIS_PAYLOAD.founding_vp.vp_id,
      name: freshGenesis.GENESIS_PAYLOAD.founding_vp.name,
      jurisdiction: freshGenesis.GENESIS_PAYLOAD.founding_vp.jurisdiction,
      jurisdiction_tier: freshGenesis.GENESIS_PAYLOAD.founding_vp.jurisdiction_tier,
      public_key: vpKeypair.publicKey,
    },
  };
  const vpTxSig = mldsaSign(canonicalTx(vpTxBody), vpKeypair.privateKey, SIG_DET);

  // Embed signatures in genesis.js
  let gSrc = fs.readFileSync(genesisJsFile, "utf8");
  gSrc = gSrc.replace(
    /GENESIS_TX_SIGNATURE\s*=\s*"[^"]*"/,
    `GENESIS_TX_SIGNATURE = "${genesisTxSig}"`
  );
  gSrc = gSrc.replace(
    /GENESIS_VP_TX_SIGNATURE\s*=\s*"[^"]*"/,
    `GENESIS_VP_TX_SIGNATURE = "${vpTxSig}"`
  );
  fs.writeFileSync(genesisJsFile, gSrc);
  ok("Bootstrap tx signatures embedded in genesis.js");

  // Clear require cache again so subsequent steps read updated signatures
  Object.keys(require.cache).forEach(key => {
    if (key.includes("genesis")) delete require.cache[key];
  });

  label("VP public key embedded", vpKeypair.publicKey.slice(0, 32) + "...");
  return vpKeypair;
}

// ─── Step 3: Mint the Genesis Block ──────────────────────────────────────────
async function mintGenesisBlock(vpKeypair) {
  head("STEP 2: Minting Genesis Block");

  // Re-read genesis module after VP key embedding (cache was cleared)
  const updatedGenesis = require("../node/src/genesis");
  const updatedPayload = updatedGenesis.GENESIS_PAYLOAD;

  if (fs.existsSync(GENESIS_FILE)) {
    info("genesis.json already exists — validating...");
    const existing = JSON.parse(fs.readFileSync(GENESIS_FILE, "utf8"));
    const expectedHash = updatedGenesis.computeGenesisHash(updatedPayload);
    if (existing.genesis_hash === expectedHash) {
      ok(`Genesis block valid. Hash: ${T.cyan}${existing.genesis_hash.slice(0, 32)}...${T.reset}`);
      return existing;
    } else {
      // Key may have changed — delete stale genesis.json and re-mint
      warn("genesis.json hash mismatch (VP key changed?) — re-minting...");
      fs.unlinkSync(GENESIS_FILE);
    }
  }

  info("Computing genesis hash...");
  const genesisHash = updatedGenesis.computeGenesisHash(updatedPayload);
  label("Genesis hash", genesisHash.slice(0, 32) + "...");
  label("Chain ID", GENESIS_CHAIN_ID);
  label("Protocol version", PROTOCOL.version);
  label("Timestamp", GENESIS_TIMESTAMP);
  label("Issuer", PROTOCOL.issuer);

  info("Signing genesis block with founding VP key...");
  // Outer block signature — deterministic so the file written to genesis.json
  // is reproducible across re-seeds (same key + same genesis_hash → same sig).
  const signature = mldsaSign(genesisHash, vpKeypair.privateKey, { deterministic: true });
  ok("Signature computed");

  const genesisBlock = {
    ...updatedPayload,
    genesis_hash: genesisHash,
    canonical_hash: shake256(canonicalJson(updatedPayload)),
    signed_at: new Date().toISOString(),
    signer_public_key: vpKeypair.publicKey,
    signature,
    environment: "production",
    build_info: {
      node_version: process.version,
      platform: process.platform,
      seed_script: "scripts/seed.js",
    },
  };

  fs.writeFileSync(GENESIS_FILE, JSON.stringify(genesisBlock, null, 2));
  ok(`Genesis block written to: ${GENESIS_FILE}`);
  ok(`${T.bold}Genesis hash: ${T.cyan}${genesisHash}${T.reset}`);

  return genesisBlock;
}

// ─── Direct-mode DAG setup ──────────────────────────────────────────────────
let _dag = null, _scoring = null, _nodeKp = null;

function initDirectDAG() {
  process.env.ZK_SKIP_VERIFY = "true";

  // Reuse the founding-node keypair across re-seeds the same way we cache
  // the VP and founder member keys. The node's public key is embedded in
  // genesis.js as `founding_node`, so a fresh keypair would shift node_id
  // → shift the founding_node blob → shift the genesis hash. Reading the
  // cached file keeps the genesis hash stable across re-seeds.
  // The companion .tip.json in genesis-data/backups/ is still written at
  // the end of seed.js; that's the operator-facing distribution copy.
  const nodeKeysFile = path.join(DATA_DIR, "founding-node-keys.json");
  const NODE_TAG = "primary-node";
  const cachedNodes = loadCachedEntries(nodeKeysFile, KEYS_FILE_TYPES.NODES);
  const cachedNode = cachedNodes?.get(NODE_TAG);
  if (cachedNode?.public_key && cachedNode?.private_key) {
    _nodeKp = {
      algorithm: "ML-DSA-65",
      publicKey: cachedNode.public_key,
      privateKey: cachedNode.private_key,
    };
    warn(`founding-node-keys.json already exists — reusing keypair for tag "${NODE_TAG}"`);
  } else {
    _nodeKp = generateMLDSAKeypair();
    writeCachedEntries(nodeKeysFile, KEYS_FILE_TYPES.NODES, [{
      tag: NODE_TAG,
      name: "The AI Lab TIP Node",
      id: generateNodeId(_nodeKp.publicKey),
      public_key: _nodeKp.publicKey,
      private_key: _nodeKp.privateKey,
      created_at: new Date().toISOString(),
      // approving_vp_tag references the matching entry in founding-vp-keys.json
      approving_vp_tag: "primary-vp",
    }]);
    ok("Founding node keypair generated and saved to founding-node-keys.json");
  }

  const cfg = loadConfig();
  // In-memory DAG: seed.js only uses the DAG as scratch space to validate
  // the genesis state shape; the canonical outputs (founder-keys.json,
  // founding-vp-keys.json, genesis.json, seed-output.json + genesis.js
  // patch) are written directly. The runtime `_writeGenesisBlock`
  // (dag.js) re-bootstraps the DB from those embedded values on first
  // `npm start`, so no on-disk seed.db is needed.
  cfg.dbPath = ":memory:";
  cfg.nodePrivateKey = _nodeKp.privateKey;
  cfg.nodePublicKey = _nodeKp.publicKey;

  _dag = initDAG(cfg);
  _scoring = initScoring(_dag, cfg);

  ok("Direct-mode DAG initialized (in-memory)");
}

function _withTxId(txBody) {
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

// ─── Step 4: Register The AI Lab as founding VP ───────────────────────────────
async function registerFoundingVP(vpKeypair) {
  head("STEP 3: Register The AI Lab Verification Provider");

  // Re-read genesis (top-level getFoundingVP import has stale GENESIS_PAYLOAD)
  const freshGenesis = require("../node/src/genesis");
  const foundingVP = freshGenesis.getFoundingVP();

  info(`Registering VP: ${foundingVP.name}`);
  label("Jurisdiction tier", foundingVP.jurisdiction_tier);
  label("URL", foundingVP.url);

  let vpRecord;

  if (useDirectMode) {
    // initDAG already bootstrapped the founding VP — update with real key
    vpRecord = _dag.getVP(foundingVP.vp_id);
    if (!vpRecord) throw new Error("Founding VP not found in DAG after bootstrap");
    _dag.saveVP({ ...vpRecord, public_key: vpKeypair.publicKey });
    vpRecord = _dag.getVP(foundingVP.vp_id);
    ok("Founding VP updated in DAG (direct mode)");
  } else {
    try {
      const vpFields = {
        name: foundingVP.name, jurisdiction_tier: foundingVP.jurisdiction_tier,
        public_key: vpKeypair.publicKey, approving_vp_id: foundingVP.vp_id,
      };
      vpRecord = await post(`${nodeUrl}/v1/vp/register`, {
        ...vpFields, council_signature: signBody(vpFields, vpKeypair.privateKey),
      });
      ok("Founding VP registered via API");
    } catch (e) {
      warn(`API registration failed: ${e.message}`);
      throw e;
    }
  }

  label("VP ID", vpRecord.vp_id);
  label("Status", vpRecord.status);

  return { vpRecord, vpKeypair };
}

// ─── Step 4b: Register seed node ─────────────────────────────────────────────
async function registerSeedNode(vpKeypair) {
  info("Registering seed node in DAG...");

  if (!useDirectMode || !_dag) {
    warn("Node registration requires direct mode with DAG — skipping");
    return null;
  }

  const nodeId = generateNodeId(_nodeKp.publicKey);
  const registeredAt = new Date().toISOString();
  const nodeName = "The AI Lab TIP Node";

  const freshGenesis = require("../node/src/genesis");
  const vpId = freshGenesis.getFoundingVP().vp_id;
  const nodeFields = { name: nodeName, public_key: _nodeKp.publicKey, approving_vp_id: vpId };
  // council_signature is embedded into founding_node inside GENESIS_PAYLOAD →
  // it must be deterministic for genesis_hash to be stable across re-seeds.
  const councilSig = signBody(nodeFields, vpKeypair.privateKey, { deterministic: true });

  const nodeTxBody = {
    tx_type: TX_TYPES.NODE_REGISTERED,
    timestamp: registeredAt,
    prev: _dag.getRecentPrev(),
    data: {
      node_id: nodeId,
      name: nodeName,
      public_key: _nodeKp.publicKey,
      council_signature: councilSig,
      approving_vp_id: vpId,
    },
  };
  const signedTx = _withTxId(nodeTxBody);
  _dag.addTx(signedTx);
  _dag.saveNode({
    node_id: nodeId,
    name: nodeName,
    public_key: _nodeKp.publicKey,
    status: "active",
    registered_at: registeredAt,
  });

  // Write node keys to .env
  const envFile = path.resolve(__dirname, "../.env");
  if (fs.existsSync(envFile)) {
    let envSrc = fs.readFileSync(envFile, "utf8");
    envSrc = envSrc.replace(/TIP_NODE_PRIVATE_KEY=.*/, `TIP_NODE_PRIVATE_KEY=${_nodeKp.privateKey}`);
    envSrc = envSrc.replace(/TIP_NODE_PUBLIC_KEY=.*/, `TIP_NODE_PUBLIC_KEY=${_nodeKp.publicKey}`);
    // Default log level to `warn` so a freshly-seeded founding node doesn't
    // flood the operator's terminal with INFO chatter from every batch /
    // anchor / rotation. Operators can still set debug/info manually.
    // Only rewrites if the line already exists; appended below if missing.
    envSrc = envSrc.replace(/TIP_LOG_LEVEL=.*/, "TIP_LOG_LEVEL=warn");
    envSrc = envSrc.replace(/TIP_CONSOLE_LEVEL=.*/, "TIP_CONSOLE_LEVEL=warn");
    fs.writeFileSync(envFile, envSrc);
    ok("Node keys + log levels written to .env");
  }

  // Embed founding node in genesis.js so initDAG can bootstrap it on any node
  const genesisJsFile = path.resolve(__dirname, "../node/src/genesis.js");
  const foundingNodeData = { node_id: nodeId, name: nodeName, public_key: _nodeKp.publicKey, council_signature: councilSig, approving_vp_id: vpId };
  let gSrc = fs.readFileSync(genesisJsFile, "utf8");
  gSrc = gSrc.replace(/founding_node:\s*(?:null|{[^}]*})/s, `founding_node: ${JSON.stringify(foundingNodeData)}`);
  fs.writeFileSync(genesisJsFile, gSrc);
  ok("Embedded founding node in genesis.js");

  // Clear require cache so subsequent steps (mintGenesisBlock, verifyDAGState)
  // see the just-embedded founding_node when they re-read genesis.js. Without
  // this, the genesis hash bakes against `founding_node=null` and the STEP 6
  // verification (which clears cache itself) computes a different hash.
  Object.keys(require.cache).forEach(key => {
    if (key.includes("genesis")) delete require.cache[key];
  });

  ok(`Seed node registered: ${nodeId}`);
  label("Node ID", nodeId);
  return { nodeId, name: nodeName, publicKey: _nodeKp.publicKey };
}

// ─── Step 5: Create founding identities (Genesis Ring) ───────────────────────
async function createGenesisRing(vpRecord, vpKeypair) {
  head("STEP 4: Creating Genesis Ring (Founding Identities)");

  const identities = [];

  for (const { member, keypair, tipId } of _foundingKeypairs) {

    // Seed uses mock proof — production would call generateDedupProof() from shared/zk.js
    const mockDedupHash = shake256Multi("seed", member.name, member.region).replace(/[^0-9]/g, "").slice(0, 20) || "12345678901234567890";
    const mockZkProof = { pi_a: ["1", "2", "3"], pi_b: [["1", "2"], ["3", "4"], ["5", "6"]], pi_c: ["1", "2", "3"], protocol: "groth16", curve: "bn128" };

    let regResult;

    if (useDirectMode) {
      // VP signs the canonical 9-field payload (schemas/register-identity).
      // tip_id_type + creator_name are signed so the type is cryptographically
      // attested at genesis, not just inferred.
      const memberType = member.tip_id_type || "personal";
      const memberCreatorName = memberType === "organization" ? member.name : null;
      const idFields = {
        region: member.region, public_key: keypair.publicKey,
        dedup_hash: mockDedupHash, zk_proof: mockZkProof,
        verification_tier: "T1", vp_id: vpRecord.vp_id, social_attested: true,
        tip_id_type: memberType,
        ...(memberCreatorName ? { creator_name: memberCreatorName } : {}),
      };
      const canonicalPayload = registerIdentitySchema.buildSigningPayload(idFields);
      const vpSignature = registerIdentitySchema.sign(canonicalPayload, vpKeypair.privateKey);

      const registeredAt = new Date().toISOString();
      const txBody = {
        tx_type: TX_TYPES.REGISTER_IDENTITY,
        timestamp: registeredAt,
        prev: _dag.getRecentPrev(),
        data: {
          tip_id: tipId,
          region: member.region.toUpperCase(),
          public_key: keypair.publicKey,
          vp_id: vpRecord.vp_id,
          verification_tier: "T1",
          tip_id_type: memberType,
          creator_name: memberCreatorName,
          social_attested: true,
          founding: true,
          dedup_hash: mockDedupHash,
          zk_proof: mockZkProof,
          vp_signature: vpSignature,
        },
      };
      const signedTx = _withTxId(txBody);
      const tx = _dag.addTx(signedTx);

      _dag.saveIdentity({
        tip_id: tipId,
        region: member.region.toUpperCase(),
        public_key: keypair.publicKey,
        vp_id: vpRecord.vp_id,
        verification_tier: "T1",
        tip_id_type: memberType,
        creator_name: memberCreatorName,
        founding: true,
        status: "active",
        registered_at: registeredAt,
        tx_id: tx.tx_id,
      });
      _dag.addDedupHash(mockDedupHash, Math.floor(new Date(registeredAt).getTime() / 1000));
      _dag.setScore(tipId, 550, 0, registeredAt);

      regResult = {
        tip_id: tipId,
        public_key: keypair.publicKey,
        private_key: keypair.privateKey,
        score: 550,
        registered_at: registeredAt,
        vp_id: vpRecord.vp_id,
        tx_id: tx.tx_id,
      };
    } else {
      try {
        const memberType = member.tip_id_type || "personal";
        const memberCreatorName = memberType === "organization" ? member.name : null;
        const idFields = {
          region: member.region, public_key: keypair.publicKey,
          dedup_hash: mockDedupHash, zk_proof: mockZkProof,
          verification_tier: "T1", vp_id: vpRecord.vp_id, social_attested: true,
          tip_id_type: memberType,
          ...(memberCreatorName ? { creator_name: memberCreatorName } : {}),
        };
        const canonicalPayload = registerIdentitySchema.buildSigningPayload(idFields);
        const vpSignature = registerIdentitySchema.sign(canonicalPayload, vpKeypair.privateKey);

        regResult = await post(`${nodeUrl}/v1/identity/register`, {
          ...idFields, vp_signature: vpSignature,
        });
      } catch (e) {
        warn(`API registration failed for ${member.name}: ${e.message}`);
        regResult = {
          tip_id: tipId,
          public_key: keypair.publicKey,
          private_key: keypair.privateKey,
          score: 550,
          registered_at: new Date().toISOString(),
          vp_id: vpRecord.vp_id,
        };
      }
    }

    const memberType = member.tip_id_type || "personal";
    const identity = {
      tag: member.tag,
      name: member.name,
      role: member.role,
      tip_id: regResult.tip_id,
      tip_id_type: memberType,
      creator_name: memberType === "organization" ? member.name : null,
      public_key: keypair.publicKey,
      private_key: keypair.privateKey,  // Stored in seed output — replace with real keys in production
      founding: true,
      score: regResult.score || 550,
      registered_at: regResult.registered_at,
    };

    identities.push(identity);
    ok(`  ${T.bold}${member.name}${T.reset}`);
    label("    TIP-ID", identity.tip_id);
    label("    Score", `${identity.score} / 1000 (${getTier(identity.score).label})`);
    label("    Role", member.role);
  }

  info(`Genesis Ring: ${identities.length} founding members created`);
  return identities;
}

// ─── Step 6: Register sample content (all four origin types) ──────────────────
async function registerSampleContent(identities) {
  head("STEP 5: Registering Sample Content (All Origin Types)");

  const author = identities.find(i => i.tag === "founder");
  if (!author) { warn("No founder identity found — skipping content registration"); return []; }

  const samples = [
    {
      origin: ORIGIN.OH,
      title: "TIP™ Protocol — Why the Internet Needs a Trust Layer",
      content: "The internet was built without an identity layer. HTTP, TCP/IP, DNS, and TLS solve routing, delivery, naming, and encryption. But none of them answer the fundamental question: who created this content, and can I trust it? This was an acceptable gap when content creation required skill and equipment. It is an existential gap now that AI can generate indistinguishable text, images, video, and audio at near-zero marginal cost. TIP™ is the protocol layer that closes this gap.",
    },
    {
      origin: ORIGIN.AA,
      title: "AI-Assisted: Post-Quantum Cryptography Overview",
      content: "Post-quantum cryptography refers to cryptographic algorithms that are secure against attacks by quantum computers. The NIST post-quantum standardisation process has selected ML-DSA-65 (Dilithium), SLH-DSA-128s (SPHINCS+), and ML-KEM-768 (Kyber) as the primary algorithms. TIP™ Protocol mandates these algorithms at the protocol level, ensuring long-term security. [This introduction was drafted by the author and expanded with AI assistance for clarity and completeness.]",
    },
    {
      origin: ORIGIN.AG,
      title: "AI-Generated: Frequently Asked Questions about TIP™",
      content: "Q: What is TIP™? A: TIP™ (Trust Identity Protocol) is an open, federated protocol for verifying human identity and declaring content provenance. Q: Is TIP™ free? A: Yes — the protocol specification is CC-BY 4.0 and free for everyone. Q: How does the trust score work? A: Scores are computed deterministically from your complete transaction history on the federated DAG. [This FAQ was generated entirely by AI from the protocol specification.]",
    },
    {
      origin: ORIGIN.MX,
      title: "Mixed: TIP™ Launch Announcement",
      content: "We are pleased to announce the launch of TIP™ Protocol v2.0. [Human-written announcement] This release includes five critical security and compliance fixes addressing privacy architecture, pre-scan calibration, identity revocation, GDPR compliance, and jurisdiction tier enforcement. [AI-generated technical summary] The cryptographic foundation uses NIST-standardised post-quantum algorithms. [Human-written conclusion] We invite developers, journalists, and researchers to implement TIP™ and join the founding network.",
    },
  ];

  const registered = [];

  for (const sample of samples) {
    const contentHash = hashContent(sample.content);
    const ctid = generateCTID(sample.origin, contentHash, author.tip_id);

    const ctFields = { author_tip_id: author.tip_id, origin_code: sample.origin, content_hash: contentHash };
    const signature = signBody(ctFields, author.private_key);

    let result;

    if (useDirectMode) {
      const registeredAt = new Date().toISOString();
      const perceptHash = perceptualHashText(sample.content);

      const contentTxBody = {
        tx_type: TX_TYPES.REGISTER_CONTENT,
        timestamp: registeredAt,
        prev: _dag.getRecentPrev(),
        data: {
          ctid,
          origin_code: sample.origin,
          origin_label: ORIGIN_LABELS[sample.origin],
          content_hash: contentHash,
          perceptual_hash: perceptHash,
          author_tip_id: author.tip_id,
          signature,
          prescan_flagged: false,
          prescan_probability: 0,
        },
      };
      const signedContentTx = _withTxId(contentTxBody);
      const tx = _dag.addTx(signedContentTx);

      _dag.saveContent({
        ctid,
        origin_code: sample.origin,
        content_hash: contentHash,
        perceptual_hash: perceptHash,
        author_tip_id: author.tip_id,
        status: "verified",
        registered_at: registeredAt,
        tx_id: tx.tx_id,
      });

      result = {
        ctid,
        origin_code: sample.origin,
        origin_label: ORIGIN_LABELS[sample.origin],
        content_hash: contentHash,
        author_tip_id: author.tip_id,
        status: "verified",
        registered_at: registeredAt,
        tx_id: tx.tx_id,
      };
    } else {
      try {
        result = await post(`${nodeUrl}/v1/content/register`, {
          ...ctFields,
          content: sample.content,
          signature,
        });
      } catch (e) {
        warn(`Content registration failed for ${sample.origin}: ${e.message}`);
        result = { ctid, origin_code: sample.origin, status: "local-only" };
      }
    }

    registered.push({ ...sample, ctid: result.ctid, status: result.status });
    ok(`  ${T.bold}${ORIGIN_LABELS[sample.origin]}${T.reset} — ${sample.title.slice(0, 45)}...`);
    label("    CTID", result.ctid);
    label("    Status", result.status);
  }

  return registered;
}

// ─── Step 7: Full DAG verification ────────────────────────────────────────────
async function verifyDAGState(genesisBlock, vpRecord, vpKeypair, identities, content) {
  head("STEP 6: DAG State Verification");

  const checks = [];
  const { mldsaVerify, verifyTxId } = require("../shared/crypto");

  // Genesis hash integrity (use fresh require — top-level imports have stale payload)
  Object.keys(require.cache).forEach(key => { if (key.includes("genesis")) delete require.cache[key]; });
  const updatedGenesis = require("../node/src/genesis");
  const expectedHash = updatedGenesis.computeGenesisHash(updatedGenesis.GENESIS_PAYLOAD);
  checks.push({
    name: "Genesis block hash",
    pass: genesisBlock.genesis_hash === expectedHash,
    detail: `${genesisBlock.genesis_hash.slice(0, 32)}...`,
  });

  // Genesis signature — real verification
  const sigValid = mldsaVerify(genesisBlock.genesis_hash, genesisBlock.signature, genesisBlock.signer_public_key);
  checks.push({
    name: "Genesis signature verified",
    pass: sigValid,
    detail: sigValid ? "ML-DSA-65 valid" : "INVALID",
  });

  // Chain ID
  checks.push({
    name: "Chain ID",
    pass: genesisBlock.chain_id === GENESIS_CHAIN_ID || genesisBlock.protocol?.chain_id === GENESIS_CHAIN_ID,
    detail: GENESIS_CHAIN_ID,
  });

  // Founding VP
  checks.push({
    name: "Founding VP registered",
    pass: !!vpRecord && !!vpRecord.vp_id,
    detail: vpRecord?.vp_id || "MISSING",
  });

  // VP public key matches genesis
  const genesisVpKey = updatedGenesis.GENESIS_PAYLOAD.founding_vp.public_key;
  checks.push({
    name: "VP key matches genesis payload",
    pass: (vpRecord.public_key || vpKeypair.publicKey) === genesisVpKey,
    detail: genesisVpKey ? genesisVpKey.slice(0, 24) + "..." : "MISSING",
  });

  // DAG tx count (direct mode)
  if (_dag) {
    const txCount = _dag.count();
    checks.push({
      name: "DAG transaction count",
      pass: txCount >= 2 + identities.length + content.length,
      detail: `${txCount} txs (expected >= ${2 + identities.length + content.length})`,
    });

    // Verify each identity exists in DAG
    let idOk = 0;
    for (const id of identities) {
      const rec = _dag.getIdentity(id.tip_id);
      if (rec && rec.status === "active") idOk++;
    }
    checks.push({
      name: "Identities in DAG",
      pass: idOk === identities.length,
      detail: `${idOk} / ${identities.length}`,
    });

    // Verify each content exists in DAG
    let ctOk = 0;
    for (const c of content) {
      const rec = _dag.getContent(c.ctid);
      if (rec) ctOk++;
    }
    checks.push({
      name: "Content in DAG",
      pass: ctOk === content.length,
      detail: `${ctOk} / ${content.length}`,
    });

    // Verify tx_ids are content-addressed
    const allTxs = _dag.getAllTxs();
    let txIdOk = 0;
    for (const tx of allTxs) {
      if (verifyTxId(tx)) txIdOk++;
    }
    checks.push({
      name: "All tx_ids content-addressed",
      pass: txIdOk === allTxs.length,
      detail: `${txIdOk} / ${allTxs.length}`,
    });
  }

  // Genesis ring
  checks.push({
    name: "Genesis ring size",
    pass: identities.length >= 2,
    detail: `${identities.length} founding members`,
  });

  // Sample content
  checks.push({
    name: "All four origin types registered",
    pass: content.length === 4,
    detail: content.map(c => c.origin).join(", "),
  });

  // TIP-ID format check
  const badIds = identities.filter(i => !i.tip_id.startsWith("tip://id/"));
  checks.push({
    name: "TIP-ID format valid",
    pass: badIds.length === 0,
    detail: badIds.length === 0 ? "All valid" : `Invalid: ${badIds.map(i => i.tip_id).join(", ")}`,
  });

  // CTID format check
  const badCtids = content.filter(c => c.ctid && !/^tip:\/\/c\/(OH|AA|AG|MX)-/.test(c.ctid));
  checks.push({
    name: "CTID format valid",
    pass: badCtids.length === 0,
    detail: badCtids.length === 0 ? "All valid" : `Invalid: ${badCtids.map(c => c.ctid).join(", ")}`,
  });

  // Node health check (only in API mode)
  if (!useDirectMode) {
    try {
      const health = await get(`${nodeUrl}/health`);
      checks.push({
        name: "Node health",
        pass: health.status === "ok",
        detail: `DAG transactions: ${health.dag_count}`,
      });
      checks.push({
        name: "Node DAG non-empty",
        pass: health.dag_count > 0,
        detail: `${health.dag_count} transactions`,
      });
    } catch (e) {
      checks.push({ name: "Node health", pass: false, detail: e.message });
    }
  }

  console.log();
  let allPass = true;
  for (const check of checks) {
    const icon = check.pass ? `${T.green}✓${T.reset}` : `${T.red}✗${T.reset}`;
    const color = check.pass ? T.reset : T.red;
    console.log(`  ${icon} ${check.name.padEnd(36)} ${T.dim}${check.detail}${T.reset}`);
    if (!check.pass) allPass = false;
  }
  console.log();

  return allPass;
}

// ─── Step 8: Write seed output ────────────────────────────────────────────────
async function writeSeedOutput(genesisBlock, vpRecord, vpKeypair, identities, content, seedNode) {
  head("STEP 7: Writing Seed Output");

  // Observer-facing summary. Plural arrays everywhere so n=1 today and
  // n=N tomorrow share one shape. Private keys live in the gitignored
  // founding-{vp,node,founder}-keys.json files, never in this output.
  const output = {
    v: 2,
    seed_version: require("../package.json").version,
    created_at: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    genesis: {
      hash: genesisBlock.genesis_hash,
      chain_id: GENESIS_CHAIN_ID,
      timestamp: GENESIS_TIMESTAMP,
      signer_pk: genesisBlock.signer_public_key,
    },
    founding_vps: [{
      tag: "primary-vp",
      vp_id: vpRecord.vp_id,
      name: vpRecord.name,
      region: "US",
      jurisdiction_tier: vpRecord.jurisdiction_tier,
      public_key: vpRecord.public_key || vpKeypair.publicKey,
    }],
    founding_nodes: seedNode ? [{
      tag: "primary-node",
      node_id: seedNode.nodeId,
      name: seedNode.name,
      public_key: seedNode.publicKey,
      approving_vp_tag: "primary-vp",
    }] : [],
    founding_identities: identities.map(i => ({
      tag: i.tag,
      tip_id: i.tip_id,
      tip_id_type: i.tip_id_type || "personal",
      name: i.name,
      role: i.role,
      region: "US",
      vp_tag: "primary-vp",
      founding: true,
      score: i.score,
      registered_at: i.registered_at,
      ...(i.creator_name ? { creator_name: i.creator_name } : {}),
    })),
    sample_content: content.map(c => ({
      origin: c.origin,
      origin_label: ORIGIN_LABELS[c.origin],
      title: c.title,
      ctid: c.ctid,
      status: c.status,
    })),
  };

  // Write non-sensitive seed output
  fs.writeFileSync(SEED_FILE, JSON.stringify(output, null, 2));
  ok(`Seed output written to: ${SEED_FILE}`);

  // Write founder private keys using the multi-entry envelope. VP keys are
  // intentionally NOT duplicated here — they live in founding-vp-keys.json.
  // Loaders that need VP keys read that file directly.
  const keysOutputFile = path.join(DATA_DIR, "founder-keys.json");
  writeCachedEntries(keysOutputFile, KEYS_FILE_TYPES.IDENTITIES, identities.map(i => ({
    tag: i.tag,
    tip_id: i.tip_id,
    tip_id_type: i.tip_id_type || "personal",
    name: i.name,
    role: i.role,
    region: "US",
    vp_tag: "primary-vp",
    public_key: i.public_key,
    private_key: i.private_key,
    created_at: i.registered_at || new Date().toISOString(),
    ...(i.creator_name ? { creator_name: i.creator_name } : {}),
  })));
  ok(`Founder keys written to: ${keysOutputFile} (chmod 600)`);

  // Write .tip.json backup files (same format as VP app's download)
  const backupDir = path.join(DATA_DIR, "backups");
  if (fs.existsSync(backupDir)) {
    for (const f of fs.readdirSync(backupDir)) {
      if (f.endsWith(".tip.json")) fs.unlinkSync(path.join(backupDir, f));
    }
  }
  fs.mkdirSync(backupDir, { recursive: true });

  const toFileName = (id) => id.replace(/[^a-zA-Z0-9-]/g, "-").replace(/-+/g, "-") + ".tip.json";

  // Founding identity backups
  for (const identity of identities) {
    const tipJson = JSON.stringify({
      v: 1,
      type: "identity",
      name: identity.name,
      tip_id: identity.tip_id,
      tip_id_type: identity.tip_id_type || "personal",
      ...(identity.creator_name ? { creator_name: identity.creator_name } : {}),
      public_key: identity.public_key,
      private_key: identity.private_key,
      created: identity.registered_at || new Date().toISOString(),
    }, null, 2);
    const filePath = path.join(backupDir, toFileName(identity.tip_id));
    fs.writeFileSync(filePath, tipJson, { mode: 0o600 });
    ok(`  Backup: ${toFileName(identity.tip_id)} — ${identity.name} (${identity.tip_id_type || "personal"})`);
  }

  // VP backup
  const vpBackup = JSON.stringify({
    v: 1,
    type: "vp",
    name: vpRecord.name,
    vp_id: vpRecord.vp_id,
    public_key: vpKeypair.publicKey,
    private_key: vpKeypair.privateKey,
    created: new Date().toISOString(),
  }, null, 2);
  fs.writeFileSync(path.join(backupDir, toFileName(vpRecord.vp_id)), vpBackup, { mode: 0o600 });
  ok(`  Backup: ${toFileName(vpRecord.vp_id)} — ${vpRecord.name} (VP)`);

  // Node backup
  if (_nodeKp && seedNode) {
    const nodeBackup = JSON.stringify({
      v: 1,
      type: "node",
      name: seedNode.name,
      node_id: seedNode.nodeId,
      public_key: _nodeKp.publicKey,
      private_key: _nodeKp.privateKey,
      created: new Date().toISOString(),
    }, null, 2);
    fs.writeFileSync(path.join(backupDir, toFileName(seedNode.nodeId)), nodeBackup, { mode: 0o600 });
    ok(`  Backup: ${toFileName(seedNode.nodeId)} — ${seedNode.name} (Node)`);
  }

  ok(`Backup .tip.json files written to: ${backupDir}`);
  warn("SECURITY: genesis-data/backups/ contains private keys. Never commit to git.");

  return output;
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log();
  console.log(`${T.bgNavy}${T.white}${T.bold}  TIP™ Protocol — Production Seed Script v2.0  ${T.reset}`);
  console.log(`${T.dim}  The AI Lab Intelligence Unobscured, Inc. | theailab.org${T.reset}`);
  console.log();
  info(`Mode:     ${useDirectMode ? "Direct (no HTTP)" : `API (${nodeUrl})`}`);
  info(`Data dir: ${DATA_DIR}`);
  console.log();

  try {
    // Initialize post-quantum crypto libraries
    await initCrypto();

    // Step 1: Generate founding VP keypair and embed in genesis source files
    const vpKeypair = await embedFoundingVPKey();

    // Step 1b: Initialize real DAG for direct mode. _writeGenesisBlock fires
    // here from the just-embedded VP + ring keys; founding_node is still
    // null at this point so the bootstrap walk skips that branch and the
    // node row gets written explicitly in Step 2b below.
    if (useDirectMode) initDirectDAG();

    // Step 2: Founding VP
    const { vpRecord } = await registerFoundingVP(vpKeypair);

    // Step 2b: Register seed node — embeds founding_node into genesis.js +
    // clears require.cache so the genesis hash computed in Step 3 below
    // sees the full payload (founding_vp + genesis_ring_keys + founding_node).
    const seedNode = await registerSeedNode(vpKeypair);

    // Step 3: Mint genesis block (signed by founding VP key) — DEFERRED to
    // after seed-node embedding so the hash + signature cover the complete
    // payload. Otherwise the STEP 6 verification (which re-reads genesis.js
    // with founding_node now set) computes a different hash and the
    // "Genesis block hash" check fails.
    const genesisBlock = await mintGenesisBlock(vpKeypair);

    // Step 4: Genesis Ring
    const identities = await createGenesisRing(vpRecord, vpKeypair);

    // Step 5: Sample content (skipped in production)
    const content = skipSampleContent ? [] : await registerSampleContent(identities);
    if (skipSampleContent) info("Sample content skipped (production mode)");

    // Step 6: Verification
    const allPass = await verifyDAGState(genesisBlock, vpRecord, vpKeypair, identities, content);

    // Step 7: Write output
    const output = await writeSeedOutput(genesisBlock, vpRecord, vpKeypair, identities, content, seedNode);

    // ── Final summary ────────────────────────────────────────────────────────
    head("SEED COMPLETE");
    label("Genesis hash", output.genesis.hash.slice(0, 48) + "...");
    label("Chain ID", output.genesis.chain_id);
    label("Founding VP", output.founding_vps[0].vp_id);
    label("Genesis ring members", output.founding_identities.length.toString());
    label("Sample content", `${output.sample_content.length} records (OH, AA, AG, MX)`);
    if (seedNode) label("Seed node", seedNode.nodeId);
    if (_dag) label("DAG transactions", `${_dag.count()}`);
    label("Validation", allPass ? `${T.green}All checks passed${T.reset}` : `${T.red}Some checks failed${T.reset}`);
    console.log();
    ok(`${T.bold}TIP™ Protocol genesis complete.${T.reset}`);
    console.log();
    if (!allPass) {
      warn("Some validation checks failed. Review the output above.");
      process.exit(1);
    }

    // Close DAG (in-memory; nothing to flush to disk).
    if (_dag) {
      _dag.close();
      ok("DAG closed (in-memory scratch).");
    }

  } catch (err) {
    if (_dag) _dag.close();
    console.error(`\n${T.red}${T.bold}SEED FAILED:${T.reset} ${err.message}`);
    if (process.env.TIP_LOG_LEVEL === "debug") console.error(err.stack);
    process.exit(1);
  }
}

main();
