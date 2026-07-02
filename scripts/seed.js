#!/usr/bin/env node
/**
 * @file tip-protocol/scripts/seed.js
 * @description Production Seed Script — End-to-End Genesis Block and DAG Bootstrap
 *
 * Genesis-block-only mint. Reads the founding roster from
 * genesis-data/genesis-members.json, generates a keypair per member/VP/node,
 * computes their ids, signs the bootstrap txs, and writes all minted values
 * (public keys, ids, signatures, seal) into genesis-data/genesis.json. It does
 * NOT seed sample content, only the genesis block.
 *
 * This script:
 *   1. Generates founding VP keypair + member keypairs from the roster
 *   2. Mints and signs the Genesis Block (signed by founding VP)
 *   3. Registers The AI Lab as the founding Verification Provider (DAG, direct mode)
 *   3b. Registers the seed node + writes keys to .env
 *   4. Registers founding identities (Genesis Ring)
 *   5. Verifies the full DAG state
 *   6. Writes seed output files
 *
 * USAGE:
 *   node --experimental-vm-modules scripts/seed.js
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const { nowMs, fromIso, isValidMs } = require("../shared/time");

// API responses come through the boundary middleware which formats ms → ISO.
// Seed.js writes seed-output.json + caches into local state — for the
// project-wide ms convention we coerce back to integer ms before persisting.
function _coerceMs(v) {
  if (v == null) return null;
  if (typeof v === "number") return v;
  if (typeof v === "string") {
    try { return fromIso(v); } catch { return null; }
  }
  return null;
}

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
  signBody,
  computeTxId,
  canonicalTx,
  canonicalJson,
} = require("../shared/crypto");

const { TX_TYPES, PROTOCOL } = require("../shared/constants");
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
const { buildBootstrapAddr } = require("../node/src/network/peer-key");
const { renderEnvFromExample } = require("./node-env-template");
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
const nodeUrl = args.find(a => a.startsWith("--node-url="))?.split("=")[1] || "http://localhost:4000";
const useDirectMode = args.includes("--direct") || !args.includes("--node-url");
// Local-only: also generate per-node env files for all founding nodes (node2+),
// wired for the docker-compose.local.yml cluster (fixed IPs/ports/DBs).
const isLocalCluster = args.includes("--local-cluster");

const DATA_DIR = path.resolve(__dirname, "../genesis-data");
const GENESIS_FILE = path.join(DATA_DIR, "genesis.json");

// Merge minted values into genesis.json and clear the require cache so the next
// require("genesis") picks them up.
function _patchGenesisJson(fields) {
  const doc = fs.existsSync(GENESIS_FILE) ? JSON.parse(fs.readFileSync(GENESIS_FILE, "utf8")) : {};
  Object.assign(doc, fields);
  fs.writeFileSync(GENESIS_FILE, JSON.stringify(doc, null, 2) + "\n");
  Object.keys(require.cache).forEach(k => { if (k.includes("genesis")) delete require.cache[k]; });
}

// Mirror the authored protocol_constants (genesis-config.json) into genesis.json
// before the payload is read, so the minted block is self-contained and a re-seed
// applies genesis-config edits. genesis.js reads them from genesis.json at runtime.
function embedProtocolConstants() {
  const cfg = JSON.parse(fs.readFileSync(path.join(DATA_DIR, "genesis-config.json"), "utf8"));
  if (!cfg.protocol_constants) throw new Error("genesis-config.json is missing protocol_constants");
  _patchGenesisJson({ protocol_constants: cfg.protocol_constants });
}

// Founding roster (the authored source of truth); seed mints keys for these.
const GENESIS_MEMBERS = JSON.parse(fs.readFileSync(path.join(DATA_DIR, "genesis-members.json"), "utf8"));
const FOUNDING_VP_DEF = GENESIS_MEMBERS.founding_vp;
const FOUNDING_NODES_DEF = GENESIS_MEMBERS.founding_nodes;
const FOUNDING_VP_TEMPLATE = Object.freeze({
  name: FOUNDING_VP_DEF.name,
  short_name: FOUNDING_VP_DEF.short_name,
  jurisdiction_tier: FOUNDING_VP_DEF.jurisdiction_tier,
  jurisdiction: FOUNDING_VP_DEF.jurisdiction,
  url: FOUNDING_VP_DEF.url,
  email: FOUNDING_VP_DEF.email,
});
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
    created_at: nowMs(),
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
const FOUNDING_MEMBERS = GENESIS_MEMBERS.founding_members;

// Keypairs generated in Step 2, used in Step 5
let _foundingKeypairs = []; // [{ member, keypair, tipId }]

// ─── Step 1: Generate founding VP + member keypairs and embed in genesis ─────
async function embedFoundingVPKey() {
  head("STEP 1: Founding VP & Member Keypairs → Genesis Payload");

  const vpKeysFile = path.join(DATA_DIR, "founding-vp-keys.json");
  const VP_TAG = FOUNDING_VP_DEF.tag;

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
      name: FOUNDING_VP_DEF.name,
      region: "US",
      id: generateVPId("US", vpKeypair.publicKey),
      public_key: vpKeypair.publicKey,
      private_key: vpKeypair.privateKey,
      created_at: nowMs(),
    }]);
    ok("Founding VP keypair generated and saved");
    warn("SECURITY: founding-vp-keys.json is chmod 600. NEVER commit to git.");
  }

  // Build founding_vp (static template + minted key/id) and write to genesis.json.
  const vpId = generateVPId("US", vpKeypair.publicKey);
  _patchGenesisJson({
    founding_vp: {
      vp_id: vpId,
      ...FOUNDING_VP_TEMPLATE,
      registered_at: GENESIS_TIMESTAMP,
      public_key: vpKeypair.publicKey,
    },
  });
  ok(`Embedded founding VP: ${vpId}`);

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

  _patchGenesisJson({ genesis_ring: genesisRing });
  ok("Wrote genesis_ring (founding TIP-IDs) to genesis.json");

  // Embed genesis_ring_keys (public keys + dedup hashes + VP signatures for initDAG)
  const ringKeys = _foundingKeypairs.map(({ member, keypair, tipId }) => {
    const dedupHash = shake256Multi("seed", member.name, member.region).replace(/[^0-9]/g, "").slice(0, 20) || "12345678901234567890";
    const tipIdType = member.tip_id_type || "personal";
    // Every founder gets their roster name (not just orgs); signed below.
    const creatorName = member.name;
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
  _patchGenesisJson({ genesis_ring_keys: ringKeys });
  ok("Wrote genesis_ring_keys (public keys + VP signatures) to genesis.json");

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

  _patchGenesisJson({ genesis_tx_signature: genesisTxSig, genesis_vp_tx_signature: vpTxSig });
  ok("Wrote bootstrap tx signatures to genesis.json");

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

  // Always re-write in canonical layout; the mint is deterministic, so this just
  // normalises field order (a changed key yields a new hash).

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

  // Merge the seal over the EXISTING genesis.json so minted fields not present
  // in GENESIS_PAYLOAD (the bootstrap-tx signatures) are preserved rather than
  // wiped by a full overwrite.
  const existing = fs.existsSync(GENESIS_FILE) ? JSON.parse(fs.readFileSync(GENESIS_FILE, "utf8")) : {};
  // Explicit field order (definition+seal, members, config last). tx signatures
  // aren't in GENESIS_PAYLOAD, so carry them over from the existing file.
  const genesisBlock = {
    version: updatedPayload.version,
    protocol: updatedPayload.protocol,
    notes: updatedPayload.notes,
    genesis_hash: genesisHash,
    signed_at: nowMs(),
    signer_public_key: vpKeypair.publicKey,
    signature,
    environment: "production",
    founding_vp: updatedPayload.founding_vp,
    founding_nodes: updatedPayload.founding_nodes,
    genesis_ring: updatedPayload.genesis_ring,
    genesis_ring_keys: updatedPayload.genesis_ring_keys,
    genesis_tx_signature: existing.genesis_tx_signature,
    genesis_vp_tx_signature: existing.genesis_vp_tx_signature,
    protocol_constants: updatedPayload.protocol_constants,
  };

  fs.writeFileSync(GENESIS_FILE, JSON.stringify(genesisBlock, null, 2) + "\n");
  ok(`Genesis block written to: ${GENESIS_FILE}`);
  ok(`${T.bold}Genesis hash: ${T.cyan}${genesisHash}${T.reset}`);

  return genesisBlock;
}

// ─── Direct-mode DAG setup ──────────────────────────────────────────────────
let _dag = null, _scoring = null, _nodeKp = null, _foundingNodeKps = [];

function initDirectDAG(vpKeypair) {
  process.env.ZK_SKIP_VERIFY = "true";

  // One keypair per founding node, cached per tag in founding-node-keys.json.
  // Reuse keeps node_id (and thus genesis_hash) stable across re-seeds; a tag
  // with no cached key gets a fresh one (e.g. newly-added founding nodes).
  const nodeKeysFile = path.join(DATA_DIR, "founding-node-keys.json");
  const cachedNodes = loadCachedEntries(nodeKeysFile, KEYS_FILE_TYPES.NODES);
  _foundingNodeKps = [];
  const entries = [];
  for (const def of FOUNDING_NODES_DEF) {
    const cached = cachedNodes?.get(def.tag);
    let kp;
    if (cached?.public_key && cached?.private_key) {
      kp = { algorithm: "ML-DSA-65", publicKey: cached.public_key, privateKey: cached.private_key };
      warn(`Reusing cached keypair for founding node tag "${def.tag}"`);
    } else {
      kp = generateMLDSAKeypair();
      ok(`Generated keypair for founding node tag "${def.tag}"`);
    }
    _foundingNodeKps.push({ def, kp });
    entries.push({
      tag: def.tag, name: def.name, id: generateNodeId(kp.publicKey),
      public_key: kp.publicKey, private_key: kp.privateKey,
      created_at: cached?.created_at || nowMs(),
      approving_vp_tag: "primary-vp",
    });
  }
  writeCachedEntries(nodeKeysFile, KEYS_FILE_TYPES.NODES, entries);

  // The seed machine operates the PRIMARY founding node (first in the roster);
  // its key goes to .env. The rest are distributed to their operators.
  _nodeKp = _foundingNodeKps[0].kp;

  // founding_nodes must be in genesis.json before initDAG: the DAG bootstrap
  // builds committee rotation 0 + the NODE_REGISTERED txs from it.
  embedFoundingNodes(vpKeypair);

  // Seed injects its own keypair (_nodeKp) below, so clear the env key sources:
  // a stale TIP_NODE_CREDENTIALS_FILE from a prior run points at a backup this
  // run hasn't written yet and would make loadConfig throw.
  delete process.env.TIP_NODE_CREDENTIALS_FILE;
  delete process.env.TIP_NODE_PRIVATE_KEY;
  delete process.env.TIP_NODE_PRIVATE_KEY_FILE;
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

// ─── Embed founding_nodes into genesis.json (must precede initDAG) ────────────
// initDAG bootstraps committee rotation 0 + the NODE_REGISTERED txs from
// genesis.founding_nodes, so every node identity + council signature must be
// written first. council_signature is deterministic, keeping genesis_hash stable
// across re-seeds. Sorted by node_id to match dag's canonical rotation-0 order.
function embedFoundingNodes(vpKeypair) {
  const vpId = require("../node/src/genesis").getFoundingVP().vp_id;
  const foundingNodes = _foundingNodeKps.map(({ def, kp }) => {
    // GH #60: algorithm is in the canonical signed bytes (the VP attests the
    // pubkey + algorithm pair). Alphabetical canonical order matching
    // schemas/_registry.js NODE_REGISTERED.
    const nodeFields = {
      algorithm: "ml-dsa-65",
      approving_vp_id: vpId,
      name: def.name,
      public_key: kp.publicKey,
    };
    return {
      node_id: generateNodeId(kp.publicKey),
      name: def.name,
      public_key: kp.publicKey,
      council_signature: signBody(nodeFields, vpKeypair.privateKey, { deterministic: true }),
      approving_vp_id: vpId,
    };
  }).sort((a, b) => (a.node_id < b.node_id ? -1 : a.node_id > b.node_id ? 1 : 0));
  _patchGenesisJson({ founding_nodes: foundingNodes });  // also clears genesis require cache
  ok(`Embedded ${foundingNodes.length} founding node(s) into genesis.json`);
}

// Filesystem-safe .tip.json name for a node id (matches the backup writer).
function nodeIdToFileName(id) {
  return id.replace(/[^a-zA-Z0-9-]/g, "-").replace(/-+/g, "-") + ".tip.json";
}

// One founding node's docker-cluster env: keypair comes from the mounted backup
// .tip.json; only node1 is the bootstrap target.
function buildLocalNodeEnv({ fn, slot, ip, apiPort, p2pPort, bootstrapAddr, shared }) {
  return renderEnvFromExample({
    TIP_NODE_ID: fn.node_id,
    PORT: apiPort,
    TIP_P2P_PORT: p2pPort,
    TIP_PUBLIC_IP: ip,
    TIP_BOOTSTRAP_PEERS: bootstrapAddr,
    TIP_ENABLE_MDNS: "false",
    TIP_DATA_DIR: "./data",          // container path; host ./node<slot>-env/data mounts to /app/data
    TIP_DB_PATH: "./data/tip.db",
    TIP_LOG_DIR: "/app/node/logs",
    TIP_PUBLIC_URL: `http://localhost:${apiPort}`,
    TIP_NODE_CREDENTIALS_FILE: `genesis-data/backups/${nodeIdToFileName(fn.node_id)}`,
    DB_DRIVER: "postgres",
    COMPOSE_PROFILES: "postgres",
    DB_HOST: shared.dbHost,
    DB_PORT: shared.dbPort,
    DB_NAME: `tip_node${slot}`,
    DB_USER: shared.dbUser,
    DB_PASSWORD: shared.dbPassword,
    TIP_CRYPTO_POOL_SIZE: shared.cryptoPool,
    ZK_SKIP_VERIFY: shared.zkSkip,
    TIP_RATE_LIMIT_MAX: shared.rateLimit,
  }, {
    headerNotes: [`local cluster node${slot}`, "Generated by seed.js --local-cluster"],
  });
}

// Env files for every non-primary founding node, wired for the local compose
// cluster (node2=.11:4100, node3=.12:4200); shared DB/ops values from node1's .env.
async function writeLocalClusterEnvs(fns, primary) {
  // No root .env yet (fresh checkout): fall back to the val() defaults.
  const rootEnvPath = path.resolve(__dirname, "../.env");
  const rootEnv = fs.existsSync(rootEnvPath) ? fs.readFileSync(rootEnvPath, "utf8") : "";
  const val = (k, d) => (rootEnv.match(new RegExp(`^${k}=(.*)$`, "m"))?.[1] ?? d);
  const shared = {
    dbHost: val("DB_HOST", "host.docker.internal"),
    dbPort: val("DB_PORT", "5432"),
    dbUser: val("DB_USER", "tip"),
    dbPassword: val("DB_PASSWORD", ""),
    zkSkip: val("ZK_SKIP_VERIFY", "true"),
    rateLimit: val("TIP_RATE_LIMIT_MAX", "10000"),
    cryptoPool: val("TIP_CRYPTO_POOL_SIZE", "2"),
  };
  // node2+ bootstrap off node1's deterministic peer id at its fixed IP.
  const bootstrapAddr = await buildBootstrapAddr(primary.node_id, "172.30.0.10", 4001);

  let slot = 2;   // node1 is slot 1 (its .env is patched separately)
  for (const fn of fns.filter((n) => n.node_id !== primary.node_id)) {
    const ip = `172.30.0.${9 + slot}`;             // slot 2 -> .11, slot 3 -> .12
    const apiPort = 4000 + (slot - 1) * 100;        // slot 2 -> 4100
    const dir = path.resolve(__dirname, `../node${slot}-env`);
    fs.mkdirSync(path.join(dir, "data"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, `node-${slot}.env`),
      buildLocalNodeEnv({ fn, slot, ip, apiPort, p2pPort: apiPort + 1, bootstrapAddr, shared }),
    );
    ok(`Generated node${slot}-env/node-${slot}.env (${fn.node_id})`);
    slot++;
  }
}

// ─── Step 4b: Confirm seed nodes + write operator .env ───────────────────────
// founding_nodes were embedded before initDAG, so _writeGenesisBlock already
// wrote the NODE_REGISTERED tx + node row for each during the genesis bootstrap
// (same path as `npm start`). Here we confirm they landed and write the PRIMARY
// node's keys to .env (this machine operates founding_nodes[0]).
async function registerSeedNode() {
  info("Confirming seed node registration...");

  if (!useDirectMode || !_dag) {
    warn("Node registration requires direct mode with DAG — skipping");
    return null;
  }

  const fns = require("../node/src/genesis").getGenesisPayload().founding_nodes;
  if (!Array.isArray(fns) || fns.length === 0) throw new Error("founding_nodes not embedded before registerSeedNode (check initDirectDAG order)");
  for (const fn of fns) {
    if (!_dag.getNode(fn.node_id)) throw new Error(`Founding node ${fn.node_id} not in DAG after genesis bootstrap`);
  }

  // This machine operates the PRIMARY founding node (its keypair is _nodeKp).
  const primary = fns.find((n) => n.public_key === _nodeKp.publicKey) || fns[0];

  // The node reads its keypair from its .tip.json backup via
  // TIP_NODE_CREDENTIALS_FILE, so the operator .env never inlines the secret.
  // The backup is written to genesis-data/backups/<node-id>.tip.json below.
  const credRel = `genesis-data/backups/${nodeIdToFileName(primary.node_id)}`;
  const credLine = `TIP_NODE_CREDENTIALS_FILE=${credRel}`;
  const envFile = path.resolve(__dirname, "../.env");
  if (fs.existsSync(envFile)) {
    let envSrc = fs.readFileSync(envFile, "utf8");
    // Idempotent across re-seeds: update an existing pointer, else convert the
    // inline key line, else append. (A stale pointer left from a prior run would
    // otherwise reference a backup this run's fresh keys just deleted.)
    if (/^TIP_NODE_CREDENTIALS_FILE=/m.test(envSrc)) {
      envSrc = envSrc.replace(/^TIP_NODE_CREDENTIALS_FILE=.*/m, credLine);
    } else if (/^TIP_NODE_PRIVATE_KEY=/m.test(envSrc)) {
      envSrc = envSrc.replace(/^TIP_NODE_PRIVATE_KEY=.*/m, credLine);
    } else {
      envSrc += `\n${credLine}\n`;
    }
    envSrc = envSrc.replace(/^TIP_NODE_PUBLIC_KEY=.*\n?/m, "");
    // Default log level to `warn` so a freshly-seeded founding node doesn't
    // flood the operator's terminal with INFO chatter from every batch /
    // anchor / rotation. Operators can still set debug/info manually.
    envSrc = envSrc.replace(/TIP_LOG_LEVEL=.*/, "TIP_LOG_LEVEL=warn");
    envSrc = envSrc.replace(/TIP_CONSOLE_LEVEL=.*/, "TIP_CONSOLE_LEVEL=warn");
    fs.writeFileSync(envFile, envSrc);
    ok(`Node credentials pointer (${credRel}) + log levels written to .env`);
  }

  // Local dev convenience: also generate node2+ env files for the docker cluster.
  if (isLocalCluster) await writeLocalClusterEnvs(fns, primary);

  ok(`Seed nodes registered: ${fns.length} (primary ${primary.node_id})`);
  label("Primary Node ID", primary.node_id);
  return { nodeId: primary.node_id, name: primary.name, publicKey: primary.public_key };
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

      const registeredAt = nowMs();
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
      _dag.addDedupHash(mockDedupHash, Math.floor(registeredAt / 1000));
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
          registered_at: nowMs(),
          vp_id: vpRecord.vp_id,
        };
      }
    }

    const memberType = member.tip_id_type || "personal";
    const identity = {
      tag: member.tag,
      name: member.name,
      tip_id: regResult.tip_id,
      tip_id_type: memberType,
      creator_name: member.name,
      public_key: keypair.publicKey,
      private_key: keypair.privateKey,  // Stored in seed output — replace with real keys in production
      founding: true,
      score: regResult.score || 550,
      registered_at: _coerceMs(regResult.registered_at),
    };

    identities.push(identity);
    ok(`  ${T.bold}${member.name}${T.reset}`);
    label("    TIP-ID", identity.tip_id);
    label("    Score", `${identity.score} / 1000 (${getTier(identity.score).label})`);
  }

  info(`Genesis Ring: ${identities.length} founding members created`);
  return identities;
}

// ─── Step 7: Full DAG verification ────────────────────────────────────────────
async function verifyDAGState(genesisBlock, vpRecord, vpKeypair, identities) {
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
      pass: txCount >= 2 + identities.length,
      detail: `${txCount} txs (expected >= ${2 + identities.length})`,
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

  // TIP-ID format check
  const badIds = identities.filter(i => !i.tip_id.startsWith("tip://id/"));
  checks.push({
    name: "TIP-ID format valid",
    pass: badIds.length === 0,
    detail: badIds.length === 0 ? "All valid" : `Invalid: ${badIds.map(i => i.tip_id).join(", ")}`,
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
async function writeSeedOutput(genesisBlock, vpRecord, vpKeypair, identities, seedNode) {
  head("STEP 7: Writing Seed Output");

  // Observer-facing summary. Plural arrays everywhere so n=1 today and
  // n=N tomorrow share one shape. Private keys live in the gitignored
  // founding-{vp,node,founder}-keys.json files, never in this output.
  const output = {
    v: 2,
    seed_version: require("../package.json").version,
    created_at: nowMs(),
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
    founding_nodes: _foundingNodeKps.map(({ def, kp }) => ({
      tag: def.tag,
      node_id: generateNodeId(kp.publicKey),
      name: def.name,
      public_key: kp.publicKey,
      approving_vp_tag: "primary-vp",
    })),
    founding_identities: identities.map(i => ({
      tag: i.tag,
      tip_id: i.tip_id,
      tip_id_type: i.tip_id_type || "personal",
      name: i.name,
      region: "US",
      vp_tag: "primary-vp",
      founding: true,
      score: i.score,
      registered_at: i.registered_at,
      ...(i.creator_name ? { creator_name: i.creator_name } : {}),
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
    region: "US",
    vp_tag: "primary-vp",
    public_key: i.public_key,
    private_key: i.private_key,
    created_at: i.registered_at || nowMs(),
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
      created: identity.registered_at || nowMs(),
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
    created: nowMs(),
  }, null, 2);
  fs.writeFileSync(path.join(backupDir, toFileName(vpRecord.vp_id)), vpBackup, { mode: 0o600 });
  ok(`  Backup: ${toFileName(vpRecord.vp_id)} — ${vpRecord.name} (VP)`);

  // Node backups: one per founding node so each operator can be handed its key.
  for (const { def, kp } of _foundingNodeKps) {
    const nodeId = generateNodeId(kp.publicKey);
    const nodeBackup = JSON.stringify({
      v: 1,
      type: "node",
      name: def.name,
      node_id: nodeId,
      public_key: kp.publicKey,
      private_key: kp.privateKey,
      created: nowMs(),
    }, null, 2);
    fs.writeFileSync(path.join(backupDir, toFileName(nodeId)), nodeBackup, { mode: 0o600 });
    ok(`  Backup: ${toFileName(nodeId)} (${def.name}, Node)`);
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

    // Step 0: copy authored protocol_constants into genesis.json before any
    // payload read, so the minted block is self-contained and edits to
    // genesis-config.json take effect on re-seed.
    embedProtocolConstants();

    // Step 1: Generate founding VP keypair and embed in genesis source files
    const vpKeypair = await embedFoundingVPKey();

    // Step 1b: Initialize real DAG for direct mode. initDirectDAG embeds
    // founding_node into genesis.json first (committee rotation 0 bootstraps
    // from it), then _writeGenesisBlock fires from the full payload.
    if (useDirectMode) initDirectDAG(vpKeypair);

    // Step 2: Founding VP
    const { vpRecord } = await registerFoundingVP(vpKeypair);

    // Step 2b: Register the seed node in the DAG (founding_node already embedded
    // by initDirectDAG; this writes the NODE_REGISTERED tx + node row).
    const seedNode = await registerSeedNode();

    // Step 2c: Re-embed bootstrap tx signatures now that founding_node is set.
    // embedFoundingVPKey() signed over GENESIS_PAYLOAD before founding_node was
    // embedded, so GENESIS_TX_SIGNATURE / GENESIS_VP_TX_SIGNATURE would be stale
    // at node startup. Re-sign over the complete payload here.
    {
      Object.keys(require.cache).forEach(key => { if (key.includes("genesis")) delete require.cache[key]; });
      const freshGenesis = require("../node/src/genesis");
      const SIG_DET = { deterministic: true };
      const genesisTxSig = mldsaSign(canonicalTx(freshGenesis.GENESIS_TX), vpKeypair.privateKey, SIG_DET);
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
      // Write the re-signed bootstrap-tx signatures to genesis.json.
      _patchGenesisJson({ genesis_tx_signature: genesisTxSig, genesis_vp_tx_signature: vpTxSig });
      ok("Re-wrote bootstrap tx signatures to genesis.json after founding_node update");
    }

    // Step 3: Mint genesis block (signed by founding VP key) — DEFERRED to
    // after seed-node embedding so the hash + signature cover the complete
    // payload. Otherwise the STEP 6 verification (which re-reads genesis.js
    // with founding_node now set) computes a different hash and the
    // "Genesis block hash" check fails.
    const genesisBlock = await mintGenesisBlock(vpKeypair);

    // Step 4: Genesis Ring
    const identities = await createGenesisRing(vpRecord, vpKeypair);

    // Step 5: Verification
    const allPass = await verifyDAGState(genesisBlock, vpRecord, vpKeypair, identities);

    // Step 7: Write output
    const output = await writeSeedOutput(genesisBlock, vpRecord, vpKeypair, identities, seedNode);

    // ── Final summary ────────────────────────────────────────────────────────
    head("SEED COMPLETE");
    label("Genesis hash", output.genesis.hash.slice(0, 48) + "...");
    label("Chain ID", output.genesis.chain_id);
    label("Founding VP", output.founding_vps[0].vp_id);
    label("Genesis ring members", output.founding_identities.length.toString());
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

if (require.main === module) main();

module.exports = { nodeIdToFileName, buildLocalNodeEnv, writeLocalClusterEnvs };
