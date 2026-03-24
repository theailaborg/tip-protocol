#!/usr/bin/env node
/**
 * @file tip-protocol/scripts/seed.js
 * @description Production Seed Script — End-to-End Genesis Block and DAG Bootstrap
 *
 * This script:
 *   1. Generates the root SLH-DSA keypair for the Genesis Block
 *   2. Mints and signs the Genesis Block
 *   3. Registers The AI Lab as the founding Verification Provider
 *   4. Registers a set of founding identities (Genesis Ring)
 *   5. Registers sample content with all four origin types
 *   6. Verifies the full DAG state and prints a health report
 *
 * USAGE:
 *   # Full production seed (generates everything from scratch):
 *   node scripts/seed.js
 *
 *   # Only generate genesis keys (first step in production):
 *   node scripts/seed.js --genesis-keys-only
 *
 *   # Seed against a running node via REST API:
 *   node scripts/seed.js --node-url http://localhost:4000
 *
 *   # Seed directly into the DAG (no HTTP, for initial bootstrap):
 *   node scripts/seed.js --direct
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

// dotenv not required for direct mode

const fs    = require("fs");
const path  = require("path");
const http  = require("http");
const https = require("https");

const {
  initCrypto,
  generateMLDSAKeypair,
  generateSLHDSAKeypair,
  mldsaSign,
  shake256,
  shake256Multi,
  generateTIPID,
  generateCTID,
  hashContent,
  perceptualHashText,
  signBody,
  computeTxId,
  signTransaction,
  canonicalTx,
} = require("../shared/crypto");

const { TX_TYPES, ORIGIN, ORIGIN_LABELS, PROTOCOL, getTier } = require("../shared/constants");
const { initDAG }     = require("../node/src/dag");
const { initScoring } = require("../node/src/scoring");
const { loadConfig }  = require("../node/src/config");
const {
  GENESIS_TX_ID,
  GENESIS_TIMESTAMP,
  GENESIS_CHAIN_ID,
  buildGenesisBlock,
  getFoundingVP,
  computeGenesisHash,
  GENESIS_PAYLOAD,
  canonicalSerialise,
} = require("../node/src/genesis");

// ─── Terminal colors ──────────────────────────────────────────────────────────
const T = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", blue: "\x1b[34m", yellow: "\x1b[33m",
  red: "\x1b[31m", cyan: "\x1b[36m", gold: "\x1b[33m", grey: "\x1b[90m",
  bgNavy: "\x1b[44m", white: "\x1b[37m",
};

const ok    = (m) => console.log(`${T.green}  ✓${T.reset} ${m}`);
const warn  = (m) => console.log(`${T.yellow}  ⚠${T.reset} ${m}`);
const info  = (m) => console.log(`${T.cyan}  ℹ${T.reset} ${m}`);
const label = (k, v) => console.log(`    ${T.dim}${k.padEnd(28)}${T.reset}${v}`);
const sep   = () => console.log(`${T.dim}  ${"─".repeat(62)}${T.reset}`);
const head  = (t) => { sep(); console.log(`  ${T.bold}${T.gold}${t}${T.reset}`); sep(); };

// ─── CLI args ─────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const genesisKeysOnly = args.includes("--genesis-keys-only");
const nodeUrl         = args.find(a => a.startsWith("--node-url="))?.split("=")[1] || "http://localhost:4000";
const useDirectMode   = args.includes("--direct") || !args.includes("--node-url");

const DATA_DIR    = path.resolve(__dirname, "../node/genesis-data");
const KEYS_FILE   = path.join(DATA_DIR, "genesis-keys.json");
const GENESIS_FILE = path.join(DATA_DIR, "genesis.json");
const SEED_FILE   = path.join(DATA_DIR, "seed-output.json");

// ─── HTTP helper (wraps Node.js http/https) ────────────────────────────────────
function post(url, body) {
  return new Promise((resolve, reject) => {
    const parsed  = new URL(url);
    const lib     = parsed.protocol === "https:" ? https : http;
    const payload = JSON.stringify(body);
    const req     = lib.request({
      hostname: parsed.hostname,
      port:     parsed.port,
      path:     parsed.pathname,
      method:   "POST",
      headers:  { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
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
    const lib    = parsed.protocol === "https:" ? https : http;
    lib.get(url, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error(`Non-JSON response: ${data.slice(0,100)}`)); }
      });
    }).on("error", reject);
  });
}

// ─── Step 1: Generate (or load) genesis root keypair ─────────────────────────
async function generateGenesisKeys() {
  head("STEP 1: Genesis Root Keypair (ML-DSA-65)");

  if (fs.existsSync(KEYS_FILE)) {
    warn("genesis-keys.json already exists — loading existing keys");
    warn("Delete genesis-data/genesis-keys.json to regenerate from scratch");
    const keys = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
    label("Public key (first 32 chars)", keys.publicKey.slice(0, 32) + "...");
    label("Key file", KEYS_FILE);
    return keys;
  }

  info("Generating ML-DSA-65 root keypair...");
  const keys = generateMLDSAKeypair();
  label("Algorithm",                  keys.algorithm);
  label("Public key (first 32 chars)", keys.publicKey.slice(0, 32) + "...");

  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(KEYS_FILE, JSON.stringify({
    algorithm:  keys.algorithm,
    publicKey:  keys.publicKey,
    privateKey: keys.privateKey, // KEEP SECURE — never commit to version control
    created_at: new Date().toISOString(),
    purpose:    "TIP™ Protocol Genesis Block root signing key",
  }, null, 2), { mode: 0o600 }); // Restricted permissions

  ok("Genesis root keypair generated and saved");
  warn("SECURITY: genesis-keys.json is chmod 600. Back it up securely. NEVER commit it to git.");
  return keys;
}

// ─── Step 2: Generate founding VP keypair and embed in genesis ───────────────
async function embedFoundingVPKey() {
  head("STEP 2: Founding VP Keypair → Genesis Payload");

  const vpKeysFile = path.join(DATA_DIR, "founding-vp-keys.json");

  let vpKeypair;
  if (fs.existsSync(vpKeysFile)) {
    warn("founding-vp-keys.json already exists — loading existing keys");
    vpKeypair = JSON.parse(fs.readFileSync(vpKeysFile, "utf8"));
    label("Public key (first 32 chars)", vpKeypair.publicKey.slice(0, 32) + "...");
  } else {
    info("Generating ML-DSA-65 keypair for founding VP...");
    vpKeypair = generateMLDSAKeypair();
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(vpKeysFile, JSON.stringify({
      algorithm:  vpKeypair.algorithm,
      publicKey:  vpKeypair.publicKey,
      privateKey: vpKeypair.privateKey,
      created_at: new Date().toISOString(),
      purpose:    "TIP™ Protocol Founding VP signing key",
    }, null, 2), { mode: 0o600 });
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

  // Clear Node.js require cache so genesis.js is re-read with the updated key
  const genesisModule = require.resolve("../node/src/genesis");
  delete require.cache[genesisModule];
  // Also clear constants/crypto since genesis depends on them
  Object.keys(require.cache).forEach(key => {
    if (key.includes("genesis")) delete require.cache[key];
  });

  // Compute and embed bootstrap tx signatures (founding VP signs both)
  // Re-read genesis module with the updated VP key
  const freshGenesis = require("../node/src/genesis");

  // Sign genesis tx
  const genesisTxSig = mldsaSign(canonicalTx(freshGenesis.GENESIS_TX), vpKeypair.privateKey);
  // Sign VP registration tx (same structure as initDAG builds)
  const vpTxBody = {
    tx_type:   "VP_REGISTERED",
    timestamp: freshGenesis.GENESIS_TIMESTAMP,
    prev:      [freshGenesis.GENESIS_TX_ID, freshGenesis.GENESIS_TX_ID],
    data: {
      vp_id:             freshGenesis.GENESIS_PAYLOAD.founding_vp.vp_id,
      name:              freshGenesis.GENESIS_PAYLOAD.founding_vp.name,
      jurisdiction_tier: freshGenesis.GENESIS_PAYLOAD.founding_vp.jurisdiction_tier,
      public_key:        vpKeypair.publicKey,
    },
  };
  const vpTxSig = mldsaSign(canonicalTx(vpTxBody), vpKeypair.privateKey);

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
async function mintGenesisBlock(rootKeys) {
  head("STEP 3: Minting Genesis Block");

  // Re-read genesis module after VP key embedding (cache was cleared)
  const updatedGenesis = require("../node/src/genesis");
  const updatedPayload = updatedGenesis.GENESIS_PAYLOAD;

  if (fs.existsSync(GENESIS_FILE)) {
    info("genesis.json already exists — validating...");
    const existing = JSON.parse(fs.readFileSync(GENESIS_FILE, "utf8"));
    const expectedHash = updatedGenesis.computeGenesisHash(updatedPayload);
    if (existing.genesis_hash === expectedHash) {
      ok(`Genesis block valid. Hash: ${T.cyan}${existing.genesis_hash.slice(0,32)}...${T.reset}`);
      return existing;
    } else {
      // Key may have changed — delete stale genesis.json and re-mint
      warn("genesis.json hash mismatch (VP key changed?) — re-minting...");
      fs.unlinkSync(GENESIS_FILE);
    }
  }

  info("Computing genesis hash...");
  const genesisHash = updatedGenesis.computeGenesisHash(updatedPayload);
  label("Genesis hash",     genesisHash.slice(0, 32) + "...");
  label("Chain ID",         GENESIS_CHAIN_ID);
  label("Protocol version", PROTOCOL.version);
  label("Timestamp",        GENESIS_TIMESTAMP);
  label("Issuer",           PROTOCOL.issuer);

  info("Signing genesis block with ML-DSA-65 root key...");
  const signature = mldsaSign(genesisHash, rootKeys.privateKey);
  ok("Signature computed");

  const genesisBlock = {
    ...updatedPayload,
    genesis_hash:         genesisHash,
    canonical_hash:       shake256(updatedGenesis.canonicalSerialise(updatedPayload)),
    signed_at:            new Date().toISOString(),
    signer_public_key:    rootKeys.publicKey,
    signature,
    environment:          "production",
    build_info: {
      node_version: process.version,
      platform:     process.platform,
      seed_script:  "scripts/seed.js",
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

  _nodeKp = generateMLDSAKeypair();
  const cfg = loadConfig();
  cfg.dbPath         = path.join(DATA_DIR, "seed.db");
  cfg.nodePrivateKey = _nodeKp.privateKey;
  cfg.nodePublicKey  = _nodeKp.publicKey;

  if (fs.existsSync(cfg.dbPath)) fs.unlinkSync(cfg.dbPath);

  _dag     = initDAG(cfg);
  _scoring = initScoring(_dag, cfg);

  ok("Direct-mode DAG initialized");
  label("DB path", cfg.dbPath);
}

function _nodeSigned(txBody) {
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, _nodeKp.privateKey);
}

// ─── Step 4: Register The AI Lab as founding VP ───────────────────────────────
async function registerFoundingVP(genesisBlock, vpKeypair) {
  head("STEP 4: Register The AI Lab Verification Provider");

  const foundingVP = getFoundingVP();

  info(`Registering VP: ${foundingVP.name}`);
  label("Jurisdiction tier", foundingVP.jurisdiction_tier);
  label("URL",               foundingVP.url);

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

  label("VP ID",   vpRecord.vp_id);
  label("Status",  vpRecord.status);

  return { vpRecord, vpKeypair };
}

// ─── Step 5: Create founding identities (Genesis Ring) ───────────────────────
async function createGenesisRing(vpRecord, vpKeypair) {
  head("STEP 5: Creating Genesis Ring (Founding Identities)");

  const foundingMembers = [
    {
      name:    "Dinesh Mendhe — Founder",
      role:    "Founder & Sole Inventor",
      region:  "US",
      tag:     "founder",
    },
    {
      name:    "Tushar Bhendarkar — Co-Founder",
      role:    "Co-Founder & Core Engineer",
      region:  "US",
      tag:     "cofounder-tushar",
    },
    {
      name:    "Vishal — Co-Founder",
      role:    "Co-Founder & Core Engineer",
      region:  "US",
      tag:     "cofounder-vishal",
    },
    {
      name:    "The AI Lab — Protocol Bot",
      role:    "Automated VP credential for testing",
      region:  "US",
      tag:     "system",
    },
    {
      name:    "Test Journalist",
      role:    "Sample founding journalist (replace with real credential)",
      region:  "US",
      tag:     "journalist",
    },
    {
      name:    "Test Researcher",
      role:    "Sample founding researcher (replace with real credential)",
      region:  "US",
      tag:     "researcher",
    },
  ];

  const identities = [];

  for (const member of foundingMembers) {
    const keypair   = generateMLDSAKeypair();
    const rootKp    = generateSLHDSAKeypair();
    const tipId     = generateTIPID(member.region, keypair.publicKey);

    // Seed uses mock proof — production would call generateDedupProof() from shared/zk.js
    const mockDedupHash = shake256Multi("seed", member.name, member.region).replace(/[^0-9]/g, "").slice(0, 20) || "12345678901234567890";
    const mockZkProof   = { pi_a: ["1","2","3"], pi_b: [["1","2"],["3","4"],["5","6"]], pi_c: ["1","2","3"], protocol: "groth16", curve: "bn128" };

    let regResult;

    if (useDirectMode) {
      // VP signs the identity fields (same as API verifies)
      const idFields = {
        region: member.region, dedup_hash: mockDedupHash, zk_proof: mockZkProof,
        verification_tier: "T1", vp_id: vpRecord.vp_id, social_attested: true,
      };
      const vpSignature = signBody(idFields, vpKeypair.privateKey);

      const registeredAt = new Date().toISOString();
      const txBody = {
        tx_type:   TX_TYPES.REGISTER_IDENTITY,
        timestamp: registeredAt,
        prev:      _dag.getRecentPrev(),
        data: {
          tip_id:            tipId,
          region:            member.region.toUpperCase(),
          public_key:        keypair.publicKey,
          root_public_key:   rootKp.publicKey,
          vp_id:             vpRecord.vp_id,
          verification_tier: "T1",
          social_attested:   true,
          founding:          false,
          dedup_hash:        mockDedupHash,
          zk_proof:          mockZkProof,
          vp_signature:      vpSignature,
        },
      };
      const signedTx = _nodeSigned(txBody);
      const tx = _dag.addTx(signedTx);

      _dag.saveIdentity({
        tip_id:          tipId,
        region:          member.region.toUpperCase(),
        public_key:      keypair.publicKey,
        root_public_key: rootKp.publicKey,
        vp_id:           vpRecord.vp_id,
        verification_tier: "T1",
        founding:        false,
        status:          "active",
        registered_at:   registeredAt,
        tx_id:           tx.tx_id,
      });
      _dag.addDedupHash(mockDedupHash);
      _dag.setScore(tipId, 550, 0);

      regResult = {
        tip_id:          tipId,
        public_key:      keypair.publicKey,
        private_key:     keypair.privateKey,
        root_public_key: rootKp.publicKey,
        root_private_key: rootKp.privateKey,
        score:           550,
        registered_at:   registeredAt,
        vp_id:           vpRecord.vp_id,
        tx_id:           tx.tx_id,
      };
    } else {
      try {
        const idFields = {
          region: member.region, dedup_hash: mockDedupHash, zk_proof: mockZkProof,
          verification_tier: "T1", vp_id: vpRecord.vp_id, social_attested: true,
        };
        const vpSignature = signBody(idFields, vpKeypair.privateKey);

        regResult = await post(`${nodeUrl}/v1/identity/register`, {
          ...idFields, vp_signature: vpSignature,
        });
      } catch (e) {
        warn(`API registration failed for ${member.name}: ${e.message}`);
        regResult = {
          tip_id:          tipId,
          public_key:      keypair.publicKey,
          private_key:     keypair.privateKey,
          root_public_key: rootKp.publicKey,
          root_private_key: rootKp.privateKey,
          score:           550,
          registered_at:   new Date().toISOString(),
          vp_id:           vpRecord.vp_id,
        };
      }
    }

    const identity = {
      tag:             member.tag,
      name:            member.name,
      role:            member.role,
      tip_id:          regResult.tip_id,
      public_key:      keypair.publicKey,
      private_key:     keypair.privateKey,  // Stored in seed output — replace with real keys in production
      root_public_key: rootKp.publicKey,
      founding:        true,
      score:           regResult.score || 550,
      registered_at:   regResult.registered_at,
    };

    identities.push(identity);
    ok(`  ${T.bold}${member.name}${T.reset}`);
    label("    TIP-ID",  identity.tip_id);
    label("    Score",   `${identity.score} / 1000 (${getTier(identity.score).label})`);
    label("    Role",    member.role);
  }

  info(`Genesis Ring: ${identities.length} founding members created`);
  return identities;
}

// ─── Step 6: Register sample content (all four origin types) ──────────────────
async function registerSampleContent(identities) {
  head("STEP 6: Registering Sample Content (All Origin Types)");

  const author = identities.find(i => i.tag === "founder");
  if (!author) { warn("No founder identity found — skipping content registration"); return []; }

  const samples = [
    {
      origin:  ORIGIN.OH,
      title:   "TIP™ Protocol — Why the Internet Needs a Trust Layer",
      content: "The internet was built without an identity layer. HTTP, TCP/IP, DNS, and TLS solve routing, delivery, naming, and encryption. But none of them answer the fundamental question: who created this content, and can I trust it? This was an acceptable gap when content creation required skill and equipment. It is an existential gap now that AI can generate indistinguishable text, images, video, and audio at near-zero marginal cost. TIP™ is the protocol layer that closes this gap.",
    },
    {
      origin:  ORIGIN.AA,
      title:   "AI-Assisted: Post-Quantum Cryptography Overview",
      content: "Post-quantum cryptography refers to cryptographic algorithms that are secure against attacks by quantum computers. The NIST post-quantum standardisation process has selected ML-DSA-65 (Dilithium), SLH-DSA-128s (SPHINCS+), and ML-KEM-768 (Kyber) as the primary algorithms. TIP™ Protocol mandates these algorithms at the protocol level, ensuring long-term security. [This introduction was drafted by the author and expanded with AI assistance for clarity and completeness.]",
    },
    {
      origin:  ORIGIN.AG,
      title:   "AI-Generated: Frequently Asked Questions about TIP™",
      content: "Q: What is TIP™? A: TIP™ (Trust Identity Protocol) is an open, federated protocol for verifying human identity and declaring content provenance. Q: Is TIP™ free? A: Yes — the protocol specification is CC-BY 4.0 and free for everyone. Q: How does the trust score work? A: Scores are computed deterministically from your complete transaction history on the federated DAG. [This FAQ was generated entirely by AI from the protocol specification.]",
    },
    {
      origin:  ORIGIN.MX,
      title:   "Mixed: TIP™ Launch Announcement",
      content: "We are pleased to announce the launch of TIP™ Protocol v2.0. [Human-written announcement] This release includes five critical security and compliance fixes addressing privacy architecture, pre-scan calibration, identity revocation, GDPR compliance, and jurisdiction tier enforcement. [AI-generated technical summary] The cryptographic foundation uses NIST-standardised post-quantum algorithms. [Human-written conclusion] We invite developers, journalists, and researchers to implement TIP™ and join the founding network.",
    },
  ];

  const registered = [];

  for (const sample of samples) {
    const contentHash = hashContent(sample.content);
    const ctid        = generateCTID(sample.origin, contentHash, author.tip_id);

    const ctFields = { author_tip_id: author.tip_id, origin_code: sample.origin, content_hash: contentHash };
    const signature = signBody(ctFields, author.private_key);

    let result;

    if (useDirectMode) {
      const registeredAt = new Date().toISOString();
      const perceptHash  = perceptualHashText(sample.content);

      const contentTxBody = {
        tx_type:   TX_TYPES.REGISTER_CONTENT,
        timestamp: registeredAt,
        prev:      _dag.getRecentPrev(),
        data: {
          ctid,
          origin_code:       sample.origin,
          origin_label:      ORIGIN_LABELS[sample.origin],
          content_hash:      contentHash,
          perceptual_hash:   perceptHash,
          author_tip_id:     author.tip_id,
          signature,
          prescan_flagged:   false,
          prescan_probability: 0,
        },
      };
      const signedContentTx = _nodeSigned(contentTxBody);
      const tx = _dag.addTx(signedContentTx);

      _dag.saveContent({
        ctid,
        origin_code:    sample.origin,
        content_hash:   contentHash,
        perceptual_hash: perceptHash,
        author_tip_id:  author.tip_id,
        status:         "verified",
        registered_at:  registeredAt,
        tx_id:          tx.tx_id,
      });

      result = {
        ctid,
        origin_code:   sample.origin,
        origin_label:  ORIGIN_LABELS[sample.origin],
        content_hash:  contentHash,
        author_tip_id: author.tip_id,
        status:        "verified",
        registered_at: registeredAt,
        tx_id:         tx.tx_id,
      };
    } else {
      try {
        result = await post(`${nodeUrl}/v1/content/register`, {
          ...ctFields,
          content:  sample.content,
          signature,
        });
      } catch (e) {
        warn(`Content registration failed for ${sample.origin}: ${e.message}`);
        result = { ctid, origin_code: sample.origin, status: "local-only" };
      }
    }

    registered.push({ ...sample, ctid: result.ctid, status: result.status });
    ok(`  ${T.bold}${ORIGIN_LABELS[sample.origin]}${T.reset} — ${sample.title.slice(0, 45)}...`);
    label("    CTID",    result.ctid);
    label("    Status",  result.status);
  }

  return registered;
}

// ─── Step 7: Full DAG verification ────────────────────────────────────────────
async function verifyDAGState(genesisBlock, vpRecord, vpKeypair, identities, content) {
  head("STEP 7: DAG State Verification");

  const checks = [];
  const { mldsaVerify, verifyTxId } = require("../shared/crypto");

  // Genesis hash integrity
  const expectedHash = computeGenesisHash(GENESIS_PAYLOAD);
  checks.push({
    name: "Genesis block hash",
    pass: genesisBlock.genesis_hash === expectedHash,
    detail: `${genesisBlock.genesis_hash.slice(0,32)}...`,
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
  const updatedGenesis = require("../node/src/genesis");
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
    detail: badIds.length === 0 ? "All valid" : `Invalid: ${badIds.map(i=>i.tip_id).join(", ")}`,
  });

  // CTID format check
  const badCtids = content.filter(c => c.ctid && !/^tip:\/\/c\/(OH|AA|AG|MX)-/.test(c.ctid));
  checks.push({
    name: "CTID format valid",
    pass: badCtids.length === 0,
    detail: badCtids.length === 0 ? "All valid" : `Invalid: ${badCtids.map(c=>c.ctid).join(", ")}`,
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
    const icon  = check.pass ? `${T.green}✓${T.reset}` : `${T.red}✗${T.reset}`;
    const color = check.pass ? T.reset : T.red;
    console.log(`  ${icon} ${check.name.padEnd(36)} ${T.dim}${check.detail}${T.reset}`);
    if (!check.pass) allPass = false;
  }
  console.log();

  return allPass;
}

// ─── Step 8: Write seed output ────────────────────────────────────────────────
async function writeSeedOutput(genesisBlock, vpRecord, vpKeypair, identities, content) {
  head("STEP 8: Writing Seed Output");

  const output = {
    seed_version:     "2.0.0",
    created_at:       new Date().toISOString(),
    environment:      process.env.NODE_ENV || "development",
    genesis: {
      hash:           genesisBlock.genesis_hash,
      chain_id:       GENESIS_CHAIN_ID,
      timestamp:      GENESIS_TIMESTAMP,
      signer_pk:      genesisBlock.signer_public_key,
    },
    founding_vp: {
      vp_id:          vpRecord.vp_id,
      name:           vpRecord.name,
      jurisdiction_tier: vpRecord.jurisdiction_tier,
      public_key:     vpRecord.public_key || vpKeypair.publicKey,
      // NOTE: VP private key intentionally NOT stored in seed output
      // It is stored in genesis-keys.json which must be kept secure
    },
    genesis_ring: identities.map(i => ({
      tag:            i.tag,
      name:           i.name,
      role:           i.role,
      tip_id:         i.tip_id,
      founding:       true,
      score:          i.score,
      registered_at:  i.registered_at,
      // Private keys stored in separate secure file — see below
    })),
    sample_content: content.map(c => ({
      origin:         c.origin,
      origin_label:   ORIGIN_LABELS[c.origin],
      title:          c.title,
      ctid:           c.ctid,
      status:         c.status,
    })),
  };

  // Write non-sensitive seed output
  fs.writeFileSync(SEED_FILE, JSON.stringify(output, null, 2));
  ok(`Seed output written to: ${SEED_FILE}`);

  // Write founder private keys to a SEPARATE secure file
  const keysOutputFile = path.join(DATA_DIR, "founder-keys.json");
  const keysOutput = {
    created_at: new Date().toISOString(),
    security_notice: "HIGHLY SENSITIVE. Keep offline. Never commit to version control.",
    genesis_ring_keys: identities.map(i => ({
      tag:          i.tag,
      name:         i.name,
      tip_id:       i.tip_id,
      private_key:  i.private_key,
      public_key:   i.public_key,
    })),
    vp_private_key: vpKeypair.privateKey,
    vp_public_key:  vpKeypair.publicKey,
  };
  fs.writeFileSync(keysOutputFile, JSON.stringify(keysOutput, null, 2), { mode: 0o600 });
  ok(`Founder keys written to: ${keysOutputFile} (chmod 600)`);
  warn("SECURITY: Add genesis-data/founder-keys.json and genesis-data/genesis-keys.json to .gitignore");

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

    // Step 1: Genesis root keys
    const rootKeys = await generateGenesisKeys();
    if (genesisKeysOnly) {
      ok("Genesis keys generated. Run without --genesis-keys-only to continue.");
      return;
    }

    // Step 2: Generate founding VP keypair and embed in genesis source files
    const vpKeypair = await embedFoundingVPKey();

    // Step 3: Genesis block (uses updated genesis payload with VP public key)
    const genesisBlock = await mintGenesisBlock(rootKeys);

    // Step 3b: Initialize real DAG for direct mode
    if (useDirectMode) initDirectDAG();

    // Step 4: Founding VP
    const { vpRecord } = await registerFoundingVP(genesisBlock, vpKeypair);

    // Step 5: Genesis Ring
    const identities = await createGenesisRing(vpRecord, vpKeypair);

    // Step 6: Sample content
    const content = await registerSampleContent(identities);

    // Step 7: Verification
    const allPass = await verifyDAGState(genesisBlock, vpRecord, vpKeypair, identities, content);

    // Step 8: Write output
    const output = await writeSeedOutput(genesisBlock, vpRecord, vpKeypair, identities, content);

    // ── Final summary ────────────────────────────────────────────────────────
    head("SEED COMPLETE");
    label("Genesis hash",        output.genesis.hash.slice(0, 48) + "...");
    label("Chain ID",            output.genesis.chain_id);
    label("Founding VP",         output.founding_vp.vp_id);
    label("Genesis ring members", output.genesis_ring.length.toString());
    label("Sample content",      `${output.sample_content.length} records (OH, AA, AG, MX)`);
    if (_dag) label("DAG transactions", `${_dag.count()}`);
    label("Validation",          allPass ? `${T.green}All checks passed${T.reset}` : `${T.red}Some checks failed${T.reset}`);
    console.log();
    ok(`${T.bold}TIP™ Protocol genesis complete.${T.reset}`);
    console.log();
    if (!allPass) {
      warn("Some validation checks failed. Review the output above.");
      process.exit(1);
    }

    // Close DAG
    if (_dag) {
      _dag.close();
      ok(`DAG closed. Seed DB: ${path.join(DATA_DIR, "seed.db")}`);
    }

  } catch (err) {
    if (_dag) _dag.close();
    console.error(`\n${T.red}${T.bold}SEED FAILED:${T.reset} ${err.message}`);
    if (process.env.TIP_LOG_LEVEL === "debug") console.error(err.stack);
    process.exit(1);
  }
}

main();
