/**
 * @file @tip-protocol/node/src/genesis.js
 * @description TIP Protocol Genesis Block — Production Implementation
 *
 * The Genesis Block is the immutable foundation of the TIP DAG. It contains:
 *
 *   1. The protocol declaration (version, issuer, spec URL, license)
 *   2. The root Verification Provider record for The AI Lab
 *   3. The founding node keypair commitments
 *   4. The Genesis Ring: founding identities (placeholder — real identities
 *      added via the seed script before launch)
 *   5. The initial trust scoring parameters
 *   6. A cryptographic seal over the entire block using SLH-DSA-128s
 *      (the most conservative post-quantum signature scheme)
 *
 * IMMUTABILITY GUARANTEE:
 *   The Genesis Block hash is computed from a canonical serialisation of all
 *   its fields. Any node that receives a genesis block with a different hash
 *   is on a different network and cannot interoperate.
 *
 *   Every subsequent transaction references the genesis block hash, making
 *   the entire DAG history traceable back to this single anchoring event.
 *
 * PRODUCTION STEPS BEFORE LAUNCH:
 *   1. Run: node scripts/seed.js --generate-genesis-keys
 *      This produces the root SLH-DSA keypair stored in genesis-data/
 *   2. Run: node scripts/seed.js --mint-genesis
 *      This writes genesis.json with a valid signature
 *   3. Commit genesis.json (NOT the private key) to version control
 *   4. Every node validates the genesis hash on startup
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { shake256, shake256Multi, generateSLHDSAKeypair, mldsaSign, mldsaVerify, computeTxId, canonicalJson, canonicalTx } = require("../../shared/crypto");
const { nowMs, fromIso } = require("../../shared/time");
const { TX_TYPES, PROTOCOL, ORIGIN } = require("../../shared/constants");
const { log } = require("./logger");

// ─── Genesis Block Constants ──────────────────────────────────────────────────
// These are FIXED and must never change once the network is live.
// Integer epoch ms for 2026-03-15T00:00:00.000Z UTC — chain wall-clock
// anchor. Every node verifies this exact value at startup.
const GENESIS_TIMESTAMP = 1773532800000; // 2026-03-15T00:00:00.000Z UTC
const GENESIS_CHAIN_ID = "tip-mainnet-v2";
const GENESIS_VP_REGION = "US";

// Minted anchor read from genesis.json, config from genesis-config.json. {} is
// tolerated during a fresh mint: seed writes the files, then re-requires.
function _loadGenesisJson(rel) {
  try { return JSON.parse(fs.readFileSync(path.resolve(__dirname, rel), "utf8")); }
  catch { return {}; }
}
const GENESIS_DOC = _loadGenesisJson("../../genesis-data/genesis.json");
const GENESIS_CONFIG = _loadGenesisJson("../../genesis-data/genesis-config.json");

const GENESIS_PAYLOAD = Object.freeze({
  version: "2",
  protocol: {
    name: PROTOCOL.name,
    short: PROTOCOL.short,
    version: PROTOCOL.version,
    chain_id: GENESIS_CHAIN_ID,
    spec_url: PROTOCOL.specUrl,
    license: PROTOCOL.license,
    issuer: PROTOCOL.issuer,
    issuer_url: PROTOCOL.issuerUrl,
  },
  notes: "TIP Protocol Genesis Block. This is the immutable foundation of the Trust Identity Protocol network. Once this block is committed to the DAG, its hash anchors every subsequent transaction.",
  founding_vp: GENESIS_DOC.founding_vp,
  founding_node: GENESIS_DOC.founding_node,
  genesis_ring: GENESIS_DOC.genesis_ring,
  genesis_ring_keys: GENESIS_DOC.genesis_ring_keys,
  protocol_constants: GENESIS_CONFIG.protocol_constants,
});

// Commits to the whole founding record, including the height-0 params. Those are
// frozen, so genesis_hash stays stable; live param changes go through governance
// (the protocol_params table / state root), not this payload.
function computeGenesisHash(payload) {
  return shake256(canonicalJson(payload));
}

const GENESIS_HASH = computeGenesisHash(GENESIS_PAYLOAD);

// ─── Content-addressed genesis tx ID ────────────────────────────────────────
// Computed from the canonical form of the genesis tx, just like all other txs.
const GENESIS_TX = Object.freeze({
  tx_type: "GENESIS",
  timestamp: GENESIS_TIMESTAMP,
  prev: [],
  data: GENESIS_PAYLOAD,
});

const GENESIS_TX_ID = computeTxId(GENESIS_TX);

// Pre-computed signatures from seed script (founding VP signs both bootstrap txs).
// Placeholder until seed runs — seed replaces these with real ML-DSA-65 signatures.
// Bootstrap-tx signatures (founding VP signs both genesis txs). Read from
// genesis.json; the mint regenerates them there whenever the payload changes.
let GENESIS_TX_SIGNATURE = GENESIS_DOC.genesis_tx_signature || "";
let GENESIS_VP_TX_SIGNATURE = GENESIS_DOC.genesis_vp_tx_signature || "";

// ─── Load or create genesis block ────────────────────────────────────────────

/**
 * Build the complete signed genesis block.
 * In production this is loaded from genesis.json (pre-signed at launch).
 * During development a self-signed genesis is generated automatically.
 *
 * @param {string} genesisDataDir  Path where genesis.json is stored
 * @param {Object} [signingKey]    { privateKey, publicKey } — required for first mint only
 * @returns {Object} The complete genesis block
 */
function buildGenesisBlock(genesisDataDir, signingKey) {
  const genesisFile = path.join(genesisDataDir, "genesis.json");

  // If genesis.json already exists, load and validate it
  if (fs.existsSync(genesisFile)) {
    const loaded = JSON.parse(fs.readFileSync(genesisFile, "utf8"));
    if (!validateGenesisBlock(loaded)) {
      throw new Error(
        `FATAL: genesis.json hash mismatch!\n` +
        `Expected: ${GENESIS_HASH}\n` +
        `Got:      ${loaded.genesis_hash}\n` +
        `This node is on a different network or genesis.json has been tampered with.`
      );
    }
    return loaded;
  }

  // Genesis does not exist yet — build it (development / first boot)
  log.warn("genesis.json not found — generating development genesis block");
  log.warn("For production: run scripts/seed.js --mint-genesis with the official root keypair");

  const { generateMLDSAKeypair: gkp } = require("../../shared/crypto");
  const devKey = signingKey || gkp();

  const block = {
    ...GENESIS_PAYLOAD,
    genesis_hash: GENESIS_HASH,
    signed_at: nowMs(),
    signer_public_key: devKey.publicKey,
    // Deterministic so the auto-generated dev genesis is reproducible across
    // node restarts: same key + same hash → identical signature → identical
    // genesis.json on every boot from an empty data dir.
    signature: mldsaSign(GENESIS_HASH, devKey.privateKey, { deterministic: true }),
    environment: process.env.NODE_ENV || "development",
  };

  // Persist for subsequent node boots
  fs.mkdirSync(genesisDataDir, { recursive: true });
  fs.writeFileSync(genesisFile, JSON.stringify(block, null, 2));
  log.info(`Development genesis block written to ${genesisFile}`);
  log.info(`Genesis hash: ${GENESIS_HASH}`);

  return block;
}

/**
 * Validate a genesis block received from a peer or loaded from disk.
 * Returns true if the hash matches the canonical payload.
 */
function validateGenesisBlock(block) {
  if (!block || !block.genesis_hash) return false;
  const expected = computeGenesisHash(GENESIS_PAYLOAD);
  return block.genesis_hash === expected;
}

/**
 * Get the genesis hash constant (used to verify incoming peer genesis blocks).
 */
function getGenesisHash() {
  return GENESIS_HASH;
}

/**
 * Get the genesis chain ID (prevents accidental cross-network connections).
 */
function getChainId() {
  return GENESIS_CHAIN_ID;
}

/**
 * Get the genesis payload (read-only).
 */
function getGenesisPayload() {
  return Object.freeze({ ...GENESIS_PAYLOAD });
}

/**
 * Get the founding VP record from the genesis payload.
 */
function getFoundingVP() {
  return Object.freeze({ ...GENESIS_PAYLOAD.founding_vp });
}

/**
 * Get initial protocol parameters from genesis.
 */
function getInitialParams() {
  return Object.freeze({ ...GENESIS_PAYLOAD.initial_params });
}

/**
 * Genesis-anchored committee — the founding-node IDs that are admitted
 * into the runtime committee from round 1, with no K-round proven wait.
 * Late joiners (any node whose id is NOT in this set) must produce for
 * `K = COMMITTEE_ROTATION_HYSTERESIS_ROUNDS` rounds before being admitted.
 *
 * Source of truth: `GENESIS_PAYLOAD.founding_node`. If genesis later grows
 * a `founding_committee: [...]` array (multi-founder chain), surface that
 * here without changing call sites.
 *
 * @returns {Set<string>} node IDs that are genesis members
 */
function getGenesisCommittee() {
  const ids = new Set();
  if (GENESIS_PAYLOAD.founding_node && GENESIS_PAYLOAD.founding_node.node_id) {
    ids.add(GENESIS_PAYLOAD.founding_node.node_id);
  }
  if (Array.isArray(GENESIS_PAYLOAD.founding_committee)) {
    for (const m of GENESIS_PAYLOAD.founding_committee) {
      if (m && m.node_id) ids.add(m.node_id);
    }
  }
  return ids;
}

/**
 * Genesis-anchored founding identities — the TIP-IDs minted by the seed
 * script and embedded in `GENESIS_PAYLOAD.genesis_ring`. These identities
 * are materialised by `initDAG` at boot; any later `REGISTER_IDENTITY` tx
 * carrying one of these tip_ids is a replay attempt and must be rejected
 * by the bootstrap-epoch gate.
 *
 * @returns {Set<string>} TIP-IDs that are genesis-ring members
 */
function getGenesisRing() {
  const ids = new Set();
  if (Array.isArray(GENESIS_PAYLOAD.genesis_ring)) {
    for (const tip_id of GENESIS_PAYLOAD.genesis_ring) {
      if (typeof tip_id === "string" && tip_id) ids.add(tip_id);
    }
  }
  return ids;
}

function verifyGenesisSignature() {
  const valid = mldsaVerify(
    canonicalTx(GENESIS_TX),
    GENESIS_TX_SIGNATURE,
    getFoundingVP().public_key,
  );
  if (!valid) throw new Error(
    "Genesis signature does not verify against GENESIS_PAYLOAD. " +
    "GENESIS_PAYLOAD was likely edited without re-running scripts/seed.js " +
    "to regenerate GENESIS_TX_SIGNATURE. Run `npm run seed` and commit " +
    "the regenerated genesis.js before starting the node.",
  );
}

function verifyGenesisVPSignature() {
  const foundingVP = getFoundingVP();
  const vpTxBody = {
    tx_type: "VP_REGISTERED",
    timestamp: GENESIS_TIMESTAMP,
    prev: [GENESIS_TX_ID, GENESIS_TX_ID],
    data: {
      vp_id: foundingVP.vp_id,
      name: foundingVP.name,
      jurisdiction: foundingVP.jurisdiction,
      jurisdiction_tier: foundingVP.jurisdiction_tier,
      public_key: foundingVP.public_key,
    },
  };
  const valid = mldsaVerify(
    canonicalTx(vpTxBody),
    GENESIS_VP_TX_SIGNATURE,
    foundingVP.public_key,
  );
  if (!valid) throw new Error(
    "VP genesis signature does not verify against GENESIS_PAYLOAD.founding_vp. " +
    "GENESIS_PAYLOAD.founding_vp was likely edited without re-running scripts/seed.js " +
    "to regenerate GENESIS_VP_TX_SIGNATURE. Run `npm run seed` and commit " +
    "the regenerated genesis.js before starting the node.",
  );
}

// PQ crypto (ML-DSA) requires an async initCrypto() call before it can verify.
// genesis.js is loaded synchronously at module scope (before initCrypto runs),
// so these checks cannot auto-run here. They are called explicitly from
// node/src/index.js right after initCrypto(), ensuring they fire before any
// DAG writes. Tests call them in beforeAll after initCrypto().

module.exports = {
  GENESIS_TX_ID,
  GENESIS_TX,
  GENESIS_TIMESTAMP,
  GENESIS_CHAIN_ID,
  GENESIS_HASH,
  GENESIS_PAYLOAD,
  GENESIS_TX_SIGNATURE,
  GENESIS_VP_TX_SIGNATURE,
  buildGenesisBlock,
  validateGenesisBlock,
  getGenesisHash,
  getChainId,
  getGenesisPayload,
  getFoundingVP,
  getInitialParams,
  getGenesisCommittee,
  getGenesisRing,
  computeGenesisHash,
  verifyGenesisSignature,
  verifyGenesisVPSignature,
};
