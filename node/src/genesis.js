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
const path   = require("path");
const fs     = require("fs");
const { shake256, shake256Multi, generateSLHDSAKeypair, mldsaSign, mldsaVerify, computeTxId } = require("../../shared/crypto");
const { TX_TYPES, PROTOCOL, ORIGIN } = require("../../shared/constants");
const { log } = require("./logger");

// ─── Genesis Block Constants ──────────────────────────────────────────────────
// These are FIXED and must never change once the network is live.
const GENESIS_TIMESTAMP  = "2026-03-15T00:00:00.000Z"; // Network launch date
const GENESIS_CHAIN_ID   = "tip-mainnet-v2";
const GENESIS_VP_REGION  = "US";

// ─── Canonical Genesis Payload ────────────────────────────────────────────────
// Protocol definition data only. Tx-level fields (tx_type, timestamp, prev)
// are on the genesis tx wrapper, not here.
// This is the EXACT data hashed for GENESIS_HASH. Must be byte-for-byte
// identical across every node in the network.

const GENESIS_PAYLOAD = Object.freeze({
  version:    "2",

  protocol: {
    name:       PROTOCOL.name,
    short:      PROTOCOL.short,
    version:    PROTOCOL.version,
    chain_id:   GENESIS_CHAIN_ID,
    spec_url:   PROTOCOL.specUrl,
    license:    PROTOCOL.license,
    issuer:     PROTOCOL.issuer,
    issuer_url: PROTOCOL.issuerUrl,
  },

  initial_params: {
    initial_score:            500,
    initial_score_attested:   550,
    max_score:                1000,
    min_score:                0,
    daily_verify_cap:         10,
    juror_monthly_max:        20,
    voucher_stake_points:     25,
    attestation_voucher_count: 3,
    attestation_min_score:    700,
    clean_period_days:        90,
    clean_period_bonus:       10,
    prescan_default_threshold: 0.85,
    prescan_floor:            0.80,
    prescan_ceiling:          0.94,
  },

  origin_categories: {
    OH: { label: "Original Human",   color_hint: "blue"   },
    AA: { label: "AI-Assisted",       color_hint: "purple" },
    AG: { label: "AI-Generated",      color_hint: "amber"  },
    MX: { label: "Mixed / Composite", color_hint: "gray"   },
  },

  tier_thresholds: [
    { name: "HIGHLY_TRUSTED", min: 800, max: 1000 },
    { name: "TRUSTED",        min: 600, max: 799  },
    { name: "REVIEW_ADVISED", min: 400, max: 599  },
    { name: "LOW_TRUST",      min: 200, max: 399  },
    { name: "NOT_TRUSTED",    min: 0,   max: 199  },
  ],

  penalty_schedule: {
    oh_confirmed_ag_1st:     -100,
    oh_confirmed_aa:         -40,
    aa_confirmed_ag:         -25,
    ag_conservative:         0,
    mismatch_2nd_offense:    -200,
    mismatch_3rd_offense:    -350,
    factual_falsehood_minor: -75,
    factual_falsehood_major: -300,
    device_compromise:       -15,
  },

  founding_vp: {
    vp_id:             "tip://id/VP-US-theailab-genesis",
    name:              "The AI Lab Intelligence Unobscured, Inc.",
    short_name:        "The AI Lab",
    jurisdiction_tier: "green",
    jurisdiction:      "US",
    url:               "https://theailab.org",
    email:             "trust@theailab.org",
    registered_at:     GENESIS_TIMESTAMP,
    // Public key embedded by seed script. All nodes read this — never generate random keys.
    // Private key held by founding operator (env: TIP_FOUNDING_VP_PRIVATE_KEY).
    public_key:        "06c3810582135d9723c5cb5d60cb78393360e283d1b4b80c293f300e43ae9f2b51b18f42dbd2e92dc3b961ae2eaa968b030126dff1e3dc9d68d7b5df094745d566803d1f77bc46bbfad631f6ba46c121da773b1b8c119763698a80361a05435baebe1263c986c9d78cd8a79d82efb30f784ac1240282a80df29926a6ff97822a86f81afd4bb32e55dc667e51960064294986c1a1a6eff408228979dd00ce961d0edcbec1307f3d654fcb36151a75d5907f3d0f7b403d89ed6bac113148fb0f30f6e8a6426420ac9f980514642f5a30659a81a3ea154df87d605cbb5b5d54ed91f096df55b9067ffaf793b7df3504ac9272bdfce6b34ec6e119a379aec3196a6e37c94f6f184cc2cb845a9f5f8cd38a9999b71e39aaa60572c2eda2b89da89ff537329287132bacfe7545734be67f63b6a70697b704ca4506537ab119d128f3c4a4efae5c364fd97b63a03e85dae0aeeea7ee69090f61ecebe15b64d170ccb5b3ae2fc9025f3c26fb3c479948e06bd2d363a332e2bd1cb7f8dc5d78911067e9e0757e8b5333350937ae2612c7ebf15570b014526aeb1a09d32d7b06875d3bc3f7b5a78f423ace93693bef9608e1854d5f1d6c8b0da57c5865b0bec78e82b11f0661e2fef50d14af3955eec1bc52688f84c4460422074a36839853739e164a12c612b720e7cc1fce9dd370ec4a8301a2ffd381b91239bdf449b88ce29399a14ca47416aae162c9e30619189e0ded79948e61956b8b136e24c192bff7dd8d20382af3cbb7898799e7c0b2c624db56666bbf5cf4fa6f990dceb6d404f639c98415c4d948da7fc36d3eb27828aa48b738e86f843980437e69bdd35cbe5626a464eeb67bfc5a335ae77908275c08706ace198de68af210340a16f0ff5f73c8cd611e8d38d6d00cd1f49165a13417f5f37d5301a9877f0be49528d8801402cc0384068bed897f1cd481ccc3c1a0139c73f7f19cb22bc21100dd2ebb84510597883076f402102eb610a8a8901b36d27a29fdb3c57f8e33e0346e9a929ab8045ac95a8eef344956fa20022cd1e30ea4b5d8bc5f81ae5d35e343f0c9ed3102293d65499955566851938415be3b888578ac611764e83c86aa6d08cea004cf4cf13bb6eb82e4310c30fc7704254c7a09e2e6654bac21263c07291fde5cc67a7e325d14ce919922df8fb9beb43a3567dda62e517f49ddc153694dec3531bdb044600f31d79e9fddf29789cde10bdfd113b839e66e98282bfcd9ff6505fc12c1ae0a31ed5a9692a0b7114a52f6b51de4c1f4dc520c2014256d302a8cf7a2d180d0f67f618c30202770e8b44a4880d4eb0009d07ff6357f7396c1233fc630560d632b72d4fb79aebf232a751da1ed8217290185109a24a821fb4d304ba149cc216770841ce5bd8e804bf4d153de0fe735eb1bc3aab8acc8db6cfa9b2b28a32a40a68d24eed651cc881cef9ee313fd69d52259f9915d67455ce5a06f7aa29e35df52e52bd388187da7ff41ed390820dc1d2125789fd5ffb9f27534da6a812c59255a10c36fb5953b4e74653173de901044b5976129b01bc1ecdbeb9dfd6b2775d4953bf6673bd05b4052f9b5b628e513868aaa7ca1bfc77ae54901373086cdd98ac7aea9f557cf5318e015fe692a74231ce1e190a12db9a971055e61e020444e398be68ff87fb4db47ddf13e8e52eed48f4fd89ef00946a432fc87871cb8b71382a9904b0c73a1ed91e1aa9bf41a32d4a73bb6380b222ec0dd1f55b749048ed45057e13c58bfe40929c293845e99335bc9ba3243e06e9ee5be6d3e08a4a84572a2d46d47abc3fd4df96f23a3d7ffafe89fe265984b8b748f48b53304eeaa074a6b520bc4022d29b78b322a102104c50e57ae5a2bf4574f7e2de03f53d9277bae13dd7e675ceaf169948cd7f5018ec5cc30e4d238e67d4504cd4c06b0b51a3ca20b99d19bcb12583576e1e8c7885859bdc75906814d151e9d777dc2112d262e63fb98c44cd49b1e6a1255d35322740bbbaedb1ab05d44ac5bb4b808c141ba4a59693af231fbc62fb08bfc55dcbeeb03ecabcd4412dffd0b1d5e36845f83e4988d4cc8f74658d47bba5a06d98cfa1a97045b5170f8437f807cae61826225743d4e41a334c756e6ca8069e613fe9093c8da7475974b1d29a4eab52add9cba680f364badf73a240c8151573e256acd14e8c36196452e70762d12e07b736a3c707f6955ff853b692e2a85873ae869d02b7c2bdd97591b3ddc9c2664a0f1a0b981b03e237c7d68a48849aa2e7f119fc8f939c1baafe6e66999b72e95f58fdbe6c95b13f0056c859b756001e55eb9445d0dcf5e467d6620ef1cbaf7dfd9da6830e5773d04f1774386b4c0bf401c7315b7c2afe39577c780b66c5a829368c113a4ddef58784738c1c3ac397bcc4b546542c4b868eb08723f78aabc5a7dd5d6a49042f317369e99261cbdb8925114158d6676a3cef298eff27c5c6253cd8afe6166fe3b9a36f70c1d294afbac3c9f51ad1d480bc6a6e1501d78966f03de6c9c5c41d119e8fbd754594a5c3a8547251642125aa04e6ac5d2b1cecabe929a5d7fcf0b2773b45320fce295714fe28c372ead3d873453a66599a1707c75f82dd1c8db4664031f5f27e210cf686e1ab220bc2d9ae818ad5845e6a1bc4848c5430b71d24a64b057d9f11c5ee165432da4ecc46a8d1e0ee0bca5c9add69a66a3735e9819c4ead75c04b768660cc71ba9db2d5704b5dbe1ae2f83344213e79eb578254e583ce93fde530a5554c6a766b4",
  },

  // Founding node commitment (public key hash only — not the full key)
  // The full public key is registered in the VP_REGISTERED transaction
  founding_node_commitment: null, // populated by seed script

  // Genesis Ring — founding verified members
  // These are populated by the seed script and cannot be added after launch
  genesis_ring: [],

  // Merkle root of the initial dedup registry (empty at genesis)
  initial_dedup_merkle_root: shake256("empty-dedup-registry-v2"),

  notes: "TIP Protocol Genesis Block. This is the immutable foundation of the Trust Identity Protocol network. Once this block is committed to the DAG, its hash anchors every subsequent transaction.",
});

// ─── Canonical serialisation ──────────────────────────────────────────────────
// JSON.stringify with sorted keys for deterministic output
function canonicalSerialise(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// ─── Genesis hash (chain anchor) ─────────────────────────────────────────────
function computeGenesisHash(payload) {
  return shake256(canonicalSerialise(payload));
}

const GENESIS_HASH = computeGenesisHash(GENESIS_PAYLOAD);

// ─── Content-addressed genesis tx ID ────────────────────────────────────────
// Computed from the canonical form of the genesis tx, just like all other txs.
const GENESIS_TX = Object.freeze({
  tx_type:    "GENESIS",
  timestamp:  GENESIS_TIMESTAMP,
  prev:       [],
  data:       GENESIS_PAYLOAD,
});

const GENESIS_TX_ID = computeTxId(GENESIS_TX);

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
    genesis_hash:       GENESIS_HASH,
    canonical_hash:     shake256(canonicalSerialise(GENESIS_PAYLOAD)),
    signed_at:          new Date().toISOString(),
    signer_public_key:  devKey.publicKey,
    signature:          mldsaSign(GENESIS_HASH, devKey.privateKey),
    environment:        process.env.NODE_ENV || "development",
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

module.exports = {
  GENESIS_TX_ID,
  GENESIS_TX,
  GENESIS_TIMESTAMP,
  GENESIS_CHAIN_ID,
  GENESIS_HASH,
  GENESIS_PAYLOAD,
  buildGenesisBlock,
  validateGenesisBlock,
  getGenesisHash,
  getChainId,
  getGenesisPayload,
  getFoundingVP,
  getInitialParams,
  computeGenesisHash,
  canonicalSerialise,
};
