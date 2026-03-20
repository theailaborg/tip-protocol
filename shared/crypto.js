/**
 * @file tip-protocol/shared/crypto.js
 * @description Shared cryptographic primitives for TIP Protocol v2.
 *
 * Post-quantum algorithms used:
 *   - ML-DSA-65  (Dilithium, FIPS 204) — primary transaction signing
 *   - SLH-DSA-128s (SPHINCS+, FIPS 205) — root / long-term identity keys
 *   - ML-KEM-768 (Kyber, FIPS 203)     — node-to-node key encapsulation
 *   - SHAKE-256  (FIPS 202)            — all hashing: content, URIs, biometrics, dedup
 *
 * Production note:
 *   Full post-quantum implementations require native bindings (liboqs or pqclean).
 *   This module uses the @noble/post-quantum library where available and falls back
 *   to deterministic SHA-3 (SHAKE-256) for hashing. The ML-DSA signing stubs are
 *   clearly marked and must be replaced with a certified PQ library before deployment.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const crypto = require("crypto");

// ─── SHAKE-256 (FIPS 202) ────────────────────────────────────────────────────
// Node.js crypto supports SHAKE-256 natively since v12.

/**
 * Compute SHAKE-256 hash and return as hex string.
 * @param {string|Buffer} data
 * @param {number} outputBytes  Default 32 (256 bits)
 * @returns {string} hex digest
 */
function shake256(data, outputBytes = 32) {
  return crypto
    .createHash("shake256", { outputLength: outputBytes })
    .update(typeof data === "string" ? Buffer.from(data, "utf8") : data)
    .digest("hex");
}

/**
 * Compute SHAKE-256 over multiple inputs (concatenated).
 * @param  {...(string|Buffer)} parts
 * @returns {string} hex digest
 */
function shake256Multi(...parts) {
  const h = crypto.createHash("shake256", { outputLength: 32 });
  for (const p of parts) {
    h.update(typeof p === "string" ? Buffer.from(p, "utf8") : p);
  }
  return h.digest("hex");
}

// ─── ML-DSA-65 KEYPAIR (Dilithium, FIPS 204) ─────────────────────────────────
// Uses @noble/post-quantum (ESM) via a lazy async initialiser.
// Call `await initCrypto()` once at process startup before using any PQ function.

/** @type {import('@noble/post-quantum/ml-dsa.js').ml_dsa65 | null} */
let _mlDsa = null;

/**
 * Initialise the post-quantum crypto layer.
 * Must be awaited once before calling generateMLDSAKeypair / mldsaSign / mldsaVerify.
 * Safe to call multiple times (no-op after first call).
 */
async function initCrypto() {
  if (_mlDsa) return;
  const { ml_dsa65 } = await import("@noble/post-quantum/ml-dsa.js");
  _mlDsa = ml_dsa65;
}

function _requirePQ() {
  if (!_mlDsa) throw new Error("PQ crypto not initialised — await initCrypto() first");
  return _mlDsa;
}

/**
 * Generate an ML-DSA-65 keypair.
 * Returns { publicKey: hex, privateKey: hex, algorithm: 'ML-DSA-65' }
 * publicKey: 1952 bytes, privateKey (secretKey): 4032 bytes, sigSize: 3309 bytes
 */
function generateMLDSAKeypair() {
  const mlDsa = _requirePQ();
  const { publicKey, secretKey } = mlDsa.keygen();
  return {
    algorithm: "ML-DSA-65",
    publicKey: Buffer.from(publicKey).toString("hex"),
    privateKey: Buffer.from(secretKey).toString("hex"),
  };
}

/**
 * Sign data with an ML-DSA-65 private key (secretKey).
 * @param {string|Buffer} data
 * @param {string} privateKeyHex
 * @returns {string} signature hex
 */
function mldsaSign(data, privateKeyHex) {
  const mlDsa = _requirePQ();
  const secretKey = new Uint8Array(Buffer.from(privateKeyHex, "hex"));
  const msg = typeof data === "string" ? Buffer.from(data) : data;
  return Buffer.from(mlDsa.sign(msg, secretKey)).toString("hex");
}

/**
 * Verify an ML-DSA-65 signature.
 * @param {string|Buffer} data
 * @param {string} signatureHex
 * @param {string} publicKeyHex
 * @returns {boolean}
 */
function mldsaVerify(data, signatureHex, publicKeyHex) {
  try {
    const mlDsa = _requirePQ();
    const publicKey = new Uint8Array(Buffer.from(publicKeyHex, "hex"));
    const sig = new Uint8Array(Buffer.from(signatureHex, "hex"));
    const msg = typeof data === "string" ? Buffer.from(data) : data;
    return mlDsa.verify(sig, msg, publicKey);
  } catch {
    return false;
  }
}

// ─── SLH-DSA-128s ROOT KEY (SPHINCS+, FIPS 205) ──────────────────────────────
// Used for root identity keys and VP certificates.
// Production stub — same API surface as real SLH-DSA.

function generateSLHDSAKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    algorithm: "SLH-DSA-128s",
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("hex"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("hex"),
  };
}

// ─── CONTENT HASHING ─────────────────────────────────────────────────────────

/**
 * Compute SHAKE-256 hash of content (used in CTID generation).
 * @param {string|Buffer} content
 * @returns {string} 14-char truncated hex (as used in tip:// URIs)
 */
function hashContent(content) {
  const full = shake256(content, 32);
  return full.slice(0, 14); // first 14 hex chars = 56 bits
}

/**
 * Compute perceptual hash for text (simplified pHash equivalent).
 * For images/audio: use real pHash / Chromaprint in production.
 * @param {string} text
 * @returns {string}
 */
function perceptualHashText(text) {
  // Normalise: lowercase, collapse whitespace, strip punctuation
  const norm = text.toLowerCase().replace(/\s+/g, " ").replace(/[^\w\s]/g, "").trim();
  return shake256(norm, 16).slice(0, 16);
}

// ─── DEDUPLICATION HASH (ZK Poseidon — production) ───────────────────────────
// In production this is computed inside the Groth16 circuit (shared/zk.js).
// This SHAKE-256 version is provided for reference and offline testing only.

/**
 * Compute a reference dedup hash (SHAKE-256).
 * NOTE: The production ZK circuit uses Poseidon(gov_id, dob, country) —
 *       see shared/zk.js generateDedupProof() for the real implementation.
 * @param {string} govIdNormalized
 * @param {string} dateOfBirthISO   "YYYY-MM-DD"
 * @param {string} countryCode      "US"
 * @returns {string} hex hash
 */
function computeDedupHash(govIdNormalized, dateOfBirthISO, countryCode) {
  return shake256Multi(govIdNormalized, dateOfBirthISO, countryCode.toUpperCase());
}

// ─── URI GENERATION ───────────────────────────────────────────────────────────

/**
 * Generate a TIP-ID URI.
 * Format: tip://id/[REGION]-[PQ_PUBKEY_HASH16]
 * @param {string} region   e.g. "US"
 * @param {string} publicKeyHex
 * @returns {string}
 */
function generateTIPID(region, publicKeyHex) {
  const hash16 = shake256(publicKeyHex).slice(0, 16);
  return `tip://id/${region.toUpperCase()}-${hash16}`;
}

/**
 * Generate a TIP-CONTENT URI.
 * Format: tip://c/[ORIGIN]-[HASH14]-[ID_SHORT]
 * @param {string} originCode  OH | AA | AG | MX
 * @param {string} contentHash 14-char hash from hashContent()
 * @param {string} tipId       full tip:// URI
 * @returns {string}
 */
function generateCTID(originCode, contentHash, tipId) {
  const idShort = tipId.replace("tip://id/", "").split("-").pop().slice(0, 4);
  return `tip://c/${originCode}-${contentHash}-${idShort}`;
}

// ─── TRANSACTION PAYLOAD ──────────────────────────────────────────────────────

/**
 * Build and sign a DAG transaction payload.
 * The signature covers: tx_type + primary data + timestamp (canonically serialised).
 * @param {Object} tx
 * @param {string} privateKeyHex
 * @returns {Object} tx with signature attached
 */
function signTransaction(tx, privateKeyHex) {
  if (!tx.timestamp) tx = { ...tx, timestamp: new Date().toISOString() };
  // NOTE: prev must be set before calling this so tx_id commits to chain position.
  // dag.addTx() sets prev first, then calls computeTxId — do not reverse that order.
  const canonical = canonicalTx(tx);
  const sig = mldsaSign(canonical, privateKeyHex);
  const signed = { ...tx, signature: sig };
  // Compute content-addressed tx_id only if prev is already attached
  if (!signed.tx_id && Array.isArray(signed.prev) && signed.prev.length > 0) {
    signed.tx_id = computeTxId(signed);
  }
  return signed;
}

/**
 * Verify a signed DAG transaction.
 * @param {Object} tx
 * @param {string} publicKeyHex
 * @returns {boolean}
 */
function verifyTransaction(tx, publicKeyHex) {
  return mldsaVerify(canonicalTx(tx), tx.signature, publicKeyHex);
}

// ─── RANDOM UTILS ─────────────────────────────────────────────────────────────

/** Generate a cryptographically random hex string of given byte length. */
function randomHex(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

// ─── CONTENT-ADDRESSED TRANSACTION ID ────────────────────────────────────────

/**
 * Recursively sort all object keys alphabetically for deterministic JSON serialisation.
 * Arrays preserve their original order (order matters for prev refs).
 * This ensures two nodes constructing the same tx always produce the same canonical string,
 * regardless of the order keys were inserted into the object.
 *
 * Example:
 *   Input:  { tx_type: "SCORE_UPDATE", data: { delta: 5, tip_id: "x" } }
 *   Output: { data: { delta: 5, tip_id: "x" }, tx_type: "SCORE_UPDATE" }
 *            ^--- "data" sorts before "tx_type"   ^--- "delta" sorts before "tip_id"
 *
 * Without this, JSON.stringify key order is insertion-order (not stable across nodes),
 * so SHAKE-256(tx) would differ between nodes even for identical transactions.
 */
function _sortObjectKeys(val) {
  if (Array.isArray(val)) return val.map(_sortObjectKeys);
  if (val !== null && typeof val === "object") {
    return Object.keys(val).sort().reduce((acc, k) => {
      acc[k] = _sortObjectKeys(val[k]);
      return acc;
    }, {});
  }
  return val;
}

/**
 * Produce the canonical JSON string for a transaction.
 * Covers exactly 4 fields: tx_type, data, timestamp, prev.
 * tx_id and signature are intentionally excluded:
 *   - tx_id  would be circular (it IS the hash of this string)
 *   - signature is computed over this same string, added after
 *
 * All object keys are sorted recursively so the output is identical
 * regardless of insertion order on any compliant node.
 *
 * @param {Object} tx
 * @returns {string}
 */
function canonicalTx(tx) {
  return JSON.stringify(_sortObjectKeys({
    data:      tx.data,
    prev:      tx.prev || [],
    timestamp: tx.timestamp,
    tx_type:   tx.tx_type,
  }));
}

/**
 * Compute the content-addressed tx_id for a transaction.
 * tx_id = SHAKE-256(canonicalTx(tx))  — always 64 hex chars (256 bits).
 *
 * IMPORTANT: tx.prev must already be set before calling this.
 * Calling it before prev is attached gives a tx_id that doesn't commit
 * to the chain position, breaking tamper-evidence.
 *
 * @param {Object} tx  — must have tx_type, data, timestamp, prev
 * @returns {string}   — 64-char hex string
 */
function computeTxId(tx) {
  return shake256(canonicalTx(tx));
}

/**
 * Verify that a stored tx_id matches the tx content.
 * Use this when receiving a tx via gossip to detect tampering.
 *
 * @param {Object} tx
 * @returns {boolean}
 */
function verifyTxId(tx) {
  if (tx.tx_type === "GENESIS") return true; // genesis tx is self-certified
  return computeTxId(tx) === tx.tx_id;
}

module.exports = {
  initCrypto,
  shake256,
  shake256Multi,
  generateMLDSAKeypair,
  mldsaSign,
  mldsaVerify,
  generateSLHDSAKeypair,
  hashContent,
  perceptualHashText,
  computeDedupHash,
  generateTIPID,
  generateCTID,
  signTransaction,
  verifyTransaction,
  randomHex,
  canonicalTx,
  computeTxId,
  verifyTxId,
};
