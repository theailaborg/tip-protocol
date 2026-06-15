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
const { nowMs } = require("./time");

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

/**
 * Incremental SHAKE-256 hasher for streaming inputs (large media uploads).
 * Same digest as shake256() for the same bytes — call .update(chunk) per
 * chunk, then .digest("hex") once.
 * @param {number} outputBytes  Default 32 (256 bits)
 * @returns {import('crypto').Hash}
 */
function shake256Incremental(outputBytes = 32) {
  return crypto.createHash("shake256", { outputLength: outputBytes });
}

// ─── ML-DSA-65 KEYPAIR (Dilithium, FIPS 204) ─────────────────────────────────
// Uses @noble/post-quantum (ESM) via a lazy async initialiser.
// Call `await initCrypto()` once at process startup before using any PQ function.

/** @type {import('@noble/post-quantum/ml-dsa.js').ml_dsa65 | null} */
let _mlDsa = null;
/** @type {import('@noble/post-quantum/slh-dsa.js').slh_dsa_shake_128s | null} */
let _slhDsa = null;

/**
 * Initialise the post-quantum crypto layer.
 * Must be awaited once before calling any PQ keygen / sign / verify function.
 * Safe to call multiple times (no-op after first call).
 */
async function initCrypto() {
  if (_mlDsa && _slhDsa) return;
  const [{ ml_dsa65 }, { slh_dsa_shake_128s }] = await Promise.all([
    import("@noble/post-quantum/ml-dsa.js"),
    import("@noble/post-quantum/slh-dsa.js"),
  ]);
  _mlDsa = ml_dsa65;
  _slhDsa = slh_dsa_shake_128s;
}

function _requirePQ() {
  if (!_mlDsa) throw new Error("PQ crypto not initialised — await initCrypto() first");
  return _mlDsa;
}

function _requireSLH() {
  if (!_slhDsa) throw new Error("PQ crypto not initialised — await initCrypto() first");
  return _slhDsa;
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
 *
 * By default uses HEDGED mode (per @noble/post-quantum default — fresh
 * entropy mixed in on every call). Hedged signatures defend against fault
 * injection + side-channel attacks where an adversary can observe many
 * signs of the same message. This is the right mode for runtime user
 * signing (disputes, votes, registrations) where the same key signs many
 * messages over time on a user's device.
 *
 * Pass `{ deterministic: true }` to switch to DETERMINISTIC mode (FIPS 204
 * §3.6, `extraEntropy: false`). Same key + same message produces a
 * byte-identical signature. Use this for genesis-time signing where
 * reproducibility is operationally valuable (stable genesis_hash across
 * re-seeds) and the threat model excludes fault-injection (key is signed
 * a small fixed number of times, then ideally retired or kept offline).
 * See `npm run seed` flow in scripts/seed.js for the canonical callers.
 *
 * @param {string|Buffer} data
 * @param {string} privateKeyHex
 * @param {Object} [opts]
 * @param {boolean} [opts.deterministic=false]
 * @returns {string} signature hex
 */
function mldsaSign(data, privateKeyHex, { deterministic = false } = {}) {
  const mlDsa = _requirePQ();
  const secretKey = new Uint8Array(Buffer.from(privateKeyHex, "hex"));
  const msg = typeof data === "string" ? Buffer.from(data) : data;
  const signOpts = deterministic ? { extraEntropy: false } : {};
  return Buffer.from(mlDsa.sign(msg, secretKey, signOpts)).toString("hex");
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

// ─── Crypto-agility dispatcher (GH #51) ──────────────────────────────────────
//
// Verifies a signature against (message, signature, public_key) using the
// algorithm declared on the signing key's row. Today only ML-DSA-65 is
// supported; future algorithms (ML-DSA-87, SLH-DSA, hybrid pq+classical)
// add a branch here + a constant in SIGNATURE_ALGORITHM. The signing
// algorithm is NEVER inlined per-signature — it's bound to the public
// key's registration. Avoids JWT-style "alg: none" downgrade attacks
// and keeps the wire compact.
//
// Throws on unknown algorithm so a misconfigured key isn't silently
// passing verification.
function verifyWithAlgorithm(message, signatureHex, publicKeyHex, algorithm) {
  // Constants imported lazily to avoid a circular dependency with
  // shared/constants.js — constants.js doesn't depend on crypto.js but
  // some test fixtures `require("shared/crypto")` first.
  const { SIGNATURE_ALGORITHM, SIGNATURE_ALGORITHM_DEFAULT } = require("./constants");
  const alg = algorithm || SIGNATURE_ALGORITHM_DEFAULT;
  switch (alg) {
    case SIGNATURE_ALGORITHM.ML_DSA_65:
      return mldsaVerify(message, signatureHex, publicKeyHex);
    // Future: case SIGNATURE_ALGORITHM.ML_DSA_87: return mldsa87Verify(...)
    // Future: case SIGNATURE_ALGORITHM.SLH_DSA_128S: return slhdsaVerify(...)
    // Future: case SIGNATURE_ALGORITHM.HYBRID_ML_DSA_65_ECDSA_P256: return hybridVerify(...)
    default:
      throw new Error(`verifyWithAlgorithm: unsupported algorithm "${alg}"`);
  }
}

// Symmetric signer dispatch. Same future-proofing as verifyWithAlgorithm.
function signWithAlgorithm(message, privateKeyHex, algorithm, opts = {}) {
  const { SIGNATURE_ALGORITHM, SIGNATURE_ALGORITHM_DEFAULT } = require("./constants");
  const alg = algorithm || SIGNATURE_ALGORITHM_DEFAULT;
  switch (alg) {
    case SIGNATURE_ALGORITHM.ML_DSA_65:
      return mldsaSign(message, privateKeyHex, opts);
    default:
      throw new Error(`signWithAlgorithm: unsupported algorithm "${alg}"`);
  }
}

// ─── SLH-DSA-128s ROOT KEY (SPHINCS+, FIPS 205) ──────────────────────────────
// Used for root identity keys and VP certificates.
// FIPS 205 compliant via @noble/post-quantum.
// publicKey: 32 bytes, secretKey: 64 bytes, signature: 7856 bytes

/**
 * Generate an SLH-DSA-SHAKE-128s keypair (FIPS 205).
 * Returns { publicKey: hex, privateKey: hex, algorithm: 'SLH-DSA-128s' }
 */
function generateSLHDSAKeypair() {
  const slhDsa = _requireSLH();
  const seed = crypto.getRandomValues(new Uint8Array(48)); // 3 × N (N=16)
  const { publicKey, secretKey } = slhDsa.keygen(seed);
  return {
    algorithm: "SLH-DSA-128s",
    publicKey: Buffer.from(publicKey).toString("hex"),
    privateKey: Buffer.from(secretKey).toString("hex"),
  };
}

/**
 * Sign data with an SLH-DSA-SHAKE-128s secret key.
 * @param {string|Buffer} data
 * @param {string} privateKeyHex
 * @returns {string} signature hex
 */
function slhdsaSign(data, privateKeyHex) {
  const slhDsa = _requireSLH();
  const secretKey = new Uint8Array(Buffer.from(privateKeyHex, "hex"));
  const msg = typeof data === "string" ? Buffer.from(data) : data;
  return Buffer.from(slhDsa.sign(msg, secretKey)).toString("hex");
}

/**
 * Verify an SLH-DSA-SHAKE-128s signature.
 * @param {string|Buffer} data
 * @param {string} signatureHex
 * @param {string} publicKeyHex
 * @returns {boolean}
 */
function slhdsaVerify(data, signatureHex, publicKeyHex) {
  try {
    const slhDsa = _requireSLH();
    const publicKey = new Uint8Array(Buffer.from(publicKeyHex, "hex"));
    const sig = new Uint8Array(Buffer.from(signatureHex, "hex"));
    const msg = typeof data === "string" ? Buffer.from(data) : data;
    return slhDsa.verify(sig, msg, publicKey);
  } catch {
    return false;
  }
}

// ─── CNA-2: CONTENT NORMALIZATION ALGORITHM v2 ──────────────────────────────
//
// Produces identical SHAKE-256 hashes for semantically identical content
// regardless of platform formatting, encoding, or syndication.
// Keeps ONLY Unicode lowercase letters, numbers, and combining marks.
//
// 10-step pipeline:
//   0. Strip TIP artifacts        (CTIDs, TIP-IDs, VP-IDs, promotional boilerplate)
//   1. Decode URL encoding        (%XX -> chars)
//   2. Strip CDATA wrappers       (RSS/Atom syndication)
//   3. Strip HTML/XML tags        (<tag> -> "")
//   4. Decode numeric entities    (&#233; -> char, &#xE9; -> char)
//   5. Remove named entities      (&amp; &nbsp; etc. -> "")
//   6. Strip Markdown URLs        (keep link text, remove targets)
//   7. Unicode NFC                (canonical composition)
//   8. Lowercase                  (case-insensitive matching)
//   9. Keep only \p{L}, \p{N}, \p{M}  (strips whitespace, punctuation, symbols)
//
// Step 0 exists for verification round-trip correctness: the CTID is derived
// FROM the content hash, so it cannot exist until after registration. When a
// verifier later re-hashes the published post (which now includes the pasted
// CTID), stripping TIP artifacts ensures the hash still matches.

const TIP_URI_PATTERN = /tip:\/\/(?:id|vp)\/[A-Z]{2}-[0-9a-f]{16}/gi;
const TIP_CTID_URI_PATTERN = /tip:\/\/c\/(?:OH|AA|AG|MX)-[0-9a-f]{14}-[0-9a-f]{4}/gi;
const TIP_BARE_CTID_PATTERN = /\b(?:OH|AA|AG|MX)-[0-9a-f]{14}-[0-9a-f]{4}\b/g;
const TIP_PROMO_PATTERNS = [
  /\bpowered\s+by\s+tip(?:\s+protocol)?\b/gi,
  /\bai\s+trust\s+id\b/gi,
  /\bai\s+trust\s+registry\b/gi,
  /\btrust\s+seal\b/gi,
  /\bverified\s+by\s+tip\b/gi,
  /\btip[\s-]+verified\b/gi,
  /\btip[\s-]+powered\b/gi,
  /\btip\s+protocol\b/gi,
  /#\s*(?:tip|tipprotocol|aitrustid|aitrustregistry|tipverified)\b/gi,
];

function stripTipArtifacts(text) {
  if (!text) return '';
  let s = text;
  s = s.replace(TIP_URI_PATTERN, '');
  s = s.replace(TIP_CTID_URI_PATTERN, '');
  s = s.replace(TIP_BARE_CTID_PATTERN, '');
  for (const re of TIP_PROMO_PATTERNS) s = s.replace(re, '');
  return s;
}

/**
 * CNA-2 normalize content for canonical hashing.
 * @param {string} text
 * @returns {string} normalized text
 */
function tipNormalize(text) {
  if (!text) return '';
  let s = text;
  s = stripTipArtifacts(s);
  try { s = decodeURIComponent(s.replace(/\+/g, ' ')); } catch { /* keep original */ }
  s = s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/gi, '$1');
  s = s.replace(/<[^>]+>/g, '');
  s = s.replace(/&#x([0-9a-fA-F]+);/gi, (_, h) => {
    try { return String.fromCodePoint(parseInt(h, 16)); } catch { return ''; }
  });
  s = s.replace(/&#(\d+);/g, (_, d) => {
    try { return String.fromCodePoint(parseInt(d, 10)); } catch { return ''; }
  });
  s = s.replace(/&[a-zA-Z][a-zA-Z0-9]*;/g, '');
  s = s.replace(/!\[[^\]]*\]\([^)]*\)/g, '');
  s = s.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1');
  s = s.replace(/\[([^\]]*)\]\[[^\]]*\]/g, '$1');
  s = s.replace(/^\[[^\]]+\]:\s.*$/gm, '');
  s = s.normalize('NFC');
  s = s.toLowerCase();
  s = s.replace(/[^\p{L}\p{N}\p{M}]/gu, '');
  return s;
}

// ─── CONTENT HASHING ─────────────────────────────────────────────────────────

/**
 * Compute CNA-2 normalized SHAKE-256 hash of content (used in CTID generation).
 * @param {string|Buffer} content
 * @returns {string} 14-char truncated hex (as used in tip:// URIs)
 */
function hashContent(content) {
  const normalized = typeof content === "string" ? tipNormalize(content) : content;
  const full = shake256(normalized, 32);
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
 * Generate a TIP-VP URI.
 * Format: tip://vp/[REGION]-[PQ_PUBKEY_HASH16]
 * @param {string} region         jurisdiction region code (e.g. "US", "DE")
 * @param {string} publicKeyHex   hex-encoded ML-DSA-65 public key
 * @returns {string}              tip://vp/... URI
 */
function generateVPId(region, publicKeyHex) {
  const hash16 = shake256(publicKeyHex).slice(0, 16);
  return `tip://vp/${region.toUpperCase()}-${hash16}`;
}

/**
 * Generate a TIP-NODE URI.
 * Format: tip://node/[PQ_PUBKEY_HASH16]
 * @param {string} publicKeyHex  hex-encoded ML-DSA-65 public key
 * @returns {string}             tip://node/... URI
 */
function generateNodeId(publicKeyHex) {
  const hash16 = shake256(publicKeyHex).slice(0, 16);
  return `tip://node/${hash16}`;
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
function signTransaction(tx, privateKeyHex, opts = {}) {
  if (!tx.timestamp) tx = { ...tx, timestamp: nowMs() };
  // NOTE: prev must be set before calling this so tx_id commits to chain position.
  // dag.addTx() sets prev first, then calls computeTxId — do not reverse that order.
  const canonical = canonicalTx(tx);
  // opts plumbs `{ deterministic: true }` through to mldsaSign for the genesis
  // signing path. Old 2-arg callers get opts={} → hedged (same behaviour as before).
  const sig = mldsaSign(canonical, privateKeyHex, opts);
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
    data: tx.data,
    prev: tx.prev || [],
    timestamp: tx.timestamp,
    tx_type: tx.tx_type,
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
  return computeTxId(tx) === tx.tx_id;
}

/**
 * Deterministic JSON serialisation with sorted keys at all nesting levels.
 * Used for body signature verification — ensures same object always produces
 * the same hash regardless of key insertion order.
 */
function canonicalJson(obj) {
  if (obj === null || obj === undefined) return String(obj);
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJson).join(",") + "]";
  return "{" + Object.keys(obj).sort().map(k => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

/**
 * Sign a set of fields with ML-DSA-65: sign(shake256(canonicalJson(fields)), privateKey).
 * Used by clients to sign request bodies and by tests to build signatures.
 *
 * `opts` plumbs through to mldsaSign — pass `{ deterministic: true }` for the
 * genesis signing path (so signed payloads are byte-identical across re-seeds).
 * Old 2-arg callers default to opts={} → hedged signing (unchanged behaviour).
 */
function signBody(fields, privateKey, opts = {}) {
  return mldsaSign(shake256(canonicalJson(fields)), privateKey, opts);
}

/**
 * Build a canonical signed-payload object applying the universal strip rule
 * (GH #85): omit undefined and null; keep "", 0, false as intentional values.
 *
 * @param {object}   data          – source object (tx.data or request body)
 * @param {string[]} required      – fields that must be present (throws if missing/null)
 * @param {string[]} optional      – fields included only when not undefined/null
 * @returns {object} canonical payload ready for canonicalJson / shake256
 */
function buildSignedPayload(data, { required = [], optional = [] } = {}) {
  const out = {};
  for (const f of required) {
    if (data[f] === undefined || data[f] === null) {
      throw new Error(`required signed field missing: ${f}`);
    }
    out[f] = data[f];
  }
  for (const f of optional) {
    if (data[f] !== undefined && data[f] !== null) out[f] = data[f];
  }
  return out;
}

/**
 * Verify a body signature over specified fields only (ignores extra client fields).
 * GH #85: strips both undefined AND null so verifyBodySignature matches the
 * universal strip rule applied by every buildSigningPayload.
 */
function verifyBodySignature(body, signature, publicKey, fields) {
  const payload = {};
  for (const f of fields) {
    if (body[f] !== undefined && body[f] !== null) payload[f] = body[f];
  }
  return mldsaVerify(shake256(canonicalJson(payload)), signature, publicKey);
}

module.exports = {
  initCrypto,
  shake256,
  shake256Multi,
  shake256Incremental,
  generateMLDSAKeypair,
  mldsaSign,
  mldsaVerify,
  // GH #51 — crypto-agility dispatchers
  verifyWithAlgorithm,
  signWithAlgorithm,
  generateSLHDSAKeypair,
  slhdsaSign,
  slhdsaVerify,
  tipNormalize,
  hashContent,
  perceptualHashText,
  computeDedupHash,
  generateTIPID,
  generateVPId,
  generateNodeId,
  generateCTID,
  signTransaction,
  verifyTransaction,
  randomHex,
  canonicalTx,
  computeTxId,
  verifyTxId,
  canonicalJson,
  signBody,
  buildSignedPayload,
  verifyBodySignature,
};
