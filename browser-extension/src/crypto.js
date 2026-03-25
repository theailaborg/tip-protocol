/**
 * @file src/crypto.js
 * @description TIP Protocol - Browser Crypto Module
 *
 * Provides:
 *   - SHAKE-256 hashing (FIPS 202 via @noble/hashes)
 *   - Ed25519 + ML-DSA-65 hybrid key generation and signing
 *       Classical layer : Ed25519  (RFC 8032)
 *       Post-quantum layer: ML-DSA-65 (FIPS 204)
 *       Private key stored: 32-byte master seed (64 hex chars)
 *       Both layers are derived from the master seed deterministically.
 *   - Private key encryption/decryption via AES-256-GCM + PBKDF2
 *   - TIP-ID and CTID generation
 *
 * Call `await initCrypto()` once at startup before using any function.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * Author: Dinesh Mendhe <chairman@theailab.org>
 * License: TIPCL-1.0
 */

"use strict";

// ════════════════════════════════════════════════════════════════════════════
// Static imports — resolved by esbuild at build time and inlined into the
// bundle. No runtime module resolution needed in the service worker.
// ════════════════════════════════════════════════════════════════════════════

import { ml_dsa65 }             from "@noble/post-quantum/ml-dsa";
import { shake256 as _shake256 } from "@noble/hashes/sha3";
import { ed25519 }               from "@noble/curves/ed25519";

/**
 * No-op — kept for API compatibility with tests and background.js.
 * Modules are resolved at bundle time via static imports above.
 */
async function initCrypto() {}

// ════════════════════════════════════════════════════════════════════════════
// HYBRID KEY SIZES (bytes → hex chars)
//
//   Master seed (stored as "privateKey"):  32 bytes  →   64 hex chars
//   Ed25519 public key:                    32 bytes  →   64 hex chars
//   Ed25519 signature:                     64 bytes  →  128 hex chars
//   ML-DSA-65 public key:                1952 bytes  → 3904 hex chars
//   ML-DSA-65 signature:                 3309 bytes  → 6618 hex chars
//
//   Combined public key  = Ed25519 pub  ‖ ML-DSA-65 pub  → 3968 hex chars
//   Combined signature   = Ed25519 sig  ‖ ML-DSA-65 sig  → 6746 hex chars
// ════════════════════════════════════════════════════════════════════════════

const ED25519_PUB_HEX = 64;   // split point in combined public key
const ED25519_SIG_HEX = 128;  // split point in combined signature

// ════════════════════════════════════════════════════════════════════════════
// SHAKE-256 (FIPS 202)
// ════════════════════════════════════════════════════════════════════════════

/**
 * SHAKE-256 hash (FIPS 202).
 * @param {Uint8Array|string} data
 * @returns {Promise<string>} 64-char hex string (256 bits)
 */
async function shake256Async(data) {
  const input = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return bufToHex(_shake256(input, { dkLen: 32 }));
}

// ════════════════════════════════════════════════════════════════════════════
// INTERNAL — SEED DERIVATION
// ════════════════════════════════════════════════════════════════════════════

/**
 * Derive the 32-byte ML-DSA-65 seed from the 32-byte master seed.
 * Domain-separated so the two algorithm seeds are independent.
 * @param {Uint8Array} masterSeed
 * @returns {Uint8Array} 32-byte ML-DSA-65 seed
 */
function _mlDsaSeed(masterSeed) {
  const input = new Uint8Array(1 + masterSeed.length);
  input[0] = 0x01;                  // domain separator: 0x00 reserved for Ed25519
  input.set(masterSeed, 1);
  return _shake256(input, { dkLen: 32 });
}

// ════════════════════════════════════════════════════════════════════════════
// KEY GENERATION — Ed25519 + ML-DSA-65 hybrid
//
//   privateKey (returned / stored): 32-byte master seed (64 hex chars)
//   publicKey (returned / stored) : Ed25519 pub ‖ ML-DSA-65 pub (3968 hex chars)
// ════════════════════════════════════════════════════════════════════════════

/**
 * Generate a hybrid Ed25519 + ML-DSA-65 keypair from a fresh random seed.
 * @returns {Promise<{algorithm: string, publicKey: string, privateKey: string}>}
 */
async function generateKeypair() {
  // 32-byte master seed — the only secret that needs to be stored/encrypted
  const masterSeed = crypto.getRandomValues(new Uint8Array(32));

  // Ed25519: classical layer
  const ed25519Pub = ed25519.getPublicKey(masterSeed);

  // ML-DSA-65: post-quantum layer, derived from a domain-separated seed
  const { publicKey: mlDsaPub } = ml_dsa65.keygen(_mlDsaSeed(masterSeed));

  return {
    algorithm:  "Ed25519+ML-DSA-65",
    publicKey:  bufToHex(ed25519Pub) + bufToHex(mlDsaPub),
    privateKey: bufToHex(masterSeed),
  };
}

// ════════════════════════════════════════════════════════════════════════════
// SIGN / VERIFY — hybrid
// ════════════════════════════════════════════════════════════════════════════

/**
 * Sign data with the hybrid private key (32-byte master seed, hex-encoded).
 * Returns a combined hex signature: Ed25519 (128 hex) ‖ ML-DSA-65 (6618 hex).
 * @param {string} data
 * @param {string} masterSeedHex  64-char hex string (32-byte master seed)
 * @returns {Promise<string>} 6746-char hex signature
 */
async function signData(data, masterSeedHex) {
  const masterSeed = new Uint8Array(hexToBuf(masterSeedHex));
  const msg        = new TextEncoder().encode(data);

  // Ed25519 signature (deterministic — RFC 8032)
  const ed25519Sig = ed25519.sign(msg, masterSeed);

  // ML-DSA-65 signature (hedged — FIPS 204 §5.2)
  const { secretKey } = ml_dsa65.keygen(_mlDsaSeed(masterSeed));
  const mlDsaSig      = ml_dsa65.sign(secretKey, msg);

  return bufToHex(ed25519Sig) + bufToHex(mlDsaSig);
}

/**
 * Verify a hybrid signature. Both layers must pass.
 * @param {string} data
 * @param {string} signatureHex   6746-char combined hex signature
 * @param {string} publicKeyHex   3968-char combined hex public key
 * @returns {Promise<boolean>}
 */
async function verifySignature(data, signatureHex, publicKeyHex) {
  try {
    const msg = new TextEncoder().encode(data);

    // Split combined public key
    const ed25519PubHex = publicKeyHex.slice(0, ED25519_PUB_HEX);
    const mlDsaPubHex   = publicKeyHex.slice(ED25519_PUB_HEX);

    // Split combined signature
    const ed25519SigHex = signatureHex.slice(0, ED25519_SIG_HEX);
    const mlDsaSigHex   = signatureHex.slice(ED25519_SIG_HEX);

    // Both must verify — failure in either layer rejects the signature
    const ed25519Ok = ed25519.verify(
      new Uint8Array(hexToBuf(ed25519SigHex)),
      msg,
      new Uint8Array(hexToBuf(ed25519PubHex))
    );
    if (!ed25519Ok) return false;

    return ml_dsa65.verify(
      new Uint8Array(hexToBuf(mlDsaPubHex)),
      msg,
      new Uint8Array(hexToBuf(mlDsaSigHex))
    );
  } catch {
    return false;
  }
}

// ════════════════════════════════════════════════════════════════════════════
// TIP-ID AND CTID GENERATION
// ════════════════════════════════════════════════════════════════════════════

/**
 * Compute TIP-ID URI from region and public key.
 * @param {string} region e.g. "US"
 * @param {string} publicKeyHex
 * @returns {Promise<string>}
 */
async function computeTIPID(region, publicKeyHex) {
  const hash = await shake256Async(publicKeyHex);
  return `tip://id/${region.toUpperCase()}-${hash.slice(0, 16)}`;
}

/**
 * Generate CTID for content.
 * @param {string} originCode "OH"|"AA"|"AG"|"MX"
 * @param {string} content
 * @param {string} authorTipId
 * @returns {Promise<string>}
 */
async function generateCTID(originCode, content, authorTipId) {
  const contentHash = await shake256Async(content);
  const idShort     = authorTipId.split("-").pop().slice(0, 4);
  return `tip://c/${originCode}-${contentHash.slice(0, 14)}-${idShort}`;
}

// ════════════════════════════════════════════════════════════════════════════
// PRIVATE KEY ENCRYPTION - AES-256-GCM + PBKDF2
// ════════════════════════════════════════════════════════════════════════════

/**
 * Encrypt a private key hex string with a password.
 * @param {string} privateKeyHex
 * @param {string} password
 * @returns {Promise<string>} encrypted base64 string (salt+iv+ciphertext)
 */
async function encryptPrivateKey(privateKeyHex, password) {
  const salt       = crypto.getRandomValues(new Uint8Array(16));
  const iv         = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
  );
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(privateKeyHex)
  );
  const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  result.set(salt, 0);
  result.set(iv, salt.length);
  result.set(new Uint8Array(encrypted), salt.length + iv.length);
  return btoa(String.fromCharCode(...result));
}

/**
 * Decrypt a private key.
 * @param {string} encryptedB64
 * @param {string} password
 * @returns {Promise<string>} privateKeyHex
 */
async function decryptPrivateKey(encryptedB64, password) {
  const data       = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
  const salt       = data.slice(0, 16);
  const iv         = data.slice(16, 28);
  const ciphertext = data.slice(28);
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);
  return new TextDecoder().decode(decrypted);
}

// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return bytes.buffer;
}

export {
  initCrypto,
  shake256Async as shake256,
  generateKeypair,
  signData,
  verifySignature,
  computeTIPID,
  generateCTID,
  encryptPrivateKey,
  decryptPrivateKey,
};
