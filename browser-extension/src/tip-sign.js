/**
 * @file browser-extension/src/tip-sign.js
 * @description TIP Protocol body signature helpers for the browser extension.
 *
 * Uses pure ML-DSA-65 (no hybrid) to match the node's verifyBodySignature.
 * The node verifies: mldsaVerify(shake256(canonicalJson(fields)), signature, publicKey)
 *
 * This file is separate from crypto.js (which has hybrid Ed25519+ML-DSA-65)
 * so we don't break existing key generation / passkey encryption.
 */

import { ml_dsa65 }             from "@noble/post-quantum/ml-dsa";
import { shake256 as _shake256 } from "@noble/hashes/sha3";

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Deterministic JSON with sorted keys at all levels.
 * Must produce identical output to shared/crypto.js canonicalJson
 * and python/shared/crypto.py canonical_json.
 */
export function canonicalJson(obj) {
  if (obj === null || obj === undefined) return String(obj);
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJson).join(",") + "]";
  return "{" + Object.keys(obj).sort().map(k => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

/**
 * SHAKE-256 hash → 64-char hex string.
 */
export function tipShake256(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  return bufToHex(_shake256(bytes, { dkLen: 32 }));
}

/**
 * Sign a set of fields with ML-DSA-65 (pure, no hybrid).
 * signature = mldsaSign(shake256(canonicalJson(fields)), privateKey)
 *
 * Accepts either:
 *   - Pure ML-DSA-65 private key (from seed/node - 4032 bytes hex)
 *   - Hybrid master seed (from extension crypto.js - 32 bytes hex, derives ML-DSA key)
 *
 * @param {Object} fields  - the fields to sign
 * @param {string} privateKeyHex - ML-DSA-65 private key or hybrid master seed (hex)
 * @returns {string} signature hex
 */
export function signBody(fields, privateKeyHex) {
  const hash = tipShake256(canonicalJson(fields));
  const hashBytes = new TextEncoder().encode(hash);
  const privBytes = hexToBytes(privateKeyHex);

  let secretKey;
  if (privBytes.length === 32) {
    // Hybrid master seed - derive ML-DSA seed: shake256(0x01 || masterSeed)
    const input = new Uint8Array(1 + 32);
    input[0] = 0x01;
    input.set(privBytes, 1);
    const mlDsaSeed = _shake256(input, { dkLen: 32 });
    secretKey = ml_dsa65.keygen(mlDsaSeed).secretKey;
  } else {
    // Pure ML-DSA-65 private key (from seed/node)
    secretKey = privBytes;
  }

  const sig = ml_dsa65.sign(secretKey, hashBytes);
  return bufToHex(sig);
}

/**
 * Build the content registration signature.
 * Client computes content_hash, signs { author_tip_id, origin_code, content_hash }.
 *
 * @param {string} authorTipId
 * @param {string} originCode   - OH|AA|AG|MX
 * @param {string} content      - raw content text
 * @param {string} mlDsaPrivateKeyHex - ML-DSA-65 private key (hex)
 * @returns {{ signature: string, contentHash: string }}
 */
export function signContentRegister(authorTipId, originCode, content, mlDsaPrivateKeyHex) {
  const contentHash = tipShake256(content);
  const sigFields = { author_tip_id: authorTipId, origin_code: originCode, content_hash: contentHash };
  const signature = signBody(sigFields, mlDsaPrivateKeyHex);
  return { signature, contentHash };
}
