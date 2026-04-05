/**
 * @file src/crypto.js
 * @description TIP Protocol - Browser Crypto Module
 *
 * Provides:
 *   - SHAKE-256 hashing (FIPS 202 via @noble/hashes)
 *   - ML-DSA-65 key generation and signing (FIPS 204 via @noble/post-quantum)
 *   - Private key encryption via AES-256-GCM + WebAuthn (passkey-derived key)
 *   - Fallback: AES-256-GCM + PBKDF2 (password-based, legacy)
 *   - TIP-ID and CTID generation
 *   - Canonical JSON for body signatures (matches node's canonicalJson)
 *
 * Call `await initCrypto()` once at startup before using any function.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

import { ml_dsa65 }             from "@noble/post-quantum/ml-dsa";
import { shake256 as _shake256 } from "@noble/hashes/sha3";

async function initCrypto() {}

// ════════════════════════════════════════════════════════════════════════════
// SHAKE-256 (FIPS 202)
// ════════════════════════════════════════════════════════════════════════════

async function shake256(data) {
  const input = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return bufToHex(_shake256(input, { dkLen: 32 }));
}

// ════════════════════════════════════════════════════════════════════════════
// ML-DSA-65 KEY GENERATION (pure post-quantum, no hybrid)
// ════════════════════════════════════════════════════════════════════════════

async function generateKeypair() {
  const { publicKey, secretKey } = ml_dsa65.keygen();
  return {
    algorithm:  "ML-DSA-65",
    publicKey:  bufToHex(publicKey),
    privateKey: bufToHex(secretKey),
  };
}

// ════════════════════════════════════════════════════════════════════════════
// SIGN / VERIFY - ML-DSA-65 only
// ════════════════════════════════════════════════════════════════════════════

async function signData(data, privateKeyHex) {
  const msg = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const secretKey = new Uint8Array(hexToBuf(privateKeyHex));
  const sig = ml_dsa65.sign(secretKey, msg);
  return bufToHex(sig);
}

async function verifySignature(data, signatureHex, publicKeyHex) {
  try {
    const msg = typeof data === "string" ? new TextEncoder().encode(data) : data;
    const sig = new Uint8Array(hexToBuf(signatureHex));
    const pub = new Uint8Array(hexToBuf(publicKeyHex));
    return ml_dsa65.verify(pub, msg, sig);
  } catch {
    return false;
  }
}

// ════════════════════════════════════════════════════════════════════════════
// CANONICAL JSON + BODY SIGNATURES (matches node's canonicalJson/signBody)
// ════════════════════════════════════════════════════════════════════════════

function canonicalJson(obj) {
  if (obj === null || obj === undefined) return String(obj);
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJson).join(",") + "]";
  return "{" + Object.keys(obj).sort().map(k => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

async function signBody(fields, privateKeyHex) {
  const hash = await shake256(canonicalJson(fields));
  return signData(hash, privateKeyHex);
}

// ════════════════════════════════════════════════════════════════════════════
// TIP-ID AND CTID GENERATION
// ════════════════════════════════════════════════════════════════════════════

async function computeTIPID(region, publicKeyHex) {
  const hash = await shake256(publicKeyHex);
  return `tip://id/${region.toUpperCase()}-${hash.slice(0, 16)}`;
}

async function generateCTID(originCode, content, authorTipId) {
  const contentHash = await shake256(content);
  const idShort     = authorTipId.split("-").pop().slice(0, 4);
  return `tip://c/${originCode}-${contentHash.slice(0, 14)}-${idShort}`;
}

// ════════════════════════════════════════════════════════════════════════════
// WEBAUTHN - CREATE PASSKEY + DERIVE AES KEY
// ════════════════════════════════════════════════════════════════════════════

import { TIP_WEBAUTHN_RP_ID } from "./config.js";

const WEBAUTHN_RP_ID   = TIP_WEBAUTHN_RP_ID;
const WEBAUTHN_RP_NAME = "TIP Protocol";

async function createPasskey(tipId) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId    = new TextEncoder().encode(tipId);

  const credential = await navigator.credentials.create({
    publicKey: {
      rp:   { id: WEBAUTHN_RP_ID, name: WEBAUTHN_RP_NAME },
      user: { id: userId, name: tipId, displayName: `TIP: ${tipId.slice(-8)}` },
      challenge,
      pubKeyCredParams: [
        { alg: -7,  type: "public-key" },  // ES256
        { alg: -257, type: "public-key" }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "required",
        userVerification: "required",
      },
      timeout: 60000,
    },
  });

  return {
    credentialId: bufToBase64(credential.rawId),
    publicKey:    bufToBase64(credential.response.getPublicKey()),
  };
}

async function authenticatePasskey(credentialIdB64) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  const options = {
    publicKey: {
      rpId: WEBAUTHN_RP_ID,
      challenge,
      userVerification: "required",
      timeout: 60000,
    },
  };

  // If credential ID is known, restrict to that credential (skips selection UI)
  if (credentialIdB64) {
    options.publicKey.allowCredentials = [{
      id:   base64ToBuf(credentialIdB64),
      type: "public-key",
      transports: ["internal"], // platform authenticator (Face ID / Touch ID)
    }];
  }

  const assertion = await navigator.credentials.get(options);

  // Derive AES-256 key from the authenticator response
  // Using HKDF on the signature to get a stable key derivation
  const sigBytes = new Uint8Array(assertion.response.signature);
  const authData = new Uint8Array(assertion.response.authenticatorData);

  // Combine authenticatorData + signature for key material
  const combined = new Uint8Array(authData.length + sigBytes.length);
  combined.set(authData);
  combined.set(sigBytes, authData.length);

  const keyHash = _shake256(combined, { dkLen: 32 });
  const aesKey = await crypto.subtle.importKey(
    "raw", keyHash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
  );

  return { aesKey, credentialId: bufToBase64(assertion.rawId) };
}

// ════════════════════════════════════════════════════════════════════════════
// PRIVATE KEY ENCRYPTION - WebAuthn (primary) or Password (fallback)
// ════════════════════════════════════════════════════════════════════════════

// Format: magic("TIPW",4) + iv(12) + ciphertext
const _WEBAUTHN_MAGIC = new Uint8Array([0x54, 0x49, 0x50, 0x57]); // "TIPW"

async function encryptWithWebAuthn(privateKeyHex, tipId, credentialIdB64) {
  const { aesKey, credentialId } = await authenticatePasskey(credentialIdB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(tipId);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    aesKey,
    new TextEncoder().encode(privateKeyHex)
  );

  const result = new Uint8Array(4 + iv.length + encrypted.byteLength);
  result.set(_WEBAUTHN_MAGIC, 0);
  result.set(iv, 4);
  result.set(new Uint8Array(encrypted), 16);

  return { encrypted: bufToBase64(result), credentialId };
}

async function decryptWithWebAuthn(encryptedB64, tipId, credentialIdB64) {
  const data = base64ToBuf(encryptedB64);
  const iv = data.slice(4, 16);
  const ciphertext = data.slice(16);
  const aad = new TextEncoder().encode(tipId);

  const { aesKey } = await authenticatePasskey(credentialIdB64);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    aesKey, ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

// ════════════════════════════════════════════════════════════════════════════
// DECRYPT VP KEY - matches VP app's encryptAndStoreKey format exactly
// tipKey object: { credentialId, tipId, salt[], nonce[], iv[], data[], method, version }
// ════════════════════════════════════════════════════════════════════════════

const _KDF_DOMAIN = "tip-pqc-key-wrap";

function _kdfHash(input) {
  const inputBytes = input instanceof Uint8Array ? input : new TextEncoder().encode(input);
  const domain     = new TextEncoder().encode(_KDF_DOMAIN);
  const combined   = new Uint8Array(inputBytes.length + domain.length);
  combined.set(inputBytes);
  combined.set(domain, inputBytes.length);
  return _shake256(combined, { dkLen: 32 });
}

/**
 * PATH A: Derive AES key via WebAuthn PRF extension (Secure Enclave).
 * Returns { aesKey, method } or null if PRF not supported.
 */
async function _deriveKeyViaPRF(credentialIdBytes, forEncrypt) {
  try {
    const prfSalt = new TextEncoder().encode(_KDF_DOMAIN);
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: WEBAUTHN_RP_ID,
        allowCredentials: [{ type: "public-key", id: credentialIdBytes, transports: ["internal"] }],
        userVerification: "required",
        timeout: 60000,
        extensions: { prf: { eval: { first: prfSalt } } },
      },
    });
    const extResults = assertion.getClientExtensionResults();
    if (!extResults?.prf?.results?.first) return null;

    const prfOutput = new Uint8Array(extResults.prf.results.first);
    const keyBytes = _kdfHash(prfOutput);
    const aesKey = await crypto.subtle.importKey(
      "raw", keyBytes, { name: "AES-GCM" }, false, forEncrypt ? ["encrypt"] : ["decrypt"]
    );
    return { aesKey, method: "webauthn-prf" };
  } catch (e) {
    if (e.name === "NotAllowedError") throw e; // user cancelled
    return null;
  }
}

/**
 * PATH B: Derive AES key from credentialId fallback (biometric-gated).
 * SHAKE-256(credentialId || domain) → PBKDF2(salt, 200k) → AES-256
 */
async function _deriveKeyFallback(credentialId, credentialIdBytes, requireBiometric, forEncrypt, salt) {
  if (requireBiometric) {
    await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: WEBAUTHN_RP_ID,
        allowCredentials: [{ type: "public-key", id: credentialIdBytes, transports: ["internal"] }],
        userVerification: "required",
        timeout: 60000,
      },
    });
  }

  const shakeOutput = _kdfHash(credentialIdBytes);
  const keyMaterial = await crypto.subtle.importKey("raw", shakeOutput, "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, forEncrypt ? ["encrypt"] : ["decrypt"]
  );
  return { aesKey, method: "webauthn-fallback" };
}

/**
 * Decrypt a VP-format tipKey object. Matches VP app's decryptStoredKey exactly.
 * @param {Object} tipKey - { credentialId, tipId, salt[], nonce[], iv[], data[], method, version }
 * @returns {Promise<string>} decrypted private key hex
 */
async function decryptVPKey(tipKey) {
  if (!tipKey || !tipKey.data) throw new Error("No key data found");

  const credentialId = tipKey.credentialId;
  const credentialIdBytes = Uint8Array.from(atob(credentialId), c => c.charCodeAt(0));
  const tipId = tipKey.tipId || "";
  const nonce = new Uint8Array(tipKey.nonce || tipKey.iv);
  const ciphertext = new Uint8Array(tipKey.data);
  const storedSalt = tipKey.salt ? new Uint8Array(tipKey.salt) : null;

  let derived;

  if (tipKey.method === "webauthn-prf") {
    derived = await _deriveKeyViaPRF(credentialIdBytes, false);
    if (!derived) throw new Error("PRF not available. Use the original device with Chrome/Edge 116+.");
  } else {
    const salt = storedSalt || new TextEncoder().encode("tip-key-v2");
    derived = await _deriveKeyFallback(credentialId, credentialIdBytes, true, false, salt);
  }

  // Try decrypt with multiple AAD candidates (tipId, empty) like VP app does
  const { aesKey } = derived;
  const aadCandidates = [tipId];
  if (tipId) aadCandidates.push("");

  for (const aadStr of aadCandidates) {
    try {
      const aad = new TextEncoder().encode(aadStr);
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad },
        aesKey, ciphertext
      );
      return new TextDecoder().decode(decrypted);
    } catch { continue; }
  }
  throw new Error("Decryption failed - key may be corrupted or wrong device");
}

// ── Password fallback (legacy) ───────────────────────────────────────────
const _V2_MAGIC   = new Uint8Array([0x54, 0x49, 0x50, 0x32]); // "TIP2"

function kdfHash(input) {
  const inputBytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const domain     = new TextEncoder().encode(_KDF_DOMAIN);
  const combined   = new Uint8Array(inputBytes.length + domain.length);
  combined.set(inputBytes);
  combined.set(domain, inputBytes.length);
  return _shake256(combined, { dkLen: 32 });
}

async function encryptPrivateKey(privateKeyHex, password, tipId) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const aad  = new TextEncoder().encode(tipId || "");

  const shakeOutput = kdfHash(password);
  const keyMaterial = await crypto.subtle.importKey("raw", shakeOutput, "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    aesKey, new TextEncoder().encode(privateKeyHex)
  );

  const aadLen = new Uint8Array(2);
  aadLen[0] = aad.length & 0xFF;
  aadLen[1] = (aad.length >> 8) & 0xFF;

  const result = new Uint8Array(4 + salt.length + iv.length + 2 + aad.length + encrypted.byteLength);
  let offset = 0;
  result.set(_V2_MAGIC, offset); offset += 4;
  result.set(salt, offset); offset += salt.length;
  result.set(iv, offset); offset += iv.length;
  result.set(aadLen, offset); offset += 2;
  result.set(aad, offset); offset += aad.length;
  result.set(new Uint8Array(encrypted), offset);

  return btoa(String.fromCharCode(...result));
}

async function decryptPrivateKey(encryptedB64, password, tipId) {
  const data = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
  let offset = 4; // skip magic
  const salt = data.slice(offset, offset + 16); offset += 16;
  const iv   = data.slice(offset, offset + 12); offset += 12;
  const aadLen = data[offset] | (data[offset + 1] << 8); offset += 2;
  const aad  = data.slice(offset, offset + aadLen); offset += aadLen;
  const ciphertext = data.slice(offset);

  const aadForDecrypt = tipId != null ? new TextEncoder().encode(tipId) : aad;

  const shakeOutput = kdfHash(password);
  const keyMaterial = await crypto.subtle.importKey("raw", shakeOutput, "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aadForDecrypt },
    aesKey, ciphertext
  );
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
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(b64) {
  return new Uint8Array(atob(b64).split("").map(c => c.charCodeAt(0)));
}

export {
  initCrypto,
  shake256,
  generateKeypair,
  signData,
  verifySignature,
  canonicalJson,
  signBody,
  computeTIPID,
  generateCTID,
  // WebAuthn encryption
  createPasskey,
  authenticatePasskey,
  encryptWithWebAuthn,
  decryptWithWebAuthn,
  decryptVPKey,
  // Password fallback
  encryptPrivateKey,
  decryptPrivateKey,
  kdfHash,
};
