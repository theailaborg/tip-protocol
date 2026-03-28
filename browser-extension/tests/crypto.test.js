/**
 * @file tests/crypto.test.js
 * @description TIP Protocol — Browser Extension Crypto Module Test Suite
 *
 * Test coverage:
 *   - SHAKE-256 hashing (FIPS 202 via @noble/hashes)
 *   - Ed25519 + ML-DSA-65 hybrid key generation (keypair sizes, uniqueness)
 *   - Hybrid sign / verify roundtrip and rejection cases
 *   - TIP-ID URI generation (computeTIPID)
 *   - CTID URI generation (generateCTID)
 *   - Private key encryption/decryption (AES-256-GCM + PBKDF2)
 *
 * Key size reference:
 *   privateKey : 64 hex chars  (32-byte master seed)
 *   publicKey  : 3968 hex chars (Ed25519 32 B + ML-DSA-65 1952 B)
 *   signature  : 6746 hex chars (Ed25519 64 B + ML-DSA-65 3309 B)
 *
 * Run: npm test
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * Author: Dinesh Mendhe <chairman@theailab.org>
 * License: TIPCL-1.0
 */

import {
  initCrypto,
  shake256,
  generateKeypair,
  signData,
  verifySignature,
  computeTIPID,
  generateCTID,
  encryptPrivateKey,
  decryptPrivateKey,
} from "../src/crypto.js";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

let keypair1, keypair2;

beforeAll(async () => {
  await initCrypto();
  keypair1 = await generateKeypair();
  keypair2 = await generateKeypair();
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 1: SHAKE-256
// ══════════════════════════════════════════════════════════════════════════════

describe("SHAKE-256", () => {

  test("1.1 produces consistent 64-char hex output", async () => {
    const h = await shake256("hello world");
    expect(typeof h).toBe("string");
    expect(h).toHaveLength(64);
    expect(h).toMatch(/^[0-9a-f]+$/);
  });

  test("1.2 is deterministic for the same input", async () => {
    const h1 = await shake256("hello world");
    const h2 = await shake256("hello world");
    expect(h1).toBe(h2);
  });

  test("1.3 produces different output for different inputs", async () => {
    const h1 = await shake256("hello world");
    const h2 = await shake256("hello world!");
    expect(h1).not.toBe(h2);
  });

  test("1.4 accepts Uint8Array input", async () => {
    const bytes = new TextEncoder().encode("hello world");
    const h = await shake256(bytes);
    expect(h).toHaveLength(64);
    expect(h).toMatch(/^[0-9a-f]+$/);
  });

  test("1.5 string and Uint8Array of same content produce same hash", async () => {
    const str   = "consistent hashing";
    const bytes = new TextEncoder().encode(str);
    expect(await shake256(str)).toBe(await shake256(bytes));
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 2: Ed25519 + ML-DSA-65 HYBRID KEY GENERATION
// ══════════════════════════════════════════════════════════════════════════════

describe("Ed25519 + ML-DSA-65 Hybrid Key Generation", () => {

  test("2.1 initCrypto is idempotent", async () => {
    await expect(initCrypto()).resolves.toBeUndefined();
    await expect(initCrypto()).resolves.toBeUndefined();
  });

  test("2.2 returns Ed25519+ML-DSA-65 algorithm label", () => {
    expect(keypair1.algorithm).toBe("Ed25519+ML-DSA-65");
  });

  test("2.3 publicKey is a hex string of 3968 chars (Ed25519 32 B + ML-DSA-65 1952 B)", () => {
    expect(typeof keypair1.publicKey).toBe("string");
    expect(keypair1.publicKey).toHaveLength(3968);
    expect(keypair1.publicKey).toMatch(/^[0-9a-f]+$/);
  });

  test("2.4 privateKey is a hex string of 64 chars (32-byte master seed)", () => {
    expect(typeof keypair1.privateKey).toBe("string");
    expect(keypair1.privateKey).toHaveLength(64);
    expect(keypair1.privateKey).toMatch(/^[0-9a-f]+$/);
  });

  test("2.5 two keypairs are distinct", () => {
    expect(keypair1.publicKey).not.toBe(keypair2.publicKey);
    expect(keypair1.privateKey).not.toBe(keypair2.privateKey);
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 3: Ed25519 + ML-DSA-65 HYBRID SIGN / VERIFY
// ══════════════════════════════════════════════════════════════════════════════

describe("Ed25519 + ML-DSA-65 Hybrid Sign / Verify", () => {

  test("3.1 signData returns a combined hex signature of 6746 chars (Ed25519 64 B + ML-DSA-65 3309 B)", async () => {
    const sig = await signData("test payload", keypair1.privateKey);
    expect(typeof sig).toBe("string");
    expect(sig).toHaveLength(6746);
    expect(sig).toMatch(/^[0-9a-f]+$/);
  });

  test("3.2 verifySignature accepts a valid hybrid signature", async () => {
    const data = "hello tip protocol";
    const sig  = await signData(data, keypair1.privateKey);
    expect(await verifySignature(data, sig, keypair1.publicKey)).toBe(true);
  });

  test("3.3 verifySignature rejects tampered message", async () => {
    const sig = await signData("original message", keypair1.privateKey);
    expect(await verifySignature("tampered message", sig, keypair1.publicKey)).toBe(false);
  });

  test("3.4 verifySignature rejects wrong public key", async () => {
    const sig = await signData("test message", keypair1.privateKey);
    expect(await verifySignature("test message", sig, keypair2.publicKey)).toBe(false);
  });

  test("3.5 verifySignature rejects corrupted signature (Ed25519 layer)", async () => {
    const data       = "some content";
    const sig        = await signData(data, keypair1.privateKey);
    const corrupted  = "ff" + sig.slice(2); // corrupt first byte of Ed25519 sig
    expect(await verifySignature(data, corrupted, keypair1.publicKey)).toBe(false);
  });

  test("3.5b verifySignature rejects corrupted signature (ML-DSA-65 layer)", async () => {
    const data       = "some content";
    const sig        = await signData(data, keypair1.privateKey);
    // Corrupt a byte deep inside the ML-DSA-65 portion (after the 128-char Ed25519 sig)
    const corrupted  = sig.slice(0, 130) + "ff" + sig.slice(132);
    expect(await verifySignature(data, corrupted, keypair1.publicKey)).toBe(false);
  });

  test("3.6 both independent signatures verify correctly for the same data", async () => {
    // ML-DSA-65 uses hedged (randomised) signing — signatures differ between calls.
    // What matters is that every signature verifies against the corresponding public key.
    const data = "same message";
    const sig1 = await signData(data, keypair1.privateKey);
    const sig2 = await signData(data, keypair1.privateKey);
    expect(await verifySignature(data, sig1, keypair1.publicKey)).toBe(true);
    expect(await verifySignature(data, sig2, keypair1.publicKey)).toBe(true);
  });

  test("3.7 keypair2 cannot verify keypair1 signature", async () => {
    const sig = await signData("cross-key test", keypair1.privateKey);
    expect(await verifySignature("cross-key test", sig, keypair2.publicKey)).toBe(false);
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 4: TIP-ID AND CTID URI GENERATION
// ══════════════════════════════════════════════════════════════════════════════

describe("TIP-ID and CTID Generation", () => {

  test("4.1 computeTIPID format: tip://id/[REGION]-[hex16]", async () => {
    const id = await computeTIPID("US", keypair1.publicKey);
    expect(id).toMatch(/^tip:\/\/id\/US-[0-9a-f]{16}$/);
  });

  test("4.2 computeTIPID is deterministic", async () => {
    const id1 = await computeTIPID("US", keypair1.publicKey);
    const id2 = await computeTIPID("US", keypair1.publicKey);
    expect(id1).toBe(id2);
  });

  test("4.3 computeTIPID uppercases region", async () => {
    const lower = await computeTIPID("us", keypair1.publicKey);
    const upper = await computeTIPID("US", keypair1.publicKey);
    expect(lower).toBe(upper);
  });

  test("4.4 computeTIPID differs for different public keys", async () => {
    const id1 = await computeTIPID("US", keypair1.publicKey);
    const id2 = await computeTIPID("US", keypair2.publicKey);
    expect(id1).not.toBe(id2);
  });

  test("4.5 generateCTID format: tip://c/[ORIGIN]-[hex14]-[hex4]", async () => {
    const tipId = await computeTIPID("US", keypair1.publicKey);
    const ctid  = await generateCTID("OH", "article content here", tipId);
    expect(ctid).toMatch(/^tip:\/\/c\/OH-[0-9a-f]{14}-[0-9a-f]{4}$/);
  });

  test("4.6 generateCTID embeds the correct origin code", async () => {
    const tipId = await computeTIPID("US", keypair1.publicKey);
    for (const origin of ["OH", "AA", "AG", "MX"]) {
      const ctid = await generateCTID(origin, "content", tipId);
      expect(ctid).toMatch(new RegExp(`^tip:\\/\\/c\\/${origin}-`));
    }
  });

  test("4.7 generateCTID changes with different content", async () => {
    const tipId = await computeTIPID("US", keypair1.publicKey);
    const c1 = await generateCTID("OH", "content A", tipId);
    const c2 = await generateCTID("OH", "content B", tipId);
    expect(c1).not.toBe(c2);
  });

  test("4.8 generateCTID is deterministic for same inputs", async () => {
    const tipId = await computeTIPID("US", keypair1.publicKey);
    const c1 = await generateCTID("AA", "same content", tipId);
    const c2 = await generateCTID("AA", "same content", tipId);
    expect(c1).toBe(c2);
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCK 5: PRIVATE KEY ENCRYPTION (AES-256-GCM + PBKDF2)
// ══════════════════════════════════════════════════════════════════════════════

describe("Private Key Encryption (AES-256-GCM)", () => {

  test("5.1 encryptPrivateKey returns a base64 string", async () => {
    const enc = await encryptPrivateKey(keypair1.privateKey, "password123");
    expect(typeof enc).toBe("string");
    expect(() => atob(enc)).not.toThrow();
  });

  test("5.2 decryptPrivateKey recovers original key", async () => {
    const password  = "my-strong-password-2026";
    const encrypted = await encryptPrivateKey(keypair1.privateKey, password);
    const decrypted = await decryptPrivateKey(encrypted, password);
    expect(decrypted).toBe(keypair1.privateKey);
  });

  test("5.3 two encryptions of same key produce different blobs (random IV/salt)", async () => {
    const enc1 = await encryptPrivateKey(keypair1.privateKey, "same-password");
    const enc2 = await encryptPrivateKey(keypair1.privateKey, "same-password");
    expect(enc1).not.toBe(enc2);
  });

  test("5.4 both blobs from 5.3 decrypt correctly", async () => {
    const password = "same-password";
    const enc1 = await encryptPrivateKey(keypair1.privateKey, password);
    const enc2 = await encryptPrivateKey(keypair1.privateKey, password);
    expect(await decryptPrivateKey(enc1, password)).toBe(keypair1.privateKey);
    expect(await decryptPrivateKey(enc2, password)).toBe(keypair1.privateKey);
  });

  test("5.5 decryptPrivateKey rejects wrong password", async () => {
    const encrypted = await encryptPrivateKey(keypair1.privateKey, "correct-password");
    await expect(decryptPrivateKey(encrypted, "wrong-password")).rejects.toThrow();
  });

  test("5.6 works with keypair2 private key as well", async () => {
    const password  = "another-password";
    const encrypted = await encryptPrivateKey(keypair2.privateKey, password);
    const decrypted = await decryptPrivateKey(encrypted, password);
    expect(decrypted).toBe(keypair2.privateKey);
  });

});
