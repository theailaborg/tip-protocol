/**
 * @file tests/schemas/key-rotated.test.js
 * @description KEY_ROTATED verifyTx: the old_key_fingerprint CAS that
 * defends against two rotations racing the same identity: the fingerprint
 * must match the live active key, else the tx is stale and rejected.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256 } = require(path.join(SHARED, "crypto"));
const keyRotatedSchema = require(path.join(SRC, "schemas", "key-rotated"));

beforeAll(async () => { await initCrypto(); });

const TIP = "tip://id/US-cccccccccccccccc";

function fakeDag({ activePubkey, status = "active", revoked = false } = {}) {
  return {
    getIdentity: (id) => (id === TIP ? { tip_id: TIP, status } : null),
    isRevoked: () => revoked,
    getActiveKey: (entityType, entityId) =>
      entityType === "identity" && entityId === TIP && activePubkey
        ? { public_key: activePubkey }
        : null,
  };
}

function rotationTx(oldKp, newKp, overrides = {}) {
  const timestamp = 1778580000000;
  return {
    timestamp,
    data: {
      tip_id: TIP,
      new_public_key: newKp.publicKey,
      algorithm: "ml-dsa-65",
      effective_at: timestamp + 60_000,
      old_key_fingerprint: shake256(oldKp.publicKey).slice(0, 32),
      ...overrides,
    },
  };
}

describe("KEY_ROTATED verifyTx: old_key_fingerprint CAS", () => {
  test("accepts when the fingerprint matches the live active key", () => {
    const oldKp = generateMLDSAKeypair();
    const newKp = generateMLDSAKeypair();
    const dag = fakeDag({ activePubkey: oldKp.publicKey });
    expect(keyRotatedSchema.verifyTx(rotationTx(oldKp, newKp), dag)).toEqual({ ok: true });
  });

  test("rejects when the active key already moved (concurrent rotation)", () => {
    const oldKp = generateMLDSAKeypair();
    const newKp = generateMLDSAKeypair();
    const otherKp = generateMLDSAKeypair();
    // Signed against oldKp, but the live active key is now otherKp.
    const dag = fakeDag({ activePubkey: otherKp.publicKey });
    expect(keyRotatedSchema.verifyTx(rotationTx(oldKp, newKp), dag))
      .toMatchObject({ ok: false, status: 409, code: "state_changed" });
  });

  test("rejects a tampered old_key_fingerprint", () => {
    const oldKp = generateMLDSAKeypair();
    const newKp = generateMLDSAKeypair();
    const dag = fakeDag({ activePubkey: oldKp.publicKey });
    const tx = rotationTx(oldKp, newKp, { old_key_fingerprint: "0".repeat(32) });
    expect(keyRotatedSchema.verifyTx(tx, dag)).toMatchObject({ ok: false, status: 409, code: "state_changed" });
  });

  test("rejects a missing old_key_fingerprint", () => {
    const oldKp = generateMLDSAKeypair();
    const newKp = generateMLDSAKeypair();
    const dag = fakeDag({ activePubkey: oldKp.publicKey });
    const tx = rotationTx(oldKp, newKp, { old_key_fingerprint: undefined });
    expect(keyRotatedSchema.verifyTx(tx, dag)).toMatchObject({ ok: false, code: "old_key_fingerprint_missing" });
  });
});
