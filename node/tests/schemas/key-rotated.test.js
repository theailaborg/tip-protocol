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

describe("KEY_ROTATED effective_at lead bound", () => {
  const { KEY_ROTATION_MAX_LEAD_MS } = require("../../../shared/constants");
  const ts = 1778580000000;

  test("effectiveAtError: below tx.timestamp, inside the lead, past the lead", () => {
    expect(keyRotatedSchema.effectiveAtError(ts - 1, ts)).toMatchObject({ code: "effective_at_invalid" });
    expect(keyRotatedSchema.effectiveAtError(ts + KEY_ROTATION_MAX_LEAD_MS, ts)).toBeNull();
    expect(keyRotatedSchema.effectiveAtError(ts + KEY_ROTATION_MAX_LEAD_MS + 1, ts)).toMatchObject({ code: "effective_at_too_far" });
    expect(keyRotatedSchema.effectiveAtError(ts + KEY_ROTATION_MAX_LEAD_MS + 1, ts, { boundLead: false })).toBeNull();
  });

  test("strict: a rotation signed by a retired key that names the active key's fingerprint is refused", () => {
    const oldKp = generateMLDSAKeypair(), activeKp = generateMLDSAKeypair(), newKp = generateMLDSAKeypair();
    const dag = {
      ...fakeDag({ activePubkey: activeKp.publicKey }),
      // At tx.timestamp the retired key still resolves (the backdated window).
      getKeyValidAt: () => ({ public_key: oldKp.publicKey, algorithm: "ml-dsa-65", valid_to_ts: 1 }),
    };
    const backdated = rotationTx(oldKp, newKp, { old_key_fingerprint: shake256(activeKp.publicKey).slice(0, 32) });
    expect(keyRotatedSchema.verifyTx(backdated, dag)).toEqual({ ok: true });
    expect(keyRotatedSchema.verifyTx(backdated, dag, { strict: true })).toMatchObject({ ok: false, code: "signer_not_active" });
    const honest = { ...dag, getKeyValidAt: () => ({ public_key: activeKp.publicKey, algorithm: "ml-dsa-65", valid_to_ts: null }) };
    expect(keyRotatedSchema.verifyTx(rotationTx(activeKp, newKp), honest, { strict: true })).toEqual({ ok: true });
  });

  test("verifyTx enforces the lead only when asked (commit path gates it on the activation epoch)", () => {
    const oldKp = generateMLDSAKeypair(), newKp = generateMLDSAKeypair();
    const dag = fakeDag({ activePubkey: oldKp.publicKey });
    const parked = rotationTx(oldKp, newKp, { effective_at: ts + 365 * 24 * 3600_000 });
    expect(keyRotatedSchema.verifyTx(parked, dag)).toEqual({ ok: true });
    expect(keyRotatedSchema.verifyTx(parked, dag, { strict: true })).toMatchObject({ ok: false, code: "effective_at_too_far" });
    expect(keyRotatedSchema.verifyTx(rotationTx(oldKp, newKp), dag, { strict: true })).toEqual({ ok: true });
  });
});
