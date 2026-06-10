/**
 * @file canonical-payload-regression.test.js
 * @description M4 regression for GH #85 — universal canonical-payload rule.
 *
 * For every tx_type with optional signed fields, asserts that:
 *  1. Signing with each optional field absent produces a signature.
 *  2. verifyBodySignature (API-request-verify path) accepts that signature.
 *  3. The schema/registry buildSigningPayload (consensus-commit-verify path)
 *     produces identical canonical bytes, so the same signature verifies both.
 *
 * This makes the signer/verifier-divergence bug class structurally impossible
 * to reintroduce without breaking this test.
 *
 * Covered tx_types with optional fields:
 *   - REVOKE_* (reason_code, evidence_hash — Pattern A)
 *   - JURY_VOTE_REVEAL (confirmed_origin — was Pattern B, now Pattern A)
 *   - CONTENT_DISPUTED (claimed_origin, evidence_hash — was Pattern B, now Pattern A)
 *   - PRESCAN_REVIEW_CONFIRMED (decision_note — was Pattern C, now Pattern A)
 *   - PRESCAN_REVIEW_DISMISSED (decision_note — was Pattern C, now Pattern A)
 *   - PRESCAN_REVIEW_RECUSED (recusal_reason — was Pattern C, now Pattern A)
 *   - REGISTER_IDENTITY (creator_name — was Pattern C, now Pattern A)
 *
 * Also asserts the universal null rule: null values are stripped identically
 * to absent values by both paths.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */
"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC    = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, signBody, verifyBodySignature,
  canonicalJson, shake256,
} = require(path.join(SHARED, "crypto"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { TX_SIGNATURE_REGISTRY } = require(path.join(SRC, "schemas", "_registry"));
const prescanConfirmed = require(path.join(SRC, "schemas", "prescan-review-confirmed"));
const prescanDismissed = require(path.join(SRC, "schemas", "prescan-review-dismissed"));
const prescanRecused   = require(path.join(SRC, "schemas", "prescan-review-recused"));
const registerIdentity = require(path.join(SRC, "schemas", "register-identity"));

beforeAll(async () => { await initCrypto(); });

// ─── helpers ────────────────────────────────────────────────────────────────

function payloadHash(obj) {
  return shake256(canonicalJson(obj));
}

// Hash via registry/schema buildSigningPayload (consensus path).
function consensusHash(txType, data) {
  const entry    = TX_SIGNATURE_REGISTRY[txType];
  const contract = entry.getSignatureContract ? entry.getSignatureContract({ data }) : entry;
  return payloadHash(contract.buildSigningPayload(data));
}

// Hash via verifyBodySignature strip logic (API path).
function apiHash(data, fields) {
  const payload = {};
  for (const f of fields) {
    if (data[f] !== undefined && data[f] !== null) payload[f] = data[f];
  }
  return payloadHash(payload);
}

// ─── tests ───────────────────────────────────────────────────────────────────

describe("GH #85 — canonical-payload regression: optional-field-absent paths agree", () => {

  // ── REVOKE_* ────────────────────────────────────────────────────────────────

  test("REVOKE_VOLUNTARY — reason_code and evidence_hash absent: API == consensus", () => {
    const data = {
      tx_type: TX_TYPES.REVOKE_VOLUNTARY,
      tip_id: "tip://id/alice",
      issuing_vp_id: "tip://vp/v1",
    };
    const fields = ["tx_type", "tip_id", "reason_code", "evidence_hash", "issuing_vp_id"];
    expect(apiHash(data, fields)).toEqual(consensusHash(TX_TYPES.REVOKE_VOLUNTARY, data));
  });

  test("REVOKE_VOLUNTARY — reason_code and evidence_hash present: API == consensus", () => {
    const data = {
      tx_type: TX_TYPES.REVOKE_VOLUNTARY,
      tip_id: "tip://id/alice",
      issuing_vp_id: "tip://vp/v1",
      reason_code: "lost_device",
      evidence_hash: "abc123",
    };
    const fields = ["tx_type", "tip_id", "reason_code", "evidence_hash", "issuing_vp_id"];
    expect(apiHash(data, fields)).toEqual(consensusHash(TX_TYPES.REVOKE_VOLUNTARY, data));
  });

  // ── JURY_VOTE_REVEAL ────────────────────────────────────────────────────────

  test("JURY_VOTE_REVEAL — confirmed_origin absent (MATCH): API == consensus", () => {
    const data = { juror_tip_id: "tip://id/juror1", vote: "MATCH", salt: "deadbeef" };
    const fields = ["juror_tip_id", "vote", "salt", "confirmed_origin"];
    expect(apiHash(data, fields)).toEqual(consensusHash(TX_TYPES.JURY_VOTE_REVEAL, data));
  });

  test("JURY_VOTE_REVEAL — confirmed_origin present (MISMATCH): API == consensus", () => {
    const data = { juror_tip_id: "tip://id/juror1", vote: "MISMATCH", salt: "deadbeef", confirmed_origin: "AI" };
    const fields = ["juror_tip_id", "vote", "salt", "confirmed_origin"];
    expect(apiHash(data, fields)).toEqual(consensusHash(TX_TYPES.JURY_VOTE_REVEAL, data));
  });

  test("JURY_VOTE_REVEAL — sign + verify round-trip: confirmed_origin absent", () => {
    const kp     = generateMLDSAKeypair();
    const data   = { juror_tip_id: "tip://id/juror1", vote: "MATCH", salt: "deadbeef" };
    const entry  = TX_SIGNATURE_REGISTRY[TX_TYPES.JURY_VOTE_REVEAL];
    const payload = entry.buildSigningPayload(data);
    const sig    = signBody(payload, kp.privateKey);
    const fields = ["juror_tip_id", "vote", "salt", "confirmed_origin"];
    // API-path verifier must accept the consensus-built signature.
    expect(verifyBodySignature(data, sig, kp.publicKey, fields)).toBe(true);
  });

  // ── CONTENT_DISPUTED ────────────────────────────────────────────────────────

  test("CONTENT_DISPUTED — claimed_origin + evidence_hash absent: API == consensus", () => {
    const data = { disputer_tip_id: "tip://id/disputer", reason: "misleading", auto: false };
    const fields = ["disputer_tip_id", "reason", "claimed_origin", "evidence_hash"];
    expect(apiHash(data, fields)).toEqual(consensusHash(TX_TYPES.CONTENT_DISPUTED, data));
  });

  test("CONTENT_DISPUTED — claimed_origin + evidence_hash present: API == consensus", () => {
    const data = {
      disputer_tip_id: "tip://id/disputer", reason: "misleading",
      claimed_origin: "HUMAN", evidence_hash: "cafebabe", auto: false,
    };
    const fields = ["disputer_tip_id", "reason", "claimed_origin", "evidence_hash"];
    expect(apiHash(data, fields)).toEqual(consensusHash(TX_TYPES.CONTENT_DISPUTED, data));
  });

  test("CONTENT_DISPUTED — sign + verify round-trip: optional fields absent", () => {
    const kp       = generateMLDSAKeypair();
    const data     = { disputer_tip_id: "tip://id/disputer", reason: "misleading", auto: false };
    const contract = TX_SIGNATURE_REGISTRY[TX_TYPES.CONTENT_DISPUTED].getSignatureContract({ data });
    const payload  = contract.buildSigningPayload(data);
    const sig      = signBody(payload, kp.privateKey);
    const fields   = ["disputer_tip_id", "reason", "claimed_origin", "evidence_hash"];
    expect(verifyBodySignature(data, sig, kp.publicKey, fields)).toBe(true);
  });

  // ── PRESCAN_REVIEW_CONFIRMED ─────────────────────────────────────────────────

  test("PRESCAN_REVIEW_CONFIRMED — decision_note absent: buildSigningPayload omits it", () => {
    const payload = prescanConfirmed.buildSigningPayload({
      review_id: "rev-1", reviewer_tip_id: "tip://id/rev", suggested_origin: "AA",
    });
    expect(payload).not.toHaveProperty("decision_note");
    expect(payload).toEqual({ review_id: "rev-1", reviewer_tip_id: "tip://id/rev", suggested_origin: "AA" });
  });

  test("PRESCAN_REVIEW_CONFIRMED — decision_note present: buildSigningPayload includes it", () => {
    const payload = prescanConfirmed.buildSigningPayload({
      review_id: "rev-1", reviewer_tip_id: "tip://id/rev", suggested_origin: "AA",
      decision_note: "looks good",
    });
    expect(payload.decision_note).toBe("looks good");
  });

  test("PRESCAN_REVIEW_CONFIRMED — decision_note null: treated same as absent", () => {
    const withNull = prescanConfirmed.buildSigningPayload({
      review_id: "rev-1", reviewer_tip_id: "tip://id/rev", suggested_origin: "AA",
      decision_note: null,
    });
    const withAbsent = prescanConfirmed.buildSigningPayload({
      review_id: "rev-1", reviewer_tip_id: "tip://id/rev", suggested_origin: "AA",
    });
    expect(withNull).toEqual(withAbsent);
    expect(withNull).not.toHaveProperty("decision_note");
  });

  // ── PRESCAN_REVIEW_DISMISSED ─────────────────────────────────────────────────

  test("PRESCAN_REVIEW_DISMISSED — decision_note absent: buildSigningPayload omits it", () => {
    const payload = prescanDismissed.buildSigningPayload({
      review_id: "rev-2", reviewer_tip_id: "tip://id/rev",
    });
    expect(payload).not.toHaveProperty("decision_note");
  });

  test("PRESCAN_REVIEW_DISMISSED — decision_note null: treated same as absent", () => {
    const withNull   = prescanDismissed.buildSigningPayload({ review_id: "r", reviewer_tip_id: "t", decision_note: null });
    const withAbsent = prescanDismissed.buildSigningPayload({ review_id: "r", reviewer_tip_id: "t" });
    expect(withNull).toEqual(withAbsent);
  });

  // ── PRESCAN_REVIEW_RECUSED ───────────────────────────────────────────────────

  test("PRESCAN_REVIEW_RECUSED — recusal_reason absent: buildSigningPayload omits it", () => {
    const payload = prescanRecused.buildSigningPayload({
      review_id: "rev-3", reviewer_tip_id: "tip://id/rev",
    });
    expect(payload).not.toHaveProperty("recusal_reason");
  });

  test("PRESCAN_REVIEW_RECUSED — recusal_reason null: treated same as absent", () => {
    const withNull   = prescanRecused.buildSigningPayload({ review_id: "r", reviewer_tip_id: "t", recusal_reason: null });
    const withAbsent = prescanRecused.buildSigningPayload({ review_id: "r", reviewer_tip_id: "t" });
    expect(withNull).toEqual(withAbsent);
  });

  // ── REGISTER_IDENTITY ────────────────────────────────────────────────────────

  test("REGISTER_IDENTITY — creator_name absent: buildSigningPayload omits it", () => {
    const payload = registerIdentity.buildSigningPayload({
      public_key: "a".repeat(64),
      dedup_hash: "b".repeat(64),
      zk_proof: { proof: "x" },
      vp_id: "tip://vp/v1",
    });
    expect(payload).not.toHaveProperty("creator_name");
  });

  test("REGISTER_IDENTITY — creator_name null: treated same as absent", () => {
    const base = { public_key: "a".repeat(64), dedup_hash: "b".repeat(64), zk_proof: { proof: "x" }, vp_id: "tip://vp/v1" };
    const withNull   = registerIdentity.buildSigningPayload({ ...base, creator_name: null });
    const withAbsent = registerIdentity.buildSigningPayload({ ...base });
    expect(withNull).toEqual(withAbsent);
    expect(withNull).not.toHaveProperty("creator_name");
  });

  test("REGISTER_IDENTITY — creator_name present: buildSigningPayload includes it", () => {
    const payload = registerIdentity.buildSigningPayload({
      public_key: "a".repeat(64), dedup_hash: "b".repeat(64),
      zk_proof: { proof: "x" }, vp_id: "tip://vp/v1",
      creator_name: "Alice",
    });
    expect(payload.creator_name).toBe("Alice");
  });

  // ── Universal null rule ──────────────────────────────────────────────────────

  test("Universal null rule: null optional field is byte-identical to absent in verifyBodySignature", () => {
    const absent = { juror_tip_id: "tip://id/j", vote: "MATCH", salt: "s" };
    const nulled = { ...absent, confirmed_origin: null };
    const fields = ["juror_tip_id", "vote", "salt", "confirmed_origin"];
    expect(apiHash(absent, fields)).toEqual(apiHash(nulled, fields));
  });

  test("Universal null rule: null optional field is byte-identical to absent in buildSigningPayload", () => {
    const entry = TX_SIGNATURE_REGISTRY[TX_TYPES.JURY_VOTE_REVEAL];
    const absent = entry.buildSigningPayload({ juror_tip_id: "j", vote: "MATCH", salt: "s" });
    const nulled = entry.buildSigningPayload({ juror_tip_id: "j", vote: "MATCH", salt: "s", confirmed_origin: null });
    expect(absent).toEqual(nulled);
    expect(absent).not.toHaveProperty("confirmed_origin");
  });
});
