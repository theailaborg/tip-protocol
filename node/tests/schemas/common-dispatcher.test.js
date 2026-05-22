/**
 * @file tests/schemas/common-dispatcher.test.js
 * @description Direct unit tests for the unified-signature dispatcher
 * in `schemas/_common.js` — exercises the three resolution paths
 * (schema's getSignatureContract, schema's static SIGNATURE_SCOPE
 * exports, registry fallback) plus the algorithm dispatch layer.
 *
 * Schema-specific behaviour is covered in
 * `tests/schemas/*-schema.test.js`. This file is the layer-agnostic
 * sweep: pass a synthetic tx + a fake dag and assert the dispatcher's
 * return shape across success / failure modes.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, signTransaction, computeTxId, mldsaSign, shake256, canonicalTx, canonicalJson,
} = require(path.join(SHARED, "crypto"));
const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS,
} = require(path.join(SHARED, "constants"));
const {
  verifyTxSignature, resolveSignatureContract,
} = require(path.join(SRC, "schemas", "_common"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/dispatcher-test";
const SUBJECT_TIP = "tip://id/US-aaaabbbbccccdddd";

function _fakeDag({ identities = {}, nodes = {}, vps = {} } = {}) {
  return {
    getIdentity: (id) => identities[id] || null,
    getNode: (id) => nodes[id] || null,
    getVP: (id) => vps[id] || null,
    isRevoked: () => false,
  };
}

describe("verifyTxSignature — input validation", () => {
  test("missing tx → tx_missing error", () => {
    const result = verifyTxSignature(null, null, _fakeDag());
    expect(result).toMatchObject({ ok: false, code: "tx_missing" });
  });

  test("missing tx.signature → signature_missing error", () => {
    const tx = { tx_type: TX_TYPES.CONTENT_VERIFIED, data: {} };
    const result = verifyTxSignature(tx, null, _fakeDag());
    expect(result).toMatchObject({ ok: false, code: "signature_missing" });
  });

  test("unresolvable contract (unknown tx_type, no schema, no registry entry) → schema_invalid", () => {
    const tx = { tx_type: "TOTALLY_FAKE_TYPE", signature: "ab".repeat(32), data: {} };
    const result = verifyTxSignature(tx, null, _fakeDag());
    expect(result).toMatchObject({ ok: false, code: "schema_invalid" });
  });
});

describe("verifyTxSignature — registry path (body-scope subject signature)", () => {
  test("CONTENT_VERIFIED valid signature returns ok:true", () => {
    const verifierKp = generateMLDSAKeypair();
    const dag = _fakeDag({
      identities: {
        [SUBJECT_TIP]: { public_key: verifierKp.publicKey, tip_id: SUBJECT_TIP },
      },
    });
    // Payload the dispatcher will rebuild via registry's buildSigningPayload.
    const data = {
      verifier_tip_id: SUBJECT_TIP,
      ctid: "tip://c/OH-aaaaaaaaaaaaaa-0001",
      verdict: "ORIGIN_CONFIRMED",
    };
    const message = shake256(canonicalJson(data));
    const signature = mldsaSign(message, verifierKp.privateKey);
    const tx = { tx_type: TX_TYPES.CONTENT_VERIFIED, data, signature };

    expect(verifyTxSignature(tx, null, dag)).toEqual({ ok: true });
  });

  test("CONTENT_VERIFIED wrong signature → signature_invalid", () => {
    const verifierKp = generateMLDSAKeypair();
    const otherKp = generateMLDSAKeypair();
    const dag = _fakeDag({
      identities: { [SUBJECT_TIP]: { public_key: verifierKp.publicKey } },
    });
    const data = {
      verifier_tip_id: SUBJECT_TIP,
      ctid: "tip://c/OH-aaaaaaaaaaaaaa-0001",
      verdict: "ORIGIN_CONFIRMED",
    };
    // Sign with the wrong key.
    const message = shake256(canonicalJson(data));
    const signature = mldsaSign(message, otherKp.privateKey);
    const tx = { tx_type: TX_TYPES.CONTENT_VERIFIED, data, signature };

    expect(verifyTxSignature(tx, null, dag)).toMatchObject({ ok: false, code: "signature_invalid" });
  });

  test("CONTENT_VERIFIED unknown verifier → signer_unknown", () => {
    const data = {
      verifier_tip_id: SUBJECT_TIP,
      ctid: "tip://c/OH-aaaaaaaaaaaaaa-0001",
      verdict: "ORIGIN_CONFIRMED",
    };
    const signature = "ab".repeat(32);
    const tx = { tx_type: TX_TYPES.CONTENT_VERIFIED, data, signature };
    expect(verifyTxSignature(tx, null, _fakeDag())).toMatchObject({
      ok: false, code: "signer_unknown",
    });
  });
});

describe("verifyTxSignature — node envelope path", () => {
  test("SCORE_UPDATE node-signed envelope verifies via canonicalTx", () => {
    const nodeKp = generateMLDSAKeypair();
    const dag = _fakeDag({
      nodes: { [NODE_ID]: { node_id: NODE_ID, public_key: nodeKp.publicKey, status: "active" } },
    });
    const txBody = {
      tx_type: TX_TYPES.SCORE_UPDATE,
      timestamp: 1777420800000,
      prev: ["deadbeef".repeat(8)],
      data: { tip_id: SUBJECT_TIP, delta: 5, reason: "test", node_id: NODE_ID },
    };
    txBody.tx_id = computeTxId(txBody);
    const signed = signTransaction(txBody, nodeKp.privateKey);

    expect(verifyTxSignature(signed, null, dag)).toEqual({ ok: true });
  });
});

describe("resolveSignatureContract — dual-mode tx types", () => {
  test("CONTENT_DISPUTED auto=true resolves to NODE envelope", () => {
    const contract = resolveSignatureContract(
      { tx_type: TX_TYPES.CONTENT_DISPUTED, data: { auto: true } },
      null,
    );
    expect(contract).toMatchObject({
      SIGNATURE_SCOPE: SIGNATURE_SCOPE.ENVELOPE,
      SIGNED_BY: SIGNED_BY_KIND.NODE,
    });
  });

  test("CONTENT_DISPUTED auto=false resolves to SUBJECT body via DISPUTER_TIP_ID", () => {
    const contract = resolveSignatureContract(
      { tx_type: TX_TYPES.CONTENT_DISPUTED, data: { auto: false, disputer_tip_id: SUBJECT_TIP } },
      null,
    );
    expect(contract).toMatchObject({
      SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
      SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
      SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.DISPUTER_TIP_ID,
    });
    expect(typeof contract.buildSigningPayload).toBe("function");
  });

  test("APPEAL_FILED SYSTEM_AUTO_ESCALATION resolves to NODE envelope", () => {
    const contract = resolveSignatureContract(
      { tx_type: TX_TYPES.APPEAL_FILED, data: { appellant_tip_id: "SYSTEM_AUTO_ESCALATION" } },
      null,
    );
    expect(contract).toMatchObject({
      SIGNATURE_SCOPE: SIGNATURE_SCOPE.ENVELOPE,
      SIGNED_BY: SIGNED_BY_KIND.NODE,
    });
  });

  test("APPEAL_FILED user-filed resolves to SUBJECT body via APPELLANT_TIP_ID", () => {
    const contract = resolveSignatureContract(
      { tx_type: TX_TYPES.APPEAL_FILED, data: { appellant_tip_id: SUBJECT_TIP } },
      null,
    );
    expect(contract).toMatchObject({
      SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
      SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
      SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.APPELLANT_TIP_ID,
    });
  });
});

describe("resolveSignatureContract — schema vs registry priority", () => {
  test("schema's getSignatureContract takes precedence over registry", () => {
    const fakeSchema = {
      getSignatureContract: () => ({
        SIGNATURE_SCOPE: SIGNATURE_SCOPE.ENVELOPE,
        SIGNED_BY: SIGNED_BY_KIND.NODE,
      }),
    };
    // Pass a tx_type that HAS a registry entry; the schema should win.
    const contract = resolveSignatureContract(
      { tx_type: TX_TYPES.CONTENT_VERIFIED, data: {} },
      fakeSchema,
    );
    expect(contract.SIGNATURE_SCOPE).toBe(SIGNATURE_SCOPE.ENVELOPE);
    expect(contract.SIGNED_BY).toBe(SIGNED_BY_KIND.NODE);
  });
});

// silence unused-import lint
void canonicalTx;
