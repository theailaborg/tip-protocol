/**
 * @file node/tests/schemas/node-operated-by.test.js
 * @description NODE_REGISTERED operated_by: the named identity must cosign the
 * same canonical bytes the approving VP signed, and adding the field must not
 * change the bytes of txs that omit it.
 */

"use strict";

const { initCrypto, generateMLDSAKeypair, shake256, canonicalJson } = require("../../../shared/crypto");
const { TX_TYPES, SIGNED_BY_KIND } = require("../../../shared/constants");
const { TX_SIGNATURE_REGISTRY } = require("../../src/schemas/_registry");
const { verifyCosignatures, signCosignature } = require("../../src/schemas/_common");

const CONTRACT = TX_SIGNATURE_REGISTRY[TX_TYPES.NODE_REGISTERED];

// Minimal dag stub: the cosignature dispatcher only needs key resolution.
function makeDag(identities) {
  return {
    getActiveKey: (entityType, ref) =>
      entityType === "identity" && identities[ref] ? identities[ref] : null,
  };
}

function baseData(extra = {}) {
  return {
    node_id: "tip://node/abc123abc123abc1",
    name: "Test Node",
    public_key: "aabbcc",
    algorithm: "ml-dsa-65",
    approving_vp_id: "tip://vp/US-1111111111111111",
    ...extra,
  };
}

let operator;
const OPERATOR_ID = "tip://id/GB-2222222222222222";

beforeAll(async () => {
  await initCrypto();
  const kp = generateMLDSAKeypair();
  operator = { public_key: kp.publicKey, private_key: kp.privateKey, algorithm: "ml-dsa-65" };
});

describe("NODE_REGISTERED operated_by", () => {
  test("omitting operated_by leaves the signed bytes unchanged", () => {
    // The field is in the optional list, so a tx without it must hash exactly
    // as it did before the field existed: required fields only.
    const data = baseData();
    const payload = CONTRACT.buildSigningPayload(data);
    const expected = {
      algorithm: "ml-dsa-65",
      approving_vp_id: data.approving_vp_id,
      name: data.name,
      public_key: data.public_key,
    };
    expect(shake256(canonicalJson(payload))).toBe(shake256(canonicalJson(expected)));
  });

  test("omitting operated_by declares no cosignature contract", () => {
    expect(CONTRACT.getCosignatureContract({ data: baseData() })).toEqual([]);
  });

  test("operated_by enters the signed bytes when present", () => {
    const withOp = CONTRACT.buildSigningPayload(baseData({ operated_by: OPERATOR_ID }));
    const without = CONTRACT.buildSigningPayload(baseData());
    expect(withOp.operated_by).toBe(OPERATOR_ID);
    expect(shake256(canonicalJson(withOp))).not.toBe(shake256(canonicalJson(without)));
  });

  test("a valid operator cosignature verifies", () => {
    const data = baseData({ operated_by: OPERATOR_ID });
    const body = CONTRACT.buildSigningPayload(data);
    data.cosignatures = [signCosignature(body, operator.private_key, SIGNED_BY_KIND.SUBJECT, OPERATOR_ID)];
    const tx = { tx_type: TX_TYPES.NODE_REGISTERED, timestamp: 1786000000000, data };
    const dag = makeDag({ [OPERATOR_ID]: operator });

    const result = verifyCosignatures(tx, CONTRACT.getCosignatureContract(tx), dag);
    expect(result.ok).toBe(true);
  });

  test("a cosignature over different bytes is rejected", () => {
    const data = baseData({ operated_by: OPERATOR_ID });
    // Sign the payload for a DIFFERENT node, then attach it to this one.
    const otherBody = CONTRACT.buildSigningPayload(baseData({ operated_by: OPERATOR_ID, name: "Other Node" }));
    data.cosignatures = [signCosignature(otherBody, operator.private_key, SIGNED_BY_KIND.SUBJECT, OPERATOR_ID)];
    const tx = { tx_type: TX_TYPES.NODE_REGISTERED, timestamp: 1786000000000, data };
    const dag = makeDag({ [OPERATOR_ID]: operator });

    expect(verifyCosignatures(tx, CONTRACT.getCosignatureContract(tx), dag).ok).toBe(false);
  });

  test("operated_by with no cosignature at all is rejected", () => {
    const data = baseData({ operated_by: OPERATOR_ID });
    const tx = { tx_type: TX_TYPES.NODE_REGISTERED, timestamp: 1786000000000, data };
    const dag = makeDag({ [OPERATOR_ID]: operator });

    const result = verifyCosignatures(tx, CONTRACT.getCosignatureContract(tx), dag);
    expect(result.ok).toBe(false);
    expect(result.code).toBe("cosignatures_missing");
  });

  test("an unregistered operator is rejected", () => {
    const data = baseData({ operated_by: OPERATOR_ID });
    const body = CONTRACT.buildSigningPayload(data);
    data.cosignatures = [signCosignature(body, operator.private_key, SIGNED_BY_KIND.SUBJECT, OPERATOR_ID)];
    const tx = { tx_type: TX_TYPES.NODE_REGISTERED, timestamp: 1786000000000, data };

    const result = verifyCosignatures(tx, CONTRACT.getCosignatureContract(tx), makeDag({}));
    expect(result.ok).toBe(false);
    expect(result.code).toBe("cosigner_unknown");
  });
});
