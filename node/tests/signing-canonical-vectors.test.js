/**
 * @file tests/signing-canonical-vectors.test.js
 * @description Golden-vector freeze for the canonical signed payload of every
 * body-scope transaction type.
 *
 * Why this exists:
 *   A signature is a commitment to specific bytes. To verify a historical tx
 *   the node must reproduce the EXACT bytes the signer hashed. So the canonical
 *   signed payload for a given tx_type must never change once a tx of that type
 *   is on a production chain. This suite pins those bytes:
 *
 *     canonicalJson(contract.buildSigningPayload(data))  ===  frozen vector
 *
 *   If anyone edits a recipe in a way that changes the field set, the key order,
 *   or the undefined/null strip behaviour, the frozen string stops matching and
 *   this test fails — i.e. it catches the exact class of change that would break
 *   verification of already-signed transactions (the GH#23 / GH#85 drift class).
 *
 *   Evolution discipline this protects:
 *     - Additive change  → append a field to the recipe's `optional` set; absent
 *       on old txs it is stripped, so their bytes are unchanged (test stays green
 *       for the old vectors, you add a new vector for the new field).
 *     - Breaking change  → mint a NEW tx_type; never mutate a live recipe.
 *
 *   To intentionally (re)freeze after an APPROVED change, regenerate the fixture
 *   with node/scripts/gen-signing-canonical-vectors.js and review the JSON diff:
 *   the canonical bytes are human-readable on purpose so a reviewer can see
 *   exactly what moved.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const { canonicalJson } = require(path.resolve(__dirname, "../../shared/crypto"));
const { SIGNATURE_SCOPE } = require(path.resolve(__dirname, "../../shared/constants"));
const { TX_SIGNATURE_REGISTRY } = require(path.resolve(__dirname, "../src/schemas/_registry"));

const VECTORS = require("./fixtures/signing-canonical-vectors.json");

// Resolve the signing contract the same way production does: a dual-mode
// tx_type exposes getSignatureContract(tx) and decides BODY vs ENVELOPE from
// tx.data; a single-mode tx_type IS the contract.
function resolveContract(txType, data) {
  const entry = TX_SIGNATURE_REGISTRY[txType];
  if (!entry) return null;
  if (typeof entry.getSignatureContract === "function") {
    return entry.getSignatureContract({ tx_type: txType, data: data || {} }) || null;
  }
  return entry;
}

// Every registry tx_type whose contract resolves to BODY scope (probed with an
// empty data object, which selects the body branch of every dual-mode type).
// These are exactly the recipes whose canonical bytes must be frozen here.
function bodyScopeRegistryTypes() {
  const out = new Set();
  for (const txType of Object.keys(TX_SIGNATURE_REGISTRY)) {
    const c = resolveContract(txType, {});
    if (c && c.SIGNATURE_SCOPE === SIGNATURE_SCOPE.BODY) out.add(txType);
  }
  return out;
}

describe("canonical signed-payload golden vectors", () => {

  test("fixture is non-empty", () => {
    expect(Object.keys(VECTORS).length).toBeGreaterThan(0);
  });

  describe("each frozen vector still reproduces byte-for-byte", () => {
    for (const [caseKey, vec] of Object.entries(VECTORS)) {
      test(caseKey, () => {
        const contract = resolveContract(vec.tx_type, vec.data);
        expect(contract).toBeTruthy();
        expect(typeof contract.buildSigningPayload).toBe("function");

        const actual = canonicalJson(contract.buildSigningPayload(vec.data));
        // The whole point: the live recipe must still emit the frozen bytes.
        expect(actual).toBe(vec.canonical);
      });
    }
  });

  test("every body-scope registry tx_type has at least one frozen vector", () => {
    const covered = new Set(Object.values(VECTORS).map(v => v.tx_type));
    const required = bodyScopeRegistryTypes();
    const missing = [...required].filter(t => !covered.has(t));
    // A new body-scope recipe added to the registry without a golden vector
    // would mean its signed bytes are unprotected against silent drift.
    expect(missing).toEqual([]);
  });

  test("strip rule holds: an omitted optional field is absent from the bytes", () => {
    // JURY_VOTE_REVEAL.confirmed_origin is optional. The required-only vector
    // must NOT contain it; the with-optional vector must.
    const reqOnly = VECTORS["JURY_VOTE_REVEAL:required_only"];
    const withOpt = VECTORS["JURY_VOTE_REVEAL:with_optional"];
    expect(reqOnly).toBeTruthy();
    expect(withOpt).toBeTruthy();
    expect(reqOnly.canonical.includes("confirmed_origin")).toBe(false);
    expect(withOpt.canonical.includes("confirmed_origin")).toBe(true);
  });
});
