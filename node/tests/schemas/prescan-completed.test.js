"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");

const { initCrypto, generateMLDSAKeypair, mldsaSign, canonicalTx, computeTxId } = require(path.join(SHARED, "crypto"));
const { getGenesisPayload } = require(path.resolve(__dirname, "../../src/genesis"));
const PC = require(path.join(SHARED, "protocol-constants"));
try { PC._resetForTesting(); } catch { /* not yet initialised */ }
PC.init(getGenesisPayload().protocol_constants);

const prescanCompletedSchema = require(path.resolve(__dirname, "../../src/schemas/prescan-completed"));
const { TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND } = require(path.join(SHARED, "constants"));

// ── Helpers ────────────────────────────────────────────────────────────────
function makeData(overrides = {}) {
  return {
    ctid: "tip://c/OH-7f2a91bc3d5e4a-a3f8",
    node_id: "tip://node/efbe3707224fb785",
    probability: 0.42,
    tier: "low",
    flagged: false,
    overall_degraded: false,
    content_type: "text",
    content_type_meta: { hint_provided: null, resolution: "derived", reason: null },
    modality_results: [],
    classifier_version: "2.0.0",
    classifier_providers_used: "ensemble(test)",
    completed_at: 1779800000000,
    node_id_field: undefined,    // ignored
    failed: false,
    failure_reason: null,
    ...overrides,
  };
}

async function makeSignedTx(data, nodeKeyPair) {
  const txBody = {
    tx_type: TX_TYPES.PRESCAN_COMPLETED,
    timestamp: 1779800000000,
    prev: [],
    data,
  };
  const txId = computeTxId(txBody);
  const withId = { ...txBody, tx_id: txId };
  const sig = mldsaSign(canonicalTx(withId), nodeKeyPair.privateKey);
  return { ...withId, signature: sig };
}

// Minimal in-memory DAG stub — only the calls verifyTx uses.
function makeDagStub(nodes) {
  return {
    getNode: (id) => nodes.get(id) || null,
  };
}

// ── Module exports ─────────────────────────────────────────────────────────
describe("prescan-completed schema — exports", () => {
  test("TX_TYPE", () => {
    expect(prescanCompletedSchema.TX_TYPE).toBe("PRESCAN_COMPLETED");
  });
  test("SIGNATURE_SCOPE + SIGNED_BY follow GH #51 contract", () => {
    expect(prescanCompletedSchema.SIGNATURE_SCOPE).toBe(SIGNATURE_SCOPE.ENVELOPE);
    expect(prescanCompletedSchema.SIGNED_BY).toBe(SIGNED_BY_KIND.NODE);
  });
  test("VALID_TIERS enumerates the 4 tiers", () => {
    expect(prescanCompletedSchema.VALID_TIERS).toEqual(["low", "elevated", "high", "critical"]);
  });
});

// ── tierFromProbability ────────────────────────────────────────────────────
describe("tierFromProbability", () => {
  const tfp = prescanCompletedSchema.tierFromProbability;
  // Genesis thresholds: elevated=0.70, high=0.90, critical=0.98
  test("low", () => {
    expect(tfp(0.00)).toBe("low");
    expect(tfp(0.50)).toBe("low");
    expect(tfp(0.6999)).toBe("low");
  });
  test("elevated", () => {
    expect(tfp(0.70)).toBe("elevated");
    expect(tfp(0.85)).toBe("elevated");
    expect(tfp(0.8999)).toBe("elevated");
  });
  test("high", () => {
    expect(tfp(0.90)).toBe("high");
    expect(tfp(0.95)).toBe("high");
    expect(tfp(0.9799)).toBe("high");
  });
  test("critical", () => {
    expect(tfp(0.98)).toBe("critical");
    expect(tfp(1.00)).toBe("critical");
  });
  test("invalid input → low", () => {
    expect(tfp(NaN)).toBe("low");
    expect(tfp(undefined)).toBe("low");
    expect(tfp("0.95")).toBe("low");
  });
});

// ── verifyTx — happy + sad paths ───────────────────────────────────────────
describe("verifyTx", () => {
  let nodeKeyPair;
  let nodes;

  beforeAll(async () => {
    await initCrypto();
    nodeKeyPair = generateMLDSAKeypair();
    nodes = new Map([
      ["tip://node/efbe3707224fb785", {
        node_id: "tip://node/efbe3707224fb785",
        public_key: nodeKeyPair.publicKey,
        status: "active",
      }],
    ]);
  });

  test("valid LOW tier passes", async () => {
    const tx = await makeSignedTx(makeData(), nodeKeyPair);
    expect(prescanCompletedSchema.verifyTx(tx, makeDagStub(nodes))).toEqual({ ok: true });
  });

  test("valid HIGH tier + flagged=true passes", async () => {
    const tx = await makeSignedTx(
      makeData({ probability: 0.95, tier: "high", flagged: true }),
      nodeKeyPair,
    );
    expect(prescanCompletedSchema.verifyTx(tx, makeDagStub(nodes))).toEqual({ ok: true });
  });

  test("tier inconsistent with probability → rejected", async () => {
    const tx = await makeSignedTx(
      makeData({ probability: 0.95, tier: "low", flagged: false }),
      nodeKeyPair,
    );
    const r = prescanCompletedSchema.verifyTx(tx, makeDagStub(nodes));
    expect(r.ok).toBe(false);
    expect(r.code).toBe("tier_probability_mismatch");
  });

  test("flagged inconsistent with tier → rejected", async () => {
    const tx = await makeSignedTx(
      makeData({ probability: 0.42, tier: "low", flagged: true }),
      nodeKeyPair,
    );
    const r = prescanCompletedSchema.verifyTx(tx, makeDagStub(nodes));
    expect(r.ok).toBe(false);
    expect(r.code).toBe("flagged_tier_mismatch");
  });

  test("unknown node → rejected", async () => {
    const tx = await makeSignedTx(
      makeData({ node_id: "tip://node/0000000000000000" }),
      nodeKeyPair,
    );
    const r = prescanCompletedSchema.verifyTx(tx, makeDagStub(nodes));
    expect(r.ok).toBe(false);
    expect(r.code).toBe("node_not_registered");
  });

  test("inactive node → rejected", async () => {
    const inactiveNodes = new Map([[
      "tip://node/efbe3707224fb785",
      { node_id: "tip://node/efbe3707224fb785", public_key: nodeKeyPair.publicKey, status: "revoked" },
    ]]);
    const tx = await makeSignedTx(makeData(), nodeKeyPair);
    const r = prescanCompletedSchema.verifyTx(tx, makeDagStub(inactiveNodes));
    expect(r.ok).toBe(false);
    expect(r.code).toBe("node_inactive");
  });

  test("tampered data → signature fails", async () => {
    const tx = await makeSignedTx(makeData(), nodeKeyPair);
    const tampered = { ...tx, data: { ...tx.data, probability: 0.99, tier: "critical", flagged: true } };
    const r = prescanCompletedSchema.verifyTx(tampered, makeDagStub(nodes));
    expect(r.ok).toBe(false);
    expect(r.code).toBe("signature_invalid");
  });

  test("invalid content_type → rejected", async () => {
    const tx = await makeSignedTx(makeData({ content_type: "podcast" }), nodeKeyPair);
    const r = prescanCompletedSchema.verifyTx(tx, makeDagStub(nodes));
    expect(r.ok).toBe(false);
    expect(r.code).toBe("content_type_invalid");
  });

  test("probability out of range → rejected", async () => {
    const tx = await makeSignedTx(makeData({ probability: 1.5 }), nodeKeyPair);
    const r = prescanCompletedSchema.verifyTx(tx, makeDagStub(nodes));
    expect(r.ok).toBe(false);
    expect(r.code).toBe("probability_invalid");
  });

  test("missing signature → rejected", async () => {
    const tx = await makeSignedTx(makeData(), nodeKeyPair);
    delete tx.signature;
    const r = prescanCompletedSchema.verifyTx(tx, makeDagStub(nodes));
    expect(r.ok).toBe(false);
    expect(r.code).toBe("signature_missing");
  });
});
