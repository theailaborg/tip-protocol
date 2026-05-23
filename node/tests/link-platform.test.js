"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../shared");
const SRC    = path.resolve(__dirname, "../src");

const { initCrypto, generateMLDSAKeypair } = require(SHARED + "/crypto");
const { TX_TYPES } = require(SHARED + "/constants");
const linkPlatformSchema = require(SRC + "/schemas/link-platform");
const { validateTransaction } = require(SRC + "/validators/tx-validator");
const { initDAG } = require(SRC + "/dag");
const { withTxId } = require(SRC + "/services/helpers");
const { nowMs } = require(SHARED + "/time");

beforeAll(async () => { await initCrypto(); });

describe("link-platform schema", () => {
  test("PLATFORM_VALUES contains exactly the 6 supported platforms", () => {
    expect(linkPlatformSchema.PLATFORM_VALUES).toEqual(
      expect.arrayContaining(["youtube", "twitter", "instagram", "linkedin", "tiktok", "rooverse"])
    );
    expect(linkPlatformSchema.PLATFORM_VALUES).toHaveLength(6);
  });

  test("buildSigningPayload returns 4 canonical fields sorted alphabetically", () => {
    const payload = linkPlatformSchema.buildSigningPayload({
      tip_id: "tip://id/IN-abcdef1234567890",
      platform: "twitter",
      handle: "@alice",
      linked_at: 1748000000000,
    });
    expect(payload).toEqual({
      handle: "@alice",
      linked_at: 1748000000000,
      platform: "twitter",
      tip_id: "tip://id/IN-abcdef1234567890",
    });
  });

  test("buildSigningPayload throws on missing tip_id", () => {
    expect(() => linkPlatformSchema.buildSigningPayload({ platform: "twitter", handle: "@x", linked_at: 1 }))
      .toThrow();
  });

  test("buildSigningPayload throws on invalid platform", () => {
    expect(() => linkPlatformSchema.buildSigningPayload({
      tip_id: "tip://id/IN-abcdef1234567890", platform: "myspace", handle: "@x", linked_at: 1,
    })).toThrow();
  });

  test("sign + verifySignature round-trip", async () => {
    const { privateKey, publicKey } = await generateMLDSAKeypair();
    const payload = linkPlatformSchema.buildSigningPayload({
      tip_id: "tip://id/IN-abcdef1234567890",
      platform: "youtube",
      handle: "@mychannel",
      linked_at: 1748000000000,
    });
    const sig = linkPlatformSchema.sign(payload, privateKey);
    expect(linkPlatformSchema.verifySignature(payload, sig, publicKey)).toBe(true);
    expect(linkPlatformSchema.verifySignature(payload, sig, publicKey.slice(0, -4) + "0000")).toBe(false);
  });
});

describe("LINK_PLATFORM tx-validator", () => {
  let dag;
  let vpPub;
  let testTipId;

  beforeAll(async () => {
    dag = initDAG({ dbPath: ":memory:" });
    const { publicKey: vpKey } = await generateMLDSAKeypair();
    vpPub = vpKey;
    dag.saveVP({ vp_id: "tip://vp/test-vp-1", public_key: vpKey, status: "active", tx_id: "genesis-vp-1" });
    testTipId = "tip://id/IN-aabbccdd11223344";
    dag.saveIdentity({ tip_id: testTipId, public_key: vpKey, vp_id: "tip://vp/test-vp-1", tx_id: "genesis-id-1" });
  });

  function makeTx(overrides = {}) {
    return withTxId({
      tx_type: TX_TYPES.LINK_PLATFORM,
      timestamp: nowMs(),
      prev: ["genesis-id-1"],
      data: {
        tip_id: testTipId,
        platform: "youtube",
        handle: "@testchannel",
        linked_at: nowMs(),
        vp_id: "tip://vp/test-vp-1",
        vp_signature: "a".repeat(256),
        ...overrides,
      },
    });
  }

  test("valid LINK_PLATFORM tx passes shape validation (ignores sig for shape layer)", () => {
    const tx = makeTx();
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(true);
  });

  test("invalid platform enum fails shape validation", () => {
    const tx = makeTx({ platform: "myspace" });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/platform/);
  });

  test("empty handle fails shape validation", () => {
    const tx = makeTx({ handle: "" });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/handle/);
  });

  test("unknown tip_id fails state validation", () => {
    const tx = makeTx({ tip_id: "tip://id/US-ffffffffffffffff" });
    const result = validateTransaction(tx, dag, { skipPrevCheck: true });
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/TIP-ID not found/);
  });
});
