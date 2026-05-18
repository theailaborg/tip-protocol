"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../shared");
const SRC = path.resolve(__dirname, "../src");
const { initCrypto } = require(path.join(SHARED, "crypto"));

describe("Genesis signature verification", () => {
  beforeAll(async () => {
    await initCrypto();
  });

  test("verifyGenesisSignature passes for committed values", () => {
    const genesis = require(path.join(SRC, "genesis"));
    expect(() => genesis.verifyGenesisSignature()).not.toThrow();
  });

  test("verifyGenesisVPSignature passes for committed values", () => {
    const genesis = require(path.join(SRC, "genesis"));
    expect(() => genesis.verifyGenesisVPSignature()).not.toThrow();
  });

  test("mldsaVerify returns false for tampered genesis tx payload", () => {
    const { mldsaVerify, canonicalTx } = require(path.join(SHARED, "crypto"));
    const { GENESIS_TX_SIGNATURE, getFoundingVP, GENESIS_TX, GENESIS_PAYLOAD } =
      require(path.join(SRC, "genesis"));

    const tamperedTx = { ...GENESIS_TX, data: { ...GENESIS_PAYLOAD, version: "TAMPERED" } };
    expect(
      mldsaVerify(canonicalTx(tamperedTx), GENESIS_TX_SIGNATURE, getFoundingVP().public_key)
    ).toBe(false);
  });

  test("mldsaVerify returns false for tampered founding_vp fields", () => {
    const { mldsaVerify, canonicalTx } = require(path.join(SHARED, "crypto"));
    const { GENESIS_VP_TX_SIGNATURE, getFoundingVP, GENESIS_TX_ID, GENESIS_TIMESTAMP } =
      require(path.join(SRC, "genesis"));

    const foundingVP = getFoundingVP();
    const tamperedVpTx = {
      tx_type: "VP_REGISTERED",
      timestamp: GENESIS_TIMESTAMP,
      prev: [GENESIS_TX_ID, GENESIS_TX_ID],
      data: { ...foundingVP, jurisdiction: "TAMPERED" },
    };
    expect(
      mldsaVerify(canonicalTx(tamperedVpTx), GENESIS_VP_TX_SIGNATURE, foundingVP.public_key)
    ).toBe(false);
  });

});
