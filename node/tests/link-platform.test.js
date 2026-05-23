"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../shared");
const SRC    = path.resolve(__dirname, "../src");

const { initCrypto, generateMLDSAKeypair } = require(SHARED + "/crypto");
const { TX_TYPES } = require(SHARED + "/constants");
const linkPlatformSchema = require(SRC + "/schemas/link-platform");

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
