/**
 * @file tests/crypto/native-mldsa-verify.test.js
 * @description Native (OpenSSL >= 3.5) ML-DSA-65 verify fast-path: byte-level
 * agreement with noble on accept AND reject, plus fallback correctness on
 * runtimes without native support (Node < 24 runs the noble-only branch).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { initCrypto, generateMLDSAKeypair, mldsaSign, mldsaVerify, hasNativeMlDsa } =
  require(path.resolve(__dirname, "../../../shared/crypto"));

beforeAll(async () => { await initCrypto(); });

describe("ML-DSA verify (native fast-path + noble fallback)", () => {
  test("noble-signed signature verifies through whichever path is active", () => {
    const kp = generateMLDSAKeypair();
    const sig = mldsaSign("interop message", kp.privateKey);
    expect(mldsaVerify("interop message", sig, kp.publicKey)).toBe(true);
  });

  test("tampered signature rejects", () => {
    const kp = generateMLDSAKeypair();
    const sig = mldsaSign("msg", kp.privateKey);
    const bad = (sig[0] === "0" ? "1" : "0") + sig.slice(1);
    expect(mldsaVerify("msg", bad, kp.publicKey)).toBe(false);
  });

  test("tampered message rejects", () => {
    const kp = generateMLDSAKeypair();
    const sig = mldsaSign("msg", kp.privateKey);
    expect(mldsaVerify("msg2", sig, kp.publicKey)).toBe(false);
  });

  test("malformed public key returns false, never throws", () => {
    const kp = generateMLDSAKeypair();
    const sig = mldsaSign("msg", kp.privateKey);
    expect(mldsaVerify("msg", sig, "deadbeef")).toBe(false);
    expect(mldsaVerify("msg", sig, "")).toBe(false);
  });

  const nativeOnly = hasNativeMlDsa() ? test : test.skip;
  nativeOnly("native and noble agree on 20 random accept/reject cases", async () => {
    const noble = await import("@noble/post-quantum/ml-dsa.js");
    for (let i = 0; i < 20; i++) {
      const kp = generateMLDSAKeypair();
      const msg = `case-${i}`;
      const sig = mldsaSign(msg, kp.privateKey);
      const tampered = i % 2 === 0;
      const testSig = tampered ? sig.slice(0, -2) + (sig.endsWith("00") ? "01" : "00") : sig;
      const nativeResult = mldsaVerify(msg, testSig, kp.publicKey);   // native path (hasNativeMlDsa)
      const nobleResult = noble.ml_dsa65.verify(
        new Uint8Array(Buffer.from(testSig, "hex")),
        Buffer.from(msg),
        new Uint8Array(Buffer.from(kp.publicKey, "hex")),
      );
      expect(nativeResult).toBe(nobleResult);
      expect(nativeResult).toBe(!tampered);
    }
  });
});
