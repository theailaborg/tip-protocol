/**
 * @file tests/shared/zk-curve-release.test.js
 * @description Proving or verifying a dedup proof must not leave snarkjs's
 * worker pool resident: the cached bn128 curve (one worker per CPU, each with
 * a WASM memory) is torn down once no call is in flight, and concurrent calls
 * share one build.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { generateDedupProof, verifyDedupProof } = require(path.resolve(__dirname, "../../../shared/zk"));

jest.setTimeout(120_000);

describe("snarkjs curve release", () => {
  test("no cached curve survives a prove + verify round trip", async () => {
    const { dedup_hash, proof } = await generateDedupProof("GOV-curve-release", "1990-01-01", "US");
    expect(globalThis.curve_bn128).toBeFalsy();

    await expect(verifyDedupProof(dedup_hash, proof)).resolves.toBe(true);
    expect(globalThis.curve_bn128).toBeFalsy();
  });

  test("concurrent verifications complete and still release the curve", async () => {
    const { dedup_hash, proof } = await generateDedupProof("GOV-curve-concurrent", "1990-01-01", "US");
    const results = await Promise.all([
      verifyDedupProof(dedup_hash, proof),
      verifyDedupProof(dedup_hash, proof),
      verifyDedupProof(dedup_hash, proof),
    ]);
    expect(results).toEqual([true, true, true]);
    expect(globalThis.curve_bn128).toBeFalsy();
  });
});
