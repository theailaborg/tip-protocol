/**
 * @file tests/lib/crypto-pool.test.js
 * @description Parity guard for the off-thread verify pool. The
 * worker runs the SAME verifyCertificate as the main thread, so its result must
 * be identical for both a valid and a tampered cert. The sync-fallback path
 * (pool size 0) must also match. This pins that offloading verify can never
 * change a node's accept/reject decision.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const ROOT = path.resolve(__dirname, "../../..");

const { initCrypto, generateMLDSAKeypair } = require(path.join(ROOT, "shared", "crypto"));
const { createBatch, createBatchAck, createCertificate, verifyCertificate } =
  require(path.join(ROOT, "node", "src", "consensus", "certificate"));
const { createCryptoPool } = require(path.join(ROOT, "node", "src", "lib", "crypto-pool"));

jest.setTimeout(20000);

let kp, cert, pubkeyMap;

beforeAll(async () => {
  await initCrypto();
  kp = generateMLDSAKeypair();
  const author = "tip://node/test-author";
  const batch = createBatch(5, author, [], kp.privateKey);
  const ack = createBatchAck(batch.hash, author, 1700000000000, kp.privateKey);
  cert = createCertificate(5, author, batch, [ack], [], kp.privateKey);
  pubkeyMap = { [author]: kp.publicKey };
});

const syncVerify = (c, quorum) => verifyCertificate(c, (id) => pubkeyMap[id] || null, quorum);

describe("crypto verify pool parity", () => {
  test("disabled pool (size 0) sync-fallback accepts a valid cert, matching main thread", async () => {
    const pool = createCryptoPool({ size: 0 });
    expect(pool.size).toBe(0);
    const res = await pool.verifyCert(cert, pubkeyMap, 1);
    expect(res.valid).toBe(true);
    expect(res.valid).toBe(syncVerify(cert, 1).valid);
    pool.shutdown();
  });

  test("worker pool (size 1) produces an identical accept to the main thread", async () => {
    const pool = createCryptoPool({ size: 1 });
    expect(pool.size).toBe(1);
    const res = await pool.verifyCert(cert, pubkeyMap, 1);
    expect(res.valid).toBe(true);
    expect(res.valid).toBe(syncVerify(cert, 1).valid);
    pool.shutdown();
  });

  test("a tampered cert is rejected identically on the worker and the main thread", async () => {
    const bad = { ...cert, signature: cert.signature.slice(0, -4) + "0000" };
    const pool = createCryptoPool({ size: 1 });
    const res = await pool.verifyCert(bad, pubkeyMap, 1);
    expect(res.valid).toBe(false);
    expect(res.valid).toBe(syncVerify(bad, 1).valid);
    pool.shutdown();
  });
});
