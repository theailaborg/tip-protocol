/**
 * @file tests/network/handshake.test.js
 * @description Unit tests for the TIP peering handshake's cryptographic
 * checks (`network/handshake.js`): genesis-hash and protocol-params-hash
 * agreement plus signature binding. Added for issue #39 / A21, which makes
 * `protocol_params_hash` a peering precondition — the closing criterion is
 * "the handshake rejects peers whose consensus-critical params don't match".
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");
const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { createPayload, verify } = require(path.join(SRC, "network", "handshake"));

const CHAIN_ID = "tip-test-chain";
const GENESIS_HASH = "a".repeat(64);
const PARAMS_HASH = "b".repeat(64);
const OTHER_PARAMS_HASH = "c".repeat(64);
const ROUND = 7;

describe("handshake verify() — protocol_params_hash agreement (#39/A21)", () => {
  let peerNodeId;
  let peerKeys;
  let getNodeKey;

  beforeAll(async () => {
    await initCrypto();
    peerKeys = await generateMLDSAKeypair();
    peerNodeId = "tip://node/peer-under-test";
    getNodeKey = (id) => (id === peerNodeId ? peerKeys.publicKey : null);
  });

  // Build a handshake payload signed by the peer over the given params hash.
  function peerHandshake(paramsHash) {
    return createPayload(
      peerNodeId,
      peerKeys.privateKey,
      CHAIN_ID,
      GENESIS_HASH,
      paramsHash,
      () => ROUND,
    );
  }

  test("accepts a peer whose protocol_params_hash matches ours", () => {
    const hs = peerHandshake(PARAMS_HASH);
    const result = verify(
      hs.nodeId, hs.chainId, hs.round, hs.signature, hs.genesisHash, hs.protocolParamsHash,
      CHAIN_ID, GENESIS_HASH, PARAMS_HASH, getNodeKey,
    );
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  test("rejects a peer whose protocol_params_hash differs from ours", () => {
    // Peer honestly presents (and signs) a different params hash.
    const hs = peerHandshake(OTHER_PARAMS_HASH);
    const result = verify(
      hs.nodeId, hs.chainId, hs.round, hs.signature, hs.genesisHash, hs.protocolParamsHash,
      CHAIN_ID, GENESIS_HASH, PARAMS_HASH, getNodeKey,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Protocol params hash mismatch/);
  });

  test("rejects a legacy peer that omits protocol_params_hash (empty field)", () => {
    // Simulates a pre-#39 node: signature is valid over the old payload shape,
    // but no params hash is sent. The empty hash must be treated as a mismatch.
    const hs = peerHandshake("");
    const result = verify(
      hs.nodeId, hs.chainId, hs.round, hs.signature, hs.genesisHash, "",
      CHAIN_ID, GENESIS_HASH, PARAMS_HASH, getNodeKey,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Protocol params hash mismatch/);
  });

  test("params hash is bound into the signature — spoofing the equality check fails the signature", () => {
    // Attacker takes a peer handshake signed over OTHER_PARAMS_HASH but presents
    // OUR hash on the wire to slip past the equality check. The signature was
    // computed over the original hash, so reconstruction must fail it.
    const hs = peerHandshake(OTHER_PARAMS_HASH);
    const result = verify(
      hs.nodeId, hs.chainId, hs.round, hs.signature, hs.genesisHash, PARAMS_HASH,
      CHAIN_ID, GENESIS_HASH, PARAMS_HASH, getNodeKey,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Invalid signature/);
  });

  test("still rejects on genesis-hash mismatch (params hash does not weaken it)", () => {
    const hs = peerHandshake(PARAMS_HASH);
    const result = verify(
      hs.nodeId, hs.chainId, hs.round, hs.signature, "f".repeat(64), hs.protocolParamsHash,
      CHAIN_ID, GENESIS_HASH, PARAMS_HASH, getNodeKey,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Genesis hash mismatch/);
  });

  test("createPayload includes protocol_params_hash in its returned object", () => {
    const hs = peerHandshake(PARAMS_HASH);
    expect(hs.protocolParamsHash).toBe(PARAMS_HASH);
    expect(typeof hs.signature).toBe("string");
    expect(hs.signature.length).toBeGreaterThan(0);
  });
});
