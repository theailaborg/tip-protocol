/**
 * @file tests/network/handshake.test.js
 * @description Handshake cryptographic checks: genesis-hash agreement and
 * signature binding. genesis_hash commits to the founding params, so this one
 * check covers chain identity and founding-config agreement.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");
const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { createPayload, verify, unauthorizedPeers, canFastReauth } = require(path.join(SRC, "network", "handshake"));

const CHAIN_ID = "tip-test-chain";
const GENESIS_HASH = "a".repeat(64);
const OTHER_GENESIS_HASH = "f".repeat(64);
const ROUND = 7;

describe("handshake verify() — genesis-hash agreement", () => {
  let peerNodeId;
  let peerKeys;
  let getNodeKey;

  beforeAll(async () => {
    await initCrypto();
    peerKeys = await generateMLDSAKeypair();
    peerNodeId = "tip://node/peer-under-test";
    getNodeKey = (id) => (id === peerNodeId ? peerKeys.publicKey : null);
  });

  function peerHandshake(genesisHash) {
    return createPayload(peerNodeId, peerKeys.privateKey, CHAIN_ID, genesisHash, () => ROUND);
  }

  test("accepts a peer whose genesis_hash matches ours", () => {
    const hs = peerHandshake(GENESIS_HASH);
    const result = verify(
      hs.nodeId, hs.chainId, hs.round, hs.signature, hs.genesisHash,
      CHAIN_ID, GENESIS_HASH, getNodeKey,
    );
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  test("rejects a peer whose genesis_hash differs from ours", () => {
    const hs = peerHandshake(OTHER_GENESIS_HASH);
    const result = verify(
      hs.nodeId, hs.chainId, hs.round, hs.signature, hs.genesisHash,
      CHAIN_ID, GENESIS_HASH, getNodeKey,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Genesis hash mismatch/);
  });

  test("genesis_hash is bound into the signature — spoofing the wire value fails the signature", () => {
    const hs = peerHandshake(OTHER_GENESIS_HASH);
    const result = verify(
      hs.nodeId, hs.chainId, hs.round, hs.signature, GENESIS_HASH,
      CHAIN_ID, GENESIS_HASH, getNodeKey,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Genesis hash mismatch|Invalid signature/);
  });

  test("rejects on chain-id mismatch", () => {
    const hs = peerHandshake(GENESIS_HASH);
    const result = verify(
      hs.nodeId, "tip-other-chain", hs.round, hs.signature, hs.genesisHash,
      CHAIN_ID, GENESIS_HASH, getNodeKey,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Chain ID mismatch/);
  });

  test("createPayload returns a signed payload", () => {
    const hs = peerHandshake(GENESIS_HASH);
    expect(hs.genesisHash).toBe(GENESIS_HASH);
    expect(typeof hs.signature).toBe("string");
    expect(hs.signature.length).toBeGreaterThan(0);
  });
});

// reHandshakeUnauthorized's peer-selection: connected peers we have NOT authorized.
describe("unauthorizedPeers (re-handshake selection)", () => {
  const conn = (id) => ({ remotePeer: { toString: () => id } });

  test("returns connected peers absent from the authorized set", () => {
    const authorized = new Map([["peer-A", "tip://node/A"]]);
    const out = unauthorizedPeers([conn("peer-A"), conn("peer-B"), conn("peer-C")], authorized);
    expect(out).toEqual(["peer-B", "peer-C"]); // peer-A skipped (authorized)
  });

  test("skips already-authorized peers (no redundant re-handshake)", () => {
    const authorized = new Map([["peer-A", "tip://node/A"], ["peer-B", "tip://node/B"]]);
    expect(unauthorizedPeers([conn("peer-A"), conn("peer-B")], authorized)).toEqual([]);
  });

  test("dedups multiple connections to the same peer", () => {
    const out = unauthorizedPeers([conn("peer-A"), conn("peer-A"), conn("peer-B")], new Map());
    expect(out).toEqual(["peer-A", "peer-B"]);
  });

  test("empty / missing connections → empty", () => {
    expect(unauthorizedPeers([], new Map())).toEqual([]);
    expect(unauthorizedPeers(null, new Map())).toEqual([]);
  });
});

// De-auth grace: a quick reconnect skips the ML-DSA handshake; a stale binding does not.
describe("canFastReauth (de-auth grace)", () => {
  const GRACE = 15000;

  test("reconnect within grace + not currently authorized → fast re-auth", () => {
    const recent = { tipNodeId: "tip://node/A", at: 1000 };
    expect(canFastReauth(recent, false, 1000 + 5000, GRACE)).toBe(true);
  });

  test("after grace passes → NOT fast re-auth (must full-handshake again)", () => {
    const recent = { tipNodeId: "tip://node/A", at: 1000 };
    expect(canFastReauth(recent, false, 1000 + GRACE + 1, GRACE)).toBe(false);
  });

  test("already authorized → NOT fast re-auth (no redundant restore)", () => {
    const recent = { tipNodeId: "tip://node/A", at: 1000 };
    expect(canFastReauth(recent, true, 1000 + 100, GRACE)).toBe(false);
  });

  test("no remembered binding → NOT fast re-auth (full handshake)", () => {
    expect(canFastReauth(undefined, false, 5000, GRACE)).toBe(false);
  });
});
