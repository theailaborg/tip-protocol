/**
 * @file tests/network/peer-key.test.js
 * @description Golden vector for deterministic libp2p peer-id derivation.
 *
 * The peer id is derived from the TIP node id, so bootstrap addresses are
 * computable offline. This locks the derivation: if the salt or algorithm ever
 * changes, every node's peer id changes and bootstrap breaks network-wide, so
 * the known vector below must never drift.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { deriveP2pPeerId, buildBootstrapAddr } = require(path.resolve(__dirname, "../../src/network/peer-key"));

// Ground truth captured from a live founding node's /health.
const NODE_ID = "tip://node/efbe3707224fb785";
const PEER_ID = "12D3KooWLNUc8q4GHqxXznxoYdLYWQnBqD12C9iAofgVGiQdhLNM";

describe("peer-key: deterministic derivation", () => {
  test("node id derives the known peer id", async () => {
    expect(await deriveP2pPeerId(NODE_ID)).toBe(PEER_ID);
  });

  test("derivation is stable across calls", async () => {
    expect(await deriveP2pPeerId(NODE_ID)).toBe(await deriveP2pPeerId(NODE_ID));
  });

  test("different node ids give different peer ids", async () => {
    expect(await deriveP2pPeerId(NODE_ID)).not.toBe(await deriveP2pPeerId("tip://node/0000000000000000"));
  });

  test("buildBootstrapAddr composes the full multiaddr", async () => {
    expect(await buildBootstrapAddr(NODE_ID, "172.30.0.10", 4001))
      .toBe(`/ip4/172.30.0.10/tcp/4001/p2p/${PEER_ID}`);
  });
});
