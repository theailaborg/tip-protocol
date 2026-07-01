/**
 * @file @tip-protocol/node/src/network/peer-key.js
 * @description Deterministic libp2p peer identity from the TIP node id.
 *
 * The same TIP node id always yields the same peer id, so a node's bootstrap
 * multiaddr is computable by anyone who knows its node id, without the node
 * running. Used by node.js at boot and by scripts that pre-generate peer envs.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256 } = require("../../../shared/crypto");

// Salt for the peer-key seed. Frozen at prod: changing it rotates every node's
// peer id, which breaks bootstrap addresses network-wide.
const PEER_KEY_SALT = ":libp2p-peer-key";

let _keys = null;
async function loadKeys() {
  if (_keys) return _keys;
  // Sequential, not Promise.all: jest's experimental ESM loader races on
  // concurrent dynamic imports ("request for X is not in cache").
  const k = await import("@libp2p/crypto/keys");
  const p = await import("@libp2p/peer-id");
  _keys = { generateKeyPairFromSeed: k.generateKeyPairFromSeed, peerIdFromPrivateKey: p.peerIdFromPrivateKey };
  return _keys;
}

async function deriveP2pPrivateKey(nodeId) {
  const { generateKeyPairFromSeed } = await loadKeys();
  const seed = Buffer.from(shake256(nodeId + PEER_KEY_SALT), "hex").subarray(0, 32);
  return generateKeyPairFromSeed("Ed25519", seed);
}

async function deriveP2pPeerId(nodeId) {
  const { peerIdFromPrivateKey } = await loadKeys();
  return peerIdFromPrivateKey(await deriveP2pPrivateKey(nodeId)).toString();
}

async function buildBootstrapAddr(nodeId, ip, port) {
  return `/ip4/${ip}/tcp/${port}/p2p/${await deriveP2pPeerId(nodeId)}`;
}

module.exports = { PEER_KEY_SALT, deriveP2pPrivateKey, deriveP2pPeerId, buildBootstrapAddr };
