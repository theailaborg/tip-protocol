/**
 * @file @tip-protocol/node/src/network/handshake.js
 * @description TIP Handshake Protocol — mutual node authentication.
 *
 * After libp2p connects two peers, they exchange TIP handshake messages
 * to prove they are registered nodes by signing with their ML-DSA-65 key.
 * Unauthorized peers are disconnected.
 *
 * Flow:
 *   1. Lower peerId initiates (deterministic — prevents duplicate handshakes)
 *   2. Initiator sends: Handshake { nodeId, round, chainId, signature }
 *   3. Responder verifies signature against node registry
 *   4. Responder sends: HandshakeAck { nodeId, round, signature }
 *   5. Initiator verifies ack
 *   6. Both mark each other as authorized
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");
const { PROTOCOL } = require("../../../shared/constants");
const { mldsaSign, mldsaVerify } = require("../../../shared/crypto");
const { encode, decode } = require("./proto");
const { getLogger } = require("../logger");

const log = getLogger("tip.handshake");

/**
 * Create handshake payload and signature.
 * Signs: "${nodeId}:${round}:${chainId}" with ML-DSA-65.
 */
function createPayload(nodeId, nodePrivateKey, chainId, getLatestRound) {
  const round = getLatestRound();
  const payload = `${nodeId}:${round}:${chainId}`;
  const signature = nodePrivateKey ? mldsaSign(payload, nodePrivateKey) : "";
  return { nodeId, round, chainId, signature };
}

/**
 * Verify a peer's handshake signature against the node registry.
 * @returns {{ valid: boolean, nodeId?: string, error?: string }}
 */
function verify(peerNodeId, peerChainId, peerRound, peerSignature, chainId, getNodeKey) {
  if (peerChainId !== chainId) {
    return { valid: false, error: `Chain ID mismatch: ${peerChainId} !== ${chainId}` };
  }

  const pubKey = getNodeKey(peerNodeId);
  if (!pubKey) {
    return { valid: false, error: `Node ${peerNodeId} not in registry` };
  }

  const payload = `${peerNodeId}:${peerRound}:${peerChainId}`;
  if (!mldsaVerify(payload, peerSignature, pubKey)) {
    return { valid: false, error: `Invalid signature from ${peerNodeId}` };
  }

  return { valid: true, nodeId: peerNodeId };
}

/**
 * Handle incoming handshake stream (we are the responder).
 * Reads the peer's handshake, verifies it, sends our ack.
 *
 * @param {{ stream, connection }} args  libp2p protocol handler args
 * @param {Object} ctx  Shared context from createNetworkNode
 */
async function handleIncoming({ stream, connection }, ctx) {
  const remotePeerId = connection.remotePeer.toString();
  try {
    // Read peer's handshake message
    let handshakeData = null;
    for await (const chunk of stream.source) {
      handshakeData = chunk.subarray();
      break;
    }

    if (!handshakeData) {
      log.warn(`Empty message from ${remotePeerId.slice(0, 12)}`);
      await stream.close();
      return;
    }

    const msg = decode("Handshake", handshakeData);
    const peerNodeId = msg.nodeId || "";
    const peerChainId = msg.chainId || "";
    const peerRound = Number(msg.latestRound || 0);
    const peerSignature = msg.signature?.toString("hex") || "";

    // Verify against node registry
    const result = verify(peerNodeId, peerChainId, peerRound, peerSignature, ctx.chainId, ctx.getNodeKey);

    if (!result.valid) {
      log.warn(`Rejected from ${remotePeerId.slice(0, 12)}: ${result.error}`);
      await stream.close();
      ctx.node.hangUp(connection.remotePeer).catch(() => { });
      return;
    }

    // Send our ack
    const hs = createPayload(ctx.nodeId, ctx.nodePrivateKey, ctx.chainId, ctx.getLatestRound);
    const ack = encode("HandshakeAck", {
      nodeId: hs.nodeId,
      latestRound: hs.round,
      merkleRoot: Buffer.from(ctx.getMerkleRoot() || "", "hex"),
      syncNeeded: Math.abs(peerRound - hs.round) > 2,
      signature: Buffer.from(hs.signature, "hex"),
    });

    await stream.sink([ack]);

    // Authorized
    ctx.authorizedPeers.set(remotePeerId, peerNodeId);
    log.info(`OK: ${peerNodeId} (peer ${remotePeerId.slice(0, 12)}) — authorized`);
    if (ctx.onPeerAuthorized) ctx.onPeerAuthorized(remotePeerId, peerNodeId);

  } catch (err) {
    log.warn(`Error from ${remotePeerId.slice(0, 12)}: ${err.message}`);
    try { await stream.close(); } catch { /* ignore */ }
  }
}

/**
 * Initiate handshake to a newly connected peer (we are the initiator).
 * Retries dial up to CONSENSUS.HANDSHAKE_MAX_RETRIES times.
 *
 * @param {string} remotePeerId  libp2p peer ID string
 * @param {Object} ctx  Shared context from createNetworkNode
 */
async function initiate(remotePeerId, ctx) {
  if (ctx.authorizedPeers.has(remotePeerId)) return;
  if (!ctx.nodeId || !ctx.nodePrivateKey) {
    log.warn("Cannot initiate — node not registered (no nodeId/privateKey)");
    return;
  }

  // Dial with retries
  const maxRetries = CONSENSUS.HANDSHAKE_MAX_RETRIES;
  let stream;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      stream = await ctx.node.dialProtocol(ctx.peerIdFromString(remotePeerId), ctx.handshakeProtocol);
      break;
    } catch (err) {
      if (attempt === maxRetries) {
        log.warn(`Dial to ${remotePeerId.slice(0, 12)} failed after ${maxRetries} attempts: ${err.message}`);
        return;
      }
      log.debug(`Dial attempt ${attempt}/${maxRetries} to ${remotePeerId.slice(0, 12)} failed, retrying...`);
      await new Promise(r => setTimeout(r, attempt * 500));
    }
  }

  try {
    // Send our handshake
    const hs = createPayload(ctx.nodeId, ctx.nodePrivateKey, ctx.chainId, ctx.getLatestRound);
    const msg = encode("Handshake", {
      nodeId: hs.nodeId,
      publicKey: Buffer.alloc(0), // not needed — registry has the key
      latestRound: hs.round,
      merkleRoot: Buffer.from(ctx.getMerkleRoot() || "", "hex"),
      protocolVersion: PROTOCOL.version,
      chainId: hs.chainId,
      signature: Buffer.from(hs.signature, "hex"),
    });

    await stream.sink([msg]);

    // Read ack with timeout
    const timeout = setTimeout(() => {
      try { stream.close(); } catch { /* ignore */ }
    }, ctx.handshakeTimeoutMs);

    let ackData = null;
    for await (const chunk of stream.source) {
      ackData = chunk.subarray();
      break;
    }
    clearTimeout(timeout);

    if (!ackData) {
      log.warn(`No ack from ${remotePeerId.slice(0, 12)}`);
      await stream.close();
      ctx.node.hangUp(ctx.peerIdFromString(remotePeerId)).catch(() => { });
      return;
    }

    // Verify ack (ack doesn't include chainId — use ours)
    const ack = decode("HandshakeAck", ackData);
    const peerNodeId = ack.nodeId || "";
    const peerRound = Number(ack.latestRound || 0);
    const peerSignature = ack.signature?.toString("hex") || "";

    const result = verify(peerNodeId, ctx.chainId, peerRound, peerSignature, ctx.chainId, ctx.getNodeKey);
    await stream.close();

    if (!result.valid) {
      log.warn(`Ack rejected from ${remotePeerId.slice(0, 12)}: ${result.error}`);
      ctx.node.hangUp(ctx.peerIdFromString(remotePeerId)).catch(() => { });
      return;
    }

    // Authorized
    ctx.authorizedPeers.set(remotePeerId, peerNodeId);
    log.info(`OK: ${peerNodeId} (peer ${remotePeerId.slice(0, 12)}) — authorized`);
    if (ctx.onPeerAuthorized) ctx.onPeerAuthorized(remotePeerId, peerNodeId);

  } catch (err) {
    log.warn(`Initiate to ${remotePeerId.slice(0, 12)} failed: ${err.message}`);
    try { await stream.close(); } catch { /* ignore */ }
  }
}

module.exports = { createPayload, verify, handleIncoming, initiate };
