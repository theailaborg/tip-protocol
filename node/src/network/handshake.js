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
const { encode, decode, bytesToHex, hexToBytes } = require("./proto");
const { buildKnownPeers, dialKnownPeers } = require("./peer-discovery");
const { getLogger } = require("../logger");

const log = getLogger("tip.handshake");

/**
 * Create handshake payload and signature.
 * Signs: "${nodeId}:${round}:${chainId}:${genesisHash}" with ML-DSA-65.
 * The genesis hash is the cryptographic anchor — chain_id is only a
 * human-readable label and can collide across forks, so we include the
 * hash (SHAKE-256 over canonical genesis payload) in both the payload
 * and the signature. Peers with mismatched genesis are rejected even if
 * their chain_id label happens to match.
 */
function createPayload(nodeId, nodePrivateKey, chainId, genesisHash, getLatestRound) {
  const round = getLatestRound();
  const payload = `${nodeId}:${round}:${chainId}:${genesisHash}`;
  const signature = nodePrivateKey ? mldsaSign(payload, nodePrivateKey) : "";
  return { nodeId, round, chainId, genesisHash, signature };
}

/**
 * Verify a peer's handshake signature against the node registry.
 * Rejects peers whose genesis_hash doesn't match ours — prevents joining
 * a forked network that happens to share our chain_id label.
 * @returns {{ valid: boolean, nodeId?: string, error?: string }}
 */
function verify(peerNodeId, peerChainId, peerRound, peerSignature, peerGenesisHash, chainId, genesisHash, getNodeKey) {
  if (peerChainId !== chainId) {
    return { valid: false, error: `Chain ID mismatch: ${peerChainId} !== ${chainId}` };
  }

  if (!peerGenesisHash || peerGenesisHash !== genesisHash) {
    return { valid: false, error: `Genesis hash mismatch: peer=${(peerGenesisHash || "").slice(0, 16)} ours=${genesisHash.slice(0, 16)}` };
  }

  const pubKey = getNodeKey(peerNodeId);
  if (!pubKey) {
    return { valid: false, error: `Node ${peerNodeId} not in registry` };
  }

  const payload = `${peerNodeId}:${peerRound}:${peerChainId}:${peerGenesisHash}`;
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
    const peerSignature = bytesToHex(msg.signature) || "";
    const peerGenesisHash = bytesToHex(msg.genesisHash) || "";

    // Verify against node registry + genesis anchor
    const result = verify(peerNodeId, peerChainId, peerRound, peerSignature, peerGenesisHash, ctx.chainId, ctx.genesisHash, ctx.getNodeKey);

    if (!result.valid) {
      log.warn(`Rejected from ${remotePeerId.slice(0, 12)}: ${result.error}`);
      // Tell the peer why we're closing — otherwise they only see their
      // own "No ack from X" timeout and have no idea whether it's a config
      // problem on their side, a registry miss, or a genesis mismatch.
      try {
        const rejectMsg = encode("HandshakeAck", {
          nodeId: ctx.nodeId || "",
          latestRound: 0,
          merkleRoot: Buffer.alloc(0),
          syncNeeded: false,
          signature: Buffer.alloc(0),
          genesisHash: Buffer.alloc(0),
          error: result.error,
        });
        await stream.sink([rejectMsg]);
      } catch { /* best-effort — if we can't send the reject, we still close */ }
      await stream.close();
      ctx.node.hangUp(connection.remotePeer).catch(() => { });
      return;
    }

    // Send our ack. Include a `known_peers` hint (#38) so the joiner can
    // dial the rest of the federation without env-var coordination. The
    // list reflects our current authorized set + live connection addresses
    // at this moment; stale entries are omitted (peers we've lost
    // connection to don't make useful bootstrap hints).
    const hs = createPayload(ctx.nodeId, ctx.nodePrivateKey, ctx.chainId, ctx.genesisHash, ctx.getLatestRound);
    const knownPeers = await buildKnownPeers(ctx.node, ctx.authorizedPeers, remotePeerId, ctx.peerIdFromString);
    const ack = encode("HandshakeAck", {
      nodeId: hs.nodeId,
      latestRound: hs.round,
      merkleRoot: hexToBytes(ctx.getMerkleRoot() || ""),
      syncNeeded: Math.abs(peerRound - hs.round) > 2,
      signature: hexToBytes(hs.signature),
      genesisHash: hexToBytes(hs.genesisHash),
      knownPeers: knownPeers.map(kp => ({ nodeId: kp.node_id, multiaddrs: kp.multiaddrs })),
    });

    await stream.sink([ack]);

    // Authorized
    ctx.authorizedPeers.set(remotePeerId, peerNodeId);
    log.notice(`OK: ${peerNodeId} (peer ${remotePeerId.slice(0, 12)}) — authorized`);
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
    const hs = createPayload(ctx.nodeId, ctx.nodePrivateKey, ctx.chainId, ctx.genesisHash, ctx.getLatestRound);
    const msg = encode("Handshake", {
      nodeId: hs.nodeId,
      publicKey: Buffer.alloc(0), // not needed — registry has the key
      latestRound: hs.round,
      merkleRoot: hexToBytes(ctx.getMerkleRoot() || ""),
      protocolVersion: PROTOCOL.version,
      chainId: hs.chainId,
      signature: hexToBytes(hs.signature),
      genesisHash: hexToBytes(hs.genesisHash),
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

    // Verify ack. Ack doesn't carry chain_id on the wire (always ours), but
    // it does carry genesis_hash so we can reject a peer with a colliding
    // chain_id label but different genesis.
    const ack = decode("HandshakeAck", ackData);

    // Explicit rejection from peer — they told us why they're closing.
    // Much more useful than the previous "No ack from X" silent timeout.
    if (ack.error) {
      log.warn(`Rejected by ${remotePeerId.slice(0, 12)}: ${ack.error}`);
      await stream.close();
      ctx.node.hangUp(ctx.peerIdFromString(remotePeerId)).catch(() => { });
      return;
    }

    const peerNodeId = ack.nodeId || "";
    const peerRound = Number(ack.latestRound || 0);
    const peerSignature = bytesToHex(ack.signature) || "";
    const peerGenesisHash = bytesToHex(ack.genesisHash) || "";

    const result = verify(peerNodeId, ctx.chainId, peerRound, peerSignature, peerGenesisHash, ctx.chainId, ctx.genesisHash, ctx.getNodeKey);
    await stream.close();

    if (!result.valid) {
      log.warn(`Ack rejected from ${remotePeerId.slice(0, 12)}: ${result.error}`);
      ctx.node.hangUp(ctx.peerIdFromString(remotePeerId)).catch(() => { });
      return;
    }

    // Authorized
    ctx.authorizedPeers.set(remotePeerId, peerNodeId);
    log.notice(`OK: ${peerNodeId} (peer ${remotePeerId.slice(0, 12)}) — authorized`);
    if (ctx.onPeerAuthorized) ctx.onPeerAuthorized(remotePeerId, peerNodeId);

    // #38: auto-dial peers the responder hinted at. Fire-and-forget —
    // each dial triggers its own peer:connect event which runs `initiate`
    // against the new peer, so trust isn't transitive — every discovered
    // peer still proves identity via TIP handshake. Empty or missing
    // list is a no-op (peer hasn't upgraded, or we're the only
    // authorized peer they know).
    const knownPeers = (ack.knownPeers || []).map(kp => ({
      node_id: kp.nodeId || "",
      multiaddrs: Array.isArray(kp.multiaddrs) ? kp.multiaddrs : [],
    }));
    if (knownPeers.length > 0) {
      dialKnownPeers(ctx.node, knownPeers, ctx.authorizedPeers, ctx.nodeId, log);
    }

  } catch (err) {
    log.warn(`Initiate to ${remotePeerId.slice(0, 12)} failed: ${err.message}`);
    try { await stream.close(); } catch { /* ignore */ }
  }
}

module.exports = { createPayload, verify, handleIncoming, initiate };
