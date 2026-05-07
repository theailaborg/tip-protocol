/**
 * @file @tip-protocol/node/src/init-network.js
 * @description P2P network + consensus layer initialization for TIP node.
 *
 * Initializes:
 *   1. Protobuf schemas
 *   2. libp2p network node (TCP, Noise, GossipSub, handshake)
 *   3. Consensus layer (Narwhal + Bullshark + mempool + commit handler)
 *   4. GossipSub topic wiring
 *
 * Returns null for both network and consensus if initialization fails
 * (node continues in single-node mode without P2P).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { createNetworkNode } = require("./network/node");
const { initConsensus } = require("./consensus");
const { loadTypes } = require("./network/proto");
const { log } = require("./logger");

/**
 * Look up a node's public key from the DAG registry.
 * Used by handshake to verify peer identity.
 */
function getNodeKey(dag, nodeId) {
  const node = dag.getNode(nodeId);
  return node?.public_key || null;
}

/**
 * Check if a libp2p peerId has been authorized via TIP handshake.
 */
function isAuthorizedPeer(network, peerId) {
  return !!network.authorizedPeers()[peerId];
}

/**
 * Initialize the P2P network and consensus layer.
 * Safe to call — catches errors and falls back to null.
 *
 * @param {Object} options
 * @param {Object} options.dag       DAG store
 * @param {Object} options.scoring   Scoring engine
 * @param {Object} options.config    Node config
 * @returns {Promise<{ network: Object|null, consensus: Object|null }>}
 */
async function initNetworkAndConsensus({ dag, scoring, config }) {
  try {
    await loadTypes();

    const p2pPort = parseInt(process.env.TIP_P2P_PORT || "4001", 10);
    const bootstrapPeers = (process.env.TIP_BOOTSTRAP_PEERS || "")
      .split(",").map(s => s.trim()).filter(Boolean);
    const enableMdns = process.env.TIP_ENABLE_MDNS !== "false";

    const network = await createNetworkNode({
      port: p2pPort,
      bootstrapPeers,
      enableMdns,
      nodeId: config.nodeRegisteredId || config.nodeId,
      nodePrivateKey: config.nodePrivateKey,
      getNodeKey: (nodeId) => getNodeKey(dag, nodeId),
      getLatestRound: () => dag.getLatestRound(),
      getMerkleRoot: () => "",
    });

    const consensus = initConsensus({
      dag, scoring, config, network,
      isAuthorizedPeer: (peerId) => isAuthorizedPeer(network, peerId),
    });

    network.setTopicHandlers({
      onMempoolTx: (data) => consensus.handlers.onBatch(data),
      // Layer 2 direct-stream fallback: same handler as gossipsub MEMPOOL but
      // called from the /tip/consensus-ack/1.0.0 stream when gossipsub mesh
      // edges are stale. Returns the ack buffer so the stream handler can write
      // it back on the same connection, closing the bidirectional loop.
      onBatch: (data) => consensus.handlers.onBatch(data),
      onConsensus: (data) => consensus.handlers.onAck(data),
      onCertificate: (data) => consensus.handlers.onCertificate(data),
      onRotationCoordination: (data, peerId) => consensus.handlers.onRotationCoordination(data, peerId),
    });

    // Joiner gating: a fresh node whose own record isn't yet in the DAG
    // registry (i.e. not the founder, and has never synced before) must wait
    // for the first peer handshake + sync before producing. Otherwise its
    // batches/acks get rejected by peers that haven't yet seen it. Founders
    // (in genesis) and previously-synced restarts both have their own node
    // record in DAG and can start producing immediately.
    const ourNodeId = config.nodeRegisteredId || config.nodeId;
    const weAreRegistered = ourNodeId && dag.getNode(ourNodeId);
    await consensus.start({ awaitPeers: !weAreRegistered });
    log.info(`Consensus ready: Narwhal + Bullshark on port ${p2pPort}`);

    return { network, consensus };
  } catch (err) {
    log.warn(`P2P/Consensus failed to start: ${err.message}`);
    log.warn("Node running without consensus — single-node mode only");
    return { network: null, consensus: null };
  }
}

module.exports = { initNetworkAndConsensus };
