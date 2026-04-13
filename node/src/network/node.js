/**
 * @file @tip-protocol/node/src/network/node.js
 * @description libp2p network node for TIP consensus.
 *
 * Sets up a libp2p node with:
 *   - TCP transport
 *   - Noise encryption (authenticated connections)
 *   - Yamux stream multiplexing
 *   - GossipSub for pub/sub (certificate + mempool broadcast)
 *   - mDNS for local peer discovery (development)
 *   - Bootstrap for known peer connections (production)
 *   - Identify protocol for peer metadata exchange
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { getLogger } = require("../logger");

const log = getLogger("tip.network");

// GossipSub topic names
const TOPICS = Object.freeze({
  CERTIFICATES: "tip/certificates",
  MEMPOOL: "tip/mempool",
  CONSENSUS: "tip/consensus",
});

/**
 * Create and start a libp2p network node.
 *
 * @param {Object} options
 * @param {number} options.port              TCP listen port (default: 4001)
 * @param {Array<string>} options.bootstrapPeers  Multiaddrs of known peers
 * @param {boolean} options.enableMdns       Enable mDNS local discovery (default: true)
 * @param {Object} options.handlers          Topic message handlers
 * @param {Function} options.handlers.onCertificate   (data, peerId) => void
 * @param {Function} options.handlers.onMempoolTx     (data, peerId) => void
 * @param {Function} options.handlers.onConsensus     (data, peerId) => void
 * @returns {Promise<Object>} Network node interface
 */
async function createNetworkNode(options = {}) {
  const {
    port = 4001,
    bootstrapPeers = [],
    enableMdns = true,
    handlers = {},
  } = options;

  // Dynamic imports (libp2p ecosystem is ESM-only)
  const { createLibp2p } = await import("libp2p");
  const { tcp } = await import("@libp2p/tcp");
  const { noise } = await import("@chainsafe/libp2p-noise");
  const { yamux } = await import("@chainsafe/libp2p-yamux");
  const { gossipsub } = await import("@chainsafe/libp2p-gossipsub");
  const { identify } = await import("@libp2p/identify");
  const { mdns } = await import("@libp2p/mdns");
  const { bootstrap } = await import("@libp2p/bootstrap");

  // Build service config
  const services = {
    identify: identify(),
    pubsub: gossipsub({
      emitSelf: false,
      allowPublishToZeroTopicPeers: true,
      heartbeatInterval: 700,
    }),
  };

  // Build peer discovery config
  const peerDiscovery = [];
  if (enableMdns) {
    peerDiscovery.push(mdns());
  }
  if (bootstrapPeers.length > 0) {
    peerDiscovery.push(bootstrap({ list: bootstrapPeers }));
  }

  // Create libp2p node
  const node = await createLibp2p({
    addresses: {
      listen: [`/ip4/0.0.0.0/tcp/${port}`],
    },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    peerDiscovery,
    services,
  });

  // Start the node
  await node.start();
  const listenAddrs = node.getMultiaddrs().map(ma => ma.toString());
  log.info(`libp2p node started on port ${port}`);
  log.info(`Peer ID: ${node.peerId.toString()}`);
  for (const addr of listenAddrs) {
    log.info(`Listening: ${addr}`);
  }

  // Subscribe to GossipSub topics
  const pubsub = node.services.pubsub;

  pubsub.subscribe(TOPICS.CERTIFICATES);
  pubsub.subscribe(TOPICS.MEMPOOL);
  pubsub.subscribe(TOPICS.CONSENSUS);
  log.info(`Subscribed to topics: ${Object.values(TOPICS).join(", ")}`);

  // Handle incoming messages
  pubsub.addEventListener("message", (event) => {
    const { topic, data } = event.detail;
    const peerId = event.detail.from?.toString() || "unknown";

    try {
      switch (topic) {
        case TOPICS.CERTIFICATES:
          if (handlers.onCertificate) handlers.onCertificate(data, peerId);
          break;
        case TOPICS.MEMPOOL:
          if (handlers.onMempoolTx) handlers.onMempoolTx(data, peerId);
          break;
        case TOPICS.CONSENSUS:
          if (handlers.onConsensus) handlers.onConsensus(data, peerId);
          break;
        default:
          log.debug(`Unknown topic message: ${topic}`);
      }
    } catch (err) {
      log.error(`Error handling ${topic} message from ${peerId}: ${err.message}`);
    }
  });

  // Log peer events
  node.addEventListener("peer:connect", (event) => {
    log.info(`Peer connected: ${event.detail.toString()}`);
  });

  node.addEventListener("peer:disconnect", (event) => {
    log.info(`Peer disconnected: ${event.detail.toString()}`);
  });

  // ── Public interface ─────────────────────────────────────────────────────

  return {
    /** The underlying libp2p node (for advanced use / custom protocols) */
    node,

    /** This node's peer ID string */
    peerId: node.peerId.toString(),

    /** All listen multiaddrs */
    multiaddrs: () => node.getMultiaddrs().map(ma => ma.toString()),

    /** Connected peer count */
    peerCount: () => node.getConnections().length,

    /** Connected peer IDs */
    peers: () => [...new Set(node.getConnections().map(c => c.remotePeer.toString()))],

    /**
     * Publish a message to a GossipSub topic.
     * @param {string} topic   One of TOPICS.*
     * @param {Buffer|Uint8Array} data  Protobuf-encoded message
     */
    async publish(topic, data) {
      try {
        await pubsub.publish(topic, data);
      } catch (err) {
        log.warn(`Publish to ${topic} failed: ${err.message}`);
      }
    },

    /**
     * Dial a specific peer by multiaddr.
     * @param {string} multiaddr  e.g. "/ip4/1.2.3.4/tcp/4001/p2p/QmPeerId..."
     */
    async dial(multiaddr) {
      try {
        const { multiaddr: ma } = await import("@multiformats/multiaddr");
        await node.dial(ma(multiaddr));
        log.info(`Dialed peer: ${multiaddr}`);
      } catch (err) {
        log.warn(`Failed to dial ${multiaddr}: ${err.message}`);
      }
    },

    /**
     * Register a custom stream protocol handler.
     * @param {string} protocol  e.g. "/tip/sync/1.0.0"
     * @param {Function} handler  ({ stream, connection }) => void
     */
    async handle(protocol, handler) {
      await node.handle(protocol, handler);
      log.info(`Registered protocol handler: ${protocol}`);
    },

    /**
     * Open a stream to a peer for a custom protocol.
     * @param {string} peerId   Remote peer ID
     * @param {string} protocol e.g. "/tip/sync/1.0.0"
     * @returns {Promise<Stream>}
     */
    async openStream(peerId, protocol) {
      const { peerIdFromString } = await import("@libp2p/peer-id");
      const remotePeer = peerIdFromString(peerId);
      return node.dialProtocol(remotePeer, protocol);
    },

    /** GossipSub topic constants */
    TOPICS,

    /** Stop the node gracefully */
    async stop() {
      pubsub.unsubscribe(TOPICS.CERTIFICATES);
      pubsub.unsubscribe(TOPICS.MEMPOOL);
      pubsub.unsubscribe(TOPICS.CONSENSUS);
      await node.stop();
      log.info("libp2p node stopped");
    },
  };
}

module.exports = { createNetworkNode, TOPICS };
