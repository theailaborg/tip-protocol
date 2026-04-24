/**
 * @file @tip-protocol/node/src/network/node.js
 * @description libp2p network node for TIP consensus.
 *
 * Creates and configures the P2P node:
 *   - TCP transport + Noise encryption + Yamux multiplexing
 *   - GossipSub pub/sub (certificate + mempool + consensus topics)
 *   - GossipSub DirectPeers: authorized federation peers are added to the
 *     pubsub direct set on handshake complete, forcing a full mesh among
 *     committee members. Bypasses random mesh selection and score-based
 *     prune so consensus messages reach every peer on the fastest path.
 *   - mDNS (local) + Bootstrap (remote) peer discovery
 *   - TIP Handshake for mutual node authentication (see handshake.js)
 *   - Per-peer rate limiting on GossipSub messages (see rate-limiter.js)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS, NETWORK } = require("../../../shared/protocol-constants");
const { shake256 } = require("../../../shared/crypto");
const { GENESIS_CHAIN_ID, getGenesisHash } = require("../genesis");
const { handleIncoming, initiate } = require("./handshake");
const { createRateLimiter } = require("./rate-limiter");
const { createDirectPeersManager, makeAuthorizationWrapper } = require("./direct-peers");
const { getLogger } = require("../logger");

const log = getLogger("tip.network");

/**
 * libp2p is ESM-only. Loaded once via dynamic import(), cached for reuse.
 */
let _lib = null;
async function loadLibp2p() {
  if (_lib) return _lib;
  const mods = await Promise.all([
    import("libp2p"),
    import("@libp2p/tcp"),
    import("@chainsafe/libp2p-noise"),
    import("@chainsafe/libp2p-yamux"),
    import("@chainsafe/libp2p-gossipsub"),
    import("@libp2p/identify"),
    import("@libp2p/mdns"),
    import("@libp2p/bootstrap"),
    import("@libp2p/crypto/keys"),
    import("@libp2p/peer-id"),
  ]);
  _lib = {
    createLibp2p: mods[0].createLibp2p,
    tcp: mods[1].tcp,
    noise: mods[2].noise,
    yamux: mods[3].yamux,
    gossipsub: mods[4].gossipsub,
    identify: mods[5].identify,
    mdns: mods[6].mdns,
    bootstrapDiscovery: mods[7].bootstrap,
    generateKeyPairFromSeed: mods[8].generateKeyPairFromSeed,
    peerIdFromString: mods[9].peerIdFromString,
  };
  return _lib;
}

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
 * @param {number}   options.port            TCP listen port (default: 4001)
 * @param {Array}    options.bootstrapPeers  Multiaddrs of known peers
 * @param {boolean}  options.enableMdns      Enable mDNS local discovery
 * @param {string}   options.nodeId          This node's TIP node ID (tip://node/...)
 * @param {string}   options.nodePrivateKey  ML-DSA-65 private key for signing
 * @param {Function} options.getNodeKey      (nodeId) => publicKey from registry
 * @param {Function} options.getLatestRound  () => current consensus round
 * @param {Function} options.getMerkleRoot   () => current merkle root hex
 * @returns {Promise<Object>} Network node interface
 */
async function createNetworkNode(options = {}) {
  const { createLibp2p, tcp, noise, yamux, gossipsub, identify, mdns, bootstrapDiscovery, generateKeyPairFromSeed, peerIdFromString } = await loadLibp2p();
  const { port = 4001, bootstrapPeers = [], enableMdns = true, nodeId = null, nodePrivateKey = null, getNodeKey = () => null, getLatestRound = () => 0, getMerkleRoot = () => "" } = options;

  // State
  let _topicHandlers = {};
  const _authorizedPeers = new Map();
  let _onPeerAuthorized = null;

  // Deterministic peer ID from TIP node ID 
  // Same TIP node ID = same libp2p peer ID across restarts.
  let privateKey;
  if (nodeId) {
    const seed = Buffer.from(shake256(nodeId + ":libp2p-peer-key"), "hex").subarray(0, 32);
    privateKey = await generateKeyPairFromSeed("Ed25519", seed);
    log.info(`Peer ID derived from TIP node ID: ${nodeId}`);
  }

  // Peer discovery
  const peerDiscovery = [];
  if (enableMdns) peerDiscovery.push(mdns());
  if (bootstrapPeers.length > 0) {
    log.info(`Bootstrap peers: ${bootstrapPeers.join(", ")}`);
    peerDiscovery.push(bootstrapDiscovery({ list: bootstrapPeers }));
  } else {
    log.warn("No bootstrap peers configured — discovery via mDNS only");
  }

  // Announce public IP if set (required for Docker / NAT deployments)
  const publicIp = process.env.TIP_PUBLIC_IP;
  const announceAddrs = publicIp ? [`/ip4/${publicIp}/tcp/${port}`] : [];

  // Create libp2p node — allow all connections at TCP level,
  // authorization happens via TIP handshake protocol after connect.
  const node = await createLibp2p({
    privateKey,
    addresses: {
      listen: [`/ip4/0.0.0.0/tcp/${port}`],
      announce: announceAddrs.length > 0 ? announceAddrs : undefined,
    },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    peerDiscovery,
    services: {
      identify: identify(),
      pubsub: gossipsub({ emitSelf: false, allowPublishToZeroTopicPeers: true, heartbeatInterval: 700 }),
    },
  });

  await node.start();
  log.info(`libp2p node started on port ${port}`);
  log.info(`Peer ID: ${node.peerId.toString()}`);
  for (const addr of node.getMultiaddrs()) log.info(`Listening: ${addr.toString()}`);

  // ── GossipSub + DirectPeers (needed by handshake ctx below) ────────────
  const pubsub = node.services.pubsub;
  pubsub.subscribe(TOPICS.CERTIFICATES);
  pubsub.subscribe(TOPICS.MEMPOOL);
  pubsub.subscribe(TOPICS.CONSENSUS);
  log.info(`Subscribed to topics: ${Object.values(TOPICS).join(", ")}`);
  const directPeers = createDirectPeersManager(pubsub, log);

  // Handshake context (shared with handshake.js functions).
  // onPeerAuthorized wires two concerns: (1) add peer to gossipsub
  // DirectPeers so consensus mesh is stable, (2) invoke the
  // consumer-registered callback. The user callback is read lazily via
  // a closure getter so late registration (after ctx construction) is
  // honored. See `makeAuthorizationWrapper` in direct-peers.js.
  const ctx = {
    node, nodeId, nodePrivateKey, getNodeKey, getLatestRound, getMerkleRoot, peerIdFromString,
    chainId: GENESIS_CHAIN_ID || "tip-mainnet-v2",
    // Genesis hash is the cryptographic network anchor. Chain_id is just a
    // label; two forks could share the same string. The hash can't collide
    // unless the entire genesis payload is identical. See issue #17.
    genesisHash: getGenesisHash(),
    handshakeProtocol: NETWORK.HANDSHAKE_PROTOCOL,
    handshakeTimeoutMs: CONSENSUS.HANDSHAKE_TIMEOUT_MS,
    authorizedPeers: _authorizedPeers,
    onPeerAuthorized: makeAuthorizationWrapper(directPeers, () => _onPeerAuthorized),
  };

  // Register handshake protocol handler
  await node.handle(ctx.handshakeProtocol, (args) => handleIncoming(args, ctx));
  log.info(`Registered protocol handler: ${ctx.handshakeProtocol}`);

  // ── Message handler — auth + rate limit + route to topic handlers
  const rateLimiter = createRateLimiter();

  pubsub.addEventListener("message", (event) => {
    const { topic, data } = event.detail;
    const peerId = event.detail.from?.toString() || "unknown";

    if (!_authorizedPeers.has(peerId)) {
      log.debug(`Dropped ${topic} message from unauthorized peer ${peerId.slice(0, 12)}`);
      return;
    }
    if (!rateLimiter.check(peerId)) {
      log.warn(`Rate limited peer ${peerId}: exceeded ${CONSENSUS.MAX_MSGS_PER_PEER_PER_SEC} msgs/sec`);
      return;
    }

    try {
      switch (topic) {
        case TOPICS.CERTIFICATES:
          if (_topicHandlers.onCertificate) _topicHandlers.onCertificate(data, peerId);
          break;
        case TOPICS.MEMPOOL:
          if (_topicHandlers.onMempoolTx) _topicHandlers.onMempoolTx(data, peerId);
          break;
        case TOPICS.CONSENSUS:
          if (_topicHandlers.onConsensus) _topicHandlers.onConsensus(data, peerId);
          break;
        default:
          log.debug(`Unknown topic message: ${topic}`);
      }
    } catch (err) {
      log.error(`Error handling ${topic} message from ${peerId}: ${err.message}`);
    }
  });

  // Log when a peer is discovered (before connection attempt)
  node.addEventListener("peer:discovery", (event) => {
    const peerId = event.detail.id.toString();
    const addrs = event.detail.multiaddrs?.map(ma => ma.toString()) || [];
    log.info(`Peer discovered: ${peerId.slice(0, 16)}... at ${addrs.join(", ") || "unknown"}`);
  });

  node.addEventListener("peer:connect", (event) => {
    const remotePeerId = event.detail.toString();
    const myPeerId = node.peerId.toString();
    // Only one side initiates handshake — lower peerId goes first (deterministic)
    if (myPeerId < remotePeerId) {
      log.info(`Peer connected: ${remotePeerId.slice(0, 16)}... — initiating handshake (we are lower ID)`);
      initiate(remotePeerId, ctx);
    } else {
      log.info(`Peer connected: ${remotePeerId.slice(0, 16)}... — waiting for their handshake (they are lower ID)`);
    }
  });

  node.addEventListener("peer:disconnect", (event) => {
    const remotePeerId = event.detail.toString();
    const tipNodeId = _authorizedPeers.get(remotePeerId);
    _authorizedPeers.delete(remotePeerId);
    directPeers.remove(remotePeerId);
    log.info(`Peer disconnected: ${remotePeerId.slice(0, 16)}...${tipNodeId ? ` (${tipNodeId})` : ""}`);
  });

  // ── Public interface ───────────────────────────────────────────────────
  return {
    /** The underlying libp2p node */
    node,

    /** This node's peer ID string */
    peerId: node.peerId.toString(),
    TOPICS,

    /** Register callback for when a peer completes TIP handshake */
    onPeerAuthorized(fn) { _onPeerAuthorized = fn; },

    /** Set GossipSub topic handlers (called after consensus init) */
    setTopicHandlers(h) { _topicHandlers = h; },

    /** All listen multiaddrs */
    multiaddrs: () => node.getMultiaddrs().map(ma => ma.toString()),

    /** Connected peer count (authorized only) */
    peerCount: () => _authorizedPeers.size,

    /** Connected authorized peer IDs (libp2p peerId) */
    peers: () => [..._authorizedPeers.keys()],

    /** Map of authorized libp2p peerId → TIP node_id */
    authorizedPeers: () => Object.fromEntries(_authorizedPeers),

    /** Snapshot of gossipsub DirectPeers set (for tests + ops diagnostics) */
    directPeers: () => directPeers.list(),

    /**
     * Publish a message to a GossipSub topic.
     * @param {string} topic   One of TOPICS.*
     * @param {Buffer|Uint8Array} data  Protobuf-encoded message
     */
    async publish(topic, data) {
      try { await pubsub.publish(topic, data); }
      catch (err) { log.warn(`Publish to ${topic} failed: ${err.message}`); }
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
      return node.dialProtocol(peerIdFromString(peerId), protocol);
    },

    async stop() {
      rateLimiter.stop();
      _authorizedPeers.clear();
      pubsub.unsubscribe(TOPICS.CERTIFICATES);
      pubsub.unsubscribe(TOPICS.MEMPOOL);
      pubsub.unsubscribe(TOPICS.CONSENSUS);
      await node.stop();
      log.info("libp2p node stopped");
    },
  };
}

module.exports = { createNetworkNode, TOPICS };