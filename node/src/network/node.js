/**
 * @file @tip-protocol/node/src/network/node.js
 * @description libp2p network node for TIP consensus.
 *
 * Sets up a libp2p node with:
 *   - TCP transport + Noise encryption + Yamux multiplexing
 *   - GossipSub for pub/sub (certificate + mempool broadcast)
 *   - mDNS (local) + Bootstrap (remote) peer discovery
 *   - TIP Handshake protocol — after libp2p connects, peers exchange
 *     TIP node IDs + ML-DSA-65 signatures to prove registry membership.
 *     Unauthorized peers are disconnected and GossipSub messages dropped.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS, NETWORK } = require("../../../shared/protocol-constants");
const { PROTOCOL } = require("../../../shared/constants");
const { mldsaSign, mldsaVerify } = require("../../../shared/crypto");
const { encode, decode } = require("./proto");
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
 * @param {number}   options.port              TCP listen port (default: 4001)
 * @param {Array}    options.bootstrapPeers    Multiaddrs of known peers
 * @param {boolean}  options.enableMdns        Enable mDNS local discovery
 * @param {Object}   options.handlers          Topic message handlers
 * @param {string}   options.nodeId            This node's TIP node ID (tip://node/...)
 * @param {string}   options.nodePrivateKey    ML-DSA-65 private key for signing handshake
 * @param {Function} options.getNodeKey        (nodeId) => publicKey from registry
 * @param {Function} options.getLatestRound    () => current consensus round
 * @param {Function} options.getMerkleRoot     () => current merkle root hex
 * @returns {Promise<Object>} Network node interface
 */
async function createNetworkNode(options = {}) {
  const {
    port = 4001,
    bootstrapPeers = [],
    enableMdns = true,
    handlers = {},
    nodeId = null,
    nodePrivateKey = null,
    getNodeKey = () => null,
    getLatestRound = () => 0,
    getMerkleRoot = () => "",
  } = options;

  // Authorized peers: libp2p peerId → TIP node_id
  // Only peers that complete the TIP handshake are authorized.
  const _authorizedPeers = new Map();

  // Callback when a peer completes handshake — used by consensus for sync
  let _onPeerAuthorized = null;

  // Dynamic imports (libp2p ecosystem is ESM-only)
  const { createLibp2p } = await import("libp2p");
  const { tcp } = await import("@libp2p/tcp");
  const { noise } = await import("@chainsafe/libp2p-noise");
  const { yamux } = await import("@chainsafe/libp2p-yamux");
  const { gossipsub } = await import("@chainsafe/libp2p-gossipsub");
  const { identify } = await import("@libp2p/identify");
  const { mdns } = await import("@libp2p/mdns");
  const { bootstrap: bootstrapDiscovery } = await import("@libp2p/bootstrap");
  const { generateKeyPairFromSeed } = await import("@libp2p/crypto/keys");

  // Derive a deterministic libp2p peer ID from the TIP node ID.
  // libp2p requires Ed25519 — we hash the node ID to get a stable 32-byte seed.
  // Same TIP node ID = same peer ID across restarts.
  let privateKey;
  if (nodeId) {
    const { shake256 } = require("../../../shared/crypto");
    const seed = Buffer.from(shake256(nodeId + ":libp2p-peer-key"), "hex").subarray(0, 32);
    privateKey = await generateKeyPairFromSeed("Ed25519", seed);
    log.info(`Peer ID derived from TIP node ID: ${nodeId}`);
  }

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
    services,
  });

  // Start the node
  await node.start();
  const listenAddrs = node.getMultiaddrs().map(ma => ma.toString());
  log.info(`libp2p node started on port ${port}`);
  log.info(`Peer ID: ${node.peerId.toString()}`);
  for (const addr of listenAddrs) log.info(`Listening: ${addr}`);

  // ── TIP Handshake Protocol ──────────────────────────────────────────────
  // After libp2p connects, both peers open a handshake stream to prove
  // they are registered TIP nodes by signing with their ML-DSA-65 key.

  const handshakeProtocol = NETWORK.HANDSHAKE_PROTOCOL;
  const handshakeTimeoutMs = CONSENSUS.HANDSHAKE_TIMEOUT_MS;
  let chainId;
  try { chainId = require("../genesis").GENESIS_CHAIN_ID; } catch { chainId = "tip-mainnet-v2"; }

  /**
   * Create the handshake payload and signature.
   */
  function _createHandshakePayload() {
    const round = getLatestRound();
    const payload = `${nodeId}:${round}:${chainId}`;
    const signature = nodePrivateKey ? mldsaSign(payload, nodePrivateKey) : "";
    return { nodeId, round, chainId, signature, payload };
  }

  /**
   * Verify a peer's handshake.
   * @returns {{ valid: boolean, nodeId?: string, error?: string }}
   */
  function _verifyHandshake(peerNodeId, peerChainId, peerRound, peerSignature) {
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
   */
  async function _handleIncomingHandshake({ stream, connection }) {
    const remotePeerId = connection.remotePeer.toString();
    try {
      // Collect the peer's handshake from the source
      let handshakeData = null;
      for await (const chunk of stream.source) {
        handshakeData = chunk.subarray();
        break;
      }

      if (!handshakeData) {
        log.warn(`Handshake: empty message from ${remotePeerId.slice(0, 12)}`);
        await stream.close();
        return;
      }

      const msg = decode("Handshake", handshakeData);
      const peerNodeId = msg.nodeId || "";
      const peerChainId = msg.chainId || "";
      const peerRound = Number(msg.latestRound || 0);
      const peerSignature = msg.signature?.toString("hex") || "";

      const result = _verifyHandshake(peerNodeId, peerChainId, peerRound, peerSignature);

      if (!result.valid) {
        log.warn(`Handshake rejected from ${remotePeerId.slice(0, 12)}: ${result.error}`);
        await stream.close();
        node.hangUp(connection.remotePeer).catch(() => { });
        return;
      }

      // Send our ack
      const hs = _createHandshakePayload();
      const ack = encode("HandshakeAck", {
        nodeId: hs.nodeId,
        latestRound: hs.round,
        merkleRoot: Buffer.from(getMerkleRoot() || "", "hex"),
        syncNeeded: Math.abs(peerRound - hs.round) > 2,
        signature: Buffer.from(hs.signature, "hex"),
      });

      await stream.sink([ack]);

      // Authorized!
      _authorizedPeers.set(remotePeerId, peerNodeId);
      log.info(`Handshake OK: ${peerNodeId} (peer ${remotePeerId.slice(0, 12)}) — authorized`);
      if (_onPeerAuthorized) _onPeerAuthorized(remotePeerId, peerNodeId);

    } catch (err) {
      log.warn(`Handshake error from ${remotePeerId.slice(0, 12)}: ${err.message}`);
      try { await stream.close(); } catch { /* ignore */ }
    }
  }

  /**
   * Initiate handshake to a newly connected peer (we are the initiator).
   */
  async function _initiateHandshake(remotePeerId) {
    if (_authorizedPeers.has(remotePeerId)) return; // already authorized
    if (!nodeId || !nodePrivateKey) {
      log.warn("Cannot initiate handshake — node not registered (no nodeId/privateKey)");
      return;
    }

    const { peerIdFromString } = await import("@libp2p/peer-id");
    const maxRetries = CONSENSUS.HANDSHAKE_MAX_RETRIES;
    let stream;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        stream = await node.dialProtocol(peerIdFromString(remotePeerId), handshakeProtocol);
        break;
      } catch (err) {
        if (attempt === maxRetries) {
          log.warn(`Handshake dial to ${remotePeerId.slice(0, 12)} failed after ${maxRetries} attempts: ${err.message}`);
          return;
        }
        log.debug(`Handshake dial attempt ${attempt}/${maxRetries} to ${remotePeerId.slice(0, 12)} failed, retrying...`);
        await new Promise(r => setTimeout(r, attempt * 500));
      }
    }

    try {
      // Send our handshake
      const hs = _createHandshakePayload();
      const msg = encode("Handshake", {
        nodeId: hs.nodeId,
        publicKey: Buffer.alloc(0), // not needed — registry has the key
        latestRound: hs.round,
        merkleRoot: Buffer.from(getMerkleRoot() || "", "hex"),
        protocolVersion: PROTOCOL.version,
        chainId: hs.chainId,
        signature: Buffer.from(hs.signature, "hex"),
      });

      await stream.sink([msg]);

      // Read ack with timeout
      const timeout = setTimeout(() => {
        try { stream.close(); } catch { /* ignore */ }
      }, handshakeTimeoutMs);

      let ackData = null;
      for await (const chunk of stream.source) {
        ackData = chunk.subarray();
        break;
      }
      clearTimeout(timeout);

      if (!ackData) {
        log.warn(`Handshake: no ack from ${remotePeerId.slice(0, 12)}`);
        await stream.close();
        node.hangUp(peerIdFromString(remotePeerId)).catch(() => { });
        return;
      }

      const ack = decode("HandshakeAck", ackData);
      const peerNodeId = ack.nodeId || "";
      const peerRound = Number(ack.latestRound || 0);
      const peerSignature = ack.signature?.toString("hex") || "";

      // Verify ack — use the same chain ID (ack doesn't include chainId)
      const result = _verifyHandshake(peerNodeId, chainId, peerRound, peerSignature);

      await stream.close();

      if (!result.valid) {
        log.warn(`Handshake ack rejected from ${remotePeerId.slice(0, 12)}: ${result.error}`);
        node.hangUp(peerIdFromString(remotePeerId)).catch(() => { });
        return;
      }

      _authorizedPeers.set(remotePeerId, peerNodeId);
      log.info(`Handshake OK: ${peerNodeId} (peer ${remotePeerId.slice(0, 12)}) — authorized`);
      if (_onPeerAuthorized) _onPeerAuthorized(remotePeerId, peerNodeId);

    } catch (err) {
      log.warn(`Handshake initiate to ${remotePeerId.slice(0, 12)} failed: ${err.message}`);
      try { await stream.close(); } catch { /* ignore */ }
    }
  }

  // Register handshake protocol handler
  await node.handle(handshakeProtocol, _handleIncomingHandshake);
  log.info(`Registered protocol handler: ${handshakeProtocol}`);

  // ── GossipSub ───────────────────────────────────────────────────────────

  const pubsub = node.services.pubsub;

  pubsub.subscribe(TOPICS.CERTIFICATES);
  pubsub.subscribe(TOPICS.MEMPOOL);
  pubsub.subscribe(TOPICS.CONSENSUS);
  log.info(`Subscribed to topics: ${Object.values(TOPICS).join(", ")}`);

  // Per-peer rate limiting
  const _peerMsgCounts = new Map();

  function _checkRateLimit(peerId) {
    const now = Date.now();
    let entry = _peerMsgCounts.get(peerId);
    if (!entry || now >= entry.resetAt) {
      entry = { count: 0, resetAt: now + 1000 };
      _peerMsgCounts.set(peerId, entry);
    }
    entry.count++;
    return entry.count <= CONSENSUS.MAX_MSGS_PER_PEER_PER_SEC;
  }

  const _rateLimitCleanup = setInterval(() => {
    const now = Date.now();
    for (const [id, entry] of _peerMsgCounts) {
      if (now >= entry.resetAt + 5000) _peerMsgCounts.delete(id);
    }
  }, 30000);

  // Handle incoming GossipSub messages — only from authorized peers
  pubsub.addEventListener("message", (event) => {
    const { topic, data } = event.detail;
    const peerId = event.detail.from?.toString() || "unknown";

    // Drop messages from unauthorized peers
    if (!_authorizedPeers.has(peerId)) {
      log.debug(`Dropped ${topic} message from unauthorized peer ${peerId.slice(0, 12)}`);
      return;
    }

    if (!_checkRateLimit(peerId)) {
      log.warn(`Rate limited peer ${peerId}: exceeded ${CONSENSUS.MAX_MSGS_PER_PEER_PER_SEC} msgs/sec`);
      return;
    }

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

  // ── Peer events ─────────────────────────────────────────────────────────

  // Log when a peer is discovered (before connection attempt)
  node.addEventListener("peer:discovery", (event) => {
    const peerId = event.detail.id.toString();
    const addrs = event.detail.multiaddrs?.map(ma => ma.toString()) || [];
    log.info(`Peer discovered: ${peerId.slice(0, 16)}... at ${addrs.join(", ") || "unknown"}`);
  });

  node.addEventListener("peer:connect", (event) => {
    const remotePeerId = event.detail.toString();
    log.info(`Peer connected: ${remotePeerId.slice(0, 16)}... — initiating handshake`);
    _initiateHandshake(remotePeerId);
  });

  node.addEventListener("peer:disconnect", (event) => {
    const remotePeerId = event.detail.toString();
    const tipNodeId = _authorizedPeers.get(remotePeerId);
    _authorizedPeers.delete(remotePeerId);
    log.info(`Peer disconnected: ${remotePeerId.slice(0, 16)}...${tipNodeId ? ` (${tipNodeId})` : ""}`);
  });

  // ── Public interface ─────────────────────────────────────────────────────

  return {
    /** The underlying libp2p node */
    node,

    /** This node's peer ID string */
    peerId: node.peerId.toString(),

    /** Register callback for when a peer completes TIP handshake */
    onPeerAuthorized(fn) { _onPeerAuthorized = fn; },

    /** All listen multiaddrs */
    multiaddrs: () => node.getMultiaddrs().map(ma => ma.toString()),

    /** Connected peer count (authorized only) */
    peerCount: () => _authorizedPeers.size,

    /** Connected authorized peer IDs (libp2p peerId) */
    peers: () => [..._authorizedPeers.keys()],

    /** Map of authorized libp2p peerId → TIP node_id */
    authorizedPeers: () => Object.fromEntries(_authorizedPeers),

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
      clearInterval(_rateLimitCleanup);
      _peerMsgCounts.clear();
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
