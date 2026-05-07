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
const { buildKnownPeers, buildPeerEntry, broadcastAnnounce, registerAnnounceHandler } = require("./peer-discovery");
const { createBootstrapReconnect } = require("./bootstrap-reconnect");
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

// Direct-stream RPC protocol for committee-rotation coordination. Replaces
// the gossipsub tip/rotation-coordination topic that empirically dropped
// large RotationProposal messages on cold meshes (live observed 2026-05-04
// rotation 13 halt). Each proposal/sig is sent via a one-shot stream over
// the existing TCP/QUIC connection between authorized peers — no mesh, no
// scoring, no topic warmth required.
const ROTATION_COORD_PROTOCOL = "/tip/rotation-coord/1.0.0";
// Direct-stream fallback for batch delivery when gossipsub mesh edges are stale.
// After node reconnections, specific directed edges in the gossipsub mesh can
// fail silently — re-broadcasts hit the same broken path indefinitely. This
// protocol lets narwhal Layer 2 push the batch payload directly over the
// existing TCP/QUIC connection, bypassing gossipsub scoring and mesh state.
const CONSENSUS_ACK_PROTOCOL = "/tip/consensus-ack/1.0.0";

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
      pubsub: gossipsub({
        emitSelf: false,
        allowPublishToZeroTopicPeers: true,
        heartbeatInterval: 700,
        // #38: enable Peer Exchange — when gossipsub prunes a peer from
        // the mesh it sends the peer a list of other peers it knows
        // (with signed peer records) so the pruned peer can re-graft
        // elsewhere. For TIP's small authorized federation this rarely
        // fires (DirectPeers keeps committee members pinned in the
        // mesh), but it's the right default and costs nothing when
        // idle. Discovery's primary mechanism remains the handshake's
        // known_peers[] field.
        doPX: true,
      }),
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

  // Direct-stream handler for narwhal Layer 2 retry fallback.
  // Receives batches that couldn't be delivered via gossipsub on broken mesh
  // edges. Dispatches to the same _topicHandlers.onBatch path as gossipsub.
  await node.handle(CONSENSUS_ACK_PROTOCOL, async ({ stream, connection }) => {
    try {
      const remotePeerId = connection.remotePeer.toString();
      // Gossipsub enforces topic-level scoring; direct streams have no such
      // gate. Without this check any peer that can TCP-dial us could inject
      // arbitrary batch payloads into consensus.
      if (!_authorizedPeers.has(remotePeerId)) {
        log.warn(`${CONSENSUS_ACK_PROTOCOL}: rejected stream from unauthorized peer ${remotePeerId.slice(0, 16)}`);
        stream.abort(new Error("unauthorized")).catch(() => {});
        return;
      }
      const bufs = [];
      for await (const chunk of stream.source) bufs.push(Buffer.from(chunk));
      const data = Buffer.concat(bufs);
      if (data.length > 0 && _topicHandlers.onBatch) _topicHandlers.onBatch(data);
      stream.close().catch(() => {});
    } catch (err) {
      log.warn(`${CONSENSUS_ACK_PROTOCOL} stream error: ${err.message}`);
    }
  });
  log.info(`Registered protocol handler: ${CONSENSUS_ACK_PROTOCOL}`);

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
    // Wrap the base authorization callback to ALSO push a #48
    // forward-on-authorize announce to every other already-authorized
    // peer, so they learn about the new peer immediately (no waiting on
    // anti-entropy backstop). The new peer itself just received the full
    // known_peers list via HandshakeAck and is excluded.
    onPeerAuthorized: (() => {
      const base = makeAuthorizationWrapper(directPeers, () => _onPeerAuthorized);
      return async (newPeerId, newTipNodeId) => {
        base(newPeerId, newTipNodeId);
        // peerStore lookup is async; wait for the entry before broadcasting.
        const entry = await buildPeerEntry(node, newPeerId, newTipNodeId, peerIdFromString);
        if (entry) broadcastAnnounce(node, _authorizedPeers, newPeerId, peerIdFromString, [entry], log);
      };
    })(),
  };

  // Register handshake protocol handler
  await node.handle(ctx.handshakeProtocol, (args) => handleIncoming(args, ctx));
  log.info(`Registered protocol handler: ${ctx.handshakeProtocol}`);

  // Bootstrap reconnect — event-driven retry chains. See ./bootstrap-reconnect.js.
  const bootstrapReconnect = createBootstrapReconnect({
    node, bootstrapPeers, authorizedPeers: _authorizedPeers, log,
  });
  bootstrapReconnect.start();

  // #48: forward-on-authorize push handler. Existing peers tell us about
  // newly-joined peers via /tip/peer-announce/1.0.0 — we authenticate the
  // sender (must be in authorizedPeers) then run dialKnownPeers on the
  // contents. Each newly-dialed peer still proves identity via TIP
  // handshake, so a malicious announcer can only waste dials.
  await registerAnnounceHandler({
    node,
    isAuthorizedPeer: (peerId) => _authorizedPeers.has(peerId),
    authorizedPeers: _authorizedPeers,
    ownNodeId: nodeId,
    log,
  });

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

    // If this was a bootstrap peer, restart its retry chain.
    bootstrapReconnect.onPeerDisconnect(remotePeerId);
  });

  // One-shot broadcast to every authorized peer over a direct stream.
  // Each peer gets its own dial → write(buf) → close. Failures on one
  // peer don't block the others; per-peer timeout protects against a
  // slow peer stalling the whole broadcast. Used for rotation-coord
  // traffic so delivery doesn't depend on gossipsub topic mesh state.
  async function broadcastToAuthorized(buf, protocol, { timeoutMs = 2000 } = {}) {
    const peerIds = [..._authorizedPeers.keys()];
    await Promise.all(peerIds.map(async (peerId) => {
      let stream = null;
      let timer = null;
      try {
        timer = setTimeout(() => {
          try { if (stream) stream.close(); } catch { /* ignore */ }
        }, timeoutMs);
        stream = await node.dialProtocol(peerIdFromString(peerId), protocol);
        await stream.sink([buf]);
      } catch (err) {
        log.debug(`broadcastToAuthorized to ${peerId.slice(0, 12)} on ${protocol} failed: ${err.message}`);
      } finally {
        if (timer) clearTimeout(timer);
        try { if (stream) stream.close(); } catch { /* ignore */ }
      }
    }));
  }

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
     * Build the `known_peers` list for sharing with another peer (#48).
     * Used by anti-entropy to attach a fresh roster to its sync-status
     * responses. Pass the recipient's libp2p peerId to exclude them from
     * their own list.
     * @param {string} excludePeerId  libp2p peerId to omit (typically the recipient)
     * @returns {Array<{node_id, multiaddrs[]}>}
     */
    knownPeers: async (excludePeerId) => buildKnownPeers(node, _authorizedPeers, excludePeerId, peerIdFromString),

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

    broadcastToAuthorized,
    ROTATION_COORD_PROTOCOL,
    CONSENSUS_ACK_PROTOCOL,

    /**
     * Force-regraft the gossipsub direct-peer edge for a TIP node ID.
     * Called by narwhal Layer 1 retry when a round is stuck (~6s).
     *
     * gossipsub does not automatically re-graft a direct peer whose mesh
     * edge went stale after a reconnection — the edge stays "open" in the
     * peer list but messages don't flow. The only way to trigger a fresh
     * GRAFT control message is to remove the peer from pubsub.direct and
     * re-add it; gossipsub sends GRAFT on the next heartbeat (~700ms).
     * @param {string} tipNodeId  TIP node_id string (tip://node/...)
     */
    refreshDirectPeer(tipNodeId) {
      const entry = [..._authorizedPeers.entries()].find(([, nId]) => nId === tipNodeId);
      if (!entry) {
        log.warn(`refreshDirectPeer: no authorized peer found for ${tipNodeId}`);
        return;
      }
      const [peerId] = entry;
      directPeers.remove(peerId);
      directPeers.add(peerId);
      log.info(`refreshDirectPeer: re-grafted ${tipNodeId} (${peerId.slice(0, 16)}...)`);
    },

    /**
     * Send a raw batch buffer directly to a peer via libp2p stream,
     * bypassing gossipsub. Called by narwhal Layer 2 retry (~12s stuck).
     *
     * The 3s dial timeout is intentional: if the peer is unreachable, we
     * must not block the retry loop — the next _scheduleRetry tick must
     * still fire. Failure is logged as warn and silently skipped; the
     * retry loop continues and will try again on the next tick.
     * @param {Buffer} batchBuf   Protobuf-encoded Batch message
     * @param {string} tipNodeId  TIP node_id of the target peer
     */
    async sendBatchDirect(batchBuf, tipNodeId) {
      const entry = [..._authorizedPeers.entries()].find(([, nId]) => nId === tipNodeId);
      if (!entry) {
        log.warn(`sendBatchDirect: no authorized peer found for ${tipNodeId}`);
        return;
      }
      const [peerId] = entry;
      let stream;
      try {
        stream = await node.dialProtocol(peerIdFromString(peerId), CONSENSUS_ACK_PROTOCOL, {
          signal: AbortSignal.timeout(3000),
        });
        await stream.sink([batchBuf]);
        await stream.close();
        log.debug(`sendBatchDirect: sent batch to ${tipNodeId} (${peerId.slice(0, 16)}...)`);
      } catch (err) {
        log.warn(`sendBatchDirect to ${tipNodeId}: ${err.message}`);
        if (stream) stream.abort(err).catch(() => {});
      }
    },

    async stop() {
      rateLimiter.stop();
      bootstrapReconnect.stop();
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