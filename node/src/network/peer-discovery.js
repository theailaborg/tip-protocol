/**
 * @file @tip-protocol/node/src/network/peer-discovery.js
 * @description Helpers for #38 libp2p-native peer discovery.
 *
 * TIP federation uses a "plant one bootstrap, discover the rest" model:
 * a joiner dials ONE known peer, completes the TIP handshake, and
 * receives a list of other authorized peers in the HandshakeAck. The
 * joiner then dials each of them and runs the same handshake. Within
 * one round-trip of bootstrap connection the joiner is meshed with the
 * full committee — no O(N²) env-var coordination.
 *
 * Trust model: known_peers is a hint, not an attestation. A malicious
 * responder could lie about the list, but every peer the joiner dials
 * still goes through the full TIP handshake (registry lookup + ML-DSA-65
 * signature verification + genesis hash check), so an unauthorized peer
 * can't sneak in via a bad hint. The worst a lying responder can do is
 * omit real peers (delaying discovery) or invent fake addresses (wasted
 * dial attempts that fail on connect or handshake).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { NETWORK } = require("../../../shared/protocol-constants");
const { encode, decode } = require("./proto");
const { toMultiaddr, getDedupedMultiaddrs } = require("./peer-utils");

/** Stream protocol for #48 forward-on-authorize push. Resolved at use-site
 * since module-load timing varies across entry points (see metrics-service
 * comment for the same pattern). */
function _announceProtocol() { return NETWORK.PEER_ANNOUNCE_PROTOCOL; }

/**
 * Build the `known_peers` list for a HandshakeAck.
 *
 * Iterates the currently-authorized peer set, reads each peer's live
 * connection multiaddr(s) from libp2p, and returns `[{node_id, multiaddrs}]`.
 * Peers with no current connections are omitted (stale entries aren't
 * useful as bootstrap hints). The peer we're responding to is excluded
 * so we don't hand them their own address back.
 *
 * @param {Object} node                   libp2p node
 * @param {Map<string, string>} authorizedPeers  libp2pPeerId → TIP node_id
 * @param {string} excludePeerId          the libp2p peerId we're responding to
 * @param {Function} peerIdFromString     libp2p peerIdFromString helper
 * @returns {Array<{node_id: string, multiaddrs: string[]}>}
 */
async function buildKnownPeers(node, authorizedPeers, excludePeerId, peerIdFromString) {
  const result = [];
  if (!node || !authorizedPeers) return result;

  for (const [libp2pPeerId, tipNodeId] of authorizedPeers.entries()) {
    if (libp2pPeerId === excludePeerId) continue;
    if (!tipNodeId) continue;

    const multiaddrs = await getDedupedMultiaddrs(node, libp2pPeerId, peerIdFromString);
    if (multiaddrs.length === 0) continue;
    result.push({ node_id: tipNodeId, multiaddrs });
  }

  return result;
}

/**
 * Build a single `{node_id, multiaddrs}` entry for one peer. Returns null
 * if the peer has no current connection or its libp2p peerId doesn't
 * resolve. Used by broadcastAnnounce to package up a newly-authorized
 * peer for forwarding to existing peers.
 */
async function buildPeerEntry(node, libp2pPeerId, tipNodeId, peerIdFromString) {
  if (!node || !libp2pPeerId || !tipNodeId) return null;
  const multiaddrs = await getDedupedMultiaddrs(node, libp2pPeerId, peerIdFromString);
  if (multiaddrs.length === 0) return null;
  return { node_id: tipNodeId, multiaddrs };
}

/**
 * Dial each peer in `knownPeers` that we don't already have a connection to.
 *
 * Runs in the background — no await on the outer call, so a slow dial
 * doesn't block handshake completion. Each successful dial triggers
 * libp2p's `peer:connect` event, which kicks off the normal
 * `initiate()` handshake path; known_peers just provides the dial target
 * so we don't need the peer's address in env vars.
 *
 * Caller is responsible for not calling this until the handshake that
 * produced `knownPeers` is verified — we trust the list only as far as
 * each resulting dial's own handshake verification.
 *
 * @param {Object} node                   libp2p node
 * @param {Array<{node_id, multiaddrs[]}>} knownPeers  from HandshakeAck
 * @param {Map<string, string>} authorizedPeers  libp2pPeerId → TIP node_id
 * @param {string} ownNodeId              our own TIP node_id (skip if present)
 * @param {Object} log                    logger
 */
function dialKnownPeers(node, knownPeers, authorizedPeers, ownNodeId, log) {
  if (!Array.isArray(knownPeers) || knownPeers.length === 0) return;
  if (!node) return;
  const _log = log || { info: () => { }, debug: () => { }, warn: () => { } };

  // Set of TIP node_ids we've already authorized — lets us skip peers we
  // already know about without needing to resolve libp2p peerIds here.
  const alreadyAuthorizedTipIds = new Set();
  if (authorizedPeers) {
    for (const tipNodeId of authorizedPeers.values()) {
      if (tipNodeId) alreadyAuthorizedTipIds.add(tipNodeId);
    }
  }

  for (const kp of knownPeers) {
    if (!kp || !kp.node_id) continue;
    if (kp.node_id === ownNodeId) continue;
    if (alreadyAuthorizedTipIds.has(kp.node_id)) continue;
    if (!Array.isArray(kp.multiaddrs) || kp.multiaddrs.length === 0) continue;

    // Fire-and-forget. libp2p dial handles multiaddr parsing, Noise
    // handshake, and triggers the peer:connect event that our
    // network/node.js listener uses to run `initiate()`. Failures are
    // logged at debug (common during bootstrap when some peers are
    // briefly unreachable).
    _dialFirstReachable(node, kp.multiaddrs, _log).catch((err) => {
      _log.debug(`dialKnownPeers: ${kp.node_id} all addrs failed: ${err.message}`);
    });
  }
}

/**
 * Try multiaddrs in order; resolve on first success, reject only if all fail.
 * Each address is converted to a Multiaddr instance — libp2p@2.x rejects
 * raw strings (see network/peer-utils.js for rationale).
 */
async function _dialFirstReachable(node, multiaddrs, log) {
  let lastErr = null;
  for (const addr of multiaddrs) {
    try {
      await node.dial(await toMultiaddr(addr));
      log.info(`dialKnownPeers: connected via ${addr}`);
      return;
    } catch (err) {
      lastErr = err;
      log.debug(`dialKnownPeers: ${addr} failed: ${err.message}`);
    }
  }
  throw lastErr || new Error("no addresses to try");
}

// ── #48: forward-on-authorize push ───────────────────────────────────────
//
// When a node authorizes a NEW peer, it pushes a PeerAnnounce to all OTHER
// already-authorized peers so they learn about the new peer immediately.
// Mesh converges sub-second instead of waiting on the anti-entropy backstop.
//
// The protocol is a one-shot stream: open, write one PeerAnnounce, close.
// Recipients pass each `known_peers` entry through `dialKnownPeers`, which
// dedups and runs the full TIP handshake on each — so a malicious announcer
// can't bypass authorization, only waste a dial.

/**
 * Push a PeerAnnounce to a single recipient. Fire-and-forget — failures
 * are logged at debug since the anti-entropy backstop will recover.
 *
 * @param {Object} node                 libp2p node
 * @param {string} recipientPeerId      libp2p peerId of the recipient (string)
 * @param {Function} peerIdFromString   libp2p peerIdFromString helper
 * @param {Array<{node_id, multiaddrs[]}>} knownPeers  payload
 * @param {Object} log
 * @returns {Promise<void>}
 */
async function pushAnnounce(node, recipientPeerId, peerIdFromString, knownPeers, log) {
  if (!node || !recipientPeerId) return;
  if (!Array.isArray(knownPeers) || knownPeers.length === 0) return;
  const _log = log || { info: () => { }, debug: () => { }, warn: () => { } };

  let stream;
  try {
    stream = await node.dialProtocol(peerIdFromString(recipientPeerId), _announceProtocol());
  } catch (err) {
    _log.debug(`pushAnnounce: dial to ${recipientPeerId.slice(0, 12)} failed: ${err.message}`);
    return;
  }

  try {
    const payload = {
      knownPeers: knownPeers.map(kp => ({
        nodeId: kp.node_id,
        multiaddrs: Array.isArray(kp.multiaddrs) ? kp.multiaddrs : [],
      })),
    };
    const buf = encode("PeerAnnounce", payload);
    await stream.sink([buf]);
    _log.debug(`pushAnnounce: sent ${knownPeers.length} entries to ${recipientPeerId.slice(0, 12)}`);
  } catch (err) {
    _log.debug(`pushAnnounce: send to ${recipientPeerId.slice(0, 12)} failed: ${err.message}`);
  } finally {
    try { await stream.close(); } catch { /* ignore */ }
  }
}

/**
 * Broadcast an announce to every authorized peer except `excludePeerId`.
 * Used when a NEW peer is authorized — the new peer is announced to all
 * EXISTING peers (the new peer itself already got the full known_peers
 * list via HandshakeAck and is excluded here).
 *
 * @param {Object} node                  libp2p node
 * @param {Map<string,string>} authorizedPeers  libp2pPeerId → TIP node_id
 * @param {string} excludePeerId         the new peer (don't announce it to itself)
 * @param {Function} peerIdFromString
 * @param {Array<{node_id, multiaddrs[]}>} knownPeers  payload
 * @param {Object} log
 */
function broadcastAnnounce(node, authorizedPeers, excludePeerId, peerIdFromString, knownPeers, log) {
  if (!node || !authorizedPeers || authorizedPeers.size === 0) return;
  if (!Array.isArray(knownPeers) || knownPeers.length === 0) return;

  for (const recipientPeerId of authorizedPeers.keys()) {
    if (recipientPeerId === excludePeerId) continue;
    // Fire-and-forget per recipient.
    pushAnnounce(node, recipientPeerId, peerIdFromString, knownPeers, log);
  }
}

/**
 * Register the inbound /tip/peer-announce/1.0.0 handler. Decodes the
 * incoming PeerAnnounce, gates on authorization (only authorized peers
 * may announce — random strangers can't trick us into dialing arbitrary
 * addresses), and dispatches each entry through `dialKnownPeers`.
 *
 * @param {Object} options
 * @param {Object}   options.node              libp2p node
 * @param {Function} options.isAuthorizedPeer  (libp2pPeerId) => boolean
 * @param {Map<string,string>} options.authorizedPeers
 * @param {string}   options.ownNodeId         our TIP node_id
 * @param {Object}   options.log
 * @returns {Promise<void>}
 */
async function registerAnnounceHandler({ node, isAuthorizedPeer, authorizedPeers, ownNodeId, log }) {
  if (!node) return;
  const _log = log || { info: () => { }, debug: () => { }, warn: () => { } };

  await node.handle(_announceProtocol(), async ({ stream, connection }) => {
    const peerId = connection?.remotePeer?.toString() || "";
    if (!isAuthorizedPeer || !isAuthorizedPeer(peerId)) {
      _log.debug(`peer-announce: dropped from unauthorized peer ${peerId.slice(0, 12)}`);
      try { await stream.close(); } catch { /* ignore */ }
      return;
    }

    try {
      // Single-message stream: read until end.
      const chunks = [];
      for await (const chunk of stream.source) {
        chunks.push(chunk.subarray ? chunk.subarray() : chunk);
      }
      const body = Buffer.concat(chunks);
      const msg = decode("PeerAnnounce", body);
      const knownPeers = (msg.knownPeers || []).map(kp => ({
        node_id: kp.nodeId || "",
        multiaddrs: Array.isArray(kp.multiaddrs) ? kp.multiaddrs : [],
      }));
      if (knownPeers.length > 0) {
        dialKnownPeers(node, knownPeers, authorizedPeers, ownNodeId, _log);
      }
    } catch (err) {
      _log.debug(`peer-announce: decode/handle from ${peerId.slice(0, 12)} failed: ${err.message}`);
    } finally {
      try { await stream.close(); } catch { /* ignore */ }
    }
  });
  _log.info(`Registered protocol handler: ${_announceProtocol()}`);
}

module.exports = {
  buildKnownPeers,
  buildPeerEntry,
  dialKnownPeers,
  pushAnnounce,
  broadcastAnnounce,
  registerAnnounceHandler,
};
