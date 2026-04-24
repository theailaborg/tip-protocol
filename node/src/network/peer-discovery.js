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
function buildKnownPeers(node, authorizedPeers, excludePeerId, peerIdFromString) {
  const result = [];
  if (!node || !authorizedPeers) return result;

  for (const [libp2pPeerId, tipNodeId] of authorizedPeers.entries()) {
    if (libp2pPeerId === excludePeerId) continue;
    if (!tipNodeId) continue;

    let multiaddrs = [];
    try {
      const pid = peerIdFromString(libp2pPeerId);
      const conns = node.getConnections(pid) || [];
      // De-duplicate addresses across multiple connections to the same peer.
      const seen = new Set();
      for (const conn of conns) {
        if (!conn || !conn.remoteAddr) continue;
        const addr = conn.remoteAddr.toString();
        if (!addr || seen.has(addr)) continue;
        seen.add(addr);
        multiaddrs.push(addr);
      }
    } catch {
      // Skip peers whose libp2p peerId we can't resolve. Their entry in
      // `authorizedPeers` will be cleaned up by the peer:disconnect
      // handler eventually; for now just omit from the hint.
      continue;
    }

    if (multiaddrs.length === 0) continue;
    result.push({ node_id: tipNodeId, multiaddrs });
  }

  return result;
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
 * libp2p's `node.dial(multiaddr)` accepts a string, array, or peerId —
 * we explicitly loop so a single bad address doesn't doom the peer.
 */
async function _dialFirstReachable(node, multiaddrs, log) {
  let lastErr = null;
  for (const addr of multiaddrs) {
    try {
      await node.dial(addr);
      log.info(`dialKnownPeers: connected via ${addr}`);
      return;
    } catch (err) {
      lastErr = err;
      log.debug(`dialKnownPeers: ${addr} failed: ${err.message}`);
    }
  }
  throw lastErr || new Error("no addresses to try");
}

module.exports = { buildKnownPeers, dialKnownPeers };
