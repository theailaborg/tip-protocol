/**
 * @file @tip-protocol/node/src/network/peer-utils.js
 * @description Reusable helpers shared across the network layer.
 *
 * Three primitives lifted out of `peer-discovery.js` and
 * `bootstrap-reconnect.js` to avoid copy-paste:
 *
 *   toMultiaddr(str)
 *     libp2p@2.x requires a Multiaddr instance for `node.dial`. Passing
 *     a string fails with `multiaddrs[0].getPeerId is not a function`
 *     because libp2p treats the string as an iterable of multiaddrs and
 *     indexes character 0. The package is ESM-only so we dynamic-import
 *     once and cache the factory.
 *
 *   peerIdFromAddr(addr)
 *     Extract the libp2p PeerID embedded at the end of a multiaddr
 *     string (`/ip4/.../tcp/.../p2p/<peerId>`). Used by reconnect logic
 *     to match a `peer:disconnect` event back to its bootstrap entry.
 *
 *   getDedupedMultiaddrs(node, libp2pPeerId, peerIdFromString)
 *     Pull the de-duplicated list of `remoteAddr` strings for every
 *     active connection libp2p has to this peer. Returns `[]` on any
 *     error (peer not resolvable, no connections, etc.). Used by
 *     `buildKnownPeers` and `buildPeerEntry` in peer-discovery.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// ── Multiaddr factory (cached dynamic import) ────────────────────────────
let _factory = null;
const _ready = import("@multiformats/multiaddr").then(mod => {
  _factory = mod.multiaddr;
});

/** Convert a multiaddr string to a Multiaddr instance. */
async function toMultiaddr(addr) {
  if (!_factory) await _ready;
  return _factory(addr);
}

// ── PeerID extraction ────────────────────────────────────────────────────
/** Extract the `<peerId>` from `…/p2p/<peerId>`. Returns null if absent. */
function peerIdFromAddr(addr) {
  const m = String(addr).match(/\/p2p\/([^/]+)$/);
  return m ? m[1] : null;
}

// ── Address discovery ────────────────────────────────────────────────────
/**
 * De-duplicated list of multiaddr strings other peers can use to dial
 * `libp2pPeerId`. Async because libp2p's peerStore is async.
 *
 * Source priority (peers we want to ANNOUNCE to others need their
 * LISTEN addresses, not their ephemeral source ports):
 *
 *   1. peerStore.get(peerId).addresses — listening addrs the peer
 *      announced via the libp2p `identify` protocol. This is the
 *      canonical source.
 *
 *   2. node.getConnections(peerId)[].remoteAddr — fallback. Only
 *      correct for OUTBOUND connections (we dialed the peer); for
 *      INBOUND connections (the peer dialed us) `remoteAddr` is the
 *      peer's ephemeral SOURCE port and is useless to forward.
 *
 * Returns [] on any error or unresolvable peer.
 */
async function getDedupedMultiaddrs(node, libp2pPeerId, peerIdFromString) {
  if (!node || !libp2pPeerId) return [];
  const seen = new Set();
  const out = [];

  let pid = null;
  try { pid = peerIdFromString(libp2pPeerId); } catch { return []; }

  // Primary: announced listen addresses from the peerStore.
  try {
    const peer = node.peerStore && (await node.peerStore.get(pid));
    const addrs = (peer && peer.addresses) || [];
    for (const a of addrs) {
      const ma = a && a.multiaddr;
      if (!ma) continue;
      const s = ma.toString();
      if (!s || seen.has(s)) continue;
      seen.add(s);
      out.push(s);
    }
  } catch {
    // peerStore miss — fall through to the connection-based fallback.
  }

  // Fallback: live connection remote addresses. Useful when peerStore
  // doesn't have an entry yet (early in the connection lifecycle) and
  // when the connection is outbound (remoteAddr is the dialed listen
  // address). Inbound entries here are useless but harmless — the
  // recipient just gets a failed dial it can ignore.
  if (out.length === 0) {
    try {
      const conns = node.getConnections(pid) || [];
      for (const conn of conns) {
        if (!conn || !conn.remoteAddr) continue;
        const s = conn.remoteAddr.toString();
        if (!s || seen.has(s)) continue;
        seen.add(s);
        out.push(s);
      }
    } catch { /* ignore */ }
  }

  return out;
}

module.exports = { toMultiaddr, peerIdFromAddr, getDedupedMultiaddrs };
