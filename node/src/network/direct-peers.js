/**
 * @file @tip-protocol/node/src/network/direct-peers.js
 * @description GossipSub DirectPeers mesh management for the TIP federation.
 *
 * Why DirectPeers: @chainsafe/libp2p-gossipsub builds a random mesh of D
 * peers per topic and prunes based on score. For small federated committees
 * (4-10 nodes) the random selection can leave two committee members without
 * a forwarding path between them (observed N3→N2 drop via N1 relay, see
 * issues.md #23). A peer in the `direct` set is:
 *   - always kept in the mesh (bypasses D/Dlo/Dhi limits)
 *   - never pruned by peer-score heuristics
 *   - always receives every publish to subscribed topics directly
 *   - auto-reconnected by the gossipsub direct-connect tick loop
 *
 * We add each peer to `pubsub.direct` after TIP handshake completes and
 * remove them on libp2p `peer:disconnect`. See narwhal-parity-gap.md §3 for
 * the long-term plan (direct streams for consensus messages); DirectPeers
 * is the stepping-stone that buys most of the reliability win today.
 *
 * @chainsafe/libp2p-gossipsub v14 exposes `this.direct` as a mutable
 * `Set<string>` of peer ID strings read on every publish/graft/prune, so
 * runtime mutation takes effect on the next heartbeat (~700ms).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

/**
 * Create a direct-peers manager bound to a specific pubsub instance.
 *
 * @param {Object} pubsub  libp2p-gossipsub instance (must expose `.direct`)
 * @param {Object} log     Logger with .info/.debug/.warn methods
 * @returns {{ add: (peerId: string) => boolean,
 *            remove: (peerId: string) => boolean,
 *            has: (peerId: string) => boolean,
 *            size: () => number,
 *            list: () => string[] }}
 */
function createDirectPeersManager(pubsub, log) {
  const _noop = () => { };
  const _log = log || { info: _noop, debug: _noop, warn: _noop };

  const _direct = () => (pubsub && pubsub.direct) || null;

  /**
   * Add peer to the pubsub direct set. Idempotent: returns false if already
   * present. Safe to call before handshake — no-ops if pubsub is missing.
   */
  function add(peerId) {
    if (!peerId) return false;
    const direct = _direct();
    if (!direct) return false;
    try {
      if (direct.has(peerId)) return false;
      direct.add(peerId);
      _log.info(`DirectPeer added: ${peerId.slice(0, 16)}...`);
      return true;
    } catch (err) {
      _log.warn(`DirectPeer add failed ${peerId.slice(0, 16)}: ${err.message}`);
      return false;
    }
  }

  /**
   * Remove peer from the pubsub direct set. Idempotent: returns false if
   * not present. Safe to call on disconnect regardless of authorization.
   */
  function remove(peerId) {
    if (!peerId) return false;
    const direct = _direct();
    if (!direct) return false;
    try {
      if (!direct.has(peerId)) return false;
      direct.delete(peerId);
      _log.debug(`DirectPeer removed: ${peerId.slice(0, 16)}...`);
      return true;
    } catch (err) {
      _log.warn(`DirectPeer remove failed ${peerId.slice(0, 16)}: ${err.message}`);
      return false;
    }
  }

  function has(peerId) {
    const direct = _direct();
    return direct ? direct.has(peerId) : false;
  }

  function size() {
    const direct = _direct();
    return direct ? direct.size : 0;
  }

  function list() {
    const direct = _direct();
    return direct ? [...direct] : [];
  }

  return { add, remove, has, size, list };
}

/**
 * Build the TIP-handshake authorization wrapper used by network/node.js.
 *
 * Contract:
 *   1. DirectPeers.add(peerId) runs FIRST — even if the user callback
 *      later throws, the peer is in the mesh (consensus traffic can
 *      start flowing immediately).
 *   2. The consumer's callback (registered via `onPeerAuthorized(fn)`
 *      after the wrapper is already constructed) is invoked SECOND.
 *      A getter closure is used so late registration is honored —
 *      consensus wires its callback after network node creation.
 *   3. If no user callback is registered, wrapper still runs add.
 *
 * @param {Object}   manager            createDirectPeersManager result
 * @param {Function} getUserCallback    () => current user callback (or null)
 * @returns {Function} (peerId, tipNodeId) => void
 */
function makeAuthorizationWrapper(manager, getUserCallback) {
  const _get = typeof getUserCallback === "function" ? getUserCallback : () => null;
  return function onAuthorized(peerId, tipNodeId) {
    manager.add(peerId);
    const fn = _get();
    if (typeof fn === "function") {
      fn(peerId, tipNodeId);
    }
  };
}

module.exports = { createDirectPeersManager, makeAuthorizationWrapper };
