/**
 * @file @tip-protocol/node/src/network/bootstrap-reconnect.js
 * @description Event-driven bootstrap-peer reconnect loop.
 *
 * @libp2p/bootstrap only emits one peer-discovery round at startup. If the
 * bootstrap peer is offline at that moment, libp2p doesn't redial it on
 * its own. Production federations need explicit retry: every bootstrap
 * peer gets its own self-rescheduling retry chain.
 *
 * Design:
 *   - Failed dial → schedule ONE setTimeout to retry.
 *   - Successful dial → chain stops. No timer until peer:disconnect fires.
 *   - peer:disconnect for a bootstrap peer → restart the chain.
 *
 * Result: zero overhead in steady state (no running timers when all
 * bootstrap peers are connected). Retry kicks back in immediately on
 * disconnect or initial failure.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { toMultiaddr, peerIdFromAddr } = require("./peer-utils");

const RECONNECT_MS = 5000;

/**
 * Build a reconnect manager for a list of bootstrap multiaddrs.
 *
 * @param {Object} options
 * @param {Object}              options.node             libp2p node (uses node.dial)
 * @param {Array<string>}       options.bootstrapPeers   list of multiaddrs
 * @param {Map<string,string>}  options.authorizedPeers  libp2pPeerId → tipNodeId
 * @param {Object}              options.log              logger
 * @param {number}              [options.intervalMs=5000] retry delay between attempts
 * @returns {Object}                                    { start, stop, onPeerDisconnect }
 */
function createBootstrapReconnect({ node, bootstrapPeers, authorizedPeers, log, intervalMs = RECONNECT_MS }) {
  if (!Array.isArray(bootstrapPeers) || bootstrapPeers.length === 0) {
    // No bootstrap peers configured (e.g. founding node) — return no-op shim
    // so callers don't need null checks.
    return { start: () => { }, stop: () => { }, onPeerDisconnect: () => { } };
  }

  const _retries = new Map();   // multiaddr → pending Timeout

  function _schedule(addr, delayMs) {
    const existing = _retries.get(addr);
    if (existing) clearTimeout(existing);

    const timer = setTimeout(async () => {
      _retries.delete(addr);

      // If the peer authorized via some other path (incoming dial,
      // peer-discovery, peer-announce), the chain's job is done.
      const expectedPeerId = peerIdFromAddr(addr);
      if (expectedPeerId && authorizedPeers.has(expectedPeerId)) return;

      try {
        await node.dial(await toMultiaddr(addr));
        log.info(`Bootstrap connected: ${addr}`);
        // Success — don't reschedule. peer:disconnect will restart.
      } catch (err) {
        // INFO not DEBUG so operators can see the retry chain without
        // flipping log level. Bootstrap-down is the most common
        // operator-visible network failure; keeping it silent at DEBUG
        // masks the exact problem we're trying to diagnose.
        log.info(`Bootstrap dial failed for ${addr}: ${err.message} — retrying in ${intervalMs}ms`);
        _schedule(addr, intervalMs);
      }
    }, delayMs);

    _retries.set(addr, timer);
  }

  return {
    /** Kick off the first attempt for every bootstrap peer. */
    start() {
      for (const addr of bootstrapPeers) _schedule(addr, 0);
    },

    /** Cancel every pending retry. Called from network.stop(). */
    stop() {
      for (const timer of _retries.values()) clearTimeout(timer);
      _retries.clear();
    },

    /**
     * Re-arm the retry chain for a bootstrap peer that just dropped.
     * Caller passes the libp2p peerId from the peer:disconnect event;
     * we match it against our bootstrap list by parsing /p2p/<id>.
     */
    onPeerDisconnect(peerId) {
      for (const addr of bootstrapPeers) {
        if (peerIdFromAddr(addr) === peerId) {
          log.debug(`Bootstrap peer ${peerId.slice(0, 12)} dropped — scheduling reconnect`);
          _schedule(addr, intervalMs);
          break;
        }
      }
    },
  };
}

module.exports = { createBootstrapReconnect };
