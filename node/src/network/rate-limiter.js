/**
 * @file @tip-protocol/node/src/network/rate-limiter.js
 * @description Per-peer GossipSub message rate limiter.
 *
 * Tracks message count per peer per second.
 * Peers exceeding CONSENSUS.MAX_MSGS_PER_PEER_PER_SEC are rate limited.
 * Stale entries cleaned up every 30 seconds.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");

/**
 * Create a per-peer rate limiter.
 * @returns {{ check: Function, stop: Function }}
 */
function createRateLimiter() {
  const _counts = new Map();

  /**
   * Check if a peer is within rate limits.
   * @param {string} peerId
   * @returns {boolean} true if allowed, false if rate limited
   */
  function check(peerId) {
    const now = Date.now();
    let entry = _counts.get(peerId);
    if (!entry || now >= entry.resetAt) {
      entry = { count: 0, resetAt: now + 1000 };
      _counts.set(peerId, entry);
    }
    entry.count++;
    return entry.count <= CONSENSUS.MAX_MSGS_PER_PEER_PER_SEC;
  }

  // Cleanup stale entries every 30 seconds
  const _cleanup = setInterval(() => {
    const now = Date.now();
    for (const [id, entry] of _counts) {
      if (now >= entry.resetAt + 5000) _counts.delete(id);
    }
  }, 30000);

  /**
   * Stop the rate limiter and clean up.
   */
  function stop() {
    clearInterval(_cleanup);
    _counts.clear();
  }

  return { check, stop };
}

module.exports = { createRateLimiter };
