/**
 * @file @tip-protocol/node/src/network/outbound-backlog.js
 * @description Per-peer gossip backlog watch. Gossipsub queues every message
 * for a peer until that peer reads it; a peer that is alive (answers pings,
 * sends requests) but has stopped reading its gossip stream grows that queue
 * without bound. Nothing else notices: pings pass, channel-health only counts
 * our direct sends, and the queue is freed only when the connection closes.
 *
 * The watch is sampled on the peer-health tick. A peer over the cap for
 * `strikes` consecutive samples should be redialed, which drops the queue.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

function createOutboundBacklog({ limitBytes, strikes = 2 } = {}) {
  if (!(limitBytes > 0)) throw new Error("createOutboundBacklog: limitBytes must be > 0");
  if (!(strikes >= 1)) throw new Error("createOutboundBacklog: strikes must be >= 1");
  const _peers = new Map();   // peerId -> { bytes, strikes }

  // Record one sample for a peer. Returns true when the peer has been over the
  // cap for `strikes` consecutive samples and should be redialed; the strike
  // count resets so the next decision needs a fresh run.
  function observe(peerId, bytes) {
    const b = Number(bytes) || 0;
    let p = _peers.get(peerId);
    if (!p) { p = { bytes: 0, strikes: 0 }; _peers.set(peerId, p); }
    p.bytes = b;
    if (b <= limitBytes) { p.strikes = 0; return false; }
    p.strikes++;
    if (p.strikes < strikes) return false;
    p.strikes = 0;
    return true;
  }

  function forget(peerId) {
    _peers.delete(peerId);
  }

  function snapshot() {
    return [..._peers].map(([peerId, p]) => ({ peerId, bytes: p.bytes, strikes: p.strikes }));
  }

  return { observe, forget, snapshot, limitBytes, strikes };
}

module.exports = { createOutboundBacklog };
