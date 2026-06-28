/**
 * @file @tip-protocol/node/src/network/channel-health.js
 * @description Per-peer outbound-delivery health + force-redial decision.
 *
 * "Connected + authorized" is not "healthy": a node's outbound push to a peer
 * can silently die after a reconnect (the re-handshake re-auths the existing
 * half-dead connection instead of rebuilding the transport), stranding every
 * push to that peer while inbound and request/response still work. This tracks
 * per-peer send outcomes so the break is observable, and signals a transport
 * rebuild (force-close + re-dial) once a peer crosses a consecutive-failure
 * bound. Pure + injectable clock: no libp2p here, so it is unit-testable.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs } = require("../../../shared/time");

function createChannelHealth({ healThreshold = 5, healCooldownMs = 30_000, now = nowMs } = {}) {
  const _peers = new Map();   // peerId → { sendOk, sendFail, consecutiveFail, lastOkAt, lastHealAt }

  function _get(peerId) {
    let h = _peers.get(peerId);
    if (!h) {
      h = { sendOk: 0, sendFail: 0, consecutiveFail: 0, lastOkAt: 0, lastHealAt: 0 };
      _peers.set(peerId, h);
    }
    return h;
  }

  // Record an outbound send outcome. Returns true when the caller should rebuild
  // the transport to this peer (sustained one-directional failure while the
  // connection still looks up).
  function recordSend(peerId, ok) {
    const h = _get(peerId);
    if (ok) {
      h.sendOk++;
      h.consecutiveFail = 0;
      h.lastOkAt = now();
      return false;
    }
    h.sendFail++;
    h.consecutiveFail++;
    const cooledDown = h.lastHealAt === 0 || now() - h.lastHealAt >= healCooldownMs;
    if (h.consecutiveFail >= healThreshold && cooledDown) {
      h.lastHealAt = now();
      h.consecutiveFail = 0;   // fresh connection starts clean; next fail re-counts
      return true;
    }
    return false;
  }

  function forget(peerId) {
    _peers.delete(peerId);
  }

  function snapshot() {
    const t = now();
    const out = [];
    for (const [peerId, h] of _peers) {
      out.push({
        peerId,
        sendOk: h.sendOk,
        sendFail: h.sendFail,
        consecutiveFail: h.consecutiveFail,
        lastOkAgeMs: h.lastOkAt ? t - h.lastOkAt : -1,
      });
    }
    return out;
  }

  return { recordSend, forget, snapshot };
}

module.exports = { createChannelHealth };
