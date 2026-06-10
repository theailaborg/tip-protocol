/**
 * @file @tip-protocol/node/src/network/heartbeat.js
 * @description #47 — Active peer-liveness probe over /tip/heartbeat/1.0.0.
 *
 * Gossipsub silence can't distinguish "peer dead" from "mesh edge stale."
 * This module adds a periodic point-to-point ping over a tiny direct stream
 * so stale connections surface proactively before they cause halts (issue #13
 * class of bug). Each pong also carries the responder's consensus state,
 * giving anti-entropy a free state update without a separate sync-status RPC.
 *
 * Protocol: /tip/heartbeat/1.0.0
 *   Ping: HeartbeatPing{ from_node_id, committed_round, merkle_root, ts }
 *   Pong: HeartbeatPong{ node_id, committed_round, merkle_root, join_state, ts }
 *
 * Failure modes:
 *   - Timeout (HEARTBEAT_TIMEOUT_MS): miss counter increments.
 *   - HEARTBEAT_SUSPECT_MISSES consecutive timeouts: onPeerSuspect fires.
 *   - Authorization failure: log + drop.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS, NETWORK } = require("../../../shared/protocol-constants");
const { nowMs } = require("../../../shared/time");
const { encode, decode, bytesToHex, hexToBytes } = require("./proto");
const { getLogger } = require("../logger");

const log = getLogger("tip.heartbeat");

/**
 * Create a heartbeat manager for peer-liveness probing.
 *
 * @param {Object}   options
 * @param {Object}   options.network            Network node (handle, openStream, authorizedPeers)
 * @param {Function} options.getSelfNodeId       () => our TIP node_id
 * @param {Function} options.getConsensusState   () => { committed_round, state_merkle_root }
 * @param {Function} [options.isAuthorizedPeer]  (libp2pPeerId) => bool
 * @param {Object}   [options.narwhal]           For join_state in pong
 * @param {Function} [options.onPeerSuspect]     (libp2pPeerId, tipNodeId) => void — called after SUSPECT_MISSES misses
 * @param {Function} [options.onPeerState]       (libp2pPeerId, state) => void — called on each successful pong
 * @param {Object}   [options.log]               Override logger
 * @returns {{ start, stop, registerHandler, peerStates }}
 */
function createHeartbeatManager({
  network,
  getSelfNodeId,
  getConsensusState,
  isAuthorizedPeer,
  narwhal,
  onPeerSuspect,
  onPeerState,
  log: customLog,
} = {}) {
  const _log = customLog || log;

  // Per-peer liveness state. Key: libp2p peerId string.
  // { consecutiveMisses, lastSeenAt, lastCommittedRound, lastMerkleRoot, lastJoinState }
  const _peerState = new Map();

  let _running = false;
  let _timer = null;

  // ── Server side: respond to heartbeat pings ──────────────────────────────

  async function registerHandler() {
    if (!network) return;
    const protocol = NETWORK.HEARTBEAT_PROTOCOL;
    await network.handle(protocol, async ({ stream, connection }) => {
      const peerId = connection?.remotePeer?.toString?.();
      if (isAuthorizedPeer && peerId && !isAuthorizedPeer(peerId)) {
        try { await stream.close(); } catch { /* ignore */ }
        return;
      }
      try {
        // Drain the ping (we don't need its payload to reply)
        for await (const _chunk of stream.source) { break; }

        const state = getConsensusState ? getConsensusState() : {};
        const pong = encode("HeartbeatPong", {
          nodeId: getSelfNodeId ? (getSelfNodeId() || "") : "",
          committedRound: state.committed_round || 0,
          merkleRoot: hexToBytes(state.state_merkle_root || ""),
          joinState: String(narwhal?.joinState?.() || "ready"),
          ts: nowMs(),
        });
        try { await stream.sink([pong]); } catch { /* ignore */ }
      } catch (err) {
        _log.debug(`heartbeat: handler error from ${peerId?.slice(0, 12)}: ${err.message}`);
      } finally {
        try { await stream.close(); } catch { /* ignore */ }
      }
    });
  }

  // ── Client side: ping one peer ───────────────────────────────────────────

  async function _pingPeer(peerId, tipNodeId) {
    const state = getConsensusState ? getConsensusState() : {};
    const ping = encode("HeartbeatPing", {
      fromNodeId: getSelfNodeId ? (getSelfNodeId() || "") : "",
      committedRound: state.committed_round || 0,
      merkleRoot: hexToBytes(state.state_merkle_root || ""),
      ts: nowMs(),
    });

    let stream = null;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { if (stream) stream.close(); } catch { /* ignore */ }
    }, CONSENSUS.HEARTBEAT_TIMEOUT_MS);

    try {
      stream = await network.openStream(peerId, NETWORK.HEARTBEAT_PROTOCOL);
      await stream.sink([ping]);

      const chunks = [];
      for await (const chunk of stream.source) {
        chunks.push(chunk.subarray ? chunk.subarray() : chunk);
      }

      if (timedOut || chunks.length === 0) {
        throw new Error(timedOut ? "timeout" : "empty response");
      }

      const pong = decode("HeartbeatPong", Buffer.concat(chunks));

      // Guard against identity spoofing: pong's node_id must match our
      // authorized-peers map entry for this libp2p peerId.
      const expectedNodeId = network.authorizedPeers ? (network.authorizedPeers()[peerId] || "") : "";
      if (pong.nodeId && expectedNodeId && pong.nodeId !== expectedNodeId) {
        _log.warn(
          `heartbeat: node_id mismatch from ${peerId.slice(0, 12)}: ` +
          `expected ${expectedNodeId.slice(-8)}, got ${pong.nodeId.slice(-8)}`
        );
        return;
      }

      // Successful pong — reset miss counter, update state.
      const ps = _peerState.get(peerId) || { consecutiveMisses: 0 };
      const wasConsecutiveMisses = ps.consecutiveMisses;
      ps.consecutiveMisses = 0;
      ps.lastSeenAt = nowMs();
      ps.lastCommittedRound = Number(pong.committedRound || 0);
      ps.lastMerkleRoot = bytesToHex(pong.merkleRoot || Buffer.alloc(0));
      ps.lastJoinState = pong.joinState || "ready";
      _peerState.set(peerId, ps);

      if (wasConsecutiveMisses > 0) {
        _log.info(`heartbeat: peer ${tipNodeId?.slice(-8) || peerId.slice(0, 12)} recovered after ${wasConsecutiveMisses} miss(es)`);
      }

      if (onPeerState) {
        onPeerState(peerId, {
          node_id: pong.nodeId || tipNodeId || peerId,
          committed_round: ps.lastCommittedRound,
          state_merkle_root: ps.lastMerkleRoot,
          join_state: ps.lastJoinState,
          checked_at: ps.lastSeenAt,
        });
      }
    } catch (err) {
      if (!_running) return;  // stopped during await — ignore

      const ps = _peerState.get(peerId) || { consecutiveMisses: 0 };
      ps.consecutiveMisses = (ps.consecutiveMisses || 0) + 1;
      _peerState.set(peerId, ps);

      _log.debug(
        `heartbeat: miss ${ps.consecutiveMisses} from ${tipNodeId?.slice(-8) || peerId.slice(0, 12)}: ${err.message}`
      );

      if (ps.consecutiveMisses >= CONSENSUS.HEARTBEAT_SUSPECT_MISSES) {
        _log.warn(
          `heartbeat: peer ${tipNodeId?.slice(-8) || peerId.slice(0, 12)} ` +
          `suspect — ${ps.consecutiveMisses} consecutive misses`
        );
        if (onPeerSuspect) onPeerSuspect(peerId, tipNodeId);
      }
    } finally {
      clearTimeout(timer);
      try { if (stream) stream.close(); } catch { /* ignore */ }
    }
  }

  // ── Periodic loop ────────────────────────────────────────────────────────

  async function _runOnce() {
    if (!_running || !network) return;
    const peers = network.authorizedPeers ? Object.entries(network.authorizedPeers()) : [];
    if (peers.length === 0) return;

    // Stagger pings across the interval window to avoid a thundering-herd on
    // reconnect. Cap individual stagger at 200ms so the first few peers still
    // get fast responses even with a large committee.
    const staggerMs = Math.min(200, Math.floor(CONSENSUS.HEARTBEAT_INTERVAL_MS / (peers.length + 1)));

    await Promise.all(peers.map(async ([peerId, tipNodeId], idx) => {
      if (!_running) return;
      if (idx > 0) await new Promise(r => setTimeout(r, idx * staggerMs));
      if (!_running) return;
      try { await _pingPeer(peerId, tipNodeId); } catch { /* errors handled inside _pingPeer */ }
    }));
  }

  function _scheduleNext() {
    if (!_running) return;
    _timer = setTimeout(async () => {
      try { await _runOnce(); } catch { /* ignore */ }
      _scheduleNext();
    }, CONSENSUS.HEARTBEAT_INTERVAL_MS);
  }

  // ── Public API ───────────────────────────────────────────────────────────

  function start() {
    if (_running) return;
    _running = true;
    _scheduleNext();
    _log.info(`heartbeat started (interval=${CONSENSUS.HEARTBEAT_INTERVAL_MS}ms, timeout=${CONSENSUS.HEARTBEAT_TIMEOUT_MS}ms, suspect_misses=${CONSENSUS.HEARTBEAT_SUSPECT_MISSES})`);
  }

  function stop() {
    _running = false;
    if (_timer) { clearTimeout(_timer); _timer = null; }
    _log.info("heartbeat stopped");
  }

  function peerStates() {
    return Object.fromEntries(_peerState);
  }

  return { start, stop, registerHandler, peerStates };
}

module.exports = { createHeartbeatManager };
