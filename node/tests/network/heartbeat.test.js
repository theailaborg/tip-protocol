/**
 * @file tests/network/heartbeat.test.js
 * @description #47 — Active peer-liveness probe unit tests.
 *
 * Covers:
 *   1. Handler registers and responds with current node state.
 *   2. Unauthorized inbound connections are rejected.
 *   3. Successful ping updates per-peer state and calls onPeerState.
 *   4. Consecutive misses increment counter and fire onPeerSuspect.
 *   5. Peer recovery after misses resets consecutiveMisses.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const { loadTypes } = require(path.join(SRC, "network/proto"));
const { encode, decode, bytesToHex, hexToBytes } = require(path.join(SRC, "network/proto"));
const { createHeartbeatManager } = require(path.join(SRC, "network/heartbeat"));
const { createStreamPair } = require(path.join(SRC, "../tests/helpers/stream-pair"));
const { CONSENSUS, NETWORK } = require(path.join(SRC, "../../shared/protocol-constants"));

const silentLog = { info: () => {}, debug: () => {}, warn: () => {} };

beforeAll(async () => {
  await loadTypes();
});

// ─── helpers ─────────────────────────────────────────────────────────────────

function mkState({ committed_round = 100, state_merkle_root = "aabb" } = {}) {
  return { committed_round, state_merkle_root };
}

function mkNarwhal(joinState = "ready") {
  return { joinState: () => joinState };
}

// Build a minimal mock network. openStreamFn: (peerId, proto) => stream | throws
function mkNetwork({ openStreamFn = null } = {}) {
  const handlers = {};
  const authorizedMap = { "peer-id-1": "tip://node/peer1", "peer-id-2": "tip://node/peer2" };
  return {
    handle: async (proto, fn) => { handlers[proto] = fn; },
    openStream: async (peerId, proto) => {
      if (!openStreamFn) throw new Error("no openStream configured");
      return openStreamFn(peerId, proto);
    },
    authorizedPeers: () => ({ ...authorizedMap }),
    handlers,
  };
}

// Simulate one complete ping-pong exchange. Returns the pong payload decoded.
async function doPingPong(hb, peerId, pongPayload) {
  const net = hb._net; // accessed via closure — see below
  throw new Error("use direct API");
}

// ── Handler invocation helper ─────────────────────────────────────────────────
// Calls the registered handler directly on a stream pair so we don't need
// to drive the timer loop, and asserts the pong content.
async function callHandler(net, handlerProto, remoteNodeId, isAuthorized = true) {
  const proto = handlerProto || NETWORK.HEARTBEAT_PROTOCOL;
  const handler = net.handlers[proto];
  if (!handler) throw new Error(`Handler not registered for ${proto}`);

  const { client, server } = createStreamPair();
  const ping = encode("HeartbeatPing", {
    fromNodeId: remoteNodeId || "tip://node/caller",
    committedRound: 50,
    merkleRoot: hexToBytes("1234"),
    ts: Date.now(),
  });

  const [, pong] = await Promise.all([
    handler({ stream: server, connection: { remotePeer: { toString: () => "peer-id-1" } } }),
    (async () => {
      await client.sink([ping]);
      const chunks = [];
      for await (const chunk of client.source) {
        chunks.push(chunk.subarray ? chunk.subarray() : chunk);
      }
      if (chunks.length === 0) return null;
      return decode("HeartbeatPong", Buffer.concat(chunks));
    })(),
  ]);
  return pong;
}

// ═══════════════════════════════════════════════════════════════════════════
describe("heartbeat handler (server side)", () => {
  test("responds with current node state", async () => {
    const net = mkNetwork();
    const hb = createHeartbeatManager({
      network: net,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => mkState({ committed_round: 42, state_merkle_root: "deadbeef" }),
      isAuthorizedPeer: () => true,
      narwhal: mkNarwhal("ready"),
      log: silentLog,
    });
    await hb.registerHandler();

    const pong = await callHandler(net, NETWORK.HEARTBEAT_PROTOCOL);

    expect(pong).not.toBeNull();
    expect(pong.nodeId).toBe("tip://node/self");
    expect(Number(pong.committedRound)).toBe(42);
    expect(bytesToHex(pong.merkleRoot)).toBe("deadbeef");
    expect(pong.joinState).toBe("ready");
  });

  test("returns immediately for unauthorized peers without writing a pong", async () => {
    const net = mkNetwork();
    let sinkCalled = false;
    const hb = createHeartbeatManager({
      network: net,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => mkState(),
      isAuthorizedPeer: () => false,
      log: silentLog,
    });
    await hb.registerHandler();

    // Intercept server.sink to detect if a pong was written.
    const proto = NETWORK.HEARTBEAT_PROTOCOL;
    const { server } = createStreamPair();
    const origSink = server.sink.bind(server);
    server.sink = async (...args) => { sinkCalled = true; return origSink(...args); };

    // Handler must return promptly — if it waits on stream.source forever this races.
    await Promise.race([
      net.handlers[proto]({ stream: server, connection: { remotePeer: { toString: () => "unknown-peer" } } }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("handler did not return")), 200)),
    ]);

    expect(sinkCalled).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe("heartbeat client side", () => {
  // Helper: build a heartbeat manager whose _pingPeer we can drive
  // by manipulating the timer to fire immediately.
  function mkHeartbeat({ openStreamFn, onPeerState, onPeerSuspect } = {}) {
    const net = mkNetwork({ openStreamFn });
    const hb = createHeartbeatManager({
      network: net,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => mkState({ committed_round: 100 }),
      isAuthorizedPeer: () => true,
      narwhal: mkNarwhal("ready"),
      onPeerState,
      onPeerSuspect,
      log: silentLog,
    });
    return { hb, net };
  }

  // Build a stream pair where the peer auto-responds with a given pong payload.
  function makePeerStream(pongPayload) {
    const { client, server } = createStreamPair();
    (async () => {
      for await (const _chunk of server.source) { break; }  // drain ping
      const pong = encode("HeartbeatPong", pongPayload);
      await server.sink([pong]);
    })();
    return client;
  }

  test("successful pong calls onPeerState with decoded state", async () => {
    const updates = [];
    const { hb } = mkHeartbeat({
      openStreamFn: () => makePeerStream({
        nodeId: "tip://node/peer1",
        committedRound: 200,
        merkleRoot: hexToBytes("cafebabe"),
        joinState: "ready",
        ts: Date.now(),
      }),
      onPeerState: (peerId, state) => updates.push({ peerId, state }),
    });

    // Drive one full cycle without relying on setTimeout by starting
    // and waiting 1 interval. Use a short timeout override via prototype.
    // Simpler: call start(), let one real timer tick fire with a jest fake-timer.
    jest.useFakeTimers();
    hb.start();
    // Advance to first tick
    await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_INTERVAL_MS + 10);
    hb.stop();
    jest.useRealTimers();

    expect(updates.length).toBeGreaterThan(0);
    const update = updates.find(u => u.peerId === "peer-id-1") || updates[0];
    expect(update.state.committed_round).toBe(200);
    expect(update.state.state_merkle_root).toBe("cafebabe");
    expect(update.state.join_state).toBe("ready");

    const states = hb.peerStates();
    expect(states["peer-id-1"].consecutiveMisses).toBe(0);
  });

  test("consecutive misses increment counter and fire onPeerSuspect", async () => {
    const suspects = [];
    const { hb } = mkHeartbeat({
      openStreamFn: () => { throw new Error("connection refused"); },
      onPeerSuspect: (peerId, tipNodeId) => suspects.push({ peerId, tipNodeId }),
    });

    jest.useFakeTimers();
    hb.start();
    // Advance enough ticks to accumulate SUSPECT_MISSES misses
    for (let i = 0; i <= CONSENSUS.HEARTBEAT_SUSPECT_MISSES; i++) {
      await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_INTERVAL_MS + 10);
    }
    hb.stop();
    jest.useRealTimers();

    const states = hb.peerStates();
    // At least one peer should have reached suspect threshold
    const suspectPeer = Object.values(states).find(
      ps => ps.consecutiveMisses >= CONSENSUS.HEARTBEAT_SUSPECT_MISSES
    );
    expect(suspectPeer).toBeDefined();
    expect(suspects.length).toBeGreaterThan(0);
  });

  test("recovery after misses resets consecutiveMisses to 0", async () => {
    let callCount = 0;
    const updates = [];

    const { hb } = mkHeartbeat({
      openStreamFn: () => {
        callCount++;
        // First 2 calls fail, subsequent calls succeed
        if (callCount <= 2) throw new Error("timeout");
        return makePeerStream({
          nodeId: "tip://node/peer1",
          committedRound: 300,
          merkleRoot: hexToBytes("aabbcc"),
          joinState: "ready",
          ts: Date.now(),
        });
      },
      onPeerState: (peerId, state) => updates.push(state),
    });

    jest.useFakeTimers();
    hb.start();
    // 4 ticks: tick 1 = miss, tick 2 = miss, tick 3 = success, tick 4 = success
    for (let i = 0; i < 4; i++) {
      await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_INTERVAL_MS + 10);
    }
    hb.stop();
    jest.useRealTimers();

    const states = hb.peerStates();
    // After recovery the miss counter should be 0 for the peer that recovered
    const recovered = Object.entries(states).find(([, ps]) => ps.consecutiveMisses === 0);
    expect(recovered).toBeDefined();
    expect(updates.some(s => s.committed_round === 300)).toBe(true);
  });
});
