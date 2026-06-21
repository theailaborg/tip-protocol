/**
 * @file tests/network/heartbeat.test.js
 * @description #47 — Active peer-liveness probe unit tests.
 *
 * Liveness-only: the heartbeat carries no consensus state (divergence
 * detection stays owned by anti-entropy). Covers:
 *   1. Handler registers and responds with a pong carrying its node_id.
 *   2. Unauthorized inbound connections are rejected without a pong.
 *   3. Successful pong resets the miss counter and records lastSeenAt.
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
const { encode, decode } = require(path.join(SRC, "network/proto"));
const { createHeartbeatManager } = require(path.join(SRC, "network/heartbeat"));
const { createStreamPair } = require(path.join(SRC, "../tests/helpers/stream-pair"));
const { CONSENSUS, NETWORK } = require(path.join(SRC, "../../shared/protocol-constants"));
const { nowMs } = require(path.join(SRC, "../../shared/time"));

const silentLog = { info: () => {}, debug: () => {}, warn: () => {} };

beforeAll(async () => {
  await loadTypes();
});

// ─── helpers ─────────────────────────────────────────────────────────────────

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

// ── Handler invocation helper ─────────────────────────────────────────────────
// Calls the registered handler directly on a stream pair so we don't need
// to drive the timer loop, and returns the decoded pong.
async function callHandler(net, handlerProto) {
  const proto = handlerProto || NETWORK.HEARTBEAT_PROTOCOL;
  const handler = net.handlers[proto];
  if (!handler) throw new Error(`Handler not registered for ${proto}`);

  const { client, server } = createStreamPair();
  const ping = encode("HeartbeatPing", { fromNodeId: "tip://node/caller", ts: nowMs() });

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
  test("responds with a pong carrying its node_id", async () => {
    const net = mkNetwork();
    const hb = createHeartbeatManager({
      network: net,
      getSelfNodeId: () => "tip://node/self",
      isAuthorizedPeer: () => true,
      log: silentLog,
    });
    await hb.registerHandler();

    const pong = await callHandler(net, NETWORK.HEARTBEAT_PROTOCOL);

    expect(pong).not.toBeNull();
    expect(pong.nodeId).toBe("tip://node/self");
    expect(Number(pong.ts)).toBeGreaterThan(0);
  });

  test("returns immediately for unauthorized peers without writing a pong", async () => {
    const net = mkNetwork();
    let sinkCalled = false;
    const hb = createHeartbeatManager({
      network: net,
      getSelfNodeId: () => "tip://node/self",
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
  function mkHeartbeat({ openStreamFn, onPeerSuspect } = {}) {
    const net = mkNetwork({ openStreamFn });
    const hb = createHeartbeatManager({
      network: net,
      getSelfNodeId: () => "tip://node/self",
      isAuthorizedPeer: () => true,
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

  test("successful pong resets miss counter and records lastSeenAt", async () => {
    const { hb } = mkHeartbeat({
      openStreamFn: () => makePeerStream({ nodeId: "tip://node/peer1", ts: nowMs() }),
    });

    jest.useFakeTimers();
    hb.start();
    await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_INTERVAL_MS + 10);
    hb.stop();
    jest.useRealTimers();

    const states = hb.peerStates();
    // peer-id-1's pong node_id matches the authorized map → counted as alive.
    expect(states["peer-id-1"]).toBeDefined();
    expect(states["peer-id-1"].consecutiveMisses).toBe(0);
    expect(states["peer-id-1"].lastSeenAt).toBeGreaterThan(0);
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

    const { hb } = mkHeartbeat({
      openStreamFn: () => {
        callCount++;
        // First 2 calls fail, subsequent calls succeed
        if (callCount <= 2) throw new Error("timeout");
        return makePeerStream({ nodeId: "tip://node/peer1", ts: nowMs() });
      },
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
    // After recovery the miss counter is 0 and a sighting was recorded for the
    // peer whose pong node_id matched the authorized map.
    const recovered = Object.entries(states).find(
      ([, ps]) => ps.consecutiveMisses === 0 && ps.lastSeenAt > 0
    );
    expect(recovered).toBeDefined();
  });
});
