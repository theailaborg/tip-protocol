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
    openStream: async (peerId, proto, opts) => {
      if (!openStreamFn) throw new Error("no openStream configured");
      return openStreamFn(peerId, proto, opts);
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
    // a verdict fired and was consumed: the streak restarts from zero
    expect(suspects.length).toBeGreaterThan(0);
    for (const ps of Object.values(states)) expect(ps.consecutiveMisses).toBeLessThan(CONSENSUS.HEARTBEAT_SUSPECT_MISSES);
  });

  test("forgive zeroes the miss counter: eviction then needs fresh misses", async () => {
    const suspects = [];
    const { hb } = mkHeartbeat({
      openStreamFn: () => { throw new Error("connection refused"); },
      onPeerSuspect: (peerId) => suspects.push(peerId),
    });
    jest.useFakeTimers();
    try {
      hb.start();
      for (let i = 0; i <= CONSENSUS.HEARTBEAT_SUSPECT_MISSES; i++) {
        await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_INTERVAL_MS + 10);
      }
      const peerId = suspects[0];
      expect(peerId).toBeDefined();
      expect(hb.peerStates()[peerId].consecutiveMisses).toBeLessThan(CONSENSUS.HEARTBEAT_SUSPECT_MISSES);   // consumed by the verdict

      hb.forgive(peerId);
      expect(hb.peerStates()[peerId].consecutiveMisses).toBe(0);
      expect(() => hb.forgive("never-seen-peer")).not.toThrow();

      // One more miss is not a verdict any more: the transfer-time misses are gone.
      const verdictsBefore = suspects.filter((p) => p === peerId).length;
      await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_INTERVAL_MS + 10);
      expect(hb.peerStates()[peerId].consecutiveMisses).toBeLessThan(CONSENSUS.HEARTBEAT_SUSPECT_MISSES);
      expect(suspects.filter((p) => p === peerId).length).toBe(verdictsBefore);
    } finally {
      hb.stop();
      jest.useRealTimers();
    }
  });

  // Our probes fail on a congested path while the peer's own pings still reach
  // us; that is queueing, not a dead peer, and must not become an eviction.
  test("no suspect verdict while the peer's own pings keep arriving", async () => {
    const suspects = [];
    const { hb, net } = mkHeartbeat({
      openStreamFn: () => { throw new Error("connection refused"); },
      onPeerSuspect: (peerId) => suspects.push(peerId),
    });
    await hb.registerHandler();
    await callHandler(net);   // an authenticated ping from peer-id-1 lands on our handler
    expect(hb.peerStates()["peer-id-1"].lastInboundAt).toBeGreaterThan(0);

    jest.useFakeTimers();
    try {
      hb.start();
      for (let i = 0; i <= CONSENSUS.HEARTBEAT_SUSPECT_MISSES; i++) {
        await callHandler(net);   // peer-id-1 keeps pinging us while our probes to it fail
        await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_INTERVAL_MS + 10);
      }
      expect(hb.peerStates()["peer-id-1"].consecutiveMisses).toBeGreaterThanOrEqual(CONSENSUS.HEARTBEAT_SUSPECT_MISSES);
      expect(suspects).not.toContain("peer-id-1");
      // peer-id-2 never pinged us: same misses, real verdict
      expect(suspects).toContain("peer-id-2");
      // once its pings stop for the silence bound AND a whole streak, the verdict is real again
      const { HEARTBEAT_INBOUND_SILENCE_MS } = require("../../../shared/constants");
      await jest.advanceTimersByTimeAsync(HEARTBEAT_INBOUND_SILENCE_MS);
      for (let i = 0; i <= CONSENSUS.HEARTBEAT_SUSPECT_MISSES; i++) {
        await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_INTERVAL_MS + 10);
      }
      expect(suspects).toContain("peer-id-1");
    } finally {
      hb.stop();
      jest.useRealTimers();
    }
  });

  // A black-holed peer makes the stream open hang until libp2p's own deadline;
  // the tick awaits every peer, so that froze the whole heartbeat (test cluster,
  // 2026-09-25: one miss in 75s, no eviction). The probe is bounded by our timer.
  test("a hung stream open is a miss at HEARTBEAT_TIMEOUT_MS and never stalls the tick", async () => {
    const suspects = [];
    const signals = [];
    const { hb } = mkHeartbeat({
      openStreamFn: (peerId, proto, opts) => { signals.push(opts && opts.signal); return new Promise(() => {}); },
      onPeerSuspect: (peerId) => suspects.push(peerId),
    });
    jest.useFakeTimers();
    try {
      hb.start();
      for (let i = 0; i <= CONSENSUS.HEARTBEAT_SUSPECT_MISSES; i++) {
        await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_INTERVAL_MS + CONSENSUS.HEARTBEAT_TIMEOUT_MS + 10);
      }
      expect(suspects).toContain("peer-id-1");
      expect(suspects).toContain("peer-id-2");
      // the open was handed our abort signal and it fired (last tick's staggered peer included)
      await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_TIMEOUT_MS);
      expect(signals.length).toBeGreaterThan(0);
      expect(signals.every((s) => s && s.aborted)).toBe(true);
    } finally {
      hb.stop();
      jest.useRealTimers();
    }
  });

  // A live peer behind a bloated link pings us in bunches; a ping older than the
  // current streak but inside HEARTBEAT_INBOUND_SILENCE_MS is still evidence.
  test("an inbound ping within the silence bound but before the streak still blocks the verdict", async () => {
    const { HEARTBEAT_INBOUND_SILENCE_MS } = require("../../../shared/constants");
    const suspects = [];
    const { hb, net } = mkHeartbeat({
      openStreamFn: () => { throw new Error("connection refused"); },
      onPeerSuspect: (peerId) => suspects.push(peerId),
    });
    await hb.registerHandler();
    jest.useFakeTimers();
    try {
      await callHandler(net);   // one ping from peer-id-1, then silence
      hb.start();
      const streak = CONSENSUS.HEARTBEAT_SUSPECT_MISSES + 1;
      for (let i = 0; i < streak; i++) await jest.advanceTimersByTimeAsync(CONSENSUS.HEARTBEAT_INTERVAL_MS + 10);
      expect(suspects).not.toContain("peer-id-1");     // ping predates the streak, inside the bound
      expect(suspects).toContain("peer-id-2");         // never heard from
      await jest.advanceTimersByTimeAsync(HEARTBEAT_INBOUND_SILENCE_MS);
      expect(suspects).toContain("peer-id-1");         // silent past the bound: real verdict
    } finally {
      hb.stop();
      jest.useRealTimers();
    }
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
