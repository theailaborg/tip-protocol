/**
 * @file tests/network/bootstrap-reconnect.test.js
 * @description Unit tests for the bootstrap reconnect manager.
 *
 * The manager owns a per-bootstrap-peer self-rescheduling retry chain.
 * Only the public surface (start / stop / onPeerDisconnect) plus
 * observable side effects on `node.dial` and the timer state are tested.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const { createBootstrapReconnect } = require(path.join(SRC, "network/bootstrap-reconnect"));

const silentLog = () => ({ info: () => { }, debug: () => { }, warn: () => { } });

/** Sleep helper for waiting on async retry chains. */
function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

/**
 * Fake libp2p node — records every dial call, optionally fails them.
 * dialImpl is keyed by addr; default is "succeed".
 */
function fakeNode(dialImpl = {}) {
  const dialCalls = [];
  return {
    dial: async (addr) => {
      // Production code passes Multiaddr instances now (libp2p@2.x requires
      // them); the fake normalises to string so assertions stay flat.
      const s = (addr && typeof addr === "object" && typeof addr.toString === "function")
        ? addr.toString()
        : addr;
      dialCalls.push(s);
      const impl = dialImpl[s];
      if (impl === "fail") throw new Error("connection refused");
      if (typeof impl === "function") return impl();
      // default: success (returns undefined)
    },
    _dialCalls: dialCalls,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
describe("createBootstrapReconnect", () => {
  test("no-op shim when bootstrapPeers is empty", () => {
    const r = createBootstrapReconnect({
      node: fakeNode(), bootstrapPeers: [], authorizedPeers: new Map(), log: silentLog(),
    });
    expect(typeof r.start).toBe("function");
    expect(typeof r.stop).toBe("function");
    // calling them must not throw
    r.start(); r.stop(); r.onPeerDisconnect("anything");
  });

  test("start() dials every bootstrap peer immediately", async () => {
    const node = fakeNode();
    const r = createBootstrapReconnect({
      node,
      bootstrapPeers: [
        "/ip4/1.1.1.1/tcp/4001/p2p/peer-A",
        "/ip4/2.2.2.2/tcp/4001/p2p/peer-B",
      ],
      authorizedPeers: new Map(),
      log: silentLog(),
      intervalMs: 50,
    });
    r.start();
    await delay(20);
    expect(node._dialCalls.sort()).toEqual([
      "/ip4/1.1.1.1/tcp/4001/p2p/peer-A",
      "/ip4/2.2.2.2/tcp/4001/p2p/peer-B",
    ]);
    r.stop();
  });

  test("successful dial does NOT reschedule (chain stops)", async () => {
    const node = fakeNode();   // all dials succeed
    const r = createBootstrapReconnect({
      node,
      bootstrapPeers: ["/ip4/1.1.1.1/tcp/4001/p2p/peer-A"],
      authorizedPeers: new Map(),
      log: silentLog(),
      intervalMs: 30,
    });
    r.start();
    await delay(100);   // enough time for several retry intervals to elapse
    expect(node._dialCalls.length).toBe(1);   // exactly one dial — success stops the chain
    r.stop();
  });

  test("failed dial schedules a retry, retries until success", async () => {
    let attemptsBeforeSuccess = 2;
    const node = {
      _dialCalls: [],
      dial: async (addr) => {
        node._dialCalls.push(addr);
        if (attemptsBeforeSuccess-- > 0) throw new Error("offline");
        // success
      },
    };
    const r = createBootstrapReconnect({
      node,
      bootstrapPeers: ["/ip4/1.1.1.1/tcp/4001/p2p/peer-A"],
      authorizedPeers: new Map(),
      log: silentLog(),
      intervalMs: 30,
    });
    r.start();
    await delay(150);   // 1st now + 2nd at +30 + 3rd at +60 = success
    expect(node._dialCalls.length).toBeGreaterThanOrEqual(3);
    // After success, no further dials.
    const beforeIdle = node._dialCalls.length;
    await delay(100);
    expect(node._dialCalls.length).toBe(beforeIdle);
    r.stop();
  });

  test("skips dial if peer authorized via another path before retry fires", async () => {
    const node = fakeNode();
    const authorizedPeers = new Map();
    const r = createBootstrapReconnect({
      node,
      bootstrapPeers: ["/ip4/1.1.1.1/tcp/4001/p2p/peer-A"],
      authorizedPeers,
      log: silentLog(),
      intervalMs: 50,
    });
    // Pre-mark the peer as authorized BEFORE start() — the kicked-off
    // retry should detect this and skip the dial entirely.
    authorizedPeers.set("peer-A", "tip://node/a");
    r.start();
    await delay(20);
    expect(node._dialCalls).toEqual([]);
    r.stop();
  });

  test("onPeerDisconnect for a bootstrap peer restarts retry chain", async () => {
    const node = fakeNode();
    const r = createBootstrapReconnect({
      node,
      bootstrapPeers: ["/ip4/1.1.1.1/tcp/4001/p2p/peer-A"],
      authorizedPeers: new Map(),
      log: silentLog(),
      intervalMs: 30,
    });
    r.start();
    await delay(20);
    expect(node._dialCalls.length).toBe(1);   // initial successful dial

    // Now simulate the peer dropping. Should schedule a fresh retry.
    r.onPeerDisconnect("peer-A");
    await delay(60);
    expect(node._dialCalls.length).toBe(2);   // re-dial after the disconnect
    r.stop();
  });

  test("onPeerDisconnect for a NON-bootstrap peer is a no-op", async () => {
    const node = fakeNode();
    const r = createBootstrapReconnect({
      node,
      bootstrapPeers: ["/ip4/1.1.1.1/tcp/4001/p2p/peer-A"],
      authorizedPeers: new Map(),
      log: silentLog(),
      intervalMs: 30,
    });
    r.start();
    await delay(20);
    expect(node._dialCalls.length).toBe(1);   // initial dial
    r.onPeerDisconnect("some-other-peer");
    await delay(60);
    expect(node._dialCalls.length).toBe(1);   // unchanged
    r.stop();
  });

  test("stop() cancels every pending retry timer", async () => {
    const node = fakeNode({ "/ip4/1.1.1.1/tcp/4001/p2p/peer-A": "fail" });
    const r = createBootstrapReconnect({
      node,
      bootstrapPeers: ["/ip4/1.1.1.1/tcp/4001/p2p/peer-A"],
      authorizedPeers: new Map(),
      log: silentLog(),
      intervalMs: 30,
    });
    r.start();
    await delay(20);   // first dial fails, schedules retry
    expect(node._dialCalls.length).toBe(1);
    r.stop();
    await delay(100);   // wait long enough that any pending retry would have fired
    expect(node._dialCalls.length).toBe(1);   // no further dials after stop()
  });
});
