/**
 * @file tests/network/peer-discovery.test.js
 * @description #38 libp2p-native peer discovery — unit tests for
 * `buildKnownPeers` and `dialKnownPeers` helpers.
 *
 * The helpers are pure wrappers over libp2p's `getConnections` and `dial`
 * APIs plus the TIP authorized-peer map, so tests can stub those two
 * surfaces and exercise every branch without standing up real network
 * nodes.
 *
 * Covered:
 *   - buildKnownPeers: one entry per authorized peer, multiaddrs pulled
 *     from live connections, excludes the responder-target peer, skips
 *     peers with no connections or unresolvable peerIds, dedups addrs
 *     across multi-connection peers, empty/missing input is a no-op
 *   - dialKnownPeers: dials every peer not already authorized, skips
 *     self by TIP node_id, tries multiaddrs in order (falls through to
 *     next on failure), empty list is a no-op, failures are logged at
 *     debug not thrown
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const { buildKnownPeers, dialKnownPeers } = require(path.join(SRC, "network", "peer-discovery"));

// ── Fake libp2p node ────────────────────────────────────────────────────

/**
 * `connections` shape: { peerIdString: [{ remoteAddr: { toString() } }, ...] }
 */
function fakeNode({ connections = {}, dialImpl } = {}) {
  const dialCalls = [];
  return {
    getConnections: (pid) => {
      const key = typeof pid === "string" ? pid : (pid && pid.toString && pid.toString()) || "";
      return connections[key] || [];
    },
    dial: async (addr) => {
      dialCalls.push(addr);
      if (dialImpl) return dialImpl(addr);
      return undefined;
    },
    _dialCalls: dialCalls,
  };
}

// peerIdFromString stub: identity (returns string). Matches our fake
// node which keys connections by string.
const peerIdFromString = (s) => s;

function silentLog() {
  return { info: () => { }, debug: () => { }, warn: () => { } };
}

function mkAddr(str) {
  return { remoteAddr: { toString: () => str } };
}

// ═══════════════════════════════════════════════════════════════════════════
describe("buildKnownPeers", () => {
  test("one entry per authorized peer with live multiaddrs", () => {
    const node = fakeNode({
      connections: {
        "peer-a": [mkAddr("/ip4/10.0.0.2/tcp/4001/p2p/peer-a")],
        "peer-b": [mkAddr("/ip4/10.0.0.3/tcp/4001/p2p/peer-b")],
      },
    });
    const authorized = new Map([
      ["peer-a", "tip://node/a"],
      ["peer-b", "tip://node/b"],
    ]);
    const result = buildKnownPeers(node, authorized, "someone-else", peerIdFromString);

    expect(result).toHaveLength(2);
    expect(result.find(r => r.node_id === "tip://node/a")).toEqual({
      node_id: "tip://node/a",
      multiaddrs: ["/ip4/10.0.0.2/tcp/4001/p2p/peer-a"],
    });
    expect(result.find(r => r.node_id === "tip://node/b")).toEqual({
      node_id: "tip://node/b",
      multiaddrs: ["/ip4/10.0.0.3/tcp/4001/p2p/peer-b"],
    });
  });

  test("excludes the peer we're responding to (the joiner)", () => {
    const node = fakeNode({
      connections: {
        "joiner": [mkAddr("/ip4/10.0.0.99/tcp/4001/p2p/joiner")],
        "peer-a": [mkAddr("/ip4/10.0.0.2/tcp/4001/p2p/peer-a")],
      },
    });
    const authorized = new Map([
      ["joiner", "tip://node/joiner"],
      ["peer-a", "tip://node/a"],
    ]);
    const result = buildKnownPeers(node, authorized, "joiner", peerIdFromString);

    expect(result).toHaveLength(1);
    expect(result[0].node_id).toBe("tip://node/a");
  });

  test("skips peers with no live connections", () => {
    const node = fakeNode({
      connections: {
        "peer-a": [mkAddr("/ip4/10.0.0.2/tcp/4001/p2p/peer-a")],
        // peer-b has NO connection entry → getConnections returns []
      },
    });
    const authorized = new Map([
      ["peer-a", "tip://node/a"],
      ["peer-b", "tip://node/b"],
    ]);
    const result = buildKnownPeers(node, authorized, "joiner", peerIdFromString);

    expect(result).toHaveLength(1);
    expect(result[0].node_id).toBe("tip://node/a");
  });

  test("dedups multiaddrs across multiple connections to same peer", () => {
    const node = fakeNode({
      connections: {
        "peer-a": [
          mkAddr("/ip4/10.0.0.2/tcp/4001/p2p/peer-a"),
          mkAddr("/ip4/10.0.0.2/tcp/4001/p2p/peer-a"),  // duplicate
          mkAddr("/ip6/::1/tcp/4001/p2p/peer-a"),
        ],
      },
    });
    const authorized = new Map([["peer-a", "tip://node/a"]]);
    const result = buildKnownPeers(node, authorized, "joiner", peerIdFromString);

    expect(result).toHaveLength(1);
    expect(result[0].multiaddrs).toEqual([
      "/ip4/10.0.0.2/tcp/4001/p2p/peer-a",
      "/ip6/::1/tcp/4001/p2p/peer-a",
    ]);
  });

  test("handles null/undefined node gracefully", () => {
    expect(buildKnownPeers(null, new Map(), "x", peerIdFromString)).toEqual([]);
    expect(buildKnownPeers(undefined, new Map(), "x", peerIdFromString)).toEqual([]);
  });

  test("handles empty authorized map", () => {
    const node = fakeNode();
    expect(buildKnownPeers(node, new Map(), "x", peerIdFromString)).toEqual([]);
  });

  test("catches peerIdFromString throws and skips that peer", () => {
    const node = fakeNode({
      connections: { "peer-a": [mkAddr("/ip4/10.0.0.2/tcp/4001/p2p/peer-a")] },
    });
    const authorized = new Map([
      ["peer-a", "tip://node/a"],
      ["bad-peer-id", "tip://node/bad"],
    ]);
    const throwingPeerIdFromString = (s) => {
      if (s === "bad-peer-id") throw new Error("invalid peer id");
      return s;
    };

    const result = buildKnownPeers(node, authorized, "joiner", throwingPeerIdFromString);
    expect(result).toHaveLength(1);
    expect(result[0].node_id).toBe("tip://node/a");
  });

  test("omits peers with empty/missing tip node_id", () => {
    const node = fakeNode({
      connections: { "peer-a": [mkAddr("/ip4/10.0.0.2/tcp/4001/p2p/peer-a")] },
    });
    const authorized = new Map([
      ["peer-a", ""],        // empty tip node_id
      ["peer-b", undefined], // missing
    ]);
    const result = buildKnownPeers(node, authorized, "joiner", peerIdFromString);
    expect(result).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe("HandshakeAck proto round-trip with known_peers", () => {
  // Verify the wire encoding actually carries the hint field, since the
  // rest of the dial flow depends on it crossing the gossipsub stream
  // intact. Complements the buildKnownPeers unit tests (which only see
  // the pre-encode shape).
  test("encode → decode preserves known_peers list", async () => {
    const { loadTypes, encode, decode } = require(path.join(SRC, "network", "proto"));
    await loadTypes();

    const known = [
      { nodeId: "tip://node/a", multiaddrs: ["/ip4/10.0.0.2/tcp/4001/p2p/a", "/ip6/::1/tcp/4001/p2p/a"] },
      { nodeId: "tip://node/b", multiaddrs: ["/ip4/10.0.0.3/tcp/4001/p2p/b"] },
    ];

    const encoded = encode("HandshakeAck", {
      nodeId: "tip://node/self",
      latestRound: 42,
      merkleRoot: Buffer.alloc(0),
      syncNeeded: false,
      signature: Buffer.alloc(0),
      genesisHash: Buffer.alloc(0),
      knownPeers: known,
    });
    const decoded = decode("HandshakeAck", encoded);

    expect(decoded.knownPeers).toHaveLength(2);
    expect(decoded.knownPeers[0].nodeId).toBe("tip://node/a");
    expect(decoded.knownPeers[0].multiaddrs).toEqual(known[0].multiaddrs);
    expect(decoded.knownPeers[1].nodeId).toBe("tip://node/b");
    expect(decoded.knownPeers[1].multiaddrs).toEqual(known[1].multiaddrs);
  });

  test("empty known_peers decodes as empty array (backward compat)", async () => {
    const { loadTypes, encode, decode } = require(path.join(SRC, "network", "proto"));
    await loadTypes();

    const encoded = encode("HandshakeAck", {
      nodeId: "tip://node/self",
      latestRound: 0,
      merkleRoot: Buffer.alloc(0),
      syncNeeded: false,
      signature: Buffer.alloc(0),
      genesisHash: Buffer.alloc(0),
      // knownPeers omitted
    });
    const decoded = decode("HandshakeAck", encoded);
    expect(decoded.knownPeers).toEqual([]);
  });
});

describe("dialKnownPeers", () => {
  test("dials every unknown peer's first multiaddr", async () => {
    const node = fakeNode();
    const authorized = new Map();
    dialKnownPeers(node, [
      { node_id: "tip://node/a", multiaddrs: ["/ip4/10.0.0.2/tcp/4001/p2p/peer-a"] },
      { node_id: "tip://node/b", multiaddrs: ["/ip4/10.0.0.3/tcp/4001/p2p/peer-b"] },
    ], authorized, "tip://node/self", silentLog());

    // dialKnownPeers is fire-and-forget — wait for microtasks to drain.
    await new Promise(r => setImmediate(r));
    expect(node._dialCalls.sort()).toEqual([
      "/ip4/10.0.0.2/tcp/4001/p2p/peer-a",
      "/ip4/10.0.0.3/tcp/4001/p2p/peer-b",
    ].sort());
  });

  test("skips self (by TIP node_id)", async () => {
    const node = fakeNode();
    dialKnownPeers(node, [
      { node_id: "tip://node/self", multiaddrs: ["/ip4/1/tcp/1/p2p/self"] },
      { node_id: "tip://node/other", multiaddrs: ["/ip4/2/tcp/2/p2p/other"] },
    ], new Map(), "tip://node/self", silentLog());

    await new Promise(r => setImmediate(r));
    expect(node._dialCalls).toEqual(["/ip4/2/tcp/2/p2p/other"]);
  });

  test("skips peers already in authorized map (by TIP node_id)", async () => {
    const node = fakeNode();
    const authorized = new Map([["some-peer", "tip://node/a"]]);
    dialKnownPeers(node, [
      { node_id: "tip://node/a", multiaddrs: ["/addr/a"] },  // already have
      { node_id: "tip://node/b", multiaddrs: ["/addr/b"] },
    ], authorized, "tip://node/self", silentLog());

    await new Promise(r => setImmediate(r));
    expect(node._dialCalls).toEqual(["/addr/b"]);
  });

  test("falls through to next multiaddr if first fails", async () => {
    let attempt = 0;
    const node = fakeNode({
      dialImpl: async (addr) => {
        attempt++;
        if (attempt === 1) throw new Error("unreachable");
        return undefined;
      },
    });
    dialKnownPeers(node, [
      { node_id: "tip://node/a", multiaddrs: ["/bad/1", "/good/2"] },
    ], new Map(), "tip://node/self", silentLog());

    await new Promise(r => setImmediate(r));
    await new Promise(r => setImmediate(r));  // second round for promise chain
    expect(node._dialCalls).toEqual(["/bad/1", "/good/2"]);
  });

  test("all multiaddrs failing does not throw out of the caller", async () => {
    const node = fakeNode({
      dialImpl: async () => { throw new Error("all unreachable"); },
    });
    // No throw from the outer call.
    expect(() => dialKnownPeers(node, [
      { node_id: "tip://node/a", multiaddrs: ["/a", "/b"] },
    ], new Map(), "tip://node/self", silentLog())).not.toThrow();

    await new Promise(r => setImmediate(r));
    await new Promise(r => setImmediate(r));
  });

  test("empty list is a no-op", async () => {
    const node = fakeNode();
    dialKnownPeers(node, [], new Map(), "tip://node/self", silentLog());
    await new Promise(r => setImmediate(r));
    expect(node._dialCalls).toEqual([]);
  });

  test("null/undefined knownPeers is a no-op", async () => {
    const node = fakeNode();
    dialKnownPeers(node, null, new Map(), "tip://node/self", silentLog());
    dialKnownPeers(node, undefined, new Map(), "tip://node/self", silentLog());
    await new Promise(r => setImmediate(r));
    expect(node._dialCalls).toEqual([]);
  });

  test("peer with missing node_id or empty multiaddrs is skipped", async () => {
    const node = fakeNode();
    dialKnownPeers(node, [
      { node_id: "", multiaddrs: ["/a"] },
      { node_id: "tip://node/b", multiaddrs: [] },
      { multiaddrs: ["/c"] },  // missing node_id
      null,                      // undefined entry
      { node_id: "tip://node/d", multiaddrs: ["/d"] },  // only this one valid
    ], new Map(), "tip://node/self", silentLog());

    await new Promise(r => setImmediate(r));
    expect(node._dialCalls).toEqual(["/d"]);
  });

  test("logger is optional", async () => {
    const node = fakeNode();
    expect(() => dialKnownPeers(node, [
      { node_id: "tip://node/a", multiaddrs: ["/a"] },
    ], new Map(), "tip://node/self")).not.toThrow();
    await new Promise(r => setImmediate(r));
  });
});
