/**
 * @file tests/network/peer-announce.test.js
 * @description #48 forward-on-authorize push — unit tests for
 * `buildPeerEntry`, `pushAnnounce`, `broadcastAnnounce`, and
 * `registerAnnounceHandler`.
 *
 * Push path is glue: encode a PeerAnnounce, open a one-shot stream to
 * each authorized peer, write, close. Failures are silent so a single
 * unreachable peer doesn't disrupt the broadcast.
 *
 * Pull-side handler is the mirror: read one PeerAnnounce, decode, dial
 * each entry through `dialKnownPeers` (deduped against current authorized
 * set). Unauthorized senders are rejected at the gate.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const { loadTypes } = require(path.join(SRC, "network/proto"));
const { NETWORK } = require(path.join(SRC, "../../shared/protocol-constants"));
const {
  buildPeerEntry,
  pushAnnounce,
  broadcastAnnounce,
  registerAnnounceHandler,
} = require(path.join(SRC, "network/peer-discovery"));
const PEER_ANNOUNCE_PROTOCOL = NETWORK.PEER_ANNOUNCE_PROTOCOL;
const { createStreamPair } = require(path.join(SRC, "../tests/helpers/stream-pair"));

const peerIdFromString = (s) => s;
const silentLog = () => ({ info: () => { }, debug: () => { }, warn: () => { } });

function mkAddr(str) {
  return { remoteAddr: { toString: () => str } };
}

beforeAll(async () => {
  // The push/handler glue uses encode/decode at runtime. Tests must boot
  // protobuf types before any of these helpers are exercised.
  await loadTypes();
});

// ═══════════════════════════════════════════════════════════════════════════
describe("buildPeerEntry", () => {
  test("returns {node_id, multiaddrs} for a peer with one connection", async () => {
    const node = {
      getConnections: (pid) => pid === "peer-a"
        ? [mkAddr("/ip4/10.0.0.2/tcp/4001/p2p/peer-a")]
        : [],
    };
    const entry = await buildPeerEntry(node, "peer-a", "tip://node/a", peerIdFromString);
    expect(entry).toEqual({
      node_id: "tip://node/a",
      multiaddrs: ["/ip4/10.0.0.2/tcp/4001/p2p/peer-a"],
    });
  });

  test("returns null when peer has no live connections", async () => {
    const node = { getConnections: () => [] };
    expect(await buildPeerEntry(node, "peer-a", "tip://node/a", peerIdFromString)).toBeNull();
  });

  test("dedups multiaddrs from multiple connections", async () => {
    const node = {
      getConnections: () => [
        mkAddr("/ip4/10.0.0.2/tcp/4001/p2p/peer-a"),
        mkAddr("/ip4/10.0.0.2/tcp/4001/p2p/peer-a"),  // dup
        mkAddr("/ip6/::1/tcp/4001/p2p/peer-a"),
      ],
    };
    const entry = await buildPeerEntry(node, "peer-a", "tip://node/a", peerIdFromString);
    expect(entry.multiaddrs).toEqual([
      "/ip4/10.0.0.2/tcp/4001/p2p/peer-a",
      "/ip6/::1/tcp/4001/p2p/peer-a",
    ]);
  });

  test("returns null for missing inputs", async () => {
    expect(await buildPeerEntry(null, "peer-a", "tip://node/a", peerIdFromString)).toBeNull();
    expect(await buildPeerEntry({ getConnections: () => [] }, "", "tip://node/a", peerIdFromString)).toBeNull();
    expect(await buildPeerEntry({ getConnections: () => [] }, "peer-a", "", peerIdFromString)).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe("pushAnnounce", () => {
  test("opens an announce stream to the recipient and writes one PeerAnnounce", async () => {
    const { client, server } = createStreamPair();
    const dialed = [];
    const node = {
      dialProtocol: async (peerId, protocol) => {
        dialed.push({ peerId, protocol });
        return client;
      },
    };
    await pushAnnounce(
      node, "peer-a", peerIdFromString,
      [{ node_id: "tip://node/x", multiaddrs: ["/ip4/1.1.1.1/tcp/4001/p2p/peer-x"] }],
      silentLog(),
    );
    // Drain server side to confirm at least one frame was sent and decode it.
    const frames = [];
    for await (const chunk of server.source) frames.push(chunk);

    expect(dialed).toHaveLength(1);
    expect(dialed[0].protocol).toBe(PEER_ANNOUNCE_PROTOCOL);
    expect(frames.length).toBeGreaterThan(0);

    const { decode } = require(path.join(SRC, "network/proto"));
    const buf = Buffer.concat(frames.map(c => Buffer.from(c)));
    const msg = decode("PeerAnnounce", buf);
    expect(msg.knownPeers).toHaveLength(1);
    expect(msg.knownPeers[0].nodeId).toBe("tip://node/x");
  });

  test("dial failure is silent (no throw)", async () => {
    const node = { dialProtocol: async () => { throw new Error("nope"); } };
    await expect(pushAnnounce(
      node, "peer-a", peerIdFromString,
      [{ node_id: "tip://node/x", multiaddrs: ["/ip4/1.1.1.1/tcp/4001/p2p/peer-x"] }],
      silentLog(),
    )).resolves.toBeUndefined();
  });

  test("empty knownPeers list is a no-op (no dial)", async () => {
    let dialed = false;
    const node = { dialProtocol: async () => { dialed = true; return null; } };
    await pushAnnounce(node, "peer-a", peerIdFromString, [], silentLog());
    expect(dialed).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe("broadcastAnnounce", () => {
  test("dials every authorized peer except the new one", async () => {
    const dialed = [];
    const node = {
      dialProtocol: async (peerId) => {
        dialed.push(peerId);
        // Return a never-resolving stream that swallows writes.
        return { sink: async () => { }, source: (async function* () { })(), close: () => { } };
      },
    };
    const authorized = new Map([
      ["peer-a", "tip://node/a"],
      ["peer-b", "tip://node/b"],
      ["new-peer", "tip://node/new"],   // the just-authorized peer
    ]);
    broadcastAnnounce(
      node, authorized, "new-peer", peerIdFromString,
      [{ node_id: "tip://node/new", multiaddrs: ["/ip4/1.1.1.1/tcp/4001/p2p/new-peer"] }],
      silentLog(),
    );
    // pushAnnounce inside is fire-and-forget; give the microtask queue a tick.
    await new Promise(r => setTimeout(r, 0));

    expect(dialed.sort()).toEqual(["peer-a", "peer-b"]);  // new-peer excluded
  });

  test("empty authorized set is a no-op", () => {
    let dialed = false;
    const node = { dialProtocol: async () => { dialed = true; return null; } };
    broadcastAnnounce(node, new Map(), "new", peerIdFromString, [{ node_id: "tip://node/x", multiaddrs: ["/x"] }], silentLog());
    expect(dialed).toBe(false);
  });

  test("empty knownPeers list is a no-op", () => {
    let dialed = false;
    const node = { dialProtocol: async () => { dialed = true; return null; } };
    broadcastAnnounce(node, new Map([["peer-a", "tip://node/a"]]), "new", peerIdFromString, [], silentLog());
    expect(dialed).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe("registerAnnounceHandler", () => {
  test("rejects unauthorized senders without dialing", async () => {
    const handlers = {};
    const node = {
      handle: async (proto, h) => { handlers[proto] = h; },
      dial: async () => { throw new Error("should not dial"); },
    };
    await registerAnnounceHandler({
      node,
      isAuthorizedPeer: () => false,
      authorizedPeers: new Map(),
      ownNodeId: "tip://node/self",
      log: silentLog(),
    });
    expect(handlers[PEER_ANNOUNCE_PROTOCOL]).toBeDefined();

    // Simulate an inbound stream from an unauthorized peer.
    const closes = [];
    const stream = {
      source: (async function* () { yield Buffer.from([]); })(),
      close: async () => { closes.push("closed"); },
    };
    const connection = { remotePeer: { toString: () => "stranger" } };
    await handlers[PEER_ANNOUNCE_PROTOCOL]({ stream, connection });
    expect(closes).toContain("closed");
  });

  test("authorized sender — decodes PeerAnnounce and dials each entry", async () => {
    const { encode } = require(path.join(SRC, "network/proto"));
    const handlers = {};
    const dialed = [];
    const node = {
      handle: async (proto, h) => { handlers[proto] = h; },
      dial: async (addr) => { dialed.push(addr?.toString?.() ?? addr); },
      getConnections: () => [],
    };
    await registerAnnounceHandler({
      node,
      isAuthorizedPeer: () => true,
      authorizedPeers: new Map([["peer-a", "tip://node/a"]]),
      ownNodeId: "tip://node/a",
      log: silentLog(),
    });

    // Build an inbound message with one new peer (not yet authorized).
    const buf = encode("PeerAnnounce", {
      knownPeers: [
        { nodeId: "tip://node/x", multiaddrs: ["/ip4/1.1.1.1/tcp/4001/p2p/peer-x"] },
      ],
    });
    const stream = {
      source: (async function* () { yield buf; })(),
      close: async () => { },
    };
    const connection = { remotePeer: { toString: () => "peer-a" } };
    await handlers[PEER_ANNOUNCE_PROTOCOL]({ stream, connection });
    // dialKnownPeers is fire-and-forget; flush microtask queue.
    await new Promise(r => setTimeout(r, 0));

    expect(dialed).toEqual(["/ip4/1.1.1.1/tcp/4001/p2p/peer-x"]);
  });

  test("self-announce is filtered (own node_id is skipped)", async () => {
    const { encode } = require(path.join(SRC, "network/proto"));
    const handlers = {};
    const dialed = [];
    const node = {
      handle: async (proto, h) => { handlers[proto] = h; },
      dial: async (addr) => { dialed.push(addr?.toString?.() ?? addr); },
      getConnections: () => [],
    };
    await registerAnnounceHandler({
      node,
      isAuthorizedPeer: () => true,
      authorizedPeers: new Map([["peer-a", "tip://node/a"]]),
      ownNodeId: "tip://node/self",
      log: silentLog(),
    });

    // Announce contains us — dialKnownPeers should skip.
    const buf = encode("PeerAnnounce", {
      knownPeers: [
        { nodeId: "tip://node/self", multiaddrs: ["/ip4/2.2.2.2/tcp/4001/p2p/self"] },
      ],
    });
    const stream = {
      source: (async function* () { yield buf; })(),
      close: async () => { },
    };
    const connection = { remotePeer: { toString: () => "peer-a" } };
    await handlers[PEER_ANNOUNCE_PROTOCOL]({ stream, connection });
    await new Promise(r => setTimeout(r, 0));

    expect(dialed).toEqual([]);  // self filter caught it
  });

  test("already-authorized entries are skipped (no duplicate dials)", async () => {
    const { encode } = require(path.join(SRC, "network/proto"));
    const handlers = {};
    const dialed = [];
    const node = {
      handle: async (proto, h) => { handlers[proto] = h; },
      dial: async (addr) => { dialed.push(addr?.toString?.() ?? addr); },
      getConnections: () => [],
    };
    await registerAnnounceHandler({
      node,
      isAuthorizedPeer: () => true,
      authorizedPeers: new Map([
        ["peer-a", "tip://node/a"],
        ["peer-x", "tip://node/x"],   // already authorized
      ]),
      ownNodeId: "tip://node/a",
      log: silentLog(),
    });

    const buf = encode("PeerAnnounce", {
      knownPeers: [
        { nodeId: "tip://node/x", multiaddrs: ["/ip4/1.1.1.1/tcp/4001/p2p/peer-x"] },
      ],
    });
    const stream = {
      source: (async function* () { yield buf; })(),
      close: async () => { },
    };
    const connection = { remotePeer: { toString: () => "peer-a" } };
    await handlers[PEER_ANNOUNCE_PROTOCOL]({ stream, connection });
    await new Promise(r => setTimeout(r, 0));

    expect(dialed).toEqual([]);  // already-authorized filter caught it
  });
});
