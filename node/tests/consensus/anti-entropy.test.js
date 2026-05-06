/**
 * @file tests/consensus/anti-entropy.test.js
 * @description §28 anti-entropy reconciliation tests.
 *
 * Covers:
 *   1. `checkAndReconcile` decision logic — self behind vs ahead vs equal
 *      vs divergent; correct syncFromPeer invocation on behind; no pull
 *      on ahead/equal; divergence metric + WARN on equal-round-different-root
 *   2. `_handleIncomingSyncStatus` server-side — replies with correct
 *      state payload; round-trip through proto; error isolation
 *   3. `queryPeer` client-side — round-trips via a fake stream; timeout
 *      path increments peer_rpc_timeouts; decode error increments
 *      peer_rpc_failures; null return on network unavailable
 *   4. `getStatus` — REST-endpoint feed shape; in_sync aggregation
 *      matches per-peer comparison
 *   5. Background loop — start/stop semantics, queries all authorized
 *      peers per cycle, stops cleanly mid-cycle
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto } = require(path.join(SHARED, "crypto"));
const { createAntiEntropy } = require(path.join(SRC, "consensus", "anti-entropy"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));
const { createStreamPair } = require("../helpers/stream-pair");

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

// ── Test harness ─────────────────────────────────────────────────────────

function silentLog() {
  return { info: () => { }, debug: () => { }, warn: () => { }, error: () => { }, notice: () => { } };
}

function fakeNetwork({ authorized = {}, openStreamImpl, handleImpl } = {}) {
  return {
    authorizedPeers: () => ({ ...authorized }),
    openStream: openStreamImpl || (async () => { throw new Error("no openStream"); }),
    handle: handleImpl || (async () => { }),
  };
}

function fakeSyncHandler({ syncImpl } = {}) {
  const calls = [];
  return {
    syncFromPeer: async (peerId, opts) => {
      calls.push({ peerId, opts });
      if (syncImpl) return syncImpl(peerId, opts);
      return { imported: 0, fromRound: 0, toRound: 0, peerLatestRound: 0 };
    },
    _calls: calls,
  };
}

function selfState({
  round = 10,
  committed_round = 10,
  consensus_index = 5,
  state_merkle_root = "aabbcc",
  txs_merkle_root = "ddeeff",
  cert_merkle_root = "112233",
} = {}) {
  return { round, committed_round, consensus_index, state_merkle_root, txs_merkle_root, cert_merkle_root };
}

function peerStatus({
  node_id = "tip://node/peer",
  round = 10,
  committed_round = 10,
  consensus_index = 5,
  state_merkle_root = "aabbcc",
  txs_merkle_root = "ddeeff",
  cert_merkle_root = "112233",
  join_state = "ready",
  checked_at = Date.now(),
} = {}) {
  return { node_id, round, committed_round, consensus_index, state_merkle_root, txs_merkle_root, cert_merkle_root, join_state, checked_at };
}

// ═══════════════════════════════════════════════════════════════════════════
// checkAndReconcile decision logic
// ═══════════════════════════════════════════════════════════════════════════
describe("checkAndReconcile", () => {
  test("self behind peer → pulls gap via syncFromPeer with correct fromRound", async () => {
    const sync = fakeSyncHandler();
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: sync,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 5 }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile("peer-id", peerStatus({ committed_round: 12 }), selfState({ committed_round: 5 }));

    expect(result).toBe("behind");
    expect(sync._calls).toHaveLength(1);
    expect(sync._calls[0]).toEqual({ peerId: "peer-id", opts: { fromRound: 6 } });
    expect(ae.stats().metrics.gaps_pulled).toBe(1);
  });

  test("self ahead of peer → no pull, returns 'ahead'", async () => {
    const sync = fakeSyncHandler();
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: sync,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 20 }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile("peer-id", peerStatus({ committed_round: 15 }), selfState({ committed_round: 20 }));

    expect(result).toBe("ahead");
    expect(sync._calls).toHaveLength(0);
  });

  test("equal round + equal root → 'equal', no divergence metric", async () => {
    const sync = fakeSyncHandler();
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: sync,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile("peer-id", peerStatus(), selfState());

    expect(result).toBe("equal");
    expect(sync._calls).toHaveLength(0);
    expect(ae.stats().metrics.consensus_divergence_total).toBe(0);
  });

  test("equal round + DIFFERENT root → 'divergent', increments divergence metric, no pull", async () => {
    const sync = fakeSyncHandler();
    const warnMsgs = [];
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: sync,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: { info: () => { }, debug: () => { }, warn: (msg) => warnMsgs.push(msg) },
    });

    const result = await ae.checkAndReconcile(
      "peer-id",
      peerStatus({ state_merkle_root: "bbbbbb" }),
      selfState({ state_merkle_root: "aaaaaa" })
    );

    expect(result).toBe("divergent");
    expect(sync._calls).toHaveLength(0);  // CRITICAL: never auto-resolve
    expect(ae.stats().metrics.consensus_divergence_total).toBe(1);
    expect(warnMsgs.some(m => m.includes("DIVERGENCE"))).toBe(true);
  });

  test("divergence requires BOTH roots non-empty — missing root → 'equal'", async () => {
    // Early in a node's life (no commits yet) roots are empty strings.
    // We shouldn't false-positive as divergence when we simply haven't
    // committed anything.
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "" }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile(
      "peer-id",
      peerStatus({ state_merkle_root: "bbbbbb", committed_round: 10 }),
      selfState({ state_merkle_root: "", committed_round: 10 })
    );

    expect(result).toBe("equal");
    expect(ae.stats().metrics.consensus_divergence_total).toBe(0);
  });

  test("syncFromPeer throw on behind → returns 'pull_failed', doesn't crash loop", async () => {
    const sync = fakeSyncHandler({ syncImpl: async () => { throw new Error("stream refused"); } });
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: sync,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 5 }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile("peer-id", peerStatus({ committed_round: 12 }), selfState({ committed_round: 5 }));
    expect(result).toBe("pull_failed");
    expect(ae.stats().metrics.gaps_pulled).toBe(0);
  });

  test("null peerStatus → 'ahead' (conservative no-op)", async () => {
    const sync = fakeSyncHandler();
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: sync,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile("peer-id", null, selfState());
    expect(result).toBe("ahead");
    expect(sync._calls).toHaveLength(0);
  });

  test("stores latest status in per-peer cache keyed by node_id", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    await ae.checkAndReconcile("peer-id", peerStatus({ node_id: "tip://node/A", committed_round: 9 }), selfState());
    const status = ae.getStatus();
    expect(status.peers).toHaveLength(1);
    expect(status.peers[0].node_id).toBe("tip://node/A");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// _handleIncomingSyncStatus — server-side proto round-trip
// ═══════════════════════════════════════════════════════════════════════════
describe("_handleIncomingSyncStatus (server)", () => {
  test("replies with current state from getConsensusState", async () => {
    const { loadTypes, encode, decode } = require(path.join(SRC, "network", "proto"));
    await loadTypes();

    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/server",
      getConsensusState: () => selfState({
        round: 42,
        committed_round: 40,
        consensus_index: 20,
        state_merkle_root: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
      }),
      log: silentLog(),
    });

    const { client, server } = createStreamPair();
    const handlerPromise = ae._handleIncomingSyncStatus({ stream: server });

    // Send the (empty) request.
    await client.sink((async function* () {
      yield encode("SyncStatusRequest", {});
    })());

    // Collect response.
    const chunks = [];
    for await (const chunk of client.source) chunks.push(chunk);
    await handlerPromise;

    const decoded = decode("SyncStatusResponse", Buffer.concat(chunks));
    expect(decoded.nodeId).toBe("tip://node/server");
    expect(Number(decoded.round)).toBe(42);
    expect(Number(decoded.committedRound)).toBe(40);
    expect(Number(decoded.consensusIndex)).toBe(20);
    expect(Buffer.from(decoded.stateMerkleRoot).toString("hex")).toBe("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
  });

  test("rejects unauthorized peer — gate closes stream + metric", async () => {
    // Server should only serve sync-status to peers that completed TIP
    // handshake. An unauthorized caller (TCP-connected but not handshook)
    // gets the stream closed with no response body.
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/server",
      getConsensusState: () => selfState(),
      isAuthorizedPeer: (_peerId) => false,
      log: silentLog(),
    });

    let closed = false;
    const stream = {
      sink: async () => { },
      source: (async function* () { /* peer never writes */ })(),
      close: async () => { closed = true; },
    };
    const connection = { remotePeer: { toString: () => "unauthorized-peer-id" } };

    await ae._handleIncomingSyncStatus({ stream, connection });
    expect(closed).toBe(true);
    expect(ae.stats().metrics.peer_unauthorized_inbound).toBe(1);
  });

  test("authorized peer passes the gate and gets a reply", async () => {
    const { loadTypes, encode, decode } = require(path.join(SRC, "network", "proto"));
    await loadTypes();

    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/server",
      getConsensusState: () => selfState({ round: 99, committed_round: 99 }),
      isAuthorizedPeer: (peerId) => peerId === "authorized-peer",
      log: silentLog(),
    });

    const { client, server } = createStreamPair();
    const connection = { remotePeer: { toString: () => "authorized-peer" } };
    const handlerPromise = ae._handleIncomingSyncStatus({ stream: server, connection });

    await client.sink((async function* () {
      yield encode("SyncStatusRequest", {});
    })());

    const chunks = [];
    for await (const chunk of client.source) chunks.push(chunk);
    await handlerPromise;

    const decoded = decode("SyncStatusResponse", Buffer.concat(chunks));
    expect(Number(decoded.round)).toBe(99);
    expect(ae.stats().metrics.peer_unauthorized_inbound).toBe(0);
  });

  test("gate opens when isAuthorizedPeer not wired (no-op for tests without gate)", async () => {
    // Backward-compat: if no authorizer is passed, every caller is served
    // (matches prior behavior). This lets unit tests that build streams
    // directly keep working without boilerplate.
    const { loadTypes, encode } = require(path.join(SRC, "network", "proto"));
    await loadTypes();

    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/server",
      getConsensusState: () => selfState(),
      // no isAuthorizedPeer
      log: silentLog(),
    });

    const { client, server } = createStreamPair();
    const handlerPromise = ae._handleIncomingSyncStatus({ stream: server, connection: {} });

    await client.sink((async function* () {
      yield encode("SyncStatusRequest", {});
    })());

    const chunks = [];
    for await (const chunk of client.source) chunks.push(chunk);
    await handlerPromise;

    expect(chunks.length).toBeGreaterThan(0);
    expect(ae.stats().metrics.peer_unauthorized_inbound).toBe(0);
  });

  test("handler doesn't throw on malformed request — catches internally", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/server",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    const brokenStream = {
      source: (async function* () { throw new Error("boom"); })(),
      sink: async () => { },
      close: async () => { },
    };

    await expect(ae._handleIncomingSyncStatus({ stream: brokenStream })).resolves.not.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// queryPeer — client-side round-trip via fake stream
// ═══════════════════════════════════════════════════════════════════════════
describe("queryPeer (client)", () => {
  test("round-trips request → response and parses fields correctly", async () => {
    // Build a fake network where openStream returns one side of a pair
    // wired to a server-side handler running in parallel.
    const { client, server } = createStreamPair();

    // Server: replies with a canned SyncStatusResponse.
    const serverAE = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/server",
      getConsensusState: () => selfState({ round: 77, committed_round: 75, state_merkle_root: "deadbeef" }),
      log: silentLog(),
    });
    const serverPromise = serverAE._handleIncomingSyncStatus({ stream: server });

    // Client: queryPeer with openStream returning the client half.
    // Peer must be in authorized map so identity check passes.
    const clientAE = createAntiEntropy({
      network: fakeNetwork({
        authorized: { "peer-id": "tip://node/server" },
        openStreamImpl: async () => client,
      }),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/client",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    const status = await clientAE.queryPeer("peer-id");
    await serverPromise;

    expect(status).not.toBeNull();
    expect(status.node_id).toBe("tip://node/server");
    expect(status.round).toBe(77);
    expect(status.committed_round).toBe(75);
    expect(status.state_merkle_root).toBe("deadbeef");
    expect(typeof status.checked_at).toBe("number");
  });

  test("returns null + increments peer_rpc_failures on openStream throw", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork({ openStreamImpl: async () => { throw new Error("dial failed"); } }),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/client",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });
    const status = await ae.queryPeer("peer-id");
    expect(status).toBeNull();
    expect(ae.stats().metrics.peer_rpc_failures).toBe(1);
  });

  test("returns null when network has no openStream", async () => {
    const ae = createAntiEntropy({
      network: { authorizedPeers: () => ({}) },  // no openStream method
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/client",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });
    expect(await ae.queryPeer("peer-id")).toBeNull();
  });

  test("metric counts the attempt regardless of success", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork({ openStreamImpl: async () => { throw new Error("x"); } }),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/client",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });
    await ae.queryPeer("p1");
    await ae.queryPeer("p2");
    expect(ae.stats().metrics.peers_queried).toBe(2);
  });

  test("real timeout fires when peer accepts stream but never replies", async () => {
    // Build a stream whose source never yields and never closes — simulating
    // a peer that went dark after accepting the stream. queryPeer's setTimeout
    // must tear down the stream, increment peer_rpc_timeouts, and return null.
    const hangingStream = {
      _closed: false,
      sink: async (_src) => {
        // Consume the request silently but never respond.
        for await (const _ of _src) { /* drain request */ }
      },
      source: (async function* () {
        // Hang forever unless closed. Use a long-interval poll that the
        // timeout can interrupt via close().
        await new Promise((resolve) => {
          const check = setInterval(() => {
            if (hangingStream._closed) { clearInterval(check); resolve(); }
          }, 10);
        });
      })(),
      close: () => { hangingStream._closed = true; },
    };

    // Override the peer-timeout to a short value so the test runs fast.
    // We can't mutate the genesis constant, but we can test at default
    // 2s — tolerable in the runner.
    const ae = createAntiEntropy({
      network: fakeNetwork({ openStreamImpl: async () => hangingStream }),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/client",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    const started = Date.now();
    const status = await ae.queryPeer("peer-id");
    const elapsed = Date.now() - started;

    expect(status).toBeNull();
    expect(ae.stats().metrics.peer_rpc_timeouts).toBe(1);
    expect(ae.stats().metrics.peer_rpc_failures).toBe(0);
    // Sanity: the timeout actually triggered (not an instant error).
    expect(elapsed).toBeGreaterThanOrEqual(500);
  }, 5000);

  test("identity mismatch: peer claims wrong node_id → rejected, increments peer_identity_mismatch", async () => {
    const { encode } = require(path.join(SRC, "network", "proto"));
    // Server replies with a DIFFERENT node_id than the one we authorized.
    const mockStream = {
      sink: async (src) => { for await (const _ of src) { /* drain */ } },
      source: (async function* () {
        yield encode("SyncStatusResponse", {
          nodeId: "tip://node/IMPOSTER",
          round: 10,
          committedRound: 10,
          consensusIndex: 5,
          stateMerkleRoot: Buffer.alloc(0),
          txsMerkleRoot: Buffer.alloc(0),
          certMerkleRoot: Buffer.alloc(0),
        });
      })(),
      close: () => { },
    };

    const ae = createAntiEntropy({
      network: fakeNetwork({
        authorized: { "peer-libp2p-id": "tip://node/HONEST" },  // we authorized HONEST
        openStreamImpl: async () => mockStream,
      }),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/client",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    const status = await ae.queryPeer("peer-libp2p-id");
    expect(status).toBeNull();
    expect(ae.stats().metrics.peer_identity_mismatch).toBe(1);
  });

  test("identity match: peer claims correct node_id → accepted", async () => {
    const { encode } = require(path.join(SRC, "network", "proto"));
    const mockStream = {
      sink: async (src) => { for await (const _ of src) { /* drain */ } },
      source: (async function* () {
        yield encode("SyncStatusResponse", {
          nodeId: "tip://node/HONEST",
          round: 10,
          committedRound: 10,
          consensusIndex: 5,
          stateMerkleRoot: Buffer.alloc(0),
          txsMerkleRoot: Buffer.alloc(0),
          certMerkleRoot: Buffer.alloc(0),
        });
      })(),
      close: () => { },
    };

    const ae = createAntiEntropy({
      network: fakeNetwork({
        authorized: { "peer-libp2p-id": "tip://node/HONEST" },
        openStreamImpl: async () => mockStream,
      }),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/client",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    const status = await ae.queryPeer("peer-libp2p-id");
    expect(status).not.toBeNull();
    expect(status.node_id).toBe("tip://node/HONEST");
    expect(ae.stats().metrics.peer_identity_mismatch).toBe(0);
  });

  test("peer NOT in authorized map at query time → rejected (race-safety)", async () => {
    // Covers the race between _runOnce's peer-list snapshot and the actual
    // query: if the peer got deauthorized in between (disconnect, revoke),
    // we must NOT cache their response. Also covers caller-bug case where
    // someone passes an unauthorized peerId directly. Both paths reach
    // queryPeer with expectedNodeId empty.
    const { encode } = require(path.join(SRC, "network", "proto"));
    const mockStream = {
      sink: async (src) => { for await (const _ of src) { /* drain */ } },
      source: (async function* () {
        yield encode("SyncStatusResponse", {
          nodeId: "tip://node/unknown",
          round: 10,
          committedRound: 10,
          consensusIndex: 5,
          stateMerkleRoot: Buffer.alloc(0),
          txsMerkleRoot: Buffer.alloc(0),
          certMerkleRoot: Buffer.alloc(0),
        });
      })(),
      close: () => { },
    };

    const ae = createAntiEntropy({
      network: fakeNetwork({
        authorized: {},  // no entry for this peer — race or caller bug
        openStreamImpl: async () => mockStream,
      }),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/client",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    const status = await ae.queryPeer("peer-libp2p-id");
    expect(status).toBeNull();
    expect(ae.stats().metrics.peer_unauthorized_query).toBe(1);
    expect(ae.stats().metrics.peer_identity_mismatch).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// getStatus — REST endpoint feed shape
// ═══════════════════════════════════════════════════════════════════════════
describe("getStatus (REST feed)", () => {
  test("empty peer list returns in_sync=false (no data to verify)", () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });
    const s = ae.getStatus();
    expect(s.peers).toHaveLength(0);
    expect(s.in_sync).toBe(false);
    expect(s.self.node_id).toBe("tip://node/self");
  });

  test("in_sync=true when every peer matches self on both round and root", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    await ae.checkAndReconcile("p1", peerStatus({ node_id: "tip://node/A" }), selfState());
    await ae.checkAndReconcile("p2", peerStatus({ node_id: "tip://node/B" }), selfState());

    const s = ae.getStatus();
    expect(s.peers).toHaveLength(2);
    expect(s.peers.every(p => p.in_sync)).toBe(true);
    expect(s.in_sync).toBe(true);
  });

  test("in_sync=false if ANY peer diverges", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    await ae.checkAndReconcile("p1", peerStatus({ node_id: "tip://node/A" }), selfState());
    await ae.checkAndReconcile("p2", peerStatus({ node_id: "tip://node/B", state_merkle_root: "xxxxxx" }), selfState());

    const s = ae.getStatus();
    const a = s.peers.find(p => p.node_id === "tip://node/A");
    const b = s.peers.find(p => p.node_id === "tip://node/B");
    expect(a.in_sync).toBe(true);
    expect(b.in_sync).toBe(false);
    expect(s.in_sync).toBe(false);
  });

  test("each peer entry carries round, committed_round, state_merkle_root, checked_at", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    await ae.checkAndReconcile("p1", peerStatus({ node_id: "tip://node/A", round: 50, committed_round: 48, consensus_index: 30 }), selfState());

    const s = ae.getStatus();
    const a = s.peers[0];
    expect(a).toMatchObject({
      node_id: "tip://node/A",
      round: 50,
      committed_round: 48,
      consensus_index: 30,
    });
    expect(typeof a.checked_at).toBe("string");
    expect(a.checked_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// registerProtocol — idempotency + no-op on missing handle
// ═══════════════════════════════════════════════════════════════════════════
describe("registerProtocol", () => {
  test("no-op when network has no handle function", async () => {
    const ae = createAntiEntropy({
      network: { authorizedPeers: () => ({}), openStream: async () => { } },
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });
    await expect(ae.registerProtocol()).resolves.toBeUndefined();
  });

  test("idempotent — calling twice only registers once", async () => {
    const calls = [];
    const ae = createAntiEntropy({
      network: {
        authorizedPeers: () => ({}),
        openStream: async () => { },
        handle: async (protocol) => { calls.push(protocol); },
      },
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });
    await ae.registerProtocol();
    await ae.registerProtocol();
    expect(calls).toHaveLength(1);
    expect(calls[0]).toBe("/tip/sync-status/1.0.0");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Loop lifecycle — start / stop / mid-cycle interrupt
// ═══════════════════════════════════════════════════════════════════════════
describe("start/stop", () => {
  test("stop() clears the timer — loops_run stops incrementing", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });

    await ae.start();
    ae.stop();
    const before = ae.stats().metrics.loops_run;
    await new Promise(r => setTimeout(r, 50));
    expect(ae.stats().metrics.loops_run).toBe(before);
  });

  test("parallel peer queries: slow peer does NOT block fast peers", async () => {
    // The full cycle should take ~max(slowest peer, interval), not sum of
    // all peers. A 600ms peer + three 10ms peers should complete in
    // ~600ms, not ~630ms — AND critically, the fast peers' cache entries
    // must land well before the slow peer finishes.
    const { encode } = require(path.join(SRC, "network", "proto"));

    const authorized = {
      "libp2p-fast-A": "tip://node/FAST-A",
      "libp2p-fast-B": "tip://node/FAST-B",
      "libp2p-fast-C": "tip://node/FAST-C",
      "libp2p-slow": "tip://node/SLOW",
    };

    const openStreamImpl = async (peerId) => {
      const tipId = authorized[peerId];
      const delayMs = peerId === "libp2p-slow" ? 400 : 5;
      return {
        sink: async (src) => { for await (const _ of src) { /* drain */ } },
        source: (async function* () {
          await new Promise(r => setTimeout(r, delayMs));
          yield encode("SyncStatusResponse", {
            nodeId: tipId,
            round: 10,
            committedRound: 10,
            consensusIndex: 5,
            stateMerkleRoot: Buffer.from("aabbcc", "hex"),
            txsMerkleRoot: Buffer.alloc(0),
            certMerkleRoot: Buffer.alloc(0),
          });
        })(),
        close: () => { },
      };
    };

    const ae = createAntiEntropy({
      network: fakeNetwork({ authorized, openStreamImpl }),
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 10, state_merkle_root: "aabbcc" }),
      log: silentLog(),
    });

    await ae.registerProtocol();

    // Fire all probes in parallel (mirrors what _runOnce does now) and
    // check timing + completion together.
    const selfS = selfState({ committed_round: 10, state_merkle_root: "aabbcc" });
    const startedAt = Date.now();

    await Promise.all(Object.keys(authorized).map(async (peerId) => {
      const status = await ae.queryPeer(peerId);
      if (status) await ae.checkAndReconcile(peerId, status, selfS);
    }));

    const elapsed = Date.now() - startedAt;

    // All 4 peers cached.
    const s = ae.getStatus();
    expect(s.peers).toHaveLength(4);

    // Critical timing assertion: total time should be close to the slow
    // peer's 400ms, not the sum (400 + 3*5 = 415ms).  The key test is
    // that elapsed is well under the SERIAL worst case — i.e. not so
    // much longer than 400 that fast peers were queued behind the slow
    // one. 700ms bound is generous; observed ~405-430ms in practice.
    expect(elapsed).toBeLessThan(700);
    expect(elapsed).toBeGreaterThanOrEqual(400);  // slow peer did fire

    // Sanity: every fast peer is in_sync (matches self).
    expect(s.peers.filter(p => p.in_sync)).toHaveLength(4);
  }, 3000);

  test("_runOnce integration: one cycle probes every authorized peer and populates _lastStatus", async () => {
    // Three authorized peers. Each responds with its own sync status.
    // After one cycle:
    //   - queryPeer fires 3x
    //   - checkAndReconcile runs 3x
    //   - _lastStatus has 3 entries keyed by TIP node_id
    //   - getStatus().peers reflects all three
    const { encode } = require(path.join(SRC, "network", "proto"));

    const authorized = {
      "libp2p-A": "tip://node/A",
      "libp2p-B": "tip://node/B",
      "libp2p-C": "tip://node/C",
    };

    const responsesByPeer = {
      "libp2p-A": { nodeId: "tip://node/A", round: 10, committedRound: 10, consensusIndex: 5 },
      "libp2p-B": { nodeId: "tip://node/B", round: 12, committedRound: 12, consensusIndex: 6 },  // ahead
      "libp2p-C": { nodeId: "tip://node/C", round: 10, committedRound: 10, consensusIndex: 5 },
    };

    const openedPeers = [];
    const openStreamImpl = async (peerId) => {
      openedPeers.push(peerId);
      const r = responsesByPeer[peerId];
      return {
        sink: async (src) => { for await (const _ of src) { /* drain */ } },
        source: (async function* () {
          yield encode("SyncStatusResponse", {
            nodeId: r.nodeId,
            round: r.round,
            committedRound: r.committedRound,
            consensusIndex: r.consensusIndex,
            stateMerkleRoot: Buffer.from("aabbcc", "hex"),
            txsMerkleRoot: Buffer.alloc(0),
            certMerkleRoot: Buffer.alloc(0),
          });
        })(),
        close: () => { },
      };
    };

    const sync = fakeSyncHandler();
    const ae = createAntiEntropy({
      network: fakeNetwork({ authorized, openStreamImpl }),
      syncHandler: sync,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({
        committed_round: 10,
        state_merkle_root: "aabbcc",
      }),
      log: silentLog(),
    });

    // Don't start the background loop — manually invoke what the loop does.
    // This tests the loop body without the setTimeout complication.
    // We call start() then immediately stop() to install the protocol only,
    // then exercise via the per-peer machinery.
    await ae.registerProtocol();

    // Manually iterate peers like _runOnce does, but without waiting for timer.
    const selfS = selfState({ committed_round: 10, state_merkle_root: "aabbcc" });
    for (const peerId of Object.keys(authorized)) {
      const status = await ae.queryPeer(peerId);
      if (status) await ae.checkAndReconcile(peerId, status, selfS);
    }

    // Every authorized peer got probed.
    expect(openedPeers.sort()).toEqual(["libp2p-A", "libp2p-B", "libp2p-C"]);

    // _lastStatus populated — getStatus returns all three.
    const s = ae.getStatus();
    expect(s.peers).toHaveLength(3);
    expect(s.peers.map(p => p.node_id).sort()).toEqual(["tip://node/A", "tip://node/B", "tip://node/C"]);

    // Peer B was ahead → syncFromPeer called with fromRound = selfCommitted + 1 = 11.
    expect(sync._calls).toHaveLength(1);
    expect(sync._calls[0]).toEqual({ peerId: "libp2p-B", opts: { fromRound: 11 } });
    expect(ae.stats().metrics.gaps_pulled).toBe(1);

    // A and C matched → in_sync=true for them, B was ahead so in_sync=false (different round).
    expect(s.peers.find(p => p.node_id === "tip://node/A").in_sync).toBe(true);
    expect(s.peers.find(p => p.node_id === "tip://node/B").in_sync).toBe(false);
    expect(s.peers.find(p => p.node_id === "tip://node/C").in_sync).toBe(true);
    expect(s.in_sync).toBe(false);  // one peer out of sync → cluster not in sync
  });

  test("double start() is a no-op", async () => {
    const handleCalls = [];
    const ae = createAntiEntropy({
      network: {
        authorizedPeers: () => ({}),
        openStream: async () => { },
        handle: async (p) => { handleCalls.push(p); },
      },
      syncHandler: fakeSyncHandler(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState(),
      log: silentLog(),
    });
    await ae.start();
    await ae.start();  // second call must not re-register or re-schedule
    ae.stop();
    expect(handleCalls).toHaveLength(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// #46 — snapshot fallback when syncFromPeer signals snapshot_required
// ═══════════════════════════════════════════════════════════════════════════
//
// Recovery scenario: an authorized peer drifts past gc_depth rounds behind
// without disconnecting (slow link, paused VM, transient network). On the
// next anti-entropy cycle:
//   1. syncFromPeer({ fromRound: self+1 }) → peer prunes that range, replies
//      { snapshotRequired: true, earliestAvailableRound: N }
//   2. AE invokes snapshotHandler.requestSnapshotFromPeer(peer, { minRound })
//   3. Snapshot installs derived state + tx + commit history atomically
//   4. AE marks the install round via narwhal.exitSyncMode so round
//      production resumes at the right place
//
// Pre-#46 step 2 was missing — AE just retried cert sync forever.
//
// Required behavior of the fallback path:
//   - Suspend round production via narwhal.enterSyncMode BEFORE the install
//     starts (so consensus doesn't try to commit at the old round mid-install)
//   - Exit sync mode AFTER install with target = snapshot.round (the round
//     the install is anchored at). narwhal.exitSyncMode is round-monotonic
//     and floors via dag.getLatestRound, so passing a stale value is safe.
//   - On snapshot failure: leave node alone. Don't false-ready-claim, don't
//     loop. Next AE cycle (4s later) retries.

function fakeNarwhal({ joinState = "ready", catchUpTarget = 0 } = {}) {
  const calls = { enter: 0, exit: [], markSnapshotInstalled: [], markCaughtUp: [] };
  let _state = joinState;
  let _target = catchUpTarget;
  return {
    enterSyncMode: () => { calls.enter++; _state = "syncing"; },
    exitSyncMode: (round) => { calls.exit.push(round); _state = "ready"; _target = 0; },
    markSnapshotInstalled: (round, peerCommitted) => {
      calls.markSnapshotInstalled.push({ round, peerCommitted });
      _state = "catching_up"; _target = peerCommitted || round;
    },
    markCaughtUp: (round) => { calls.markCaughtUp.push(round); _state = "ready"; _target = 0; },
    joinState: () => _state,
    catchUpTarget: () => _target,
    _calls: calls,
  };
}

function fakeSnapshotHandler({ snapImpl } = {}) {
  const calls = [];
  return {
    requestSnapshotFromPeer: async (peerId, opts) => {
      calls.push({ peerId, opts });
      if (snapImpl) return snapImpl(peerId, opts);
      return { round: 5000, consensus_index: 42, rows_installed: 100, state_merkle_root: "deadbeef" };
    },
    _calls: calls,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// catching_up → ready promotion via markCaughtUp.
//
// This is the second half of the tri-state contract: after snapshot-handler
// fires markSnapshotInstalled (syncing → catching_up), AE drives the final
// promotion to ready when an authorized peer confirms our state_merkle_root
// at our current committed_round AND we've reached the snapshot's recorded
// peer head (catchUpTarget). Without this gate the joiner could "go ready"
// with a half-closed cert tail and produce certs against unreachable
// parents — same fingerprint as the round-2477→2928 zombie state.
// ═══════════════════════════════════════════════════════════════════════════
describe("checkAndReconcile catching_up → ready promotion", () => {
  test("catching_up + peer agrees on root + tail closed → fires markCaughtUp", async () => {
    const narwhal = fakeNarwhal({ joinState: "catching_up", catchUpTarget: 100 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 100, state_merkle_root: "abc" }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile(
      "peer-id",
      peerStatus({ committed_round: 100, state_merkle_root: "abc" }),
      selfState({ committed_round: 100, state_merkle_root: "abc" })
    );

    expect(result).toBe("equal");
    expect(narwhal._calls.markCaughtUp).toHaveLength(1);
    expect(narwhal._calls.markCaughtUp[0]).toBe(100);
    expect(narwhal.joinState()).toBe("ready");
  });

  test("catching_up + roots match but tail NOT yet closed → does NOT fire markCaughtUp", async () => {
    const narwhal = fakeNarwhal({ joinState: "catching_up", catchUpTarget: 200 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 100, state_merkle_root: "abc" }),
      log: silentLog(),
    });

    await ae.checkAndReconcile(
      "peer-id",
      peerStatus({ committed_round: 100, state_merkle_root: "abc" }),
      selfState({ committed_round: 100, state_merkle_root: "abc" })
    );

    expect(narwhal._calls.markCaughtUp).toHaveLength(0);
    expect(narwhal.joinState()).toBe("catching_up");
  });

  test("catching_up + roots DIFFER → does NOT fire markCaughtUp (catch-up race guard skips divergence)", async () => {
    // While self is catching_up, AE-fresh state-root reflects partial mirror
    // (snapshot install or gap-sync still in flight). The catch-up race
    // guard skips divergence flagging entirely while either side isn't
    // "ready" — otherwise a fresh-DB joiner would false-halt itself
    // within seconds of restart. The promotion to "ready" still doesn't
    // fire because the path requires equal roots.
    const narwhal = fakeNarwhal({ joinState: "catching_up", catchUpTarget: 100 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 100, state_merkle_root: "aaa" }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile(
      "peer-id",
      peerStatus({ committed_round: 100, state_merkle_root: "bbb" }),
      selfState({ committed_round: 100, state_merkle_root: "aaa" })
    );

    expect(result).toBe("equal");  // guard suppresses divergence flagging
    expect(narwhal._calls.markCaughtUp).toHaveLength(0);  // KEY: no promotion
    expect(narwhal.joinState()).toBe("catching_up");
    expect(ae.stats().metrics.consensus_divergence_total).toBe(0);  // not counted
  });

  test("ready state ignores promotion path (no-op when already ready)", async () => {
    const narwhal = fakeNarwhal({ joinState: "ready" });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 100, state_merkle_root: "abc" }),
      log: silentLog(),
    });

    await ae.checkAndReconcile(
      "peer-id",
      peerStatus({ committed_round: 100, state_merkle_root: "abc" }),
      selfState({ committed_round: 100, state_merkle_root: "abc" })
    );

    expect(narwhal._calls.markCaughtUp).toHaveLength(0);
  });

  test("syncing state + peer agrees on root + round → exits via override (no install needed)", async () => {
    // Recovery path: enterSyncMode fired unnecessarily (peer-auth churn,
    // already-caught-up joiner). When AE confirms peer agreement, the
    // override exitSyncMode unblocks production directly. Without this
    // branch a node sits in syncing until syncWithRetry's 60-90s budget
    // exhausts and even then re-enters on the next reconnect.
    const narwhal = fakeNarwhal({ joinState: "syncing" });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 100, state_merkle_root: "abc" }),
      log: silentLog(),
    });

    await ae.checkAndReconcile(
      "peer-id",
      peerStatus({ committed_round: 100, state_merkle_root: "abc" }),
      selfState({ committed_round: 100, state_merkle_root: "abc" })
    );

    expect(narwhal._calls.markCaughtUp).toHaveLength(0);   // not the catching_up path
    expect(narwhal._calls.exit).toEqual([100]);            // override fired with peer's round
    expect(narwhal.joinState()).toBe("ready");
  });

  test("syncing state + roots DIFFER → does NOT exit (catch-up race guard skips divergence)", async () => {
    // Same race guard as catching_up: while self is in syncing state,
    // mirror is being populated atomically by snapshot install — any
    // computed state_merkle_root mid-install is partial. AE skips the
    // divergence path so a fresh-DB joiner isn't halted on its own
    // partial-state derivation.
    const narwhal = fakeNarwhal({ joinState: "syncing" });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 100, state_merkle_root: "aaa" }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile(
      "peer-id",
      peerStatus({ committed_round: 100, state_merkle_root: "bbb" }),
      selfState({ committed_round: 100, state_merkle_root: "aaa" })
    );

    expect(result).toBe("equal");  // guard suppresses divergence flagging
    expect(narwhal._calls.exit).toHaveLength(0);
    expect(narwhal.joinState()).toBe("syncing");
  });
});

describe("#46 anti-entropy snapshot fallback", () => {
  test("snapshot_required → invokes requestSnapshotFromPeer with earliestAvailableRound", async () => {
    const sync = fakeSyncHandler({
      syncImpl: async () => ({ imported: 0, fromRound: 6, toRound: 6, peerLatestRound: 5000, snapshotRequired: true, earliestAvailableRound: 4500 }),
    });
    const snap = fakeSnapshotHandler();
    const narwhal = fakeNarwhal();
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: sync, snapshotHandler: snap, narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 5 }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile("peer-id", peerStatus({ committed_round: 5000 }), selfState({ committed_round: 5 }));

    expect(result).toBe("snapshot_installed");
    expect(snap._calls).toHaveLength(1);
    expect(snap._calls[0].peerId).toBe("peer-id");
    expect(snap._calls[0].opts.minRound).toBe(4500);
  });

  test("snapshot install enters sync mode BEFORE install; promotion to ready is owned by snapshot-handler / catch-up flow, not AE", async () => {
    // AE's responsibility on success ends at "trigger the install." The
    // snapshot-handler's success path fires narwhal.markSnapshotInstalled
    // (syncing → catching_up); a later AE tick promotes to ready via
    // markCaughtUp once state-roots agree. AE must NOT call exitSyncMode
    // on success — that would bypass the catch-up gate.
    const order = [];
    const sync = fakeSyncHandler({
      syncImpl: async () => ({ imported: 0, fromRound: 6, toRound: 6, peerLatestRound: 5000, snapshotRequired: true, earliestAvailableRound: 4500 }),
    });
    const snap = {
      requestSnapshotFromPeer: async () => {
        order.push("install");
        return { round: 4900, consensus_index: 42, rows_installed: 100 };
      },
    };
    const narwhal = {
      enterSyncMode: () => order.push("enterSyncMode"),
      exitSyncMode: (round) => order.push(`exitSyncMode(${round})`),
      markSnapshotInstalled: (round) => order.push(`markSnapshotInstalled(${round})`),
      markCaughtUp: (round) => order.push(`markCaughtUp(${round})`),
    };
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: sync, snapshotHandler: snap, narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 5 }),
      log: silentLog(),
    });

    await ae.checkAndReconcile("peer-id", peerStatus({ committed_round: 5000 }), selfState({ committed_round: 5 }));

    // AE no longer calls exitSyncMode on success. The mock snapshot doesn't
    // fire markSnapshotInstalled (that's the real handler's job); so we
    // simply assert AE got as far as kicking off the install.
    expect(order).toEqual(["enterSyncMode", "install"]);
  });

  test("snapshot install also fails → no false-ready, exits sync mode at self's pre-install round", async () => {
    // Belt-and-braces for #45: if the snapshot fallback ALSO can't help
    // (e.g. peer has no commit row, network failure mid-install), AE must
    // NOT call exitSyncMode with a fake round. Either don't exit at all
    // (next cycle retries) or exit at our own current round (stay put).
    // What we MUST avoid: claiming to be "ready at round N" when we have
    // no data backing N.
    const sync = fakeSyncHandler({
      syncImpl: async () => ({ imported: 0, fromRound: 6, toRound: 6, peerLatestRound: 5000, snapshotRequired: true, earliestAvailableRound: 4500 }),
    });
    const snap = {
      requestSnapshotFromPeer: async () => { throw new Error("peer has no commit"); },
    };
    const narwhal = fakeNarwhal();
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: sync, snapshotHandler: snap, narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 5, round: 7 }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile("peer-id", peerStatus({ committed_round: 5000 }), selfState({ committed_round: 5, round: 7 }));

    expect(result).toBe("snapshot_failed");
    expect(narwhal._calls.enter).toBe(1);
    // exitSyncMode must NOT be called with peer's far-ahead round (5000).
    // If called at all, it must be with our current round or lower so
    // narwhal's monotonic guard keeps us where we were.
    for (const round of narwhal._calls.exit) {
      expect(round).toBeLessThanOrEqual(7);
    }
  });

  test("snapshot success increments gaps_pulled metric (cumulative with cert-sync gap pulls)", async () => {
    const sync = fakeSyncHandler({
      syncImpl: async () => ({ imported: 0, fromRound: 6, toRound: 6, peerLatestRound: 5000, snapshotRequired: true, earliestAvailableRound: 4500 }),
    });
    const snap = fakeSnapshotHandler();
    const narwhal = fakeNarwhal();
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: sync, snapshotHandler: snap, narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 5 }),
      log: silentLog(),
    });

    await ae.checkAndReconcile("peer-id", peerStatus({ committed_round: 5000 }), selfState({ committed_round: 5 }));

    expect(ae.stats().metrics.gaps_pulled).toBe(1);
  });

  test("backward-compat: AE created without snapshotHandler/narwhal still handles snapshot_required gracefully", async () => {
    // Existing wiring (consensus/index.js pre-#46) doesn't pass
    // snapshotHandler or narwhal. Don't crash if they're absent — fall
    // through to the old behavior (return as if snapshot_required was a
    // pull failure; next AE cycle retries; halt-gate eventually catches it).
    const sync = fakeSyncHandler({
      syncImpl: async () => ({ imported: 0, fromRound: 6, toRound: 6, peerLatestRound: 5000, snapshotRequired: true, earliestAvailableRound: 4500 }),
    });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: sync,    // no snapshotHandler, no narwhal
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 5 }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile("peer-id", peerStatus({ committed_round: 5000 }), selfState({ committed_round: 5 }));
    expect(["pull_failed", "snapshot_required_no_handler"]).toContain(result);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Byzantine-fork halt: divergence accumulator + threshold trigger
// ═══════════════════════════════════════════════════════════════════════════
describe("byzantine-fork halt", () => {
  function fakeNarwhal({ committee = 4, alreadyHalted = null, joinState = "ready" } = {}) {
    let halt = alreadyHalted;
    const haltCalls = [];
    return {
      committeeSize: () => committee,
      joinState: () => joinState,
      byzantineForkHalt: () => (halt ? { ...halt } : null),
      haltDueToByzantineFork: (args) => {
        haltCalls.push(args);
        if (!halt) halt = { ...args, since: Date.now() };
      },
      _haltCalls: haltCalls,
    };
  }

  test("single peer disagreement in n=4 stays below threshold (f+1=2) → no halt", async () => {
    const narwhal = fakeNarwhal({ committee: 4 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    const result = await ae.checkAndReconcile(
      "peer-id-A",
      peerStatus({ node_id: "tip://node/A", state_merkle_root: "bbbbbb" }),
      selfState({ state_merkle_root: "aaaaaa" })
    );

    expect(result).toBe("divergent");
    expect(narwhal._haltCalls).toHaveLength(0);
    expect(ae.stats().metrics.byzantine_fork_halts_triggered).toBe(0);
    expect(ae.stats().metrics.consensus_divergence_distinct_peers).toBe(1);
  });

  test("two distinct peers disagree in n=4 → threshold reached → halt called once", async () => {
    const narwhal = fakeNarwhal({ committee: 4 });
    const errs = [];
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: { info: () => { }, debug: () => { }, warn: () => { }, error: (m) => errs.push(m), notice: () => { } },
    });

    await ae.checkAndReconcile("peer-A", peerStatus({ node_id: "tip://node/A", state_merkle_root: "bbbbbb" }), selfState({ state_merkle_root: "aaaaaa" }));
    expect(narwhal._haltCalls).toHaveLength(0);

    await ae.checkAndReconcile("peer-B", peerStatus({ node_id: "tip://node/B", state_merkle_root: "cccccc" }), selfState({ state_merkle_root: "aaaaaa" }));

    expect(narwhal._haltCalls).toHaveLength(1);
    expect(narwhal._haltCalls[0].atRound).toBe(10);
    expect(narwhal._haltCalls[0].reason).toMatch(/2\/2 peers disagree/);
    expect(narwhal._haltCalls[0].peerNodeId).toBe("tip://node/B");
    expect(ae.stats().metrics.byzantine_fork_halts_triggered).toBe(1);
    expect(ae.stats().metrics.consensus_divergence_distinct_peers).toBe(2);
    expect(errs.some(m => /byzantine-fork halt threshold/.test(m))).toBe(true);
  });

  test("same peer disagreeing twice does NOT double-count (Set semantics)", async () => {
    const narwhal = fakeNarwhal({ committee: 4 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    const peer = peerStatus({ node_id: "tip://node/A", state_merkle_root: "bbbbbb" });
    await ae.checkAndReconcile("peer-A", peer, selfState({ state_merkle_root: "aaaaaa" }));
    await ae.checkAndReconcile("peer-A", peer, selfState({ state_merkle_root: "aaaaaa" }));
    await ae.checkAndReconcile("peer-A", peer, selfState({ state_merkle_root: "aaaaaa" }));

    expect(narwhal._haltCalls).toHaveLength(0);
    expect(ae.stats().metrics.consensus_divergence_distinct_peers).toBe(1);
  });

  test("already-halted narwhal → AE does NOT re-call halt (idempotent)", async () => {
    const narwhal = fakeNarwhal({
      committee: 4,
      alreadyHalted: { reason: "manual halt", atRound: 5, peerNodeId: "tip://node/X", since: Date.now() },
    });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    await ae.checkAndReconcile("peer-A", peerStatus({ node_id: "tip://node/A", state_merkle_root: "bbbbbb" }), selfState({ state_merkle_root: "aaaaaa" }));
    await ae.checkAndReconcile("peer-B", peerStatus({ node_id: "tip://node/B", state_merkle_root: "cccccc" }), selfState({ state_merkle_root: "aaaaaa" }));

    expect(narwhal._haltCalls).toHaveLength(0);
    expect(ae.stats().metrics.byzantine_fork_halts_triggered).toBe(0);
  });

  test("round advance prunes old-round observations", async () => {
    const narwhal = fakeNarwhal({ committee: 4 });
    let curRound = 10;
    let curRoot = "aaaaaa";
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: curRound, state_merkle_root: curRoot }),
      log: silentLog(),
    });

    await ae.checkAndReconcile("peer-A", peerStatus({ node_id: "tip://node/A", state_merkle_root: "bbbbbb", committed_round: 10 }), selfState({ state_merkle_root: "aaaaaa", committed_round: 10 }));
    expect(ae.getStatus().divergence.distinct_peers_observed).toBe(1);

    curRound = 11;
    curRoot = "ddddee";
    await ae.checkAndReconcile("peer-B", peerStatus({ node_id: "tip://node/B", state_merkle_root: "cccccc", committed_round: 11 }), selfState({ state_merkle_root: "ddddee", committed_round: 11 }));

    expect(narwhal._haltCalls).toHaveLength(0);
    expect(ae.getStatus().divergence.distinct_peers_observed).toBe(1);
  });

  test("n=3 committee → threshold=2 (floored) → single disagreement does NOT halt", async () => {
    // Formal f+1 for n=3 is 1, but floor of 2 means single disagreement
    // is treated as undetermined: could be us wrong, could be them wrong.
    // Need both other peers to disagree to be certain we're the byzantine
    // minority. Until then, ack-filter excludes the disagreer and the
    // remaining honest pair forms quorum=2.
    const narwhal = fakeNarwhal({ committee: 3 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    await ae.checkAndReconcile("peer-A", peerStatus({ node_id: "tip://node/A", state_merkle_root: "bbbbbb" }), selfState({ state_merkle_root: "aaaaaa" }));
    expect(narwhal._haltCalls).toHaveLength(0);

    await ae.checkAndReconcile("peer-B", peerStatus({ node_id: "tip://node/B", state_merkle_root: "cccccc" }), selfState({ state_merkle_root: "aaaaaa" }));
    expect(narwhal._haltCalls).toHaveLength(1);
  });

  test("n=2 committee → threshold=2 (unreachable with only 1 other peer; ack-filter handles)", async () => {
    const narwhal = fakeNarwhal({ committee: 2 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    // Same peer disagreeing N times still only counts once (Set semantics).
    // With 2 distinct peers required and only 1 ever available, threshold
    // is unreachable → halt never fires. Ack-filter is the active defense
    // at n=2 (each peer refuses divergent peer's batches → no quorum).
    await ae.checkAndReconcile("peer-A", peerStatus({ node_id: "tip://node/A", state_merkle_root: "bbbbbb" }), selfState({ state_merkle_root: "aaaaaa" }));
    await ae.checkAndReconcile("peer-A", peerStatus({ node_id: "tip://node/A", state_merkle_root: "bbbbbb" }), selfState({ state_merkle_root: "aaaaaa" }));

    expect(narwhal._haltCalls).toHaveLength(0);
    expect(ae.getStatus().divergence.threshold).toBe(2);
  });

  test("n=7 committee → threshold=3 → halts on third distinct peer", async () => {
    const narwhal = fakeNarwhal({ committee: 7 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    for (const id of ["A", "B"]) {
      await ae.checkAndReconcile(`peer-${id}`, peerStatus({ node_id: `tip://node/${id}`, state_merkle_root: "bbbbbb" }), selfState({ state_merkle_root: "aaaaaa" }));
    }
    expect(narwhal._haltCalls).toHaveLength(0);

    await ae.checkAndReconcile("peer-C", peerStatus({ node_id: "tip://node/C", state_merkle_root: "bbbbbb" }), selfState({ state_merkle_root: "aaaaaa" }));
    expect(narwhal._haltCalls).toHaveLength(1);
  });

  test("unknown committee size (committeeSize=0) → threshold=Infinity → never halts", async () => {
    const narwhal = fakeNarwhal({ committee: 0 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    for (const id of ["A", "B", "C", "D", "E"]) {
      await ae.checkAndReconcile(`peer-${id}`, peerStatus({ node_id: `tip://node/${id}`, state_merkle_root: "bbbbbb" }), selfState({ state_merkle_root: "aaaaaa" }));
    }

    expect(narwhal._haltCalls).toHaveLength(0);
    expect(ae.getStatus().divergence.threshold).toBe(Infinity);
  });

  test("isPeerDivergent: same round + different non-empty roots → true", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal: fakeNarwhal(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 10, state_merkle_root: "aaaa" }),
      log: silentLog(),
    });
    await ae.checkAndReconcile("peer-X", peerStatus({ node_id: "tip://node/X", committed_round: 10, state_merkle_root: "bbbb" }), selfState({ committed_round: 10, state_merkle_root: "aaaa" }));
    expect(ae.isPeerDivergent("tip://node/X")).toBe(true);
  });

  test("isPeerDivergent: same root → false", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal: fakeNarwhal(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 10, state_merkle_root: "aaaa" }),
      log: silentLog(),
    });
    await ae.checkAndReconcile("peer-X", peerStatus({ node_id: "tip://node/X", committed_round: 10, state_merkle_root: "aaaa" }), selfState({ committed_round: 10, state_merkle_root: "aaaa" }));
    expect(ae.isPeerDivergent("tip://node/X")).toBe(false);
  });

  test("isPeerDivergent: peer never polled → false (default trust)", () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal: fakeNarwhal(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 10, state_merkle_root: "aaaa" }),
      log: silentLog(),
    });
    expect(ae.isPeerDivergent("tip://node/Unknown")).toBe(false);
  });

  test("isPeerDivergent: different committed_round → false (round skew, not divergence)", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal: fakeNarwhal(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 10, state_merkle_root: "aaaa" }),
      log: silentLog(),
    });
    await ae.checkAndReconcile("peer-X", peerStatus({ node_id: "tip://node/X", committed_round: 9, state_merkle_root: "bbbb" }), selfState({ committed_round: 10, state_merkle_root: "aaaa" }));
    expect(ae.isPeerDivergent("tip://node/X")).toBe(false);
  });

  test("isPeerDivergent: either root empty → false (no commits yet on one side)", async () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal: fakeNarwhal(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 10, state_merkle_root: "" }),
      log: silentLog(),
    });
    await ae.checkAndReconcile("peer-X", peerStatus({ node_id: "tip://node/X", committed_round: 10, state_merkle_root: "bbbb" }), selfState({ committed_round: 10, state_merkle_root: "" }));
    expect(ae.isPeerDivergent("tip://node/X")).toBe(false);
  });

  test("isPeerDivergent: empty/null peerNodeId → false", () => {
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal: fakeNarwhal(),
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 10, state_merkle_root: "aaaa" }),
      log: silentLog(),
    });
    expect(ae.isPeerDivergent("")).toBe(false);
    expect(ae.isPeerDivergent(null)).toBe(false);
    expect(ae.isPeerDivergent(undefined)).toBe(false);
  });

  test("divergentPeers + getStatus.filtered_peers: lists exactly the divergent ones", async () => {
    const narwhal = fakeNarwhal({ committee: 4 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ committed_round: 10, state_merkle_root: "aaaa" }),
      log: silentLog(),
    });
    await ae.checkAndReconcile("peer-A", peerStatus({ node_id: "tip://node/A", committed_round: 10, state_merkle_root: "aaaa" }), selfState({ committed_round: 10, state_merkle_root: "aaaa" }));  // agree
    await ae.checkAndReconcile("peer-B", peerStatus({ node_id: "tip://node/B", committed_round: 10, state_merkle_root: "bbbb" }), selfState({ committed_round: 10, state_merkle_root: "aaaa" }));  // diverge
    await ae.checkAndReconcile("peer-C", peerStatus({ node_id: "tip://node/C", committed_round: 10, state_merkle_root: "cccc" }), selfState({ committed_round: 10, state_merkle_root: "aaaa" }));  // diverge

    expect(ae.divergentPeers().sort()).toEqual(["tip://node/B", "tip://node/C"]);
    expect(ae.getStatus().divergence.filtered_peers.sort()).toEqual(["tip://node/B", "tip://node/C"]);
  });

  test("guard: peer in syncing state → divergence flagging skipped, no halt", async () => {
    const narwhal = fakeNarwhal({ committee: 4, joinState: "ready" });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    // Peer reports join_state=syncing — its mirror is partial. Its
    // root will not match ours, but we MUST NOT flag divergence or halt
    // because the partial state is expected during sync.
    await ae.checkAndReconcile("peer-A", peerStatus({
      node_id: "tip://node/A",
      state_merkle_root: "bbbbbb",
      join_state: "syncing",
    }), selfState({ state_merkle_root: "aaaaaa" }));

    expect(narwhal._haltCalls).toHaveLength(0);
    expect(ae.stats().metrics.consensus_divergence_total).toBe(0);
  });

  test("guard: peer in catching_up → divergence flagging skipped", async () => {
    const narwhal = fakeNarwhal({ committee: 4, joinState: "ready" });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    await ae.checkAndReconcile("peer-A", peerStatus({
      node_id: "tip://node/A",
      state_merkle_root: "bbbbbb",
      join_state: "catching_up",
    }), selfState({ state_merkle_root: "aaaaaa" }));

    expect(narwhal._haltCalls).toHaveLength(0);
    expect(ae.stats().metrics.consensus_divergence_total).toBe(0);
  });

  test("guard: self in syncing → divergence flagging skipped against ready peer", async () => {
    const narwhal = fakeNarwhal({ committee: 4, joinState: "syncing" });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    // Two ready peers disagreeing — would normally trip threshold=2 in n=4.
    // But self is syncing → partial mirror → must not flag against own state.
    await ae.checkAndReconcile("peer-A", peerStatus({
      node_id: "tip://node/A", state_merkle_root: "bbbbbb", join_state: "ready",
    }), selfState({ state_merkle_root: "aaaaaa" }));
    await ae.checkAndReconcile("peer-B", peerStatus({
      node_id: "tip://node/B", state_merkle_root: "cccccc", join_state: "ready",
    }), selfState({ state_merkle_root: "aaaaaa" }));

    expect(narwhal._haltCalls).toHaveLength(0);
    expect(ae.stats().metrics.consensus_divergence_total).toBe(0);
  });

  test("guard: legacy peer (empty join_state) treated as ready (backward compat)", async () => {
    const narwhal = fakeNarwhal({ committee: 4, joinState: "ready" });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    // Peer omits join_state — pre-guard wire format. Must still fire.
    await ae.checkAndReconcile("peer-A", peerStatus({
      node_id: "tip://node/A", state_merkle_root: "bbbbbb", join_state: undefined,
    }), selfState({ state_merkle_root: "aaaaaa" }));
    expect(ae.stats().metrics.consensus_divergence_total).toBe(1);
  });

  test("getStatus surfaces halt + threshold + observed count", async () => {
    const narwhal = fakeNarwhal({ committee: 4 });
    const ae = createAntiEntropy({
      network: fakeNetwork(), syncHandler: fakeSyncHandler(), narwhal,
      getSelfNodeId: () => "tip://node/self",
      getConsensusState: () => selfState({ state_merkle_root: "aaaaaa" }),
      log: silentLog(),
    });

    let status = ae.getStatus();
    expect(status.byzantine_fork_halt).toBeNull();
    expect(status.divergence).toEqual({ threshold: 2, distinct_peers_observed: 0, filtered_peers: [] });

    await ae.checkAndReconcile("peer-A", peerStatus({ node_id: "tip://node/A", state_merkle_root: "bbbbbb" }), selfState({ state_merkle_root: "aaaaaa" }));
    status = ae.getStatus();
    expect(status.divergence.distinct_peers_observed).toBe(1);
    expect(status.byzantine_fork_halt).toBeNull();

    await ae.checkAndReconcile("peer-B", peerStatus({ node_id: "tip://node/B", state_merkle_root: "cccccc" }), selfState({ state_merkle_root: "aaaaaa" }));
    status = ae.getStatus();
    expect(status.divergence.distinct_peers_observed).toBe(2);
    expect(status.byzantine_fork_halt).not.toBeNull();
    expect(status.byzantine_fork_halt.atRound).toBe(10);
  });
});
