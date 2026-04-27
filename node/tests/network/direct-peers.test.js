/**
 * @file tests/network/direct-peers.test.js
 * @description DirectPeers mesh-management lifecycle tests.
 *
 * Covers the helper that mutates libp2p-gossipsub's `direct` set on
 * TIP-handshake authorization and peer disconnect (issues.md #23 fix).
 * The manager is a thin wrapper over a Set<string>, but the guarantees it
 * enforces — idempotent add/remove, no-op under missing pubsub, no-op on
 * missing peerId — are the invariants the rest of consensus relies on.
 *
 * No real libp2p: we pass a fake pubsub with `{ direct: new Set() }`
 * because that's exactly the contract we depend on from gossipsub v14.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const { createDirectPeersManager, makeAuthorizationWrapper } = require(path.join(SRC, "network", "direct-peers"));

function fakePubsub() {
  return { direct: new Set() };
}

function silentLog() {
  return { info: () => { }, debug: () => { }, warn: () => { } };
}

const PEER_A = "12D3KooWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PEER_B = "12D3KooWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

describe("createDirectPeersManager", () => {
  test("add inserts peerId into pubsub.direct and returns true", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());
    expect(mgr.add(PEER_A)).toBe(true);
    expect(pubsub.direct.has(PEER_A)).toBe(true);
    expect(mgr.has(PEER_A)).toBe(true);
    expect(mgr.size()).toBe(1);
  });

  test("add is idempotent — returns false on second call, set unchanged", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());
    mgr.add(PEER_A);
    expect(mgr.add(PEER_A)).toBe(false);
    expect(pubsub.direct.size).toBe(1);
  });

  test("remove deletes peerId and returns true", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());
    mgr.add(PEER_A);
    expect(mgr.remove(PEER_A)).toBe(true);
    expect(pubsub.direct.has(PEER_A)).toBe(false);
    expect(mgr.size()).toBe(0);
  });

  test("remove is idempotent — returns false when peer not present", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());
    expect(mgr.remove(PEER_A)).toBe(false);
    mgr.add(PEER_A);
    mgr.remove(PEER_A);
    expect(mgr.remove(PEER_A)).toBe(false);
  });

  test("multiple peers tracked independently", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());
    mgr.add(PEER_A);
    mgr.add(PEER_B);
    expect(mgr.size()).toBe(2);
    expect(mgr.list().sort()).toEqual([PEER_A, PEER_B].sort());
    mgr.remove(PEER_A);
    expect(mgr.list()).toEqual([PEER_B]);
  });

  test("no-op when pubsub is null/undefined", () => {
    const mgr = createDirectPeersManager(null, silentLog());
    expect(mgr.add(PEER_A)).toBe(false);
    expect(mgr.remove(PEER_A)).toBe(false);
    expect(mgr.has(PEER_A)).toBe(false);
    expect(mgr.size()).toBe(0);
    expect(mgr.list()).toEqual([]);
  });

  test("no-op when pubsub.direct is missing (non-gossipsub pubsub)", () => {
    const mgr = createDirectPeersManager({}, silentLog());
    expect(mgr.add(PEER_A)).toBe(false);
    expect(mgr.size()).toBe(0);
  });

  test("empty/falsy peerId is rejected", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());
    expect(mgr.add("")).toBe(false);
    expect(mgr.add(null)).toBe(false);
    expect(mgr.add(undefined)).toBe(false);
    expect(mgr.remove("")).toBe(false);
    expect(mgr.remove(null)).toBe(false);
    expect(pubsub.direct.size).toBe(0);
  });

  test("thrown error in Set.add is caught and returns false", () => {
    const throwingSet = {
      has: () => false,
      add: () => { throw new Error("boom"); },
      delete: () => true,
      get size() { return 0; },
      [Symbol.iterator]: function* () { },
    };
    const mgr = createDirectPeersManager({ direct: throwingSet }, silentLog());
    expect(mgr.add(PEER_A)).toBe(false);
  });

  test("thrown error in Set.delete is caught and returns false", () => {
    const throwingSet = {
      has: () => true,
      add: () => { },
      delete: () => { throw new Error("boom"); },
      get size() { return 1; },
      [Symbol.iterator]: function* () { yield PEER_A; },
    };
    const mgr = createDirectPeersManager({ direct: throwingSet }, silentLog());
    expect(mgr.remove(PEER_A)).toBe(false);
  });

  test("logger is optional — manager works with no log arg", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub);
    expect(() => mgr.add(PEER_A)).not.toThrow();
    expect(pubsub.direct.has(PEER_A)).toBe(true);
  });

  test("list returns snapshot — mutation doesn't affect manager state", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());
    mgr.add(PEER_A);
    const snapshot = mgr.list();
    snapshot.push("fake");
    expect(mgr.size()).toBe(1);
    expect(mgr.list()).toEqual([PEER_A]);
  });

  test("lifecycle: add → remove → add again re-inserts", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());
    mgr.add(PEER_A);
    mgr.remove(PEER_A);
    expect(mgr.has(PEER_A)).toBe(false);
    expect(mgr.add(PEER_A)).toBe(true);
    expect(mgr.has(PEER_A)).toBe(true);
  });
});

describe("makeAuthorizationWrapper", () => {
  // These tests exercise the EXACT function used by network/node.js, not
  // a reimplementation. Any refactor that breaks the wiring contract
  // (ordering, late-registration, optional callback) fails here.

  test("adds peer to direct set AND invokes user callback (happy path)", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());

    let captured = null;
    let userCallback = (peerId, tipNodeId) => {
      captured = { peerId, tipNodeId };
    };

    const wrapper = makeAuthorizationWrapper(mgr, () => userCallback);
    wrapper(PEER_A, "tip://node/alice");

    expect(pubsub.direct.has(PEER_A)).toBe(true);
    expect(captured).toEqual({ peerId: PEER_A, tipNodeId: "tip://node/alice" });
  });

  test("ordering: add runs BEFORE user callback", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());

    // When the user callback runs, the peer must already be in the direct
    // set — consensus handlers in the callback may rely on that invariant
    // (e.g. "peer is in mesh, safe to start sending to it").
    let directSetAtCallbackTime = null;
    const userCallback = (peerId) => {
      directSetAtCallbackTime = pubsub.direct.has(peerId);
    };

    const wrapper = makeAuthorizationWrapper(mgr, () => userCallback);
    wrapper(PEER_A, "tip://node/x");

    expect(directSetAtCallbackTime).toBe(true);
  });

  test("works with no user callback registered yet (null)", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());

    const wrapper = makeAuthorizationWrapper(mgr, () => null);
    expect(() => wrapper(PEER_A, "tip://node/x")).not.toThrow();
    expect(pubsub.direct.has(PEER_A)).toBe(true);
  });

  test("honors LATE-REGISTERED user callback (closure read at call time)", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());

    // node.js constructs the wrapper at startup BEFORE consensus is ready
    // to register its callback. The wrapper reads _onPeerAuthorized via a
    // getter closure, so late registration must be honored. Without this,
    // consensus's peer-sync callback would silently never fire.
    let userCallback = null;
    const wrapper = makeAuthorizationWrapper(mgr, () => userCallback);

    // First handshake — callback not yet registered.
    wrapper(PEER_A, "tip://node/alice");
    expect(pubsub.direct.has(PEER_A)).toBe(true);

    // Consensus registers its callback later.
    let seen = [];
    userCallback = (peerId, tipNodeId) => { seen.push({ peerId, tipNodeId }); };

    // Second handshake — callback must fire.
    wrapper(PEER_B, "tip://node/bob");
    expect(pubsub.direct.has(PEER_B)).toBe(true);
    expect(seen).toEqual([{ peerId: PEER_B, tipNodeId: "tip://node/bob" }]);
  });

  test("non-function user callback is ignored safely", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());

    // Guards against a stale non-function value being returned by the
    // getter (e.g. someone sets it to a string by mistake).
    const wrapper = makeAuthorizationWrapper(mgr, () => "not-a-function");
    expect(() => wrapper(PEER_A, "tip://node/x")).not.toThrow();
    expect(pubsub.direct.has(PEER_A)).toBe(true);
  });

  test("user-callback throw does not undo the direct-set add", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());

    const wrapper = makeAuthorizationWrapper(mgr, () => () => {
      throw new Error("consensus callback failed");
    });

    expect(() => wrapper(PEER_A, "tip://node/x")).toThrow("consensus callback failed");
    // Critical: the mesh membership is independent of the callback —
    // even if peer-sync fails to start, the peer is still in the mesh.
    expect(pubsub.direct.has(PEER_A)).toBe(true);
  });

  test("falsy getUserCallback arg defaults to no-op", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());

    // Passing null/undefined as the getter — wrapper should still add.
    const wrapper = makeAuthorizationWrapper(mgr, null);
    expect(() => wrapper(PEER_A, "tip://node/x")).not.toThrow();
    expect(pubsub.direct.has(PEER_A)).toBe(true);
  });

  test("repeated wrapper calls are idempotent at the direct-set level", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());

    let callCount = 0;
    const userCallback = () => { callCount++; };
    const wrapper = makeAuthorizationWrapper(mgr, () => userCallback);

    wrapper(PEER_A, "tip://node/x");
    wrapper(PEER_A, "tip://node/x");  // e.g. peer re-handshakes after reconnect

    expect(pubsub.direct.size).toBe(1);
    expect(callCount).toBe(2);  // user callback fires on every handshake
  });

  test("disconnect-then-reauthorize flow: wrapper re-adds after remove", () => {
    const pubsub = fakePubsub();
    const mgr = createDirectPeersManager(pubsub, silentLog());
    const wrapper = makeAuthorizationWrapper(mgr, () => null);

    wrapper(PEER_A, "tip://node/alice");
    expect(pubsub.direct.has(PEER_A)).toBe(true);

    // Simulate peer:disconnect.
    mgr.remove(PEER_A);
    expect(pubsub.direct.has(PEER_A)).toBe(false);

    // Peer reconnects → new handshake → wrapper runs again.
    wrapper(PEER_A, "tip://node/alice");
    expect(pubsub.direct.has(PEER_A)).toBe(true);
  });
});
