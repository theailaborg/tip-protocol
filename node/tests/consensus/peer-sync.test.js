/**
 * @file tests/consensus/peer-sync.test.js
 * @description §14 Part 3 — join-flow integration tests for peer-sync.js.
 *
 * Focus: the snapshot-first, cert-replay-fallback ordering that
 * `onPeerAuthorized` implements on peer authorization. We stand up a
 * source (with a signed committed snapshot) and a destination (empty
 * DAG), wire them through the in-memory stream pair, and assert:
 *
 *   - Happy path: snapshot installs, bullshark marked up to snap.round,
 *     destination's state_merkle_root equals source's.
 *   - Peer has no commit: tryFastSyncSnapshot returns 0 without throwing;
 *     orchestrator falls through to cert replay.
 *   - No snapshot handler wired: returns 0 immediately (backwards-compat).
 *
 * Does NOT exercise the cert-replay phase here — that path is already
 * covered by the existing sync-handler + tip-protocol.test.js. We're
 * only testing the §14 addition and its interaction with the existing
 * flow, not re-covering cert sync.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createSnapshotHandler } = require(path.join(SRC, "sync", "snapshot-handler"));
const { tryFastSyncSnapshot, onPeerAuthorized } = require(path.join(SRC, "consensus", "peer-sync"));
const { computeStateMerkleRoot } = require(path.join(SRC, "consensus", "state-root"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));

const { createStreamPair } = require("../helpers/stream-pair");
const { buildCommittedDag } = require("../helpers/commit-builder");

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

/**
 * Kick off a source-side `_handleIncomingSnapshot` in the background
 * (on the server half of the stream pair) so the client's call to
 * `requestSnapshotFromPeer` can complete. Returns the promise so the
 * caller can await it for test determinism.
 */
function runServer(sourceHandler, server) {
  return sourceHandler._handleIncomingSnapshot(server, "test-client").catch(() => {
    // Server-side errors (e.g. stream close after a client reject) are
    // surfaced on the client side — swallow here so Jest's unhandled-
    // rejection watcher doesn't flag them.
  });
}

function makeSnapshotHandlerPair({ sourceDag, destDag }) {
  const { client, server } = createStreamPair();
  const sourceHandler = createSnapshotHandler({
    dag: sourceDag,
    network: { node: {}, handle: async () => { } },
    isAuthorizedPeer: () => true,
  });
  const destHandler = createSnapshotHandler({
    dag: destDag,
    network: { node: {}, openStream: async () => client },
    isAuthorizedPeer: () => true,
  });
  return { sourceHandler, destHandler, server };
}

describe("§14 Part 3 — tryFastSyncSnapshot", () => {
  test("returns snap round and calls bullshark.markOrderedUpTo on success", async () => {
    const fx = buildCommittedDag({ committeeSize: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { sourceHandler, destHandler, server } = makeSnapshotHandlerPair({
      sourceDag: fx.sourceDag, destDag,
    });

    const marked = [];
    const bullshark = { markOrderedUpTo: (r) => marked.push(r) };

    const [, snapRound] = await Promise.all([
      runServer(sourceHandler, server),
      tryFastSyncSnapshot("peer-id-12345", "TIP_NODE_A",
        { snapshotHandler: destHandler, bullshark }),
    ]);

    expect(snapRound).toBe(2);
    expect(marked).toEqual([2]);
    // Destination's derived state matches source — end-to-end install worked.
    expect(computeStateMerkleRoot(destDag)).toBe(fx.stateRoot);
  });

  test("returns 0 without throwing when peer has no qualifying commit", async () => {
    const emptySource = initDAG({ dbPath: ":memory:" });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { sourceHandler, destHandler, server } = makeSnapshotHandlerPair({
      sourceDag: emptySource, destDag,
    });

    const marked = [];
    const bullshark = { markOrderedUpTo: (r) => marked.push(r) };

    const [, snapRound] = await Promise.all([
      runServer(sourceHandler, server),
      tryFastSyncSnapshot("peer-id-12345", "TIP_NODE_A",
        { snapshotHandler: destHandler, bullshark }),
    ]);

    expect(snapRound).toBe(0);
    expect(marked).toEqual([]);    // never advanced bullshark — nothing to mark
  });

  test("returns 0 immediately when no snapshotHandler is provided (backwards-compat)", async () => {
    const bullshark = { markOrderedUpTo: jest.fn() };
    const snapRound = await tryFastSyncSnapshot("peer", "A", { snapshotHandler: null, bullshark });
    expect(snapRound).toBe(0);
    expect(bullshark.markOrderedUpTo).not.toHaveBeenCalled();
  });
});

describe("§14 Part 3 — onPeerAuthorized join-flow orchestration", () => {
  /**
   * Build a minimal stub sync-handler that records what cert-sync range
   * would be pulled. We DON'T stand up the cert-sync protocol here —
   * that path is already covered elsewhere. We only need to verify the
   * orchestrator passes the correct `fromRound` after a snapshot install.
   */
  function stubSyncHandler() {
    const calls = [];
    return {
      calls,
      syncFromPeer: async (peerId, opts) => {
        calls.push({ peerId, opts });
        // Return an empty cert catch-up — joiner lands exactly at snap.round
        // which is the common case on a quiet network.
        return { imported: 0, fromRound: opts?.fromRound || 1, toRound: opts?.fromRound || 1, peerLatestRound: opts?.fromRound || 0 };
      },
    };
  }

  function stubNarwhal() {
    const events = [];
    return {
      events,
      enterSyncMode: () => events.push("enter"),
      exitSyncMode: (r) => events.push(["exit", r]),
    };
  }

  test("snapshot succeeds → cert-sync asked for snapRound+1 onwards, exitSyncMode at snap round", async () => {
    const fx = buildCommittedDag({ committeeSize: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { sourceHandler, destHandler, server } = makeSnapshotHandlerPair({
      sourceDag: fx.sourceDag, destDag,
    });

    const syncHandler = stubSyncHandler();
    const narwhal = stubNarwhal();
    const markedRounds = [];
    const bullshark = { markOrderedUpTo: (r) => markedRounds.push(r) };
    const commitHandler = { commitOrderedTxs: () => ({ committed: 0, dropped: 0 }) };

    await Promise.all([
      runServer(sourceHandler, server),
      onPeerAuthorized("peer-123", "TIP_NODE_A", {
        syncHandler,
        snapshotHandler: destHandler,
        commitHandler, dag: destDag, narwhal, bullshark,
        nodeId: "OUR_NODE",
      }),
    ]);

    // Snapshot installed → bullshark advanced.
    expect(markedRounds).toContain(2);
    // Cert sync called with fromRound = snap.round + 1 = 3.
    expect(syncHandler.calls.length).toBe(1);
    expect(syncHandler.calls[0].opts.fromRound).toBe(3);
    // Narwhal entered then exited sync mode; exit round >= snap.round.
    expect(narwhal.events[0]).toBe("enter");
    const exitEvent = narwhal.events.find(e => Array.isArray(e) && e[0] === "exit");
    expect(exitEvent).toBeTruthy();
    expect(exitEvent[1]).toBeGreaterThanOrEqual(2);
    // Destination's state_merkle_root matches source's.
    expect(computeStateMerkleRoot(destDag)).toBe(fx.stateRoot);
  });

  test("no snapshot available → cert-sync starts from default (fromRound undefined), flow still completes", async () => {
    const emptySource = initDAG({ dbPath: ":memory:" });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { sourceHandler, destHandler, server } = makeSnapshotHandlerPair({
      sourceDag: emptySource, destDag,
    });

    const syncHandler = stubSyncHandler();
    const narwhal = stubNarwhal();
    const bullshark = { markOrderedUpTo: jest.fn() };
    const commitHandler = { commitOrderedTxs: () => ({ committed: 0, dropped: 0 }) };

    await Promise.all([
      runServer(sourceHandler, server),
      onPeerAuthorized("peer-123", "TIP_NODE_A", {
        syncHandler,
        snapshotHandler: destHandler,
        commitHandler, dag: destDag, narwhal, bullshark,
        nodeId: "OUR_NODE",
      }),
    ]);

    // Snapshot declined → no markOrderedUpTo from Phase 1.
    expect(bullshark.markOrderedUpTo).not.toHaveBeenCalled();
    // Cert-sync called without fromRound override (undefined triggers
    // syncHandler's default: dag.getLatestRound() + 1).
    expect(syncHandler.calls.length).toBe(1);
    expect(syncHandler.calls[0].opts.fromRound).toBeUndefined();
    // Narwhal still completes sync-mode cycle cleanly.
    expect(narwhal.events[0]).toBe("enter");
    expect(narwhal.events.some(e => Array.isArray(e) && e[0] === "exit")).toBe(true);
  });
});
