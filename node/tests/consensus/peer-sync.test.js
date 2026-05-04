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

function makeSnapshotHandlerPair({ sourceDag, destDag, destNarwhal = null }) {
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
    narwhal: destNarwhal,
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
    let _state = "ready";
    return {
      events,
      enterSyncMode: () => { events.push("enter"); _state = "syncing"; },
      exitSyncMode: (r) => { events.push(["exit", r]); _state = "ready"; },
      markSnapshotInstalled: (round, peerCommittedRound) => {
        events.push(["markSnapshotInstalled", round, peerCommittedRound]);
        _state = "catching_up";
      },
      markCaughtUp: (r) => { events.push(["markCaughtUp", r]); _state = "ready"; },
      joinState: () => _state,
      catchUpTarget: () => 0,
    };
  }

  test("snapshot succeeds → cert-sync asked for snapRound+1 onwards; install transitions narwhal syncing → catching_up (promotion to ready owned by AE)", async () => {
    const fx = buildCommittedDag({ committeeSize: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const narwhal = stubNarwhal();
    const { sourceHandler, destHandler, server } = makeSnapshotHandlerPair({
      sourceDag: fx.sourceDag, destDag, destNarwhal: narwhal,
    });

    const syncHandler = stubSyncHandler();
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
    // Narwhal entered sync mode and the install path transitioned it to
    // catching_up. Promotion to ready is owned by anti-entropy's
    // markCaughtUp (driven by state-root agreement with peers), so we
    // should NOT see an exit event from peer-sync.
    expect(narwhal.events[0]).toBe("enter");
    const installEvent = narwhal.events.find(e => Array.isArray(e) && e[0] === "markSnapshotInstalled");
    expect(installEvent).toBeTruthy();
    expect(installEvent[1]).toBeGreaterThanOrEqual(2);
    expect(narwhal.joinState()).toBe("catching_up");
    expect(narwhal.events.some(e => Array.isArray(e) && e[0] === "exit")).toBe(false);
    // Destination's state_merkle_root matches source's.
    expect(computeStateMerkleRoot(destDag)).toBe(fx.stateRoot);
  });

  test("#45: cert-sync returns snapshotRequired → bootstrap retries snapshot, then re-syncs from new anchor", async () => {
    // Live-observed gap: peer's cert GC horizon is past the joiner's
    // requested round → sync-handler returns { imported: 0,
    // snapshotRequired: true, earliestAvailableRound: N }. Pre-fix the
    // bootstrap path ignored snapshotRequired (only branched on
    // imported > 0), called exitSyncMode at peerLatestRound with an
    // empty cert chain, and the joiner tried to participate at a
    // round it had zero parent context for. Post-fix the path retries
    // the snapshot once and only exits sync mode after the retry
    // produces a usable anchor.
    const destDag = initDAG({ dbPath: ":memory:" });

    // First cert-sync call: peer-GC'd past our request → snapshotRequired.
    // Second call (after the fix's retry-snapshot path): success at
    // peerLatestRound with no remaining gap.
    const syncCalls = [];
    const syncHandler = {
      calls: syncCalls,
      syncFromPeer: async (peerId, opts) => {
        syncCalls.push({ peerId, opts });
        if (syncCalls.length === 1) {
          return {
            imported: 0,
            fromRound: opts?.fromRound || 1,
            toRound: opts?.fromRound || 1,
            peerLatestRound: 45520,
            snapshotRequired: true,
            earliestAvailableRound: 45000,
          };
        }
        return { imported: 0, fromRound: opts?.fromRound, toRound: opts?.fromRound, peerLatestRound: 45520 };
      },
    };

    // Stub snapshotHandler with two scripted responses: first call
    // (Phase 1) → no qualifying commit; second call (the #45 fallback) →
    // a snapshot at round 45000. The two-call requirement IS the
    // signal that the fix wired up the retry path.
    const snapshotCalls = [];
    const snapshotHandler = {
      requestSnapshotFromPeer: async (peerId, opts) => {
        snapshotCalls.push({ peerId, opts });
        if (snapshotCalls.length === 1) return null;  // Phase 1 declined
        return {
          round: 45000,
          peer_committed_round: 45520,
          peer_consensus_index: 17000,
          consensus_index: 16000,
          rows_installed: 76,
        };
      },
    };

    const narwhal = stubNarwhal();
    const marked = [];
    const consensusIndexes = [];
    const bullshark = {
      markOrderedUpTo: (r) => marked.push(r),
      setConsensusIndex: (i) => consensusIndexes.push(i),
    };
    const commitHandler = { commitOrderedTxs: () => ({ committed: 0, dropped: 0 }) };

    await onPeerAuthorized("peer-gc-pruned", "TIP_NODE_A", {
      syncHandler, snapshotHandler,
      commitHandler, dag: destDag, narwhal, bullshark,
      nodeId: "OUR_NODE",
    });

    // Two cert-sync calls: first hit snapshotRequired, second ran from
    // tryFastSyncSnapshot's returned anchor + 1. The helper returns
    // snap.round (the actual snapshot round, NOT peer_committed_round)
    // so cert-sync pulls the [snap.round+1, peer_committed_round] gap —
    // those certs are needed for participants.getActiveCommittee to
    // populate the K-window. (See peer-sync.js:124 comment for the live
    // 2026-05-02 halt fingerprint that surfaced this fix.) snap.round =
    // 45000 → fromRound = 45001.
    expect(syncCalls.length).toBe(2);
    expect(syncCalls[1].opts.fromRound).toBe(45001);
    // Two snapshot attempts: Phase 1 declined, fallback installed.
    expect(snapshotCalls.length).toBe(2);
    // Bullshark advanced from the fallback snapshot's
    // peer_committed_round, not just the anchor.
    expect(marked).toContain(45520);
    // Sync mode entered + exited; exit round reflects the peer's
    // latest, NOT the original (broken) high round with no state.
    expect(narwhal.events[0]).toBe("enter");
    // Snapshot is provided via a stub here (not the real handler), so it
    // doesn't fire markSnapshotInstalled and narwhal stays in syncing.
    // peer-sync's fallback gate (joinState === "syncing" after cert-sync)
    // promotes to ready at peerLatestRound — this preserves the legacy
    // behavior for callers that don't use the install-driven flow.
    const exitEvent = narwhal.events.find(e => Array.isArray(e) && e[0] === "exit");
    expect(exitEvent).toBeTruthy();
    expect(exitEvent[1]).toBe(45520);
  });

  test("#45: cert-sync says snapshotRequired AND snapshot fallback fails → bootstrap stays in sync mode", async () => {
    // The "stay in sync mode" branch — pre-fix the bootstrap would
    // exitSyncMode at peerLatestRound regardless of having no state.
    // Post-fix: when both phases fail, return early so anti-entropy or
    // another peer's onPeerAuthorized retries with a different peer.
    // Without this guard the joiner ends up at a high round with an
    // empty DAG and breaks parent-walk on the next round.
    const destDag = initDAG({ dbPath: ":memory:" });

    const syncCalls = [];
    const syncHandler = {
      calls: syncCalls,
      syncFromPeer: async (peerId, opts) => {
        syncCalls.push({ peerId, opts });
        return {
          imported: 0,
          fromRound: opts?.fromRound || 1,
          toRound: opts?.fromRound || 1,
          peerLatestRound: 45520,
          snapshotRequired: true,
          earliestAvailableRound: 45000,
        };
      },
    };

    // Both snapshot calls return null — Phase 1 declined AND fallback
    // declined. The fix must short-circuit on the second null.
    const snapshotCalls = [];
    const snapshotHandler = {
      requestSnapshotFromPeer: async () => {
        snapshotCalls.push(true);
        return null;
      },
    };

    const narwhal = stubNarwhal();
    const bullshark = { markOrderedUpTo: jest.fn(), setConsensusIndex: jest.fn() };
    const commitHandler = { commitOrderedTxs: () => ({ committed: 0, dropped: 0 }) };

    await onPeerAuthorized("peer-no-snap", "TIP_NODE_A", {
      syncHandler, snapshotHandler,
      commitHandler, dag: destDag, narwhal, bullshark,
      nodeId: "OUR_NODE",
    });

    // Exactly ONE cert-sync call — the second-attempt path is gated
    // on a successful snapshot retry, which didn't happen.
    expect(syncCalls.length).toBe(1);
    // Two snapshot attempts: Phase 1 + fallback. Both failed.
    expect(snapshotCalls.length).toBe(2);
    // Narwhal entered sync mode but DID NOT exit — this is the safety
    // property the fix preserves. Pre-fix exitSyncMode would have been
    // called with peerLatestRound (45520) and an empty DAG.
    expect(narwhal.events[0]).toBe("enter");
    const exitEvent = narwhal.events.find(e => Array.isArray(e) && e[0] === "exit");
    expect(exitEvent).toBeUndefined();
    // Bullshark unchanged — neither phase advanced state.
    expect(bullshark.markOrderedUpTo).not.toHaveBeenCalled();
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
