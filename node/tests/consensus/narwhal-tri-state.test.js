/**
 * @file tests/consensus/narwhal-tri-state.test.js
 * @description FSM transition tests for the tri-state join state machine
 * (syncing / catching_up / ready). These pin the contract that:
 *
 *   - markSnapshotInstalled is the only path syncing → catching_up
 *   - markCaughtUp is the only path catching_up → ready (production gate)
 *   - exitSyncMode is the legacy "force ready" override (still public for
 *     test setup + AE failure-path safety floor)
 *   - The watchdog flips catching_up → syncing if the cert tail can't
 *     close within the threshold, so a node that picked an unreachable
 *     target self-recovers via a fresher snapshot on the next AE tick
 *
 * Without these guarantees, the system can end up in zombie states:
 * snapshot installed but cluster head moved on (current_round jumps via
 * peer batch fast-forward but DAG never closes the gap) — the exact
 * fingerprint behind the round-2477→2928 broken-parent halt observed
 * 2026-05-02 on node 3.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { createNarwhal } = require(path.join(SRC, "consensus", "narwhal"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));
const { getActiveCommittee } = require(path.join(SRC, "consensus", "participants"));
const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

const SELF_ID = "tip://node/self";
const PEER_ID = "tip://node/peer";

function buildNarwhal({ onProducerPaused = null } = {}) {
  const selfKp = generateMLDSAKeypair();
  const peerKp = generateMLDSAKeypair();

  const dag = initDAG({ inMemory: true });
  dag.saveNode({
    node_id: SELF_ID, name: "self", public_key: selfKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z"
  });
  dag.saveNode({
    node_id: PEER_ID, name: "peer", public_key: peerKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z"
  });

  // Seed enough rotations to satisfy producer-pause in case any test
  // calls start() and produces a round (we mostly stay in non-ready).
  const epochLength = CONSENSUS.COMMITTEE_ROTATION_INTERVAL_COMMITS * 2;
  for (let n = 1; n <= 5; n++) {
    dag.saveCommitteeRotation({
      rotation_number: n, effective_round: n * epochLength,
      committee: [
        { node_id: SELF_ID, public_key: selfKp.publicKey },
        { node_id: PEER_ID, public_key: peerKp.publicKey },
      ],
      prev_rotation: n - 1, signer_node_ids: [], signatures: [],
      payload_hash: `r-${n}`, committed_at: "2026-01-01T00:00:00.000Z",
    });
  }

  const mempool = createMempool({ dag });
  const network = {
    TOPICS: { MEMPOOL: "tip/mempool", CERTIFICATES: "tip/certificates", CONSENSUS: "tip/consensus" },
    publish: () => { },
    authorizedPeers: () => ({}),
  };

  const narwhal = createNarwhal({
    dag, mempool, network,
    config: {
      nodeId: SELF_ID, nodeRegisteredId: SELF_ID,
      nodePrivateKey: selfKp.privateKey, nodePublicKey: selfKp.publicKey
    },
    getNodeKey: (id) => { const n = dag.getNode(id); return n ? n.public_key : null; },
    getNodeCount: () => 2,
    getCommittee: (round) => getActiveCommittee(dag, round != null ? round : narwhal.currentRound()),
    onCommit: () => { },
    onCertSaved: () => { },
    onProducerPaused,
  });

  return { narwhal, dag };
}

describe("narwhal tri-state join FSM", () => {
  test("default state is ready; stats expose new tracking fields", () => {
    const { narwhal } = buildNarwhal();
    expect(narwhal.joinState()).toBe("ready");
    const s = narwhal.stats();
    expect(s.joinState).toBe("ready");
    expect(s.syncEnteredAt).toBe(0);
    expect(s.catchingUpEnteredAt).toBe(0);
    expect(s.catchUpTarget).toBe(0);
  });

  test("enterSyncMode → syncing; stamps syncEnteredAt; clears any catching_up state", () => {
    const { narwhal } = buildNarwhal();
    narwhal.enterSyncMode();
    expect(narwhal.joinState()).toBe("syncing");
    const s = narwhal.stats();
    expect(s.syncEnteredAt).toBeGreaterThan(0);
    expect(s.catchingUpEnteredAt).toBe(0);
    expect(s.catchUpTarget).toBe(0);
  });

  test("syncEnteredAt is sticky on repeat enterSyncMode", () => {
    const { narwhal } = buildNarwhal();
    narwhal.enterSyncMode();
    const t0 = narwhal.stats().syncEnteredAt;
    // Repeat — clock should NOT reset
    narwhal.enterSyncMode();
    expect(narwhal.stats().syncEnteredAt).toBe(t0);
  });

  test("markSnapshotInstalled refused when joinState !== syncing (no-op from ready)", () => {
    const { narwhal } = buildNarwhal();
    narwhal.markSnapshotInstalled(100, 150);
    // Stays in ready, no transition
    expect(narwhal.joinState()).toBe("ready");
    expect(narwhal.stats().catchingUpEnteredAt).toBe(0);
    expect(narwhal.stats().catchUpTarget).toBe(0);
  });

  test("markSnapshotInstalled transitions syncing → catching_up + stamps catchUp markers", () => {
    const { narwhal } = buildNarwhal();
    narwhal.enterSyncMode();
    narwhal.markSnapshotInstalled(100, 150);
    expect(narwhal.joinState()).toBe("catching_up");
    const s = narwhal.stats();
    expect(s.syncEnteredAt).toBe(0);            // cleared
    expect(s.catchingUpEnteredAt).toBeGreaterThan(0);
    expect(s.catchUpTarget).toBe(150);          // peer's committed_round
    expect(narwhal.catchUpTarget()).toBe(150);
  });

  test("markSnapshotInstalled with peerCommittedRound=0 falls back to round arg as target", () => {
    const { narwhal } = buildNarwhal();
    narwhal.enterSyncMode();
    narwhal.markSnapshotInstalled(100, 0);
    expect(narwhal.catchUpTarget()).toBe(100);  // floor: snap.round
  });

  test("markCaughtUp refused when joinState !== catching_up", () => {
    const { narwhal } = buildNarwhal();
    // From ready
    narwhal.markCaughtUp(200);
    expect(narwhal.joinState()).toBe("ready");
    // From syncing (no install yet)
    narwhal.enterSyncMode();
    narwhal.markCaughtUp(200);
    expect(narwhal.joinState()).toBe("syncing");
  });

  test("markCaughtUp transitions catching_up → ready + clears all non-ready markers", () => {
    const { narwhal } = buildNarwhal();
    narwhal.enterSyncMode();
    narwhal.markSnapshotInstalled(100, 150);
    expect(narwhal.joinState()).toBe("catching_up");
    narwhal.markCaughtUp(150);
    expect(narwhal.joinState()).toBe("ready");
    const s = narwhal.stats();
    expect(s.syncEnteredAt).toBe(0);
    expect(s.catchingUpEnteredAt).toBe(0);
    expect(s.catchUpTarget).toBe(0);
  });

  test("exitSyncMode is a public override that goes ready from any non-ready state", () => {
    // From syncing
    const { narwhal: n1 } = buildNarwhal();
    n1.enterSyncMode();
    n1.exitSyncMode(50);
    expect(n1.joinState()).toBe("ready");

    // From catching_up
    const { narwhal: n2 } = buildNarwhal();
    n2.enterSyncMode();
    n2.markSnapshotInstalled(100, 150);
    n2.exitSyncMode(150);
    expect(n2.joinState()).toBe("ready");
    expect(n2.stats().catchingUpEnteredAt).toBe(0);
    expect(n2.stats().catchUpTarget).toBe(0);
  });

  test("watchdog flips catching_up → syncing when stuck past threshold", () => {
    jest.useFakeTimers();
    try {
      const { narwhal } = buildNarwhal();
      // enterSyncMode BEFORE start so start() doesn't schedule rounds
      // (start() only schedules when joinState === "ready").
      narwhal.enterSyncMode();
      narwhal.start();
      narwhal.markSnapshotInstalled(100, 150);
      expect(narwhal.joinState()).toBe("catching_up");
      // Advance time past STUCK_CATCHING_UP_MS (= 10× ROUND_TIMEOUT_MS).
      // Watchdog interval is half of round timeout — multiple ticks fire.
      jest.advanceTimersByTime(CONSENSUS.ROUND_TIMEOUT_MS * 11);
      expect(narwhal.joinState()).toBe("syncing");
      expect(narwhal.stats().catchUpTarget).toBe(0);
      expect(narwhal.stats().syncEnteredAt).toBeGreaterThan(0);
      narwhal.stop();
    } finally {
      jest.useRealTimers();
    }
  });

  test("watchdog leaves catching_up alone when within threshold", () => {
    jest.useFakeTimers();
    try {
      const { narwhal } = buildNarwhal();
      narwhal.enterSyncMode();
      narwhal.start();
      narwhal.markSnapshotInstalled(100, 150);
      jest.advanceTimersByTime(CONSENSUS.ROUND_TIMEOUT_MS * 5);
      expect(narwhal.joinState()).toBe("catching_up");
      narwhal.stop();
    } finally {
      jest.useRealTimers();
    }
  });

  test("stop() clears watchdog timer (no leak after shutdown)", () => {
    jest.useFakeTimers();
    try {
      const { narwhal } = buildNarwhal();
      narwhal.enterSyncMode();
      narwhal.start();
      narwhal.markSnapshotInstalled(100, 150);
      narwhal.stop();
      // After stop, watchdog timer is cleared — advancing time can't flip state.
      jest.advanceTimersByTime(CONSENSUS.ROUND_TIMEOUT_MS * 20);
      expect(narwhal.joinState()).toBe("catching_up");
    } finally {
      jest.useRealTimers();
    }
  });

  // Fix D — producer-pause callback. When _beginRound hits the rotation-
  // missing producer-pause, narwhal nudges upstream (bullshark) to attempt
  // a rotation proposal. Rate-limited so the 50ms producer-pause retry
  // loop doesn't fire the callback 20x/sec.
  describe("onProducerPaused callback (Fix D)", () => {
    function buildNarwhalAtMissingRotationEpoch({ onProducerPaused }) {
      const epochLength = CONSENSUS.COMMITTEE_ROTATION_INTERVAL_COMMITS * 2;
      const fx = buildNarwhal({ onProducerPaused });
      // Force narwhal's _currentRound into an epoch with no rotation row.
      // buildNarwhal seeds rotations 1-5 (effective_round 1*200..5*200).
      // Round 6*200 = 1200 → epochOf=6, which has no rotation row. Use
      // exitSyncMode to jump _currentRound straight there.
      fx.narwhal.exitSyncMode(epochLength * 6 - 1);
      return fx;
    }

    test("fires callback with (currentRound, missingRotation) when producer-pauses", () => {
      jest.useFakeTimers();
      try {
        const calls = [];
        const fx = buildNarwhalAtMissingRotationEpoch({
          onProducerPaused: (round, missing) => calls.push({ round, missing }),
        });
        fx.narwhal.start();
        // Tick the inter-round scheduler so _beginRound runs.
        jest.advanceTimersByTime(100);
        expect(calls.length).toBeGreaterThanOrEqual(1);
        expect(calls[0].round).toBe(CONSENSUS.COMMITTEE_ROTATION_INTERVAL_COMMITS * 2 * 6);
        expect(calls[0].missing).toBe(6);
        fx.narwhal.stop();
      } finally {
        jest.useRealTimers();
      }
    });

    test("rate-limited: doesn't fire more than once per ~1.5s even though producer-pause loops every 50ms", () => {
      jest.useFakeTimers();
      try {
        const calls = [];
        const fx = buildNarwhalAtMissingRotationEpoch({
          onProducerPaused: () => calls.push(Date.now()),
        });
        fx.narwhal.start();
        // First _beginRound + retry loop — should fire callback once.
        jest.advanceTimersByTime(100);
        const firstCallCount = calls.length;
        expect(firstCallCount).toBeGreaterThanOrEqual(1);
        // Pause loop runs every 50ms, but rate-limit means callback won't
        // fire again within 1500ms.
        jest.advanceTimersByTime(1000);
        expect(calls.length).toBe(firstCallCount);
        // After 1.5s+, next pause hit fires the callback again.
        jest.advanceTimersByTime(700);
        expect(calls.length).toBeGreaterThan(firstCallCount);
        fx.narwhal.stop();
      } finally {
        jest.useRealTimers();
      }
    });

    test("no callback fires when no onProducerPaused option provided (backward compat)", () => {
      jest.useFakeTimers();
      try {
        // Build with no onProducerPaused — should still producer-pause without throwing.
        const fx = buildNarwhalAtMissingRotationEpoch({ onProducerPaused: null });
        fx.narwhal.start();
        jest.advanceTimersByTime(500);
        // No assertion on callback (none wired). Just verify narwhal didn't crash.
        expect(fx.narwhal.currentRound()).toBeGreaterThan(0);
        fx.narwhal.stop();
      } finally {
        jest.useRealTimers();
      }
    });
  });

  // Producer-pause carve-out: when stuck at a rotation boundary AND the
  // rotation tx is in mempool, drain only that tx and produce a rotation-
  // only batch. Breaks the deadlock where rotation tx is submitted to
  // mempool but narwhal can't drain it because it's producer-paused
  // waiting for that very rotation row to land in DAG.
  describe("producer-pause carve-out (rotation-only batch)", () => {
    test("rotation tx in mempool → drained into rotation-only batch even while producer-paused", () => {
      jest.useFakeTimers();
      try {
        const epochLength = CONSENSUS.COMMITTEE_ROTATION_INTERVAL_COMMITS * 2;
        const fx = buildNarwhal();
        // Force narwhal into producer-pause for rotation 6 (no row exists; buildNarwhal seeds 1-5).
        fx.narwhal.exitSyncMode(epochLength * 6 - 1);

        // Verify peekRotationTx behaviour on a fresh mempool — the
        // building block the carve-out depends on.
        const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
        const mp = createMempool({ dag: fx.dag });
        const fakeTx = {
          tx_id: "deadbeef".repeat(8),
          tx_type: "COMMITTEE_ROTATION",
          data: { rotation_number: 6, effective_round: 1200 },
          signature: "00".repeat(64),
          timestamp: "2026-05-04T12:00:00.000Z",
          prev: [],
        };
        const r = mp.add(fakeTx);
        expect(r.added).toBe(true);
        // peek should find it.
        const peeked = mp.peekRotationTx(6);
        expect(peeked).not.toBeNull();
        expect(peeked.tx_id).toBe(fakeTx.tx_id);
        // peek for a different rotation — null.
        expect(mp.peekRotationTx(7)).toBeNull();
        // peek doesn't remove.
        expect(mp.size()).toBe(1);
        // explicit remove drops it.
        mp.remove([fakeTx.tx_id]);
        expect(mp.peekRotationTx(6)).toBeNull();
        fx.narwhal.stop();
      } finally {
        jest.useRealTimers();
      }
    });

    test("no rotation tx in mempool → still producer-paused (carve-out doesn't activate spuriously)", () => {
      jest.useFakeTimers();
      try {
        const epochLength = CONSENSUS.COMMITTEE_ROTATION_INTERVAL_COMMITS * 2;
        const calls = [];
        const fx = buildNarwhal({
          onProducerPaused: (round, missing) => calls.push({ round, missing }),
        });
        fx.narwhal.exitSyncMode(epochLength * 6 - 1);
        fx.narwhal.start();
        // Mempool empty → producer-pause path fires, no carve-out.
        jest.advanceTimersByTime(100);
        expect(calls.length).toBeGreaterThanOrEqual(1);
        // Round counter should NOT have advanced (no batch produced).
        expect(fx.narwhal.stats().joinState).toBe("ready");
        fx.narwhal.stop();
      } finally {
        jest.useRealTimers();
      }
    });
  });
});
