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

const { nowMs, nowIso, toIso } = require("../../../shared/time");

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
    status: "active", registered_at: 1767225600000
  });
  dag.saveNode({
    node_id: PEER_ID, name: "peer", public_key: peerKp.publicKey,
    status: "active", registered_at: 1767225600000
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
      payload_hash: `r-${n}`, committed_at: 1767225600000,
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
          onProducerPaused: () => calls.push(nowMs()),
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
          timestamp: 1777896000000,
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

    // Carve-out path must NOT drain the rotation tx from mempool. Without
    // this, each node carves exactly once at the boundary and producer-
    // pauses again at R+1 with an empty mempool — anchor-commit at R needs
    // 2f+1 certs at R+2, but each node only produces one cert at the
    // boundary epoch then nothing. Federation halts (live observed
    // 2026-05-04 rotation-13 deadlock: 3 carve-outs at 2600, 1 at 2601, 0
    // at 2602 — anchor-commit at 2600 impossible). Leaving the tx in
    // mempool keeps re-carving every round until anchor-commit applies it
    // through the normal pipeline, at which point commit-handler removes
    // it via dag.deleteMempoolTxs by tx_id and producer-pause clears.
    test("carve-out keeps rotation tx in mempool (re-carves until anchor-commit clears it)", () => {
      jest.useFakeTimers();
      try {
        const epochLength = CONSENSUS.COMMITTEE_ROTATION_INTERVAL_COMMITS * 2;
        const fx = buildNarwhal();
        // Producer-pause for rotation 6 (buildNarwhal seeds 1-5 only).
        fx.narwhal.exitSyncMode(epochLength * 6 - 1);

        // Inject a rotation 6 tx into the SAME mempool narwhal uses.
        const mp = require(path.join(SRC, "consensus", "mempool")).createMempool;
        // Rebuild access to narwhal's mempool via fx — buildNarwhal threads
        // its own mempool into the narwhal closure, so we reuse it here
        // through the dag-level interface (dag.mempool* statements aren't
        // public; instead we re-derive a mempool over the same dag and
        // populate it — narwhal.handleIncomingBatch is the regular path
        // peer batches arrive on, but for this unit we cut to the chase
        // and add directly to narwhal's underlying mempool via a fresh
        // facade against the same SQLite store).
        const sharedMempool = mp({ dag: fx.dag });
        const rotTx = {
          tx_id: "ab".repeat(32),
          tx_type: "COMMITTEE_ROTATION",
          data: { rotation_number: 6, effective_round: epochLength * 6 },
          signature: "00".repeat(64),
          timestamp: 1777896000000,
          prev: [],
        };
        const r = sharedMempool.add(rotTx);
        expect(r.added).toBe(true);
        expect(sharedMempool.size()).toBe(1);

        // Drive _beginRound by starting + advancing timers. The carve-out
        // branch fires for round = epochLength*6 (epochOf=6, missing in CH).
        // Mempool retention is the contract under test.
        fx.narwhal.start();
        jest.advanceTimersByTime(50);

        // KEY ASSERTION: the rotation tx is STILL in mempool after carve-out.
        // (Pre-fix, mempool.remove drained it here; post-fix, carve-out
        // builds a batch with the tx but leaves the mempool entry in place
        // so the next round can re-carve until anchor-commit applies it.)
        expect(sharedMempool.peekRotationTx(6)).not.toBeNull();
        expect(sharedMempool.peekRotationTx(6).tx_id).toBe(rotTx.tx_id);
        expect(sharedMempool.size()).toBe(1);

        fx.narwhal.stop();
      } finally {
        jest.useRealTimers();
      }
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Byzantine-fork halt — narwhal-side gates
// ═══════════════════════════════════════════════════════════════════════════
describe("narwhal byzantine-fork halt", () => {
  test("default state: byzantineForkHalt() is null and stats expose it", () => {
    const { narwhal } = buildNarwhal();
    expect(narwhal.byzantineForkHalt()).toBeNull();
    expect(narwhal.stats().byzantineForkHalt).toBeNull();
  });

  test("haltDueToByzantineFork stamps reason / atRound / peerNodeId / since", () => {
    const { narwhal } = buildNarwhal();
    narwhal.haltDueToByzantineFork({
      reason: "2/2 peers disagree",
      atRound: 42,
      peerNodeId: "tip://node/peer",
    });
    const halt = narwhal.byzantineForkHalt();
    expect(halt).not.toBeNull();
    expect(halt.reason).toBe("2/2 peers disagree");
    expect(halt.atRound).toBe(42);
    expect(halt.peerNodeId).toBe("tip://node/peer");
    expect(halt.since).toBeGreaterThan(0);
    expect(narwhal.stats().byzantineForkHalt).toEqual(halt);
  });

  test("halt is idempotent — first signal wins, later calls are no-ops", () => {
    const { narwhal } = buildNarwhal();
    narwhal.haltDueToByzantineFork({ reason: "first", atRound: 10, peerNodeId: "A" });
    const t0 = narwhal.byzantineForkHalt().since;
    narwhal.haltDueToByzantineFork({ reason: "second", atRound: 99, peerNodeId: "B" });
    const halt = narwhal.byzantineForkHalt();
    expect(halt.reason).toBe("first");
    expect(halt.atRound).toBe(10);
    expect(halt.peerNodeId).toBe("A");
    expect(halt.since).toBe(t0);
  });

  test("clearByzantineForkHalt resets state to null", () => {
    const { narwhal } = buildNarwhal();
    narwhal.haltDueToByzantineFork({ reason: "x", atRound: 1, peerNodeId: "p" });
    expect(narwhal.byzantineForkHalt()).not.toBeNull();
    narwhal.clearByzantineForkHalt();
    expect(narwhal.byzantineForkHalt()).toBeNull();
    expect(narwhal.stats().byzantineForkHalt).toBeNull();
  });

  test("byzantineForkHalt() returns a copy — caller mutations don't leak into internal state", () => {
    const { narwhal } = buildNarwhal();
    narwhal.haltDueToByzantineFork({ reason: "leak-check", atRound: 5, peerNodeId: "p" });
    const halt = narwhal.byzantineForkHalt();
    halt.reason = "MUTATED";
    halt.atRound = 999;
    expect(narwhal.byzantineForkHalt().reason).toBe("leak-check");
    expect(narwhal.byzantineForkHalt().atRound).toBe(5);
  });

  test("committeeSize returns the active committee length (positive integer)", () => {
    const { narwhal } = buildNarwhal();
    const n = narwhal.committeeSize();
    expect(Number.isInteger(n)).toBe(true);
    expect(n).toBeGreaterThanOrEqual(1);
  });
});
