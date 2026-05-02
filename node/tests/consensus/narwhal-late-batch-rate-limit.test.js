/**
 * @file tests/consensus/narwhal-late-batch-rate-limit.test.js
 * @description #64 follow-up: assert the late-batch ack WARN is rate-limited
 * per peer instead of firing once per round.
 *
 * Symptom this guards against (live-observed 2026-05-02 warm-up logs):
 *   - At quorum=1 boot, every round advances faster than gossip RTT, so
 *     every incoming batch arrives "late" relative to local _currentRound.
 *     Pre-rate-limit, narwhal logged a WARN per (round, peer) — flooding
 *     warn.log with one-per-round entries that drowned operator-relevant
 *     warnings (cert verify failures, equivocation, etc).
 *
 * Test stance: drive multiple late batches from the same peer at the same
 * local round, verify only the first emits a WARN. Then advance local
 * round by ≥ LATE_BATCH_LOG_INTERVAL_ROUNDS, verify the next late batch
 * emits a summary WARN with the running count. The metric
 * `batches_acked_late` must still increment per-batch — rate limit is a
 * log-only filter, not a metric filter.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");

// Patch logger.getLogger BEFORE narwhal loads, so narwhal's module-scoped
// `log` const captures our warn-spy wrapper. Order matters: narwhal
// destructures `getLogger` at module load time, so the swap must happen
// before its require runs.
const loggerMod = require(path.join(SRC, "logger"));
const _origGetLogger = loggerMod.getLogger;
const _warnCalls = [];
const _wrappedNarwhalLogger = (() => {
  const real = _origGetLogger("tip.narwhal");
  return {
    error: (...a) => real.error(...a),
    warn: (...a) => { _warnCalls.push(a.join(" ")); },
    info: (...a) => real.info(...a),
    debug: (...a) => real.debug(...a),
    notice: (...a) => real.notice(...a),
    rateWarn: (...a) => real.rateWarn(...a),
  };
})();
loggerMod.getLogger = (source) => source === "tip.narwhal"
  ? _wrappedNarwhalLogger
  : _origGetLogger(source);

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { createNarwhal } = require(path.join(SRC, "consensus", "narwhal"));
const { createBatch } = require(path.join(SRC, "consensus", "certificate"));
const { serializeBatch } = require(path.join(SRC, "consensus", "certificate-codec"));
const { loadTypes, encode } = require(path.join(SRC, "network", "proto"));

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

afterAll(() => {
  loggerMod.getLogger = _origGetLogger;
});

beforeEach(() => {
  _warnCalls.length = 0;
});

// ─── Harness ───────────────────────────────────────────────────────────────
// Two-peer harness mirroring narwhal-stale-batch.test.js. We add a third
// peer (PEER_C) for the multi-peer rate-limit test below.

function buildNarwhal() {
  const selfKp = generateMLDSAKeypair();
  const peerBKp = generateMLDSAKeypair();
  const peerCKp = generateMLDSAKeypair();
  const SELF_ID = "tip://node/self";
  const PEER_B_ID = "tip://node/peerB";
  const PEER_C_ID = "tip://node/peerC";

  const dag = initDAG({ dbPath: ":memory:" });
  for (const [id, name, kp] of [
    [SELF_ID, "self", selfKp],
    [PEER_B_ID, "peerB", peerBKp],
    [PEER_C_ID, "peerC", peerCKp],
  ]) {
    dag.saveNode({
      node_id: id, name, public_key: kp.publicKey,
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
  }

  const mempool = createMempool({ dag });
  const published = [];
  const network = {
    TOPICS: { MEMPOOL: "tip/mempool", CERTIFICATES: "tip/certificates", CONSENSUS: "tip/consensus" },
    publish: (topic, buf) => { published.push({ topic, len: buf?.length || 0 }); },
    authorizedPeers: () => ({
      [PEER_B_ID]: { publicKey: peerBKp.publicKey },
      [PEER_C_ID]: { publicKey: peerCKp.publicKey },
    }),
  };

  const narwhal = createNarwhal({
    dag, mempool, network,
    config: {
      nodeId: SELF_ID, nodeRegisteredId: SELF_ID,
      nodePrivateKey: selfKp.privateKey, nodePublicKey: selfKp.publicKey,
    },
    getNodeKey: (nodeId) => {
      const n = dag.getNode(nodeId);
      return n ? n.public_key : null;
    },
    getNodeCount: () => 3,
    getCommittee: () => [SELF_ID, PEER_B_ID, PEER_C_ID],
    onCommit: () => { },
    onCertSaved: () => { },
  });

  return { narwhal, dag, mempool, network, published, peerBKp, peerCKp, SELF_ID, PEER_B_ID, PEER_C_ID };
}

function makePeerBatchBytes({ round, peerKp, peerId, txs = [] }) {
  const batch = createBatch(round, peerId, txs, peerKp.privateKey);
  return encode("Batch", serializeBatch(batch));
}

// Count WARN entries whose body matches the late-batch ack signature.
function lateBatchWarnCount() {
  return _warnCalls.filter((line) => line.includes("ack'ing late batch")).length;
}

// ═══════════════════════════════════════════════════════════════════════════
describe("narwhal late-batch ack WARN rate-limit (#64 follow-up)", () => {
  test("first late batch from a peer emits one WARN; subsequent ones at the same local round are suppressed but still counted", () => {
    const fx = buildNarwhal();
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);  // currentRound = 100
    expect(fx.narwhal.currentRound()).toBe(100);

    // Drive 5 late batches from peerB at distinct rounds 99..95 — all
    // within VOTES_RETENTION_ROUNDS=5 so all are ack-eligible. Distinct
    // batch.rounds keep equivocation defense from short-circuiting on
    // duplicate (round, author).
    for (let r = 99; r >= 95; r--) {
      fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
        round: r, peerKp: fx.peerBKp, peerId: fx.PEER_B_ID,
      }));
    }

    expect(lateBatchWarnCount()).toBe(1);
    expect(fx.narwhal.stats().metrics.batches_acked_late).toBe(5);

    fx.narwhal.stop();
  });

  test("after the rate-limit interval elapses, the next late batch emits a summary WARN with the running count", () => {
    const fx = buildNarwhal();
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);  // currentRound = 100

    // First sighting → 1 WARN, tracker.count=1, lastLoggedRound=100.
    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 99, peerKp: fx.peerBKp, peerId: fx.PEER_B_ID,
    }));
    expect(lateBatchWarnCount()).toBe(1);

    // Two more late batches at the same currentRound — all suppressed.
    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 98, peerKp: fx.peerBKp, peerId: fx.PEER_B_ID,
    }));
    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 97, peerKp: fx.peerBKp, peerId: fx.PEER_B_ID,
    }));
    expect(lateBatchWarnCount()).toBe(1);

    // Advance currentRound by exactly LATE_BATCH_LOG_INTERVAL_ROUNDS=60
    // so the gap satisfies `currentRound - lastLoggedRound >= 60`.
    fx.narwhal.exitSyncMode(159);  // currentRound = 160
    expect(fx.narwhal.currentRound()).toBe(160);

    // Late batch at the new currentRound — summary WARN should fire.
    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 159, peerKp: fx.peerBKp, peerId: fx.PEER_B_ID,
    }));
    expect(lateBatchWarnCount()).toBe(2);

    // The summary line carries the running batch count since the last
    // WARN. After 1 initial + 2 suppressed + this trigger = 4 late
    // batches in the window — that's what the summary should report.
    const lastWarn = _warnCalls[_warnCalls.length - 1];
    expect(lastWarn).toMatch(/late batches from this peer since last log/);
    expect(lastWarn).toMatch(/4 late batches/);

    // Metric still counts every late ack — log-only filter, not data loss.
    expect(fx.narwhal.stats().metrics.batches_acked_late).toBe(4);

    fx.narwhal.stop();
  });

  test("rate-limit is per-peer — a different peer's first late batch logs immediately", () => {
    const fx = buildNarwhal();
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);  // currentRound = 100

    // peerB → first sighting, 1 WARN.
    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 99, peerKp: fx.peerBKp, peerId: fx.PEER_B_ID,
    }));
    expect(lateBatchWarnCount()).toBe(1);

    // peerB again at a different round → suppressed.
    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 98, peerKp: fx.peerBKp, peerId: fx.PEER_B_ID,
    }));
    expect(lateBatchWarnCount()).toBe(1);

    // peerC → first sighting from a *different* author, must log
    // immediately rather than inheriting peerB's suppression window.
    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 99, peerKp: fx.peerCKp, peerId: fx.PEER_C_ID,
    }));
    expect(lateBatchWarnCount()).toBe(2);

    fx.narwhal.stop();
  });
});
