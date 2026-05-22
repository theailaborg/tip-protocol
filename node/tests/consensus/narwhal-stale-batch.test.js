/**
 * @file tests/consensus/narwhal-stale-batch.test.js
 * @description Regression test for the narwhal `handleIncomingBatch`
 * stale-batch silent-drop bug.
 *
 * Bug fingerprint (`narwhal.js:375-380`): when a peer's batch arrives at
 * a round LESS than the local node's `_currentRound`, we drop it without
 * ack, silently. Reference Narwhal does NOT do this — peers should ack
 * any well-formed batch (subject only to equivocation defense), and the
 * cert can form retroactively.
 *
 * Live impact (verified 2026-04-29 / 2026-04-30):
 *   - Node 1's user-submitted REGISTER_IDENTITY tx at round 10244 was
 *     orphaned because nodes 2 + 3 had already advanced to round 10245
 *     by the time the batch reached them (~270ms gossip latency, past
 *     the ~2s round boundary).
 *   - The two peers logged "Round 10245: ignoring stale batch for round
 *     10244 from <node 1>" and dropped without ack.
 *   - Node 1's batch never formed a cert → tx never reached commit
 *     phase → user got 200 + tip_id from the API but GET 404'd forever.
 *
 * Test stance: asserts the CORRECT (post-fix) behavior — late batches
 * within a bounded look-back window are acked normally, and only
 * batches older than `VOTES_RETENTION_ROUNDS` are rejected as
 * beyond-horizon. So this file fails RED today (proving the bug
 * exists in code) and turns GREEN once the fix lands. Standard TDD
 * regression seal: green = fixed, red = regressed.
 *
 * For the broader "no-loss invariant" test (every accepted mempool tx
 * either commits or is logged as explicitly rejected), see issues.md
 * Multi-node #63 — that needs a 3-node in-process cluster harness.
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
const { createBatch } = require(path.join(SRC, "consensus", "certificate"));
const { serializeBatch } = require(path.join(SRC, "consensus", "certificate-codec"));
const { loadTypes, encode } = require(path.join(SRC, "network", "proto"));

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

// ─── Harness ───────────────────────────────────────────────────────────────
// Two nodes — `self` (the local narwhal under test) and a synthetic peer
// `B` whose only role is to produce a batch we hand-deliver via
// `handleIncomingBatch`. We track every `network.publish` so the test
// can assert that no ack was emitted in response.

function buildNarwhal() {
  const selfKp = generateMLDSAKeypair();
  const peerKp = generateMLDSAKeypair();
  const SELF_ID = "tip://node/self";
  const PEER_ID = "tip://node/peerB";

  const dag = initDAG({ dbPath: ":memory:" });
  // Register both nodes so getNodeKey resolves; narwhal rejects batches
  // from unregistered authors at line 324.
  dag.saveNode({
    node_id: SELF_ID, name: "self", public_key: selfKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  dag.saveNode({
    node_id: PEER_ID, name: "peerB", public_key: peerKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });

  const mempool = createMempool({ dag });

  const published = [];  // [{topic, buf}, ...]
  const network = {
    TOPICS: { MEMPOOL: "tip/mempool", CERTIFICATES: "tip/certificates", CONSENSUS: "tip/consensus" },
    publish: (topic, buf) => { published.push({ topic, len: buf?.length || 0 }); },
    authorizedPeers: () => ({ [PEER_ID]: { publicKey: peerKp.publicKey } }),
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
    getNodeCount: () => 2,
    getCommittee: () => [SELF_ID, PEER_ID],
    onCommit: () => { },
    onCertSaved: () => { },
  });

  return { narwhal, dag, mempool, network, published, selfKp, peerKp, SELF_ID, PEER_ID };
}

/**
 * Build a serialized peer batch encoded as wire bytes — the shape
 * `handleIncomingBatch` consumes off the gossip topic.
 */
function makePeerBatchBytes({ round, peerKp, peerId, txs = [] }) {
  const batch = createBatch(round, peerId, txs, peerKp.privateKey);
  return encode("Batch", serializeBatch(batch));
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Pin the current (BUGGY) behavior — late batches are dropped silently
// ═══════════════════════════════════════════════════════════════════════════

describe("narwhal handleIncomingBatch — late-batch ack within look-back horizon (#64 regression)", () => {
  test("late batch within bounded look-back is ACK'd, not silently dropped (live-observed 2026-04-29 round 10244 silent-loss)", () => {
    const fx = buildNarwhal();
    fx.narwhal.start();

    // Force-advance self past the peer's batch round. exitSyncMode advances
    // narwhal._currentRound to max(peerLatestRound, dag.latestRound) + 1.
    // We pick a 2-round gap (well inside the VOTES_RETENTION_ROUNDS=5
    // look-back window the fix introduces) to mirror the live-observed
    // ~270ms gossip latency that crossed exactly one round boundary in
    // the 2026-04-29 incident — that's the most realistic case of a
    // tx-bearing batch arriving "late but recoverable".
    fx.narwhal.exitSyncMode(6);  // → currentRound = 7
    expect(fx.narwhal.currentRound()).toBe(7);

    // Peer's batch at round 5 — late by 2 rounds. Inside any reasonable
    // VOTES_RETENTION_ROUNDS look-back; the equivocation guard at
    // narwhal.js:387-398 already prevents double-signing, so safety holds.
    const ackCountBefore = fx.published.filter(p => p.topic === fx.network.TOPICS.CONSENSUS).length;
    const peerBatchBuf = makePeerBatchBytes({
      round: 5, peerKp: fx.peerKp, peerId: fx.PEER_ID, txs: [],
    });
    fx.narwhal.handleIncomingBatch(peerBatchBuf);

    const ackCountAfter = fx.published.filter(p => p.topic === fx.network.TOPICS.CONSENSUS).length;

    // ── EXPECTED (post-fix) behavior ──
    // The peer's late batch should be ack'd normally. Reference Narwhal
    // (Mysten/Sui) acks any well-formed batch up to the look-back
    // horizon; the cert can form retroactively, the leader's parent
    // walk picks it up. Today these assertions FAIL RED — narwhal.js:377
    // returns early on `batch.round < _currentRound` without ever
    // calling `_recordAck` or `network.publish(CONSENSUS, ...)`. After
    // the fix lands they turn GREEN.
    //
    // If you find this test failing red, that's the bug; don't "fix"
    // the test — fix the code at narwhal.js:377 (relax to bounded
    // `< _currentRound - VOTES_RETENTION_ROUNDS`).
    expect(ackCountAfter).toBe(ackCountBefore + 1);              // ack emitted
    expect(fx.narwhal.stats().metrics.batches_received).toBe(1); // batch counted

    fx.narwhal.stop();
  });

  test("batch beyond look-back horizon (very old) IS still rejected — bounded, not unconditional accept", () => {
    const fx = buildNarwhal();
    fx.narwhal.start();

    // Self at round 100; peer's batch at round 1 — way past any
    // reasonable VOTES_RETENTION_ROUNDS (default 5). Bounded look-back
    // means we still refuse this one (defense against malicious peers
    // flooding ancient-round batches).
    fx.narwhal.exitSyncMode(99);
    expect(fx.narwhal.currentRound()).toBe(100);

    const ackCountBefore = fx.published.filter(p => p.topic === fx.network.TOPICS.CONSENSUS).length;
    const peerBatchBuf = makePeerBatchBytes({
      round: 1, peerKp: fx.peerKp, peerId: fx.PEER_ID, txs: [],
    });
    fx.narwhal.handleIncomingBatch(peerBatchBuf);

    const ackCountAfter = fx.published.filter(p => p.topic === fx.network.TOPICS.CONSENSUS).length;
    // Both pre-fix (any `<` drop) and post-fix (bounded look-back drop)
    // produce the same outcome here — the test passes today AND after
    // the fix. It's a control + sanity that the fix doesn't go too far.
    expect(ackCountAfter).toBe(ackCountBefore);
    expect(fx.narwhal.stats().metrics.batches_received).toBe(0);

    fx.narwhal.stop();
  });

  test("batch at same round is ack'd normally (control — no stale drop applies)", () => {
    const fx = buildNarwhal();
    fx.narwhal.start();

    // Advance self to round 5; peer's batch is also round 5.
    fx.narwhal.exitSyncMode(4);
    expect(fx.narwhal.currentRound()).toBe(5);

    const ackCountBefore = fx.published.filter(p => p.topic === fx.network.TOPICS.CONSENSUS).length;
    const peerBatchBuf = makePeerBatchBytes({
      round: 5, peerKp: fx.peerKp, peerId: fx.PEER_ID, txs: [],
    });
    fx.narwhal.handleIncomingBatch(peerBatchBuf);

    const ackCountAfter = fx.published.filter(p => p.topic === fx.network.TOPICS.CONSENSUS).length;

    // Same-round batch follows the happy path: signature verifies, peer is
    // registered, no equivocation, ack emitted on CONSENSUS topic.
    expect(ackCountAfter).toBe(ackCountBefore + 1);
    expect(fx.narwhal.stats().metrics.batches_received).toBe(1);

    fx.narwhal.stop();
  });

  test("batch at future round triggers fast-forward and ACKs at the new round (control — non-stale drift path)", () => {
    const fx = buildNarwhal();
    fx.narwhal.start();
    expect(fx.narwhal.currentRound()).toBeGreaterThanOrEqual(1);

    // Peer has advanced to round 100 — self should fast-forward and ack.
    const ackCountBefore = fx.published.filter(p => p.topic === fx.network.TOPICS.CONSENSUS).length;
    const peerBatchBuf = makePeerBatchBytes({
      round: 100, peerKp: fx.peerKp, peerId: fx.PEER_ID, txs: [],
    });
    fx.narwhal.handleIncomingBatch(peerBatchBuf);

    expect(fx.narwhal.currentRound()).toBe(100);
    const ackCountAfter = fx.published.filter(p => p.topic === fx.network.TOPICS.CONSENSUS).length;
    expect(ackCountAfter).toBe(ackCountBefore + 1);
    expect(fx.narwhal.stats().metrics.fast_forwards).toBeGreaterThanOrEqual(1);

    fx.narwhal.stop();
  });
});
