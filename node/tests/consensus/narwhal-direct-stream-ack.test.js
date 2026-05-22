/**
 * @file tests/consensus/narwhal-direct-stream-ack.test.js
 * @description Direct-stream ack delivery (#46) — the structural fix for
 * the sub_quorum halt class observed in #13.
 *
 * Pre-#46 acks rode the gossipsub CONSENSUS topic (broadcast + lossy). A
 * single dropped mesh edge in an exact-quorum committee (e.g. 5 nodes,
 * 4-of-5 quorum) silently dropped an ack → cert never sealed → 16-min
 * halt observed live.
 *
 * Post-#46 acks ride a direct libp2p stream (`/tip/consensus-ack/1.0.0`).
 * Sender tries direct first, falls back to gossip if the direct send
 * fails or rejects. Receiver is idempotent (existing `_batchAcks` dedup).
 *
 * These tests exercise the sender side end-to-end:
 *   1. Direct send succeeds → no gossip publish + `acks_sent_direct` increments
 *   2. Direct send returns `false` → gossip fallback publishes + `acks_sent_fallback`
 *   3. Direct send rejects → gossip fallback publishes + `acks_sent_fallback`
 *   4. Network has no `sendAckDirect` (back-compat, old peer) → gossip-only path
 *   5. Duplicate batch arrival → cached ack re-emitted via direct stream
 *
 * The narwhal code calls `sendAckDirect(...).then(...).catch(...)` so the
 * branch fires on a microtask. Each test awaits a `Promise.resolve()` tick
 * before asserting on the gossip channel.
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

const SELF_ID = "tip://node/self";
const PEER_B_ID = "tip://node/peerB";
const PEER_C_ID = "tip://node/peerC";
const CONSENSUS_TOPIC = "tip/consensus";

// Build a narwhal wired to a mock network where `sendAckDirect` is a Jest
// mock the test controls. Returns the narwhal handle plus all the mocks
// for assertions.
function buildFixture({ sendAckDirectImpl = null, omitSendAckDirect = false } = {}) {
  const selfKp = generateMLDSAKeypair();
  const peerBKp = generateMLDSAKeypair();
  const peerCKp = generateMLDSAKeypair();
  const dag = initDAG({ dbPath: ":memory:" });

  for (const [id, name, kp] of [
    [SELF_ID, "self", selfKp],
    [PEER_B_ID, "peerB", peerBKp],
    [PEER_C_ID, "peerC", peerCKp],
  ]) {
    dag.saveNode({
      node_id: id, name, public_key: kp.publicKey,
      status: "active", registered_at: 1767225600000,
    });
  }

  const committee = [SELF_ID, PEER_B_ID, PEER_C_ID];
  const mempool = createMempool({ dag });
  const published = [];
  const sendAckDirectMock = sendAckDirectImpl
    ? jest.fn(sendAckDirectImpl)
    : jest.fn(async () => true);

  const network = {
    TOPICS: { MEMPOOL: "tip/mempool", CERTIFICATES: "tip/certificates", CONSENSUS: CONSENSUS_TOPIC },
    publish: (topic, buf) => { published.push({ topic, len: buf?.length || 0 }); },
    authorizedPeers: () => ({
      [PEER_B_ID]: { publicKey: peerBKp.publicKey },
      [PEER_C_ID]: { publicKey: peerCKp.publicKey },
    }),
  };
  if (!omitSendAckDirect) network.sendAckDirect = sendAckDirectMock;

  const narwhal = createNarwhal({
    dag, mempool, network,
    config: {
      nodeId: SELF_ID, nodeRegisteredId: SELF_ID,
      nodePrivateKey: selfKp.privateKey, nodePublicKey: selfKp.publicKey,
    },
    getNodeKey: (id) => dag.getNode(id)?.public_key || null,
    getNodeCount: () => committee.length,
    getCommittee: () => committee,
    onCommit: () => { },
    onCertSaved: () => { },
  });

  return { narwhal, dag, network, published, sendAckDirectMock, peerBKp, peerCKp };
}

function makePeerBatchBytes({ round, peerKp, peerId, txs = [] }) {
  const batch = createBatch(round, peerId, txs, peerKp.privateKey);
  return encode("Batch", serializeBatch(batch));
}

// `sendAckDirect(...).then().catch()` resolves on the microtask queue.
// Yield twice to let both then-and-catch arms settle before assertions.
async function flushPromises() {
  await Promise.resolve();
  await Promise.resolve();
}

describe("narwhal direct-stream ack (#46) — sender path", () => {
  test("direct send succeeds → no gossip publish, acks_sent_direct increments", async () => {
    const fx = buildFixture({ sendAckDirectImpl: async () => true });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));
    await flushPromises();

    expect(fx.sendAckDirectMock).toHaveBeenCalledTimes(1);
    expect(fx.sendAckDirectMock.mock.calls[0][1]).toBe(PEER_B_ID);
    expect(fx.published.filter(p => p.topic === CONSENSUS_TOPIC)).toEqual([]);
    expect(fx.narwhal.stats().metrics.acks_sent_direct).toBe(1);
    expect(fx.narwhal.stats().metrics.acks_sent_fallback || 0).toBe(0);
    fx.narwhal.stop();
  });

  test("direct send returns false → gossip fallback publishes, acks_sent_fallback increments", async () => {
    const fx = buildFixture({ sendAckDirectImpl: async () => false });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));
    await flushPromises();

    expect(fx.sendAckDirectMock).toHaveBeenCalledTimes(1);
    expect(fx.published.filter(p => p.topic === CONSENSUS_TOPIC).length).toBe(1);
    expect(fx.narwhal.stats().metrics.acks_sent_direct || 0).toBe(0);
    expect(fx.narwhal.stats().metrics.acks_sent_fallback).toBe(1);
    fx.narwhal.stop();
  });

  test("direct send rejects → gossip fallback publishes, acks_sent_fallback increments", async () => {
    const fx = buildFixture({ sendAckDirectImpl: async () => { throw new Error("dial failed"); } });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));
    await flushPromises();

    expect(fx.sendAckDirectMock).toHaveBeenCalledTimes(1);
    expect(fx.published.filter(p => p.topic === CONSENSUS_TOPIC).length).toBe(1);
    expect(fx.narwhal.stats().metrics.acks_sent_fallback).toBe(1);
    fx.narwhal.stop();
  });

  test("network without sendAckDirect (back-compat / old peer) → gossip-only path", async () => {
    const fx = buildFixture({ omitSendAckDirect: true });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));
    await flushPromises();

    expect(fx.published.filter(p => p.topic === CONSENSUS_TOPIC).length).toBe(1);
    fx.narwhal.stop();
  });

  test("duplicate batch arrival → cached ack re-emitted via direct stream", async () => {
    const fx = buildFixture({ sendAckDirectImpl: async () => true });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    const batchBuf = makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    });
    fx.narwhal.handleIncomingBatch(batchBuf);
    await flushPromises();
    const directCallsAfterFirst = fx.sendAckDirectMock.mock.calls.length;
    expect(directCallsAfterFirst).toBe(1);

    // Second arrival of the same batch (peer didn't get our first ack
    // and retried) → narwhal should re-send the cached ack via direct
    // stream (A9 / #30 band-aid folded into #46).
    fx.narwhal.handleIncomingBatch(batchBuf);
    await flushPromises();

    expect(fx.sendAckDirectMock.mock.calls.length).toBe(directCallsAfterFirst + 1);
    expect(fx.published.filter(p => p.topic === CONSENSUS_TOPIC)).toEqual([]);
    fx.narwhal.stop();
  });

  test("direct send succeeds for one author, fails for another in the same round", async () => {
    // Asymmetric mesh: direct to peerB ok, direct to peerC fails → gossip
    // fallback fires only for C. Catches the 5-node mesh-asymmetric class
    // from #13 where dropping a single edge halted the chain pre-#46.
    const fx = buildFixture({
      sendAckDirectImpl: async (_ackBuf, authorNodeId) =>
        authorNodeId === PEER_B_ID,   // ok for B, false for C
    });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));
    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerCKp, peerId: PEER_C_ID,
    }));
    await flushPromises();

    expect(fx.sendAckDirectMock).toHaveBeenCalledTimes(2);
    expect(fx.published.filter(p => p.topic === CONSENSUS_TOPIC).length).toBe(1);
    expect(fx.narwhal.stats().metrics.acks_sent_direct).toBe(1);
    expect(fx.narwhal.stats().metrics.acks_sent_fallback).toBe(1);
    fx.narwhal.stop();
  });
});
