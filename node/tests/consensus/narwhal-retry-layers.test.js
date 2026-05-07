/**
 * @file tests/consensus/narwhal-retry-layers.test.js
 * @description Layer 1: after 3 stuck retries, narwhal must call
 * network.refreshDirectPeer for each committee peer missing an ack.
 * Layer 2: after 6 stuck retries, narwhal must call network.sendBatchDirect
 * with the current batch buffer for each peer still missing an ack.
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
const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

afterEach(() => {
  jest.useRealTimers();
});

const SELF_ID = "tip://node/self";
const PEER_B_ID = "tip://node/peerB";
const PEER_C_ID = "tip://node/peerC";

function buildNarwhal({ refreshDirectPeer, sendBatchDirect } = {}) {
  const selfKp = generateMLDSAKeypair();
  const dag = initDAG({ inMemory: true });
  for (const [id, kp] of [
    [SELF_ID, selfKp],
    [PEER_B_ID, generateMLDSAKeypair()],
    [PEER_C_ID, generateMLDSAKeypair()],
  ]) {
    dag.saveNode({
      node_id: id, name: id, public_key: kp.publicKey,
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
  }

  const mempool = createMempool({ dag });
  const network = {
    TOPICS: { MEMPOOL: "tip/mempool", CERTIFICATES: "tip/certificates", CONSENSUS: "tip/consensus" },
    publish: () => {},
    authorizedPeers: () => ({}),
    refreshDirectPeer: refreshDirectPeer || jest.fn(),
    sendBatchDirect: sendBatchDirect || jest.fn(),
  };

  const narwhal = createNarwhal({
    dag, mempool, network,
    config: {
      nodeId: SELF_ID, nodeRegisteredId: SELF_ID,
      nodePrivateKey: selfKp.privateKey, nodePublicKey: selfKp.publicKey,
    },
    getNodeKey: (nodeId) => { const n = dag.getNode(nodeId); return n ? n.public_key : null; },
    getNodeCount: () => 3,
    getCommittee: () => [SELF_ID, PEER_B_ID, PEER_C_ID],
    onCommit: () => {},
    onCertSaved: () => {},
  });

  return { narwhal, network };
}

describe("narwhal retry Layer 1 — gossipsub mesh refresh", () => {
  test("after 3 stuck retries, calls network.refreshDirectPeer for each non-acking peer", () => {
    jest.useFakeTimers();
    const refreshSpy = jest.fn();
    const { narwhal } = buildNarwhal({ refreshDirectPeer: refreshSpy });

    narwhal.start();
    narwhal.exitSyncMode(0);

    // No peer batches → no acks → cert quorum (2 of 2 peers) never met
    // Advance clock to trigger exactly 3 retries
    jest.advanceTimersByTime(CONSENSUS.ROUND_TIMEOUT_MS * 3);

    expect(refreshSpy).toHaveBeenCalledTimes(2); // PEER_B_ID + PEER_C_ID
    expect(refreshSpy).toHaveBeenCalledWith(PEER_B_ID);
    expect(refreshSpy).toHaveBeenCalledWith(PEER_C_ID);
    expect(refreshSpy).not.toHaveBeenCalledWith(SELF_ID);

    narwhal.stop();
  });

  test("does NOT call refreshDirectPeer before retry 3", () => {
    jest.useFakeTimers();
    const refreshSpy = jest.fn();
    const { narwhal } = buildNarwhal({ refreshDirectPeer: refreshSpy });

    narwhal.start();
    narwhal.exitSyncMode(0);

    jest.advanceTimersByTime(CONSENSUS.ROUND_TIMEOUT_MS * 2);

    expect(refreshSpy).not.toHaveBeenCalled();

    narwhal.stop();
  });
});

describe("narwhal retry Layer 2 — direct stream fallback", () => {
  test("after 6 stuck retries, calls network.sendBatchDirect for each non-acking peer", () => {
    jest.useFakeTimers();
    const sendSpy = jest.fn();
    const { narwhal } = buildNarwhal({ sendBatchDirect: sendSpy });

    narwhal.start();
    narwhal.exitSyncMode(0);

    jest.advanceTimersByTime(CONSENSUS.ROUND_TIMEOUT_MS * 6);

    const calledNodeIds = sendSpy.mock.calls.map(([, nodeId]) => nodeId);
    expect(calledNodeIds).toContain(PEER_B_ID);
    expect(calledNodeIds).toContain(PEER_C_ID);
    expect(calledNodeIds).not.toContain(SELF_ID);

    // buf must be a non-empty Buffer (the encoded batch)
    const [firstBuf] = sendSpy.mock.calls[0];
    expect(Buffer.isBuffer(firstBuf)).toBe(true);
    expect(firstBuf.length).toBeGreaterThan(0);

    narwhal.stop();
  });

  test("does NOT call sendBatchDirect before retry 6", () => {
    jest.useFakeTimers();
    const sendSpy = jest.fn();
    const { narwhal } = buildNarwhal({ sendBatchDirect: sendSpy });

    narwhal.start();
    narwhal.exitSyncMode(0);

    jest.advanceTimersByTime(CONSENSUS.ROUND_TIMEOUT_MS * 5);

    expect(sendSpy).not.toHaveBeenCalled();

    narwhal.stop();
  });
});
