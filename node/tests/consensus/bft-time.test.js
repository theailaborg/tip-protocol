/**
 * @file tests/consensus/bft-time.test.js
 * @description BFT-Time tests — ack-level signed_at signing scope, cert-level
 * median computation, cert verification rejection paths, Bullshark anchor
 * monotonicity gate, genesis floor, and codec round-trip.
 *
 * Covers the consensus-core invariants the rest of the system relies on:
 *
 *   1. signed_at is part of the ack signature scope (tampering invalidates).
 *   2. cert.timestamp = exact median(acks.signed_at). Recomputable by any
 *      receiver — no author-side bumping.
 *   3. cert.hash includes timestamp; tampering with timestamp post-sign
 *      produces a hash mismatch.
 *   4. Median tolerates one byzantine outlier in 2f+1 inputs.
 *   5. Bullshark rejects anchors whose cert.timestamp <= last anchor's.
 *   6. Round 1 anchor is gated by `bft_time_genesis_ms` (genesis floor).
 *   7. Codec round-trips both fields through the wire format.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256 } = require(path.join(SHARED, "crypto"));
const PC = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));

beforeAll(async () => {
  await initCrypto();
});
const {
  createBatch, verifyBatch,
  createBatchAck, verifyBatchAck,
  computeMedianTimestamp,
  createCertificate, verifyCertificate,
  computeQuorum,
} = require(path.join(SRC, "consensus", "certificate"));
const {
  serializeBatchAck, deserializeBatchAck,
  serializeCertificate, deserializeCertificate,
} = require(path.join(SRC, "consensus", "certificate-codec"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));

// Synthetic node IDs and keys reused across tests.
function _makeKey() { return generateMLDSAKeypair(); }

// Helper: build a real cert from N committee nodes with explicit signed_ats.
function _buildCert(round, txs, parentHashes, signedAts, committeeKeys) {
  const author = committeeKeys[0];
  const batch = createBatch(round, author.nodeId, txs, author.privateKey);
  const acks = committeeKeys.map(({ nodeId, privateKey }, i) =>
    createBatchAck(batch.hash, nodeId, signedAts[i], privateKey)
  );
  const cert = createCertificate(round, author.nodeId, batch, acks, parentHashes, author.privateKey);
  return cert;
}

function _committee(n) {
  const keys = [];
  for (let i = 0; i < n; i++) {
    const kp = _makeKey();
    keys.push({ nodeId: `tip://node/n${i}`, ...kp });
  }
  return keys;
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. computeMedianTimestamp — pure helper
// ═══════════════════════════════════════════════════════════════════════════
describe("BFT-Time: computeMedianTimestamp", () => {
  test("odd count: returns exact middle element", () => {
    expect(computeMedianTimestamp([100, 200, 300, 400, 500])).toBe(300);
    expect(computeMedianTimestamp([5, 1, 3, 2, 4])).toBe(3);  // unsorted input
  });

  test("even count: floor((mid_low + mid_high) / 2) — deterministic integer", () => {
    expect(computeMedianTimestamp([100, 200, 300, 400])).toBe(Math.floor((200 + 300) / 2));
    expect(computeMedianTimestamp([1, 2, 3, 4])).toBe(2);  // floor((2+3)/2) = 2
  });

  test("byzantine outlier: one bad value cannot move the median (5-of-5)", () => {
    const honest = [1745851845100, 1745851845120, 1745851845150, 1745851845180];
    const byzantine = 9999999999999;
    const median = computeMedianTimestamp([...honest, byzantine]);
    // sorted: [100, 120, 150, 180, 9999999999999] — middle is 150
    expect(median).toBe(1745851845150);
  });

  test("rejects empty input", () => {
    expect(() => computeMedianTimestamp([])).toThrow();
  });

  test("rejects non-integer / non-positive entries", () => {
    expect(() => computeMedianTimestamp([1, 2, 0, 3])).toThrow();
    expect(() => computeMedianTimestamp([1, 2, -5, 3])).toThrow();
    expect(() => computeMedianTimestamp([1, 2, 3.5, 4])).toThrow();
    expect(() => computeMedianTimestamp([1, 2, "3", 4])).toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. BatchAck — signed_at in signature scope
// ═══════════════════════════════════════════════════════════════════════════
describe("BFT-Time: BatchAck signature includes signed_at", () => {
  let publicKey, privateKey;
  const nodeId = "tip://node/n0";
  let batchHash;
  const t = 1745851845000;

  beforeAll(() => {
    const kp = _makeKey();
    publicKey = kp.publicKey;
    privateKey = kp.privateKey;
    batchHash = shake256("test-batch");
  });

  test("createBatchAck binds signed_at into signature; verifyBatchAck accepts", () => {
    const ack = createBatchAck(batchHash, nodeId, t, privateKey);
    expect(ack.signed_at).toBe(t);
    expect(verifyBatchAck(ack, publicKey).valid).toBe(true);
  });

  test("tampered signed_at invalidates the ack signature", () => {
    const ack = createBatchAck(batchHash, nodeId, t, privateKey);
    const tampered = { ...ack, signed_at: t + 1 };
    expect(verifyBatchAck(tampered, publicKey).valid).toBe(false);
  });

  test("rejects ack with non-positive signed_at", () => {
    expect(() => createBatchAck(batchHash, nodeId, 0, privateKey)).toThrow();
    expect(() => createBatchAck(batchHash, nodeId, -1, privateKey)).toThrow();
  });

  test("rejects ack with non-integer signed_at", () => {
    expect(() => createBatchAck(batchHash, nodeId, 1.5, privateKey)).toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Certificate — median + hash includes timestamp + verification
// ═══════════════════════════════════════════════════════════════════════════
describe("BFT-Time: Certificate construction and verification", () => {
  let committee, getKey, quorum;

  beforeAll(() => {
    committee = _committee(3);  // quorum = 2
    getKey = (id) => {
      const k = committee.find(c => c.nodeId === id);
      return k ? k.publicKey : null;
    };
    quorum = computeQuorum(committee.length);
  });

  test("createCertificate sets cert.timestamp = median(acks.signed_at)", () => {
    const signedAts = [100, 200, 300];  // odd count → median = 200
    const cert = _buildCert(1, [], [], signedAts, committee);
    expect(cert.timestamp).toBe(200);
  });

  test("verifyCertificate accepts a freshly-built cert", () => {
    const cert = _buildCert(2, [], [], [1000, 1100, 1200], committee);
    const result = verifyCertificate(cert, getKey, quorum);
    expect(result.valid).toBe(true);
  });

  test("tampered cert.timestamp is rejected (hash mismatch)", () => {
    const cert = _buildCert(2, [], [], [1000, 1100, 1200], committee);
    const tampered = { ...cert, timestamp: cert.timestamp + 1 };
    const result = verifyCertificate(tampered, getKey, quorum);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/hash mismatch/i);
  });

  test("tampered ack.signed_at causes median mismatch in cert verification", () => {
    const cert = _buildCert(2, [], [], [1000, 1100, 1200], committee);
    const tamperedAcks = cert.acknowledgments.map((a, i) =>
      i === 0 ? { ...a, signed_at: 9999999 } : a
    );
    const tamperedCert = { ...cert, acknowledgments: tamperedAcks };
    const result = verifyCertificate(tamperedCert, getKey, quorum);
    expect(result.valid).toBe(false);
    // Either ack-sig fails first (most likely) or median mismatch fires.
    expect(result.error).toMatch(/(signature invalid|timestamp mismatch)/i);
  });

  test("missing cert.timestamp is rejected", () => {
    const cert = _buildCert(2, [], [], [1000, 1100, 1200], committee);
    const noTs = { ...cert, timestamp: 0 };
    const result = verifyCertificate(noTs, getKey, quorum);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/timestamp/i);
  });

  test("byzantine outlier in 2f+1 acks: cert.timestamp = honest median", () => {
    const c4 = _committee(4);
    const cert = _buildCert(2, [], [], [1000, 1100, 1200, 9999999999999], c4);
    const sorted = [1000, 1100, 1200, 9999999999999];
    const expected = Math.floor((sorted[1] + sorted[2]) / 2);  // floor((1100+1200)/2) = 1150
    expect(cert.timestamp).toBe(expected);
    expect(cert.timestamp).toBeLessThan(2000);  // outlier did NOT move median
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Codec round-trip — wire format preserves both fields
// ═══════════════════════════════════════════════════════════════════════════
describe("BFT-Time: codec round-trip", () => {
  let committee;

  beforeAll(() => {
    committee = _committee(3);
  });

  test("BatchAck signed_at survives serialize → deserialize", () => {
    const { publicKey, privateKey, nodeId } = committee[0];
    const ack = createBatchAck(shake256("b"), nodeId, 1745851845000, privateKey);
    const wire = serializeBatchAck(ack);
    const parsed = deserializeBatchAck(wire);
    expect(parsed.signed_at).toBe(ack.signed_at);
    expect(verifyBatchAck(parsed, publicKey).valid).toBe(true);
  });

  test("Certificate timestamp + ack signed_ats survive serialize → deserialize", () => {
    const cert = _buildCert(5, [], [], [1000, 1100, 1200], committee);
    const wire = serializeCertificate(cert);
    const parsed = deserializeCertificate(wire);
    expect(parsed.timestamp).toBe(cert.timestamp);
    expect(parsed.acknowledgments.map(a => a.signed_at))
      .toEqual(cert.acknowledgments.map(a => a.signed_at));
    expect(parsed.hash).toBe(cert.hash);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. Bullshark monotonicity gate + genesis floor
// ═══════════════════════════════════════════════════════════════════════════
describe("BFT-Time: Bullshark anchor monotonicity gate", () => {
  const NODE_ID = "tip://node/n1";
  const NODE_NAME = "n1";

  function _setup() {
    const dag = initDAG({ dbPath: ":memory:" });
    dag.saveNode({
      node_id: NODE_ID,
      name: NODE_NAME,
      public_key: "00",
      status: "active",
      registered_at: "2026-01-01T00:00:00.000Z",
    });
    return dag;
  }

  function _mkCert(round, timestamp, parentHashes = []) {
    return {
      hash: shake256(`cert:${round}:${NODE_ID}:${timestamp}`),
      round,
      author_node_id: NODE_ID,
      batch: { round, author_node_id: NODE_ID, txs: [], hash: shake256(`b:${round}`), signature: "00" },
      acknowledgments: [],
      parent_hashes: parentHashes,
      signature: "00",
      timestamp,
    };
  }

  function _drive(bullshark, dag, round, timestamp, parentHashes) {
    const proposeRound = round - 1;
    const proposeCert = _mkCert(proposeRound, timestamp, parentHashes);
    dag.saveCertificate(proposeCert);
    const voteCert = _mkCert(round, timestamp + 1, [proposeCert.hash]);
    dag.saveCertificate(voteCert);
    bullshark.onRoundComplete([voteCert], round);
    return proposeCert;
  }

  test("first anchor with cert.timestamp >= bft_time_genesis_ms commits", () => {
    const dag = _setup();
    const ts = PC.CONSENSUS.BFT_TIME_GENESIS_MS + 1000;
    const bullshark = createBullshark({
      dag,
      getNodeIds: () => [NODE_ID],
      onOrderedTxs: () => {},
    });
    _drive(bullshark, dag, 4, ts, []);
    expect(bullshark.stats().metrics.anchors_committed).toBe(1);
  });

  test("first anchor with cert.timestamp <= bft_time_genesis_ms is rejected (genesis floor)", () => {
    const dag = _setup();
    const ts = PC.CONSENSUS.BFT_TIME_GENESIS_MS;  // exactly at floor — rejected (must be strictly >)
    const bullshark = createBullshark({
      dag,
      getNodeIds: () => [NODE_ID],
      onOrderedTxs: () => {},
    });
    _drive(bullshark, dag, 4, ts, []);
    expect(bullshark.stats().metrics.anchors_committed).toBe(0);
  });

  test("subsequent anchor with cert.timestamp <= prev anchor is rejected (monotonicity)", () => {
    const dag = _setup();
    const t1 = PC.CONSENSUS.BFT_TIME_GENESIS_MS + 1000;
    const bullshark = createBullshark({
      dag,
      getNodeIds: () => [NODE_ID],
      onOrderedTxs: () => {},
    });
    const c1 = _drive(bullshark, dag, 4, t1, []);
    expect(bullshark.stats().metrics.anchors_committed).toBe(1);

    // Try to commit a later anchor with timestamp that goes BACKWARDS.
    _drive(bullshark, dag, 6, t1 - 1, [c1.hash]);
    expect(bullshark.stats().metrics.anchors_committed).toBe(1);  // still 1 — second rejected
  });

  test("monotonicity floor advances after each successful anchor commit", () => {
    const dag = _setup();
    const t0 = PC.CONSENSUS.BFT_TIME_GENESIS_MS + 1000;
    const bullshark = createBullshark({
      dag,
      getNodeIds: () => [NODE_ID],
      onOrderedTxs: () => {},
    });
    const c1 = _drive(bullshark, dag, 4, t0, []);
    const c2 = _drive(bullshark, dag, 6, t0 + 1000, [c1.hash]);
    _drive(bullshark, dag, 8, t0 + 2000, [c2.hash]);
    expect(bullshark.stats().metrics.anchors_committed).toBe(3);
  });
});
