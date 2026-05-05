/**
 * @file tests/consensus/narwhal-partition-safety.test.js
 * @description Regression: 4-node committee, partition into {A,B}|{C,D} →
 * neither side advances. Locks the partition-safety property of cert-
 * history-based runtime committee:
 *
 *   round_advance(R) requires 2f+1 certs at R
 *   2f+1 certs at R requires peer cooperation
 *   peer cooperation across the partition is impossible
 *   ⇒ round R does not advance, K-window stays anchored, committee
 *     stays {A,B,C,D}, quorum stays 3 (out of 4) — UNREACHABLE by either
 *     half alone. Both sides halt. No split-brain.
 *
 * If runtime committee were derived from chain-of-trust (the §4 design),
 * this property would not hold cleanly because chain commits arrive at
 * different times on different nodes. With cert history, both sides see
 * the same DAG state (deterministic), so both compute the same committee
 * and reach the same conclusion: cannot advance.
 *
 * Single-node test (this file approximates a 4-node committee from one
 * narwhal's perspective): we register 4 nodes, seed cert history so all 4
 * are proven, and deliver only one peer's batch+ack to simulate the
 * surviving partition half ({self, peer_b}) where peers c and d are
 * unreachable. Verifies self can't seal its own cert (only 2 of 3 acks)
 * and round doesn't advance.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto, generateMLDSAKeypair, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { createNarwhal } = require(path.join(SRC, "consensus", "narwhal"));
const { createBatch, createBatchAck } = require(path.join(SRC, "consensus", "certificate"));
const { serializeBatch, serializeBatchAck } = require(path.join(SRC, "consensus", "certificate-codec"));
const { loadTypes, encode } = require(path.join(SRC, "network", "proto"));
const { getActiveCommittee } = require(path.join(SRC, "consensus", "participants"));
const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

const SELF_ID = "tip://node/self";
const PEER_B_ID = "tip://node/peerB";
const PEER_C_ID = "tip://node/peerC";
const PEER_D_ID = "tip://node/peerD";

function _seedProvenCertHistory(dag, nodeId, fromRound, toRound) {
  for (let r = fromRound; r <= toRound; r++) {
    const certHash = shake256(`seed-cert-${nodeId}-${r}`);
    dag.saveCertificate({
      hash: certHash, round: r, author_node_id: nodeId,
      signature: "00",
      batch: { txs: [], hash: shake256(`seed-batch-${nodeId}-${r}`) },
      parent_hashes: [], acknowledgments: [],
    });
  }
}

function build4NodeNarwhal({ currentRound = 1000 } = {}) {
  const selfKp = generateMLDSAKeypair();
  const peerBKp = generateMLDSAKeypair();
  const peerCKp = generateMLDSAKeypair();
  const peerDKp = generateMLDSAKeypair();

  const dag = initDAG({ inMemory: true });
  const peers = [
    [SELF_ID, selfKp], [PEER_B_ID, peerBKp],
    [PEER_C_ID, peerCKp], [PEER_D_ID, peerDKp],
  ];
  for (const [id, kp] of peers) {
    dag.saveNode({
      node_id: id, name: id, public_key: kp.publicKey,
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
  }
  // #75 atomic boundary: seed rotations with effective_round = N * EPOCH_LENGTH_ROUNDS
  // so producer-pause's `getCommitteeRotation(epochOf(round))` check passes for
  // every round up to the test's currentRound.
  const intervalCommits = CONSENSUS.COMMITTEE_ROTATION_INTERVAL_COMMITS;
  const epochLength = intervalCommits * 2;
  const maxEpoch = Math.floor(currentRound / epochLength);
  const fourCommittee = peers.map(([id, kp]) => ({ node_id: id, public_key: kp.publicKey }));
  for (let n = 1; n <= maxEpoch; n++) {
    dag.saveCommitteeRotation({
      rotation_number: n,
      effective_round: n * epochLength,
      committee: fourCommittee,
      prev_rotation: n - 1,
      signer_node_ids: [],
      signatures: [],
      payload_hash: `test-partition-rotation-${n}`,
      committed_at: "2026-01-01T00:00:00.000Z",
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
      [PEER_D_ID]: { publicKey: peerDKp.publicKey },
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
    getNodeCount: () => 4,
    getCommittee: (round) => getActiveCommittee(dag, round != null ? round : narwhal.currentRound()),
    onCommit: () => {},
    onCertSaved: () => {},
  });

  return { narwhal, dag, mempool, network, published, selfKp, peerBKp, peerCKp, peerDKp };
}

describe("narwhal — 4-node partition halts both halves (no split-brain)", () => {
  test("partition {self, peer_b} | {peer_c, peer_d}: surviving half cannot reach quorum=3", async () => {
    const fx = build4NodeNarwhal({ currentRound: 1000 });

    fx.narwhal.start();
    fx.narwhal.exitSyncMode(999);

    // Pre-condition: all 4 proven, quorum = ceil(2*4/3) = 3.
    const committee = getActiveCommittee(fx.dag, 1000);
    expect(committee.sort()).toEqual([SELF_ID, PEER_B_ID, PEER_C_ID, PEER_D_ID].sort());
    expect(fx.narwhal.stats().quorum).toBe(3);

    // Wait for self to build its batch.
    await new Promise(r => setTimeout(r, 50));
    expect(fx.narwhal.currentRound()).toBe(1000);

    // Simulate the surviving partition half: peer_b's ack lands.
    // peer_c and peer_d are unreachable — no batches, no acks.
    const selfBatch = createBatch(1000, SELF_ID, [], fx.selfKp.privateKey);
    const peerBAck = createBatchAck(
      selfBatch.hash, PEER_B_ID, Date.now(), fx.peerBKp.privateKey
    );
    fx.narwhal.handleIncomingAck(encode("BatchAck", serializeBatchAck(peerBAck)));

    // Self now has 2 acks (self + peer_b). Quorum is 3. Cert won't seal.
    // Wait long enough for any retry cycles to happen.
    await new Promise(r => setTimeout(r, 150));

    // Round did NOT advance — quorum unmeetable.
    expect(fx.narwhal.currentRound()).toBe(1000);
    expect(fx.narwhal.stats().metrics.certs_created).toBe(0);

    // Committee still {A,B,C,D} — no auto-shrink under partition.
    // K-window is anchored to currentRound which hasn't advanced.
    const committeeAfter = getActiveCommittee(fx.dag, fx.narwhal.currentRound());
    expect(committeeAfter.sort()).toEqual([SELF_ID, PEER_B_ID, PEER_C_ID, PEER_D_ID].sort());
    expect(fx.narwhal.stats().quorum).toBe(3);

    fx.narwhal.stop();
  }, 5000);

  test("control: full quorum (3 of 4 acks) DOES allow cert sealing", async () => {
    // Sanity-check the test harness: with 3 acks (self + peer_b + peer_c),
    // self's cert seals because acks (3) ≥ quorum (3). Confirms the prior
    // test's "no advance" outcome is from missing acks, not a harness bug.
    const fx = build4NodeNarwhal({ currentRound: 1000 });

    fx.narwhal.start();
    fx.narwhal.exitSyncMode(999);
    await new Promise(r => setTimeout(r, 50));

    const selfBatch = createBatch(1000, SELF_ID, [], fx.selfKp.privateKey);
    const ackB = createBatchAck(selfBatch.hash, PEER_B_ID, Date.now(), fx.peerBKp.privateKey);
    const ackC = createBatchAck(selfBatch.hash, PEER_C_ID, Date.now(), fx.peerCKp.privateKey);
    fx.narwhal.handleIncomingAck(encode("BatchAck", serializeBatchAck(ackB)));
    fx.narwhal.handleIncomingAck(encode("BatchAck", serializeBatchAck(ackC)));

    await new Promise(r => setTimeout(r, 100));

    // With 3 acks (self + B + C), cert should have sealed.
    expect(fx.narwhal.stats().metrics.certs_created).toBeGreaterThanOrEqual(1);

    fx.narwhal.stop();
  }, 5000);
});
