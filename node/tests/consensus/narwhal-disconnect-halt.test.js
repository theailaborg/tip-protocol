/**
 * @file tests/consensus/narwhal-disconnect-halt.test.js
 * @description Regression: 2-node committee, peer disconnects → round
 * advance halts. The K-window cannot slide past the disconnected peer's
 * last cert because round advance is gated by current quorum, and
 * current quorum is gated by cert history (which can't slide without
 * round advance). This circular gating is what gives the cert-history-
 * based runtime committee its partition safety property.
 *
 * Why this matters: under the old (§4) chain-of-trust runtime committee,
 * a chain rotation jumped quorum mid-flight — founding's view said 2,
 * node 2's view said 1, deadlock. The fix moved runtime committee to
 * cert history (gossip-replicated, deterministic across nodes). This
 * test pins the partition-safety side effect: a peer that goes offline
 * keeps the surviving node's quorum at the pre-disconnect size, so the
 * surviving node halts (rather than auto-shrinking and continuing alone,
 * which would risk split-brain if the "disconnected" peer is actually
 * still alive on the other side of a partition).
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
const PEER_ID = "tip://node/peer";

function _seedProvenCertHistory(dag, nodeId, fromRound, toRound) {
  // Seed certs for this nodeId across [fromRound, toRound] so the
  // proven-node filter (waveStartRound - earliest >= K) lets them
  // qualify as committee members.
  for (let r = fromRound; r <= toRound; r++) {
    const certHash = shake256(`seed-cert-${nodeId}-${r}`);
    dag.saveCertificate({
      hash: certHash,
      round: r,
      author_node_id: nodeId,
      signature: "00",
      batch: { txs: [], hash: shake256(`seed-batch-${nodeId}-${r}`) },
      parent_hashes: [],
      acknowledgments: [],
    });
  }
}

function buildNarwhal({ currentRound = 100 } = {}) {
  const selfKp = generateMLDSAKeypair();
  const peerKp = generateMLDSAKeypair();

  const dag = initDAG({ inMemory: true });
  dag.saveNode({
    node_id: SELF_ID, name: "self", public_key: selfKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  dag.saveNode({
    node_id: PEER_ID, name: "peer", public_key: peerKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });

  // Seed both as proven: certs from round 1 to currentRound-1.
  // K = COMMITTEE_ROTATION_HYSTERESIS_ROUNDS (default 300). For the proven
  // filter to pass at currentRound, earliest cert must be ≥ K rounds before
  // waveStart(currentRound). We seed from round 1, so any currentRound > K
  // works. Use currentRound = 1000 (well past K).
  const seedFromRound = 1;
  const seedToRound = currentRound - 1;
  _seedProvenCertHistory(dag, SELF_ID, seedFromRound, seedToRound);
  _seedProvenCertHistory(dag, PEER_ID, seedFromRound, seedToRound);

  const mempool = createMempool({ dag });

  const published = [];
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
    getCommittee: (round) => getActiveCommittee(dag, round != null ? round : narwhal.currentRound()),
    onCommit: () => {},
    onCertSaved: () => {},
  });

  return { narwhal, dag, mempool, network, published, selfKp, peerKp };
}

describe("narwhal — peer disconnect halts round advance (partition-safety property)", () => {
  test("2-node committee, peer offline: surviving node CANNOT advance past quorum-blocked round", async () => {
    const fx = buildNarwhal({ currentRound: 1000 });

    fx.narwhal.start();
    // exitSyncMode jumps currentRound to its arg + 1, bypassing snapshot/sync.
    fx.narwhal.exitSyncMode(999);
    expect(fx.narwhal.currentRound()).toBe(1000);

    // Pre-condition: committee derivation says quorum = 2 (both nodes proven).
    const committee = getActiveCommittee(fx.dag, 1000);
    expect(committee.sort()).toEqual([SELF_ID, PEER_ID].sort());
    expect(fx.narwhal.stats().quorum).toBe(2);

    // Let _beginRound run (scheduled with delay 0). Self builds batch +
    // self-ack but cannot reach quorum=2 without peer ack. _tryCreateCertificate
    // returns early (acks=1 < quorum=2). Round timer would normally fire but
    // we don't wait for it — we just verify state didn't advance.
    await new Promise(r => setTimeout(r, 50));

    const roundBefore = fx.narwhal.currentRound();
    const certsCreatedBefore = fx.narwhal.stats().metrics.certs_created;

    // Wait enough for any retry/round-timer activity. Critically, no peer
    // ack/batch is delivered in this window — peer is "offline."
    await new Promise(r => setTimeout(r, 100));

    // Round did NOT advance — self could not seal own cert (acks < quorum)
    // and _roundCertificates.size < quorum.
    expect(fx.narwhal.currentRound()).toBe(roundBefore);
    expect(fx.narwhal.stats().metrics.certs_created).toBe(certsCreatedBefore);

    // Committee derivation is still {self, peer} — K-window is anchored to
    // currentRound, which hasn't advanced, so the disconnected peer is NOT
    // dropped from the committee (no auto-shrink under disconnect).
    const committeeAfter = getActiveCommittee(fx.dag, fx.narwhal.currentRound());
    expect(committeeAfter.sort()).toEqual([SELF_ID, PEER_ID].sort());
    expect(fx.narwhal.stats().quorum).toBe(2);

    fx.narwhal.stop();
  }, 5000);

  test("peer returns: round advances once peer ack lands", async () => {
    const fx = buildNarwhal({ currentRound: 1000 });

    fx.narwhal.start();
    fx.narwhal.exitSyncMode(999);

    // Wait for self to build its batch.
    await new Promise(r => setTimeout(r, 50));

    const roundBefore = fx.narwhal.currentRound();
    expect(roundBefore).toBe(1000);

    // Reach into the published-batch list to find self's batch hash so
    // peer can build a valid ack for it. The batch is published on
    // network.TOPICS.MEMPOOL — but we can also reconstruct it: we know
    // self produced batch at round 1000 with empty txs (mempool empty).
    // Easier path: build peer's ack against self's known batch contents.
    //
    // Actually self's batch was constructed with createBatch(1000, SELF_ID,
    // [], selfPrivKey). createBatch is deterministic for the same inputs,
    // so we can reconstruct it.
    const selfBatch = createBatch(1000, SELF_ID, [], fx.selfKp.privateKey);

    // Peer sends ack of self's batch. signed_at is in ms.
    const peerAck = createBatchAck(
      selfBatch.hash, PEER_ID, Date.now(), fx.peerKp.privateKey
    );
    const ackBuf = encode("BatchAck", serializeBatchAck(peerAck));
    fx.narwhal.handleIncomingAck(ackBuf);

    // Peer also needs to send its own batch so self has a peer cert at
    // round 1000 (for _roundCertificates.size to reach quorum). Otherwise
    // even with self's cert sealed, _tryAdvanceRound sees only 1 cert.
    const peerBatch = createBatch(1000, PEER_ID, [], fx.peerKp.privateKey);
    const peerBatchBuf = encode("Batch", serializeBatch(peerBatch));
    fx.narwhal.handleIncomingBatch(peerBatchBuf);

    // Self acks peer's batch automatically inside handleIncomingBatch. Peer
    // would then ack peer's own batch and broadcast a cert; we simulate
    // peer's cert directly.
    // For the peer cert to form, peer needs 2 acks of its batch: peer's
    // self-ack + self's ack. Peer would build the cert and broadcast it.
    // We construct it here.
    const { createCertificate } = require(path.join(SRC, "consensus", "certificate"));
    const peerSelfAck = createBatchAck(peerBatch.hash, PEER_ID, Date.now(), fx.peerKp.privateKey);
    const selfAckOfPeerBatch = createBatchAck(peerBatch.hash, SELF_ID, Date.now(), fx.selfKp.privateKey);
    const peerCert = createCertificate(
      1000, PEER_ID, peerBatch,
      [peerSelfAck, selfAckOfPeerBatch],
      [],  // no parents (round 1000 isn't 1)
      fx.peerKp.privateKey
    );
    const { serializeCertificate } = require(path.join(SRC, "consensus", "certificate-codec"));
    const peerCertBuf = encode("Certificate", serializeCertificate(peerCert));
    fx.narwhal.handleIncomingCertificate(peerCertBuf);

    // Allow async processing.
    await new Promise(r => setTimeout(r, 200));

    // Round should now have advanced: self's cert formed (self+peer acks),
    // peer's cert delivered, _roundCertificates.size reached quorum=2.
    expect(fx.narwhal.currentRound()).toBeGreaterThan(roundBefore);

    fx.narwhal.stop();
  }, 5000);
});
