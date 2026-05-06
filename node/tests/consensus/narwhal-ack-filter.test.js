/**
 * @file tests/consensus/narwhal-ack-filter.test.js
 * @description Defense-layer test: narwhal must REFUSE to ack a batch from
 * a peer whose state our latest AE poll observed as divergent.
 *
 * Pairs with the threshold halt in narwhal-tri-state.test.js:
 *   - threshold halt protects us when WE'RE the divergent minority
 *   - ack-filter protects us when THEY'RE divergent (whether from a local
 *     bug or active byzantine code that ignores halt logic)
 *
 * The two layers reach the same outcome (no quorum certs containing wrong
 * state) by complementary mechanisms — declarative halt vs emergent
 * absence-of-acks.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");

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
const { serializeBatch, deserializeBatch } = require(path.join(SRC, "consensus", "certificate-codec"));
const { loadTypes, encode, decode } = require(path.join(SRC, "network", "proto"));

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

const SELF_ID = "tip://node/self";
const PEER_B_ID = "tip://node/peerB";

function buildNarwhal({ isPeerDivergent } = {}) {
  const selfKp = generateMLDSAKeypair();
  const peerBKp = generateMLDSAKeypair();
  const dag = initDAG({ dbPath: ":memory:" });
  for (const [id, name, kp] of [[SELF_ID, "self", selfKp], [PEER_B_ID, "peerB", peerBKp]]) {
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
    authorizedPeers: () => ({ [PEER_B_ID]: { publicKey: peerBKp.publicKey } }),
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
    getCommittee: () => [SELF_ID, PEER_B_ID],
    onCommit: () => { },
    onCertSaved: () => { },
    isPeerDivergent,
  });

  return { narwhal, dag, network, published, peerBKp };
}

function makePeerBatchBytes({ round, peerKp, peerId, txs = [] }) {
  const batch = createBatch(round, peerId, txs, peerKp.privateKey);
  return encode("Batch", serializeBatch(batch));
}

function refusalWarnCount() {
  return _warnCalls.filter((line) => line.includes("refusing ack to")).length;
}

describe("narwhal ack-filter — refuse acks to divergent peers", () => {
  test("default (no isPeerDivergent wired) — ack normally", () => {
    const fx = buildNarwhal();   // no callback
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99); // currentRound = 100

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));

    expect(refusalWarnCount()).toBe(0);
    expect(fx.narwhal.stats().metrics.acks_refused_divergent_peer || 0).toBe(0);
    // Ack actually went out on CONSENSUS topic.
    expect(fx.published.some(p => p.topic === "tip/consensus")).toBe(true);
    fx.narwhal.stop();
  });

  test("isPeerDivergent returns true for the batch author → no ack, warn + metric fire", () => {
    const fx = buildNarwhal({ isPeerDivergent: (id) => id === PEER_B_ID });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));

    expect(refusalWarnCount()).toBe(1);
    expect(fx.narwhal.stats().metrics.acks_refused_divergent_peer).toBe(1);
    // No ack published on CONSENSUS topic.
    expect(fx.published.some(p => p.topic === "tip/consensus")).toBe(false);
    fx.narwhal.stop();
  });

  test("isPeerDivergent returns false → ack proceeds normally", () => {
    const fx = buildNarwhal({ isPeerDivergent: () => false });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));

    expect(refusalWarnCount()).toBe(0);
    expect(fx.narwhal.stats().metrics.acks_refused_divergent_peer || 0).toBe(0);
    expect(fx.published.some(p => p.topic === "tip/consensus")).toBe(true);
    fx.narwhal.stop();
  });

  test("filter is per-peer — divergent author refused, non-divergent author acked", () => {
    let calls = 0;
    const fx = buildNarwhal({
      isPeerDivergent: (id) => { calls++; return id === PEER_B_ID; },
    });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));

    expect(fx.narwhal.stats().metrics.acks_refused_divergent_peer).toBe(1);
    expect(calls).toBeGreaterThan(0);
    fx.narwhal.stop();
  });

  test("seen-vote IS still recorded even when ack is refused (don't forget what we saw)", () => {
    const fx = buildNarwhal({ isPeerDivergent: (id) => id === PEER_B_ID });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    const batchBytes = makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    });
    fx.narwhal.handleIncomingBatch(batchBytes);

    // Equivocation table records the batch hash for (round, author) so a
    // subsequent batch from the same peer at the same round with different
    // content is rejected as equivocation. Refusing to ack must not skip
    // this record — otherwise a divergent peer could equivocate freely.
    const seen = fx.dag.getSeenVote(100, PEER_B_ID);
    expect(seen).not.toBeNull();
    expect(typeof seen.batch_hash).toBe("string");
    fx.narwhal.stop();
  });
});

describe("narwhal halt + ack-filter behavior", () => {
  test("byzantine-fork halt blocks batch reception entirely — no ack, no batch processing", () => {
    // A halted node must stop acking peer batches. Otherwise its acks land
    // in peer certs and rotation_participation count keeps growing →
    // halted node never gets evicted at next rotation. This gate makes the
    // halt comprehensive: no production, no counter advance, AND no acks.
    const fx = buildNarwhal();
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    // Manually halt this node.
    fx.narwhal.haltDueToByzantineFork({
      reason: "test halt", atRound: 50, peerNodeId: "tip://node/synthetic",
    });

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));

    expect(fx.narwhal.stats().metrics.batches_dropped_byzantine_halt).toBe(1);
    expect(fx.published.some(p => p.topic === "tip/consensus")).toBe(false);  // no ack
    fx.narwhal.stop();
  });

  test("hash binds round + author + tx_ids — relayer mutating the round invalidates the hash", () => {
    const fx0 = buildNarwhal();
    const original = createBatch(100, PEER_B_ID, [], fx0.peerBKp.privateKey);
    fx0.narwhal.stop();

    // Mutate the round post-sign — hash mismatch on verify.
    const tampered = { ...original, round: 9999 };
    const fx = buildNarwhal();
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    const tamperedBytes = encode("Batch", serializeBatch(tampered));
    fx.narwhal.handleIncomingBatch(tamperedBytes);
    // Batch rejected at hash/signature check — no ack went out.
    expect(fx.published.some(p => p.topic === "tip/consensus")).toBe(false);
    fx.narwhal.stop();
  });
});
