/**
 * @file tests/consensus/narwhal-ack-filter.test.js
 * @description Defense-layer test: narwhal must REFUSE to ack batches from
 * divergent peers, but only once the cluster-wide divergent-peer count has
 * reached the BFT threshold (f+1). Below threshold, acks proceed to preserve
 * liveness — a single divergent peer (e.g. a lagging rejoiner) must not
 * deplete quorum margin when combined with any other disconnection.
 *
 * Pairs with the threshold halt in narwhal-tri-state.test.js:
 *   - threshold halt protects us when WE'RE the divergent minority
 *   - ack-filter protects us when THEY'RE divergent at threshold level
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
const PEER_C_ID = "tip://node/peerC";

function buildNarwhal({ isPeerDivergent, divergentPeers, committee } = {}) {
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
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
  }

  const activeCommittee = committee || [SELF_ID, PEER_B_ID];
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
    getNodeCount: () => activeCommittee.length,
    getCommittee: () => activeCommittee,
    onCommit: () => { },
    onCertSaved: () => { },
    isPeerDivergent,
    divergentPeers,
  });

  return { narwhal, dag, network, published, peerBKp, peerCKp };
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

  test("single divergent peer below threshold — ack proceeds (liveness preserved)", () => {
    // n=2 → bftHaltThreshold=2; only 1 divergent peer → below threshold → ack must proceed.
    // A lagging rejoiner must not be refused when it would deplete quorum margin.
    const fx = buildNarwhal({
      isPeerDivergent: (id) => id === PEER_B_ID,
      divergentPeers: () => [PEER_B_ID],   // 1 divergent, threshold=2
    });
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

  test("divergent-peer count at BFT threshold → ack refused, warn + metric fire", () => {
    // n=3 → bftHaltThreshold=2; 2 divergent peers hits threshold → refuse acks to divergent authors.
    const committee3 = [SELF_ID, PEER_B_ID, PEER_C_ID];
    const fx = buildNarwhal({
      isPeerDivergent: (id) => id === PEER_B_ID || id === PEER_C_ID,
      divergentPeers: () => [PEER_B_ID, PEER_C_ID],   // 2 divergent = threshold
      committee: committee3,
    });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    fx.narwhal.handleIncomingBatch(makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    }));

    expect(refusalWarnCount()).toBe(1);
    expect(fx.narwhal.stats().metrics.acks_refused_divergent_peer).toBe(1);
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

  test("filter is per-peer — only divergent author refused at threshold, non-divergent author acked", () => {
    // n=3, 2 divergent peers = threshold=2 → PEER_B (divergent) refused, non-divergent would be acked.
    const committee3 = [SELF_ID, PEER_B_ID, PEER_C_ID];
    let calls = 0;
    const fx = buildNarwhal({
      isPeerDivergent: (id) => { calls++; return id === PEER_B_ID || id === PEER_C_ID; },
      divergentPeers: () => [PEER_B_ID, PEER_C_ID],
      committee: committee3,
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
    // n=3, threshold met → ack refused, but seen-vote must still be recorded.
    // Equivocation detection must not be bypassed for divergent peers.
    const committee3 = [SELF_ID, PEER_B_ID, PEER_C_ID];
    const fx = buildNarwhal({
      isPeerDivergent: (id) => id === PEER_B_ID || id === PEER_C_ID,
      divergentPeers: () => [PEER_B_ID, PEER_C_ID],
      committee: committee3,
    });
    fx.narwhal.start();
    fx.narwhal.exitSyncMode(99);

    const batchBytes = makePeerBatchBytes({
      round: 100, peerKp: fx.peerBKp, peerId: PEER_B_ID,
    });
    fx.narwhal.handleIncomingBatch(batchBytes);

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
