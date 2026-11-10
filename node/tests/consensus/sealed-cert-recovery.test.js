/**
 * @file tests/consensus/sealed-cert-recovery.test.js
 * @description A tx sealed into a node's own certificate must reach a committed
 * anchor, or be recorded as rejected. Never lost silently, never applied twice.
 *
 * Live incident, 2026-11-10: two REGISTER_CONTENT txs were accepted with 202,
 * drained into the seed's own batch, sealed into its certificate, and then no
 * committed anchor ever reached that certificate. The mempool was empty, no
 * tx_rejections row existed, and cert GC later deleted the certificate.
 *
 * Covers:
 *   1. requeue: own certificates still uncommitted after the requeue delay put
 *      their txs back at the front of the mempool, only from the activation;
 *   2. in-anchor dedup: from the activation a tx_id is applied at most once
 *      per anchor, so a requeued copy can never apply twice;
 *   3. no silent loss: a tx in an own certificate about to be pruned, never
 *      committed or rejected, gets a sealed_never_committed row.
 *
 * Runs on the virtual-clock cluster (tests/helpers/cluster.js). The cluster's
 * clock sits before the mainnet activation, so most tests set
 * TIP_SEALED_REQUEUE_ACTIVATION_MS=0.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { TX_REJECTION_REASON, SEALED_REQUEUE_ACTIVATION_MS } = require(path.join(SHARED, "constants"));
const { nowMs } = require(path.join(SHARED, "time"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));
const gate = require(path.join(SRC, "consensus", "sealed-requeue-gate"));
const { createInProcessCluster } = require(path.join(__dirname, "..", "helpers", "cluster"));

const ENV = "TIP_SEALED_REQUEUE_ACTIVATION_MS";
let savedEnv;
beforeAll(async () => { await initCrypto(); await loadTypes(); savedEnv = process.env[ENV]; });
afterAll(() => { if (savedEnv === undefined) delete process.env[ENV]; else process.env[ENV] = savedEnv; });
beforeEach(() => {
  process.env[ENV] = "0";
  jest.useFakeTimers({ doNotFake: ["setImmediate", "queueMicrotask", "nextTick"] });
});
afterEach(() => jest.useRealTimers());

const PEERS = [1, 2, 3];

// Ordered by consensus: on every DAG, or rejected by commit-handler after
// ordering (the cluster records only ordered txs there).
function ordered(cluster, txId) {
  return cluster.nodes.every((n) => n.dag.getTx(txId)) || cluster.commitHandlerRejections.has(txId);
}

function sealedNeverCommitted(cluster, txId) {
  return cluster.nodes.some((n) => {
    const r = n.dag.getTxRejection(txId);
    return r && r.reason === TX_REJECTION_REASON.SEALED_NEVER_COMMITTED;
  });
}

function certTopic(cluster, outTicks, inTicks) {
  for (const p of PEERS) {
    cluster.setTopicDelay(0, p, "certificates", outTicks);
    cluster.setTopicDelay(p, 0, "certificates", inTicks);
  }
}

function makeTx(tag) {
  const body = {
    tx_type: "REGISTER_CONTENT", timestamp: nowMs(), prev: [],
    data: { ctid: `tip://content/test-${tag}`, content_hash: shake256(`test-${tag}`) },
  };
  body.tx_id = computeTxId(body);
  return body;
}

describe("activation gate", () => {
  test("mainnet value, env override, and the 10-minute requeue margin", () => {
    delete process.env[ENV];
    expect(gate.sealedRequeueGateMs()).toBe(SEALED_REQUEUE_ACTIVATION_MS);
    expect(gate.inAnchorDedupActive(SEALED_REQUEUE_ACTIVATION_MS - 1)).toBe(false);
    expect(gate.inAnchorDedupActive(SEALED_REQUEUE_ACTIVATION_MS)).toBe(true);
    expect(gate.inAnchorDedupActive(0)).toBe(false);
    expect(gate.requeueActive(SEALED_REQUEUE_ACTIVATION_MS)).toBe(false);
    expect(gate.requeueActive(SEALED_REQUEUE_ACTIVATION_MS + gate.REQUEUE_SKEW_MARGIN_MS)).toBe(true);
    process.env[ENV] = "1000";
    expect(gate.sealedRequeueGateMs()).toBe(1000);
  });
});

describe("in-anchor dedup", () => {
  test("from the activation a tx_id inside one anchor is processed once; before it, as today", async () => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(2);
      const ch = cluster.nodes[0].commitHandler;
      const tx = makeTx("dedup");

      process.env[ENV] = "1000";
      const after = ch.commitOrderedTxs([tx, { ...tx }], 900001, { certTimestamp: 5000 });
      expect(ch.metrics().in_anchor_duplicates_skipped).toBe(1);

      const tx2 = makeTx("dedup-before");
      const before = ch.commitOrderedTxs([tx2, { ...tx2 }], 900003, { certTimestamp: 500 });
      expect(ch.metrics().in_anchor_duplicates_skipped).toBe(1);
      // From the activation only the first copy is handled (committed or
      // rejected); before it both copies are handled, exactly as on main.
      expect(after.dropped + after.committed).toBe(1);
      expect(before.dropped + before.committed).toBe(2);
    } finally {
      cluster.stop();
    }
  });
});

describe("sealed-but-never-committed recovery", () => {
  // Both delay patterns lost the tx silently on main (no commit, no rejection
  // row, not in the mempool): node0's certificates land after peers moved on,
  // and node0 skips a round, which cuts its own chain.
  test.each([
    ["node0 certificates 3 ticks late, peers' 1 tick late to node0", 3, 1, 6],
    ["node0 certificates 4 ticks late, peers' 2 ticks late to node0", 4, 2, 8],
  ])("%s: the sealed tx still reaches a committed anchor", async (_name, out, inn, win) => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(4);
      const txId = cluster.nodes[0].submitTx();
      certTopic(cluster, out, inn);
      for (let i = 0; i < win; i++) await cluster.tickRound();
      certTopic(cluster, 0, 0);
      await cluster.tickRounds(60);

      expect(ordered(cluster, txId)).toBe(true);
      expect(sealedNeverCommitted(cluster, txId)).toBe(false);
    } finally {
      cluster.stop();
    }
  }, 240000);

  test("requeue: a sealed certificate nobody links is requeued after 30 rounds, and the tx commits once", async () => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(4);
      const txId = cluster.nodes[0].submitTx();

      // The certificate node0 seals next reaches peers far too late to be
      // linked, and node0 seals nothing else for a long stretch.
      certTopic(cluster, 20, 0);
      await cluster.tickRound();
      expect(cluster.nodes[0].narwhal.stats().sealedAwaitingCommit).toBeGreaterThan(0);
      for (const p of PEERS) cluster.setTopicDelay(0, p, "mempool", 20);
      for (let i = 0; i < 20; i++) await cluster.tickRound();
      certTopic(cluster, 0, 0);
      for (const p of PEERS) cluster.setTopicDelay(0, p, "mempool", 0);
      await cluster.tickRounds(70);

      const n0 = cluster.nodes[0].narwhal.stats();
      expect(n0.metrics.sealed_txs_requeued).toBeGreaterThan(0);
      expect(ordered(cluster, txId)).toBe(true);
      expect(sealedNeverCommitted(cluster, txId)).toBe(false);
      for (const n of cluster.nodes) {
        const row = n.dag.getTx(txId);
        if (row) expect(row.tx_id).toBe(txId);
      }
      expect(n0.sealedAwaitingCommit).toBe(0);
    } finally {
      cluster.stop();
    }
  }, 240000);

  test("before the activation nothing is requeued: the due tx is only counted", async () => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(2);
      process.env[ENV] = String(nowMs() + 24 * 60 * 60 * 1000);
      const n0 = cluster.nodes[0];
      const tx = makeTx("pre-activation");
      n0.narwhal._noteOwnCertSealed({ hash: "d".repeat(64), round: -1000, batch: { txs: [tx] } });
      n0.narwhal._checkSealedAwaiting();

      expect(n0.mempool.has(tx.tx_id)).toBe(false);
      const m = n0.narwhal.stats().metrics;
      expect(m.sealed_txs_requeued).toBe(0);
      expect(m.sealed_requeue_before_activation).toBe(1);
      expect(n0.dag.getTxRejection(tx.tx_id)).toBeFalsy();
    } finally {
      cluster.stop();
    }
  });

  test("requeue budget: 3 requeues, then the tx is left alone and never marked rejected early", async () => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(2);
      const n0 = cluster.nodes[0];
      const tx = makeTx("budget");

      for (let i = 0; i < 4; i++) {
        n0.narwhal._noteOwnCertSealed({ hash: `${i}`.repeat(64), round: -1000, batch: { txs: [tx] } });
        n0.narwhal._checkSealedAwaiting();
        n0.mempool.remove([tx.tx_id]);
      }
      const m = n0.narwhal.stats().metrics;
      expect(m.sealed_txs_requeued).toBe(3);
      expect(m.sealed_requeue_budget_spent).toBe(1);
      expect(n0.dag.getTxRejection(tx.tx_id)).toBeFalsy();
    } finally {
      cluster.stop();
    }
  });

  test("settled txs are never requeued", async () => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(2);
      const n0 = cluster.nodes[0];
      const committed = makeTx("settled-committed");
      const rejected = makeTx("settled-rejected");
      n0.dag.addTx(committed);
      n0.dag.saveTxRejection({ tx_id: rejected.tx_id, reason: "revalidation_failed", dropper_node_id: n0.nodeId, tx_type: rejected.tx_type, tx_data: rejected });

      n0.narwhal._noteOwnCertSealed({ hash: "a".repeat(64), round: -1000, batch: { txs: [committed, rejected] } });
      n0.narwhal._checkSealedAwaiting();

      expect(n0.mempool.has(committed.tx_id)).toBe(false);
      expect(n0.mempool.has(rejected.tx_id)).toBe(false);
      expect(n0.narwhal.stats().metrics.sealed_txs_requeued).toBe(0);
      expect(n0.narwhal.stats().sealedAwaitingCommit).toBe(0);
    } finally {
      cluster.stop();
    }
  });

  test("cert GC sweep: only this node's own uncommitted txs get a row; committed, queued and peer txs do not", async () => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(2);
      const n0 = cluster.nodes[0];
      const lost = makeTx("gc-lost");
      const done = makeTx("gc-done");
      const queued = makeTx("gc-queued");
      const peers = makeTx("gc-peer");
      n0.dag.addTx(done);
      n0.dag.saveMempoolTx(queued);
      const base = { acknowledgments: [], parent_hashes: [], signature: "00", timestamp: nowMs() };
      n0.dag.saveCertificate({ ...base, hash: "b".repeat(64), round: 3, author_node_id: n0.nodeId, batch: { hash: "c".repeat(64), txs: [lost, done, queued] } });
      n0.dag.saveCertificate({ ...base, hash: "e".repeat(64), round: 3, author_node_id: cluster.nodes[1].nodeId, batch: { hash: "9".repeat(64), txs: [peers] } });

      const recorded = n0.bullshark._recordUnorderedBeforePrune(10);
      expect(recorded).toBe(1);
      expect(n0.dag.getTxRejection(lost.tx_id).reason).toBe(TX_REJECTION_REASON.SEALED_NEVER_COMMITTED);
      expect(n0.dag.getTxRejection(done.tx_id)).toBeFalsy();
      expect(n0.dag.getTxRejection(queued.tx_id)).toBeFalsy();
      expect(n0.dag.getTxRejection(peers.tx_id)).toBeFalsy();
      // The next sweep starts where this one ended: nothing is recorded twice.
      expect(n0.bullshark._recordUnorderedBeforePrune(10)).toBe(0);
    } finally {
      cluster.stop();
    }
  });
});
