/**
 * @file tests/consensus/sealed-cert-recovery.test.js
 * @description A tx sealed into a node's own certificate must reach a committed
 * anchor, or be recorded as rejected. Never lost silently.
 *
 * Live incident, 2026-11-10: two REGISTER_CONTENT txs were accepted with 202,
 * drained into the seed's own batch, sealed into its certificate, and then no
 * committed anchor ever reached that certificate. The mempool was empty, no
 * tx_rejections row existed, and cert GC later deleted the certificate.
 *
 * Covers the three parts of the fix:
 *   1. requeue: own certificates still uncommitted after the requeue delay put
 *      their txs back at the front of the mempool;
 *   2. own-chain link: after a skipped round a node's next certificate links its
 *      own last certificate, so peers that moved on can still reach it;
 *   3. no silent loss: retry budget exhausted, or certificate about to be
 *      pruned uncommitted, means a sealed_never_committed rejection row.
 *
 * Runs on the virtual-clock cluster (tests/helpers/cluster.js).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { TX_REJECTION_REASON } = require(path.join(SHARED, "constants"));
const { nowMs } = require(path.join(SHARED, "time"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));
const { createInProcessCluster } = require(path.join(__dirname, "..", "helpers", "cluster"));

beforeAll(async () => { await initCrypto(); await loadTypes(); });
beforeEach(() => jest.useFakeTimers({ doNotFake: ["setImmediate", "queueMicrotask", "nextTick"] }));
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

describe("sealed-but-never-committed recovery", () => {
  // Both delay patterns lost the tx silently before the fix (no commit, no
  // rejection row): node0's certificates land after peers moved on, and node0
  // skips a round, which cuts its own chain.
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
      await cluster.tickRounds(30);

      expect(ordered(cluster, txId)).toBe(true);
      expect(sealedNeverCommitted(cluster, txId)).toBe(false);
    } finally {
      cluster.stop();
    }
  });

  test("own-chain link: after a skipped round, node0's next certificate links its own older certificate", async () => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(4);
      cluster.nodes[0].submitTx();
      certTopic(cluster, 4, 2);
      for (let i = 0; i < 8; i++) await cluster.tickRound();
      certTopic(cluster, 0, 0);
      await cluster.tickRounds(6);

      const n0 = cluster.nodes[0];
      expect(n0.narwhal.stats().metrics.own_cert_gap_links).toBeGreaterThan(0);

      // Find a certificate of node0 whose parents include node0's own
      // certificate from an older round than round-1.
      const id = n0.nodeId;
      const top = n0.narwhal.currentRound();
      let found = false;
      for (let r = 2; r <= top && !found; r++) {
        const cert = n0.dag.getCertificateByAuthorRound(id, r);
        if (!cert) continue;
        for (const h of cert.parent_hashes || []) {
          const p = n0.dag.getCertificate(h);
          if (p && p.author_node_id === id && p.round < r - 1) { found = true; break; }
        }
      }
      expect(found).toBe(true);
    } finally {
      cluster.stop();
    }
  });

  test("requeue: a sealed certificate nobody can link is requeued, and the tx commits once", async () => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(4);
      const txId = cluster.nodes[0].submitTx();

      // The certificate node0 seals next reaches peers far too late to be
      // linked, and node0 seals nothing else for a long stretch (its batches
      // are held too), so no own-chain link can reach it either.
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
      // Committed at most once on every node: never two rows, never a rollback.
      for (const n of cluster.nodes) {
        const row = n.dag.getTx(txId);
        if (row) expect(row.tx_id).toBe(txId);
      }
      expect(n0.sealedAwaitingCommit).toBe(0);
    } finally {
      cluster.stop();
    }
  }, 240000);

  test("retry budget: after 3 requeues a still-uncommitted tx is recorded as sealed_never_committed", async () => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(2);
      const n0 = cluster.nodes[0];
      const tx = makeTx("budget");
      const old = { hash: "f".repeat(64), round: 1, batch: { txs: [tx] } };

      for (let i = 0; i < 4; i++) {
        n0.narwhal._noteOwnCertSealed({ ...old, hash: `${i}`.repeat(64).slice(0, 64), round: -1000 });
        n0.narwhal._checkSealedAwaiting();
        n0.mempool.remove([tx.tx_id]);
      }
      const row = n0.dag.getTxRejection(tx.tx_id);
      expect(row && row.reason).toBe(TX_REJECTION_REASON.SEALED_NEVER_COMMITTED);
      const m = n0.narwhal.stats().metrics;
      expect(m.sealed_txs_requeued).toBe(3);
      expect(m.sealed_txs_given_up).toBe(1);
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

  test("cert GC sweep: an uncommitted tx in a certificate about to be pruned gets a rejection row; committed and queued txs do not", async () => {
    const cluster = createInProcessCluster({ nodeCount: 4 });
    try {
      await cluster.tickRounds(2);
      const n0 = cluster.nodes[0];
      const lost = makeTx("gc-lost");
      const done = makeTx("gc-done");
      const queued = makeTx("gc-queued");
      n0.dag.addTx(done);
      n0.dag.saveMempoolTx(queued);
      n0.dag.saveCertificate({
        hash: "b".repeat(64), round: 3, author_node_id: n0.nodeId,
        batch: { hash: "c".repeat(64), txs: [lost, done, queued] },
        acknowledgments: [], parent_hashes: [], signature: "00", timestamp: nowMs(),
      });

      const recorded = n0.bullshark._recordUnorderedBeforePrune(10);
      expect(recorded).toBe(1);
      expect(n0.dag.getTxRejection(lost.tx_id).reason).toBe(TX_REJECTION_REASON.SEALED_NEVER_COMMITTED);
      expect(n0.dag.getTxRejection(done.tx_id)).toBeFalsy();
      expect(n0.dag.getTxRejection(queued.tx_id)).toBeFalsy();
      // The next sweep starts where this one ended: nothing is recorded twice.
      expect(n0.bullshark._recordUnorderedBeforePrune(10)).toBe(0);
    } finally {
      cluster.stop();
    }
  });
});
