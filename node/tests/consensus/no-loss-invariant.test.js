/**
 * @file tests/consensus/no-loss-invariant.test.js
 * @description No-loss invariant on the deterministic in-process cluster.
 *
 * The consensus pipeline's most important safety property: once a tx enters the
 * mempool it MUST either land on every honest node's DAG or be explicitly
 * rejected by commit-handler. Never silent loss. A tx that is neither persisted
 * nor recorded as rejected vanished somewhere in narwhal/bullshark, the exact
 * bug class behind the late-batch and fast-forward-clobber P1s.
 *
 * Runs on the virtual-clock cluster (tests/helpers/cluster.js): explicit ticks,
 * controllable per-edge delays, millisecond runtime.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto } = require(path.join(SHARED, "crypto"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));
const { createInProcessCluster } = require(path.join(__dirname, "..", "helpers", "cluster"));

beforeAll(async () => { await initCrypto(); await loadTypes(); });
beforeEach(() => jest.useFakeTimers({ doNotFake: ["setImmediate", "queueMicrotask", "nextTick"] }));
afterEach(() => jest.useRealTimers());

// Assert the no-loss invariant for a set of submitted tx ids: each is on EVERY
// node's DAG, or is in the cluster's commit-handler rejection log. Never silent.
function assertNoLoss(cluster, txIds) {
  for (const txId of txIds) {
    const landed = cluster.nodes.every((n) => n.dag.getTx(txId));
    const rejected = cluster.commitHandlerRejections.has(txId);
    expect({ txId, landedOrRejected: landed || rejected }).toEqual({ txId, landedOrRejected: true });
  }
}

describe("consensus no-loss invariant (virtual clock)", () => {
  test("liveness: a healthy 3-node cluster advances anchor commits via the virtual clock", async () => {
    const cluster = createInProcessCluster({ nodeCount: 3 });
    try {
      await cluster.tickRounds(5);
      for (const n of cluster.nodes) expect(n.bullshark.lastCommittedRound()).toBeGreaterThan(0);
    } finally {
      cluster.stop();
    }
  });

  test("30 txs across 3 nodes: every tx lands on every DAG or is explicitly rejected", async () => {
    const cluster = createInProcessCluster({ nodeCount: 3 });
    try {
      const txIds = [];
      for (let i = 0; i < 30; i++) txIds.push(cluster.nodes[i % 3].submitTx());
      await cluster.tickRounds(14);
      assertNoLoss(cluster, txIds);
    } finally {
      cluster.stop();
    }
  });

  test("with a delayed edge, no tx is silently lost", async () => {
    const cluster = createInProcessCluster({ nodeCount: 3 });
    try {
      // Hold one edge back a couple of ticks to scramble message ordering; BFT
      // retries/rebroadcasts should still get every tx committed or rejected.
      cluster.setDelay(0, 1, 2);
      const txIds = [];
      for (let i = 0; i < 9; i++) txIds.push(cluster.nodes[i % 3].submitTx());
      await cluster.tickRounds(18);
      assertNoLoss(cluster, txIds);
    } finally {
      cluster.stop();
    }
  });
});
