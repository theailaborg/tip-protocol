/**
 * @file tests/consensus/deterministic-commit-sim.test.js
 * @description Real narwhal + bullshark + commit-handler nodes on the virtual-clock bus under the
 * deterministic commit rule, with a one-way slow link inside the committee and a registered node outside
 * it: the committee keeps committing, every node commits the same anchors with the same txs, nothing is
 * lost, and the outsider still earns the participation that admits it although its votes no longer count.
 * The bus delivers in whole rounds, so the vote-timing race itself is covered by
 * bullshark-deterministic-commit.test.js.
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

const ROUNDS = 24;
const OUTSIDER = 3;

function sameCommonPrefix(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i].round !== b[i].round || a[i].txIds.join() !== b[i].txIds.join()) return false;
  }
  return true;
}

test("a one-way slow committee link and an outsider: same anchors everywhere, no loss, outsider credited", async () => {
  const cluster = createInProcessCluster({ nodeCount: 4, committeeSize: 3, activationMs: 0 });
  try {
    // Node 1 sees node 2's batches and certs a round late; node 0 sees them on time.
    cluster.setDelay(2, 1, 1);
    const txIds = [];
    for (let t = 0; t < ROUNDS; t++) {
      txIds.push(cluster.nodes[t % 4].submitTx());
      await cluster.tickRound();
    }
    await cluster.tickRounds(4);

    const committee = cluster.nodes.slice(0, OUTSIDER);
    for (const n of committee) expect(n.bullshark.lastCommittedRound()).toBeGreaterThan(ROUNDS / 2);
    expect(cluster.nodes[OUTSIDER].narwhal.stats().metrics.own_certs_sealed).toBeGreaterThan(ROUNDS / 2);

    const groups = cluster.nodes.map((n) => n.committedGroups);
    for (let i = 0; i < groups.length; i++) {
      for (let j = i + 1; j < groups.length; j++) expect({ i, j, same: sameCommonPrefix(groups[i], groups[j]) }).toEqual({ i, j, same: true });
    }

    for (const txId of txIds) {
      const landed = committee.every((n) => n.dag.getTx(txId)) || cluster.commitHandlerRejections.has(txId);
      expect({ txId, landed }).toEqual({ txId, landed: true });
    }

    const outsiderId = cluster.nodes[OUTSIDER].nodeId;
    const credits = committee.map((n) => (n.dag.getRotationParticipation(0).find((r) => r.node_id === outsiderId) || {}).count || 0);
    expect(credits[0]).toBeGreaterThan(0);
    expect(new Set(committee.map((n) => n.bullshark.stats().consensusIndex)).size).toBe(1);
    expect(new Set(credits).size).toBe(1);
  } finally {
    cluster.stop();
  }
}, 120000);
