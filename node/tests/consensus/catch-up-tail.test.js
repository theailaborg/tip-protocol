/**
 * @file tests/consensus/catch-up-tail.test.js
 * @description Layer-1 catch-up tail correctness on the deterministic cluster.
 *
 * The existing tests pin the join FSM at Layer 2 (narwhal-tri-state, peer-sync,
 * anti-entropy). This drives the same FSM end-to-end through a REAL multi-node
 * run: a node falls behind while the rest keep committing, then rejoins, walks
 * syncing -> catching_up -> ready, and its committed round converges to the
 * cluster head as it processes the real cert tail.
 *
 * The cluster stands in for peer-sync (replaying the captured cert tail) and the
 * orchestrator (calling markSnapshotInstalled / markCaughtUp), exactly the roles
 * anti-entropy + snapshot-handler play in production; narwhal's FSM and
 * bullshark's ordering are the real code under test.
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

const committedOf = (n) => n.bullshark.lastCommittedRound();

describe("catch-up tail (virtual clock, Layer-1)", () => {
  test("a node that fell behind rejoins, catches up its cert tail, and reaches ready", async () => {
    const cluster = createInProcessCluster({ nodeCount: 3 });
    try {
      await cluster.tickRounds(4);
      const joiner = cluster.nodes[2];

      // The node goes offline; the other two keep committing (quorum 2 of 3).
      cluster.partition(2);
      await cluster.tickRounds(10);
      const lead = Math.max(committedOf(cluster.nodes[0]), committedOf(cluster.nodes[1]));
      const behind = committedOf(joiner);
      expect(lead - behind).toBeGreaterThan(2); // it genuinely fell behind

      // Rejoin: walk the FSM syncing -> catching_up while the cluster replays the
      // cert tail (peer-sync's role), then assert the committed round converges.
      joiner.narwhal.enterSyncMode();
      expect(joiner.narwhal.joinState()).toBe("syncing");
      joiner.narwhal.markSnapshotInstalled(behind, lead);
      expect(joiner.narwhal.joinState()).toBe("catching_up");

      cluster.heal(2);
      await cluster.feedCertTail(2);
      await cluster.tickRounds(3);

      // The cert tail closed: the rejoiner caught up to the cluster head.
      expect(committedOf(joiner)).toBeGreaterThanOrEqual(lead);

      // Orchestrator marks it caught up: catching_up -> ready.
      joiner.narwhal.markCaughtUp(committedOf(joiner));
      expect(joiner.narwhal.joinState()).toBe("ready");
    } finally {
      cluster.stop();
    }
  });

  test("once ready, the rejoined node resumes committing in lockstep with the cluster", async () => {
    const cluster = createInProcessCluster({ nodeCount: 3 });
    try {
      await cluster.tickRounds(4);
      const joiner = cluster.nodes[2];

      cluster.partition(2);
      await cluster.tickRounds(8);
      const behind = committedOf(joiner);

      joiner.narwhal.enterSyncMode();
      joiner.narwhal.markSnapshotInstalled(behind, committedOf(cluster.nodes[0]));
      cluster.heal(2);
      await cluster.feedCertTail(2);
      await cluster.tickRounds(3);
      joiner.narwhal.markCaughtUp(committedOf(joiner));

      // Drive a few more rounds; all three should advance together now.
      const before = committedOf(joiner);
      await cluster.tickRounds(4);
      for (const n of cluster.nodes) expect(committedOf(n)).toBeGreaterThan(before);
      const rounds = cluster.nodes.map(committedOf);
      expect(Math.max(...rounds) - Math.min(...rounds)).toBeLessThanOrEqual(2);
    } finally {
      cluster.stop();
    }
  });
});
