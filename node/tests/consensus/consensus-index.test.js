/**
 * @file tests/consensus/consensus-index.test.js
 * @description #44 — `consensus_index` semantics: monotonic counter of
 * EVERY anchor commit (tx-bearing or not), persisted across restarts via
 * the `consensus_meta` key-value table.
 *
 * Pre-#44 behavior: counter incremented only on tx-bearing rounds (gated
 * by `orderedTxs.length > 0`), so idle federations had `consensus_index=0`
 * indefinitely while anchors_committed ticked to 100+. Dashboards
 * reported the network as halted when it was perfectly healthy.
 *
 * Post-#44 contract:
 *   - Increments on every successful anchor commit (matches Mysten's
 *     `sub_dag_index` convention; same as anchors_committed but persisted)
 *   - Persisted via `consensus_meta` single-row kv table; survives
 *     restart with exact value
 *   - Commit rows still get `consensus_index` stamps but only on
 *     tx-bearing rounds, so commit-row indices have GAPS for empty
 *     anchors (the `idx_commits_index` UNIQUE constraint allows gaps)
 *
 * Setup mirrors gc-triggers.test.js: 1-node committee (quorum=1) so
 * each vote-round cert self-certifies and commits deterministically.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../../../shared/time");

const path = require("path");
const fs = require("fs");
const os = require("os");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));

beforeAll(async () => { await initCrypto(); });

// ── Test harness ─────────────────────────────────────────────────────────

const NODE_ID = "tip://node/n1";

function registerNode(dag) {
  dag.saveNode({
    node_id: NODE_ID,
    name: "n1",
    public_key: "00",
    status: "active",
    registered_at: 1767225600000,
  });
}

// BFT-Time monotonic floor for synthetic certs. Each call advances by 1ms
// so anchors land in strictly-increasing order, satisfying bullshark's
// monotonicity gate without coupling to wall-clock.
const BFT_T0 = 1773532801000; // 1ms past genesis floor
function _certTsForRound(round) {
  return BFT_T0 + round; // 1ms per round — strictly increasing
}

function makeCert(round, txs = [], parentHashes = []) {
  const hash = shake256(`cert:${round}:${NODE_ID}:${txs.length}`);
  return {
    hash,
    round,
    author_node_id: NODE_ID,
    batch: { round, author_node_id: NODE_ID, txs, signature: "00" },
    acknowledgments: [],
    parent_hashes: parentHashes,
    signature: "00",
    timestamp: _certTsForRound(round),
  };
}

/**
 * Drive N anchor commits. Each commit's batch carries `txsPerCommit`
 * txs — pass 0 to simulate an idle federation, pass >0 to simulate
 * tx-bearing rounds. Returns the final vote round reached.
 */
function driveCommits(bullshark, dag, count, { txsPerCommit = 0 } = {}) {
  const start = bullshark.lastCommittedRound() + 1;
  const firstPropose = start % 2 === 1 ? start : start + 1;

  let prevHash = null;
  if (firstPropose > 1) {
    const prior = dag.getCertificatesByRound(firstPropose - 1);
    if (prior.length > 0) prevHash = prior[0].hash;
  }

  for (let i = 0; i < count; i++) {
    const proposeRound = firstPropose + i * 2;
    const voteRound = proposeRound + 1;

    // The leader's anchor cert at proposeRound carries the txs to commit.
    const txs = txsPerCommit > 0
      ? Array.from({ length: txsPerCommit }, (_, k) => ({
        tx_id: shake256(`tx:${proposeRound}:${k}`),
        tx_type: "TEST",
        timestamp: 1767225600000,
        prev: [],
        data: { i: k },
      }))
      : [];

    const proposeCert = makeCert(proposeRound, txs, prevHash ? [prevHash] : []);
    dag.saveCertificate(proposeCert);
    const voteCert = makeCert(voteRound, [], [proposeCert.hash]);
    dag.saveCertificate(voteCert);
    prevHash = voteCert.hash;

    bullshark.onRoundComplete([voteCert], voteRound);
  }
}

function setupBullshark(dag) {
  registerNode(dag);
  const bullshark = createBullshark({
    dag,
    getNodeIds: () => [NODE_ID],
    onOrderedTxs: () => { /* no-op */ },
  });
  return bullshark;
}

// ═══════════════════════════════════════════════════════════════════════════

describe("#44 consensus_index — increments on every anchor commit (idle-network safe)", () => {
  test("idle federation: consensus_index ticks on every anchor even with zero txs", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const bullshark = setupBullshark(dag);

    driveCommits(bullshark, dag, 5, { txsPerCommit: 0 });

    expect(bullshark.stats().metrics.anchors_committed).toBe(5);
    expect(bullshark.stats().consensusIndex).toBe(5);    // CRITICAL: matches anchors, not 0
  });

  test("active federation: consensus_index matches anchor count, regardless of tx volume", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const bullshark = setupBullshark(dag);

    driveCommits(bullshark, dag, 3, { txsPerCommit: 5 });    // 3 tx-bearing
    driveCommits(bullshark, dag, 4, { txsPerCommit: 0 });    // 4 idle
    driveCommits(bullshark, dag, 2, { txsPerCommit: 1 });    // 2 tx-bearing

    expect(bullshark.stats().metrics.anchors_committed).toBe(9);
    expect(bullshark.stats().consensusIndex).toBe(9);        // same — pure anchor count
  });

  test("commit rows are still gated on tx-bearing rounds (no empty rows written)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const bullshark = setupBullshark(dag);

    driveCommits(bullshark, dag, 2, { txsPerCommit: 1 });    // anchors 1, 2 — written
    driveCommits(bullshark, dag, 3, { txsPerCommit: 0 });    // anchors 3, 4, 5 — no row written
    driveCommits(bullshark, dag, 1, { txsPerCommit: 1 });    // anchor 6 — written

    // 9 anchors total but only 3 commit rows (the tx-bearing ones).
    expect(bullshark.stats().consensusIndex).toBe(6);

    // Commit rows preserve the "this is anchor #N" stamp with gaps for
    // skipped idle rounds. Indices 1, 2, 6 — NOT 1, 2, 3.
    const commits = dag.getCommitsFromRound(0);
    expect(commits).toHaveLength(3);
    const indices = commits.map(c => c.consensus_index).sort((a, b) => a - b);
    expect(indices).toEqual([1, 2, 6]);                     // gap proves no empty rows
  });
});

describe("#44 consensus_index — persistence via consensus_meta", () => {
  test("counter survives DB close + reopen with exact value (idle case)", () => {
    const dbPath = path.join(os.tmpdir(), `tip-cidx-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
    try {
      const dag = initDAG({ dbPath });
      const bullshark = setupBullshark(dag);

      // 5 idle anchors — counter is in memory only, would be lost
      // without consensus_meta persistence (no commit rows written).
      driveCommits(bullshark, dag, 5, { txsPerCommit: 0 });
      expect(bullshark.stats().consensusIndex).toBe(5);

      // Close — flushes consensus_meta to disk.
      if (typeof dag.close === "function") dag.close();

      // Reopen — fresh bullshark instance, must recover counter.
      const dag2 = initDAG({ dbPath });
      const bullshark2 = setupBullshark(dag2);
      expect(bullshark2.stats().consensusIndex).toBe(5);    // exact recovery
      if (typeof dag2.close === "function") dag2.close();
    } finally {
      try { if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath); } catch { /* ignore */ }
    }
  });

  test("counter survives restart with mixed tx-bearing + idle history", () => {
    const dbPath = path.join(os.tmpdir(), `tip-cidx-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
    try {
      const dag = initDAG({ dbPath });
      const bullshark = setupBullshark(dag);

      driveCommits(bullshark, dag, 2, { txsPerCommit: 1 });
      driveCommits(bullshark, dag, 3, { txsPerCommit: 0 });
      driveCommits(bullshark, dag, 1, { txsPerCommit: 1 });
      expect(bullshark.stats().consensusIndex).toBe(6);

      if (typeof dag.close === "function") dag.close();

      const dag2 = initDAG({ dbPath });
      const bullshark2 = setupBullshark(dag2);
      expect(bullshark2.stats().consensusIndex).toBe(6);

      // After restart, next commit continues the sequence — no reset to
      // last commit-row's index (which would be 6 if recovered from
      // commits.consensus_index alone, but that's wrong if the restart
      // happened mid-idle-stretch).
      driveCommits(bullshark2, dag2, 1, { txsPerCommit: 1 });
      expect(bullshark2.stats().consensusIndex).toBe(7);
      if (typeof dag2.close === "function") dag2.close();
    } finally {
      try { if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath); } catch { /* ignore */ }
    }
  });

  test("legacy DB without consensus_meta: falls back to max(commits.consensus_index)", () => {
    // Simulates upgrading from a pre-#44 DB. The old column-on-commits
    // value is the floor; the in-memory counter starts there. Counter
    // may temporarily under-report on idle until next tx-bearing commit
    // re-anchors it via consensus_meta — that's acceptable, and exact
    // accuracy resumes from the next anchor.
    const dbPath = path.join(os.tmpdir(), `tip-cidx-legacy-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
    try {
      const dag = initDAG({ dbPath });
      registerNode(dag);

      // Manually seed the commits table as if we'd been running the old
      // gated-only behavior — 3 commit rows with consensus_index 1, 2, 3.
      for (let i = 1; i <= 3; i++) {
        dag.saveCommit({
          round: i * 2,
          anchor_cert_hash: shake256(`legacy:${i}`),
          leader_node_id: NODE_ID,
          committee: [NODE_ID],
          support_count: 1,
          consensus_index: i,
          committed_at: 1767225600000,
          state_merkle_root: "0".repeat(64),
          txs_merkle_root: "0".repeat(64),
          ack_signer_ids: [],
          ack_signatures: [],
        });
      }

      // No consensus_meta value yet — fresh bullshark must fall back to
      // max(commits.consensus_index) = 3.
      const bullshark = setupBullshark(dag);
      expect(bullshark.stats().consensusIndex).toBe(3);

      if (typeof dag.close === "function") dag.close();
    } finally {
      try { if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath); } catch { /* ignore */ }
    }
  });
});

describe("#44 consensus_meta accessors", () => {
  test("setConsensusMeta / getConsensusMeta round-trips", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    expect(dag.getConsensusMeta("missing")).toBeNull();
    dag.setConsensusMeta("foo", "42");
    expect(dag.getConsensusMeta("foo")).toBe("42");
    dag.setConsensusMeta("foo", "100");                     // replace, not append
    expect(dag.getConsensusMeta("foo")).toBe("100");
  });

  test("multiple keys coexist in the kv table", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    dag.setConsensusMeta("a", "1");
    dag.setConsensusMeta("b", "2");
    dag.setConsensusMeta("c", "3");
    expect(dag.getConsensusMeta("a")).toBe("1");
    expect(dag.getConsensusMeta("b")).toBe("2");
    expect(dag.getConsensusMeta("c")).toBe("3");
  });
});
