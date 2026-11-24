/**
 * @file tests/consensus/bullshark-install-pause.test.js
 * @description Commit ordering pauses while a snapshot install runs and resumes
 * from the install's frontier, committing every anchor that arrived meanwhile
 * in order, exactly as an unpaused node would.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));
const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/n1";
const BFT_T0 = CONSENSUS.BFT_TIME_GENESIS_MS + 1000;

function makeCert(round, parentHashes, txs = []) {
  return {
    hash: shake256(`cert:${round}:${NODE_ID}`),
    round,
    author_node_id: NODE_ID,
    batch: { round, author_node_id: NODE_ID, txs, signature: "00" },
    acknowledgments: [],
    parent_hashes: parentHashes,
    signature: "00",
    timestamp: BFT_T0 + round,
  };
}

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: "00", status: "active", registered_at: 1767225600000 });
  const ordered = [];
  const bullshark = createBullshark({
    dag,
    getNodeIds: () => [NODE_ID],
    onOrderedTxs: (txs, voteRound) => {
      ordered.push({ voteRound, txIds: txs.map((t) => t.tx_id) });
      return { committed: txs.length, dropped: 0 };
    },
  });
  return { dag, bullshark, ordered };
}

// Saves `waves` propose/vote cert pairs (one tx per propose cert) and reports
// each vote round to bullshark, as narwhal does on round completion.
function feedWaves(dag, bullshark, waves) {
  let prev = null;
  let lastVote = 0;
  for (let i = 0; i < waves; i++) {
    const propose = 2 * i + 1;
    const pc = makeCert(propose, prev ? [prev] : [], [{ tx_id: `tx-${propose}`, tx_type: "TEST", timestamp: BFT_T0 + propose }]);
    dag.saveCertificate(pc);
    const vc = makeCert(propose + 1, [pc.hash]);
    dag.saveCertificate(vc);
    prev = vc.hash;
    lastVote = propose + 1;
    bullshark.onRoundComplete([vc], lastVote);
  }
  return lastVote;
}

describe("bullshark ordering pause during a snapshot install", () => {
  test("while paused no anchor commits; resuming commits every anchor in order, same as an unpaused node", () => {
    const control = setup();
    feedWaves(control.dag, control.bullshark, 4);

    const node = setup();
    node.bullshark.pauseOrdering();
    const lastVote = feedWaves(node.dag, node.bullshark, 4);
    expect(node.bullshark.orderingPaused()).toBe(true);
    expect(node.bullshark.lastCommittedRound()).toBe(0);
    expect(node.ordered).toHaveLength(0);
    expect(node.bullshark.stats().metrics.anchor_checks_paused).toBe(4);

    node.bullshark.resumeOrdering(lastVote);
    expect(node.bullshark.orderingPaused()).toBe(false);
    expect(node.bullshark.lastCommittedRound()).toBe(control.bullshark.lastCommittedRound());
    expect(node.ordered).toEqual(control.ordered);
    expect(node.ordered.map((o) => o.voteRound)).toEqual([2, 4, 6, 8]);
  });

  test("resume continues from a frontier raised by the install, committing only the anchors past it", () => {
    const node = setup();
    node.bullshark.pauseOrdering();
    const lastVote = feedWaves(node.dag, node.bullshark, 4);
    node.bullshark.cancelPendingCommit(4);   // the install's cut, as onSnapshotInstalled sets it
    node.bullshark.resumeOrdering(lastVote);
    expect(node.ordered.map((o) => o.voteRound)).toEqual([6, 8]);
    expect(node.bullshark.lastCommittedRound()).toBe(8);
  });
});
