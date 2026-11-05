/**
 * @file tests/consensus/bullshark-deterministic-commit.test.js
 * @description Nodes holding the same DAG commit the same anchors in the same groups, whenever each
 * vote certificate reached them, and only committee members' votes count.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));

beforeAll(async () => { await initCrypto(); });

const A = "tip://node/a";
const B = "tip://node/b";
const C = "tip://node/c";
const D = "tip://node/d";
const COMMITTEE = [A, B, C];
const T = CONSENSUS.BFT_TIME_GENESIS_MS + 60_000;
const ACTIVE = 0;
const LEGACY = Number.MAX_SAFE_INTEGER;

function cert(author, round, parents = []) {
  const tag = `${author}-${round}`;
  return {
    hash: shake256(`cert-${tag}`),
    round,
    author_node_id: author,
    signature: "00",
    timestamp: T + round * 1000,
    batch: { hash: shake256(`batch-${tag}`), txs: [{ tx_id: `tx-${tag}` }] },
    parent_hashes: parents.map((p) => p.hash),
    acknowledgments: [],
  };
}

function node(activationMs) {
  const dag = initDAG({ inMemory: true });
  const groups = [];
  const bullshark = createBullshark({
    dag,
    getNodeIds: () => COMMITTEE,
    onOrderedTxs: (txs, round) => {
      groups.push({ round, txs: txs.map((t) => t.tx_id) });
      return { committed: txs.length, dropped: 0 };
    },
    proposer: null,
    onMissingCertsTimeout: () => { },
    deterministicCommitActivationMs: activationMs,
  });
  const save = (...certs) => certs.forEach((c) => dag.saveCertificate(c));
  return { dag, bullshark, groups, save };
}

// Leaders: round 1 -> A, round 3 -> B. C's round 2 cert misses A1, and round 3 certs other than A's
// miss A2, so the anchor of round 3 reaches A1 only through B2.
function buildDag() {
  const a1 = cert(A, 1), b1 = cert(B, 1), c1 = cert(C, 1);
  const a2 = cert(A, 2, [a1, b1, c1]), b2 = cert(B, 2, [a1, b1, c1]), c2 = cert(C, 2, [b1, c1]);
  const a3 = cert(A, 3, [a2, b2, c2]), b3 = cert(B, 3, [b2, c2]), c3 = cert(C, 3, [b2, c2]);
  const a4 = cert(A, 4, [a3, b3, c3]), b4 = cert(B, 4, [b3, c3]), c4 = cert(C, 4, [b3, c3]);
  return { a1, b1, c1, a2, b2, c2, a3, b3, c3, a4, b4, c4 };
}

// X holds A's vote for A1 when it checks round 2; Y gets it only after committing round 4.
function runTwoViews(activationMs) {
  const d = buildDag();
  const x = node(activationMs);
  x.save(d.a1, d.b1, d.c1, d.a2, d.b2, d.c2);
  x.bullshark.onRoundComplete([], 2);
  x.save(d.a3, d.b3, d.c3, d.a4, d.b4, d.c4);
  x.bullshark.onRoundComplete([], 4);

  const y = node(activationMs);
  y.save(d.a1, d.b1, d.c1, d.b2, d.c2);
  y.bullshark.onRoundComplete([], 2);
  y.save(d.b3, d.c3, d.b4, d.c4);
  y.bullshark.onRoundComplete([], 4);
  y.save(d.a2, d.a3, d.a4);
  y.bullshark.onRoundComplete([], 2);
  y.bullshark.onRoundComplete([], 4);
  return { x, y, d };
}

describe("bullshark: the committed sequence depends on the DAG, not on vote arrival", () => {
  test("before the activation the two views commit different groups (the fork)", () => {
    const { x, y } = runTwoViews(LEGACY);
    expect(x.groups.map((g) => g.round)).toEqual([2, 4]);
    expect(y.groups.map((g) => g.round)).toEqual([4]);
    expect(y.groups).not.toEqual(x.groups);
  });

  test("from the activation a skipped anchor commits before the anchor that reaches it", () => {
    const { x, y } = runTwoViews(ACTIVE);
    expect(x.groups.map((g) => g.round)).toEqual([2, 4]);
    expect(y.groups).toEqual(x.groups);
    expect(y.groups[0].txs).toEqual(["tx-tip://node/a-1"]);
    expect(y.bullshark.stats().consensusIndex).toBe(x.bullshark.stats().consensusIndex);
    expect(y.bullshark.stats().metrics.anchors_committed_linked).toBe(1);
    expect(y.dag.getCommit(2).txs_merkle_root).toBe(x.dag.getCommit(2).txs_merkle_root);
    expect(y.dag.getCommit(4).state_merkle_root).toBe(x.dag.getCommit(4).state_merkle_root);
  });

  test("a node replaying the complete DAG commits the same sequence", () => {
    const { x, d } = runTwoViews(ACTIVE);
    const z = node(ACTIVE);
    z.save(...Object.values(d));
    z.bullshark.driveCommit(4);
    expect(z.groups).toEqual(x.groups);
  });

  test("an anchor no later anchor reaches is not committed, and its certs ride the next anchor", () => {
    const d = buildDag();
    const y = node(ACTIVE);
    // Without B2's link to A1 nothing reaches A1, so it never commits on its own.
    const b2 = cert(B, 2, [d.b1, d.c1]);
    const b3 = cert(B, 3, [b2, d.c2]), c3 = cert(C, 3, [b2, d.c2]);
    const b4 = cert(B, 4, [b3, c3]), c4 = cert(C, 4, [b3, c3]);
    y.save(d.a1, d.b1, d.c1, b2, d.c2, b3, c3, b4, c4);
    y.bullshark.onRoundComplete([], 2);
    y.bullshark.onRoundComplete([], 4);
    expect(y.groups.map((g) => g.round)).toEqual([4]);
    expect(y.groups[0].txs).not.toContain("tx-tip://node/a-1");
  });
});

describe("bullshark: only committee members vote on an anchor", () => {
  function supportFromOutsider(activationMs) {
    const a1 = cert(A, 1), b1 = cert(B, 1), c1 = cert(C, 1);
    const b2 = cert(B, 2, [a1, b1, c1]), c2 = cert(C, 2, [b1, c1]), d2 = cert(D, 2, [a1, b1, c1]);
    const n = node(activationMs);
    n.save(a1, b1, c1, b2, c2, d2);
    n.bullshark.onRoundComplete([], 2);
    return n;
  }

  test("a vote certificate from a registered node outside the committee does not count", () => {
    const n = supportFromOutsider(ACTIVE);
    expect(n.groups).toEqual([]);
    expect(n.bullshark.stats().metrics.anchors_no_support).toBe(1);
  });

  test("before the activation the outsider's vote still counts (old rule unchanged)", () => {
    const n = supportFromOutsider(LEGACY);
    expect(n.groups.map((g) => g.round)).toEqual([2]);
  });
});

describe("bullshark: an anchor never commits on a partial history", () => {
  test("a missing ancestor parks the anchor without moving the anchor count", () => {
    jest.useFakeTimers();
    try {
      const d = buildDag();
      const n = node(ACTIVE);
      n.save(d.a1, d.c1, d.b2, d.c2, d.b3, d.c3, d.b4, d.c4);   // b1, an ancestor of anchor B3, missing
      n.bullshark.onRoundComplete([], 4);
      expect(n.groups).toEqual([]);
      expect(n.bullshark.stats().consensusIndex).toBe(0);
      expect(n.bullshark.stats().metrics.anchors_deferred_incomplete_dag).toBe(1);

      n.save(d.b1);
      n.bullshark.onCertSaved(d.b1.hash);
      expect(n.groups.map((g) => g.round)).toEqual([2, 4]);
      expect(n.bullshark.stats().consensusIndex).toBe(2);
    } finally {
      jest.useRealTimers();
    }
  });
});
