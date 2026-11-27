/**
 * @file tests/consensus/bullshark-snapshot-align.test.js
 * @description After a snapshot install the commit frontier and anchor count equal the snapshot's, lowered if needed.
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

beforeAll(async () => { await initCrypto(); });

const NODE = "tip://node/self";

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const bullshark = createBullshark({ dag, getNodeIds: () => [NODE], onOrderedTxs: () => { } });
  return { dag, bullshark };
}

function seedCert(dag, round) {
  const hash = shake256(`align-cert-${round}`);
  dag.saveCertificate({
    hash, round, author_node_id: NODE, signature: "00",
    batch: { txs: [], hash: shake256(`align-batch-${round}`) }, parent_hashes: [], acknowledgments: [],
  });
  return hash;
}

const BFT_T0 = require(path.join(SHARED, "protocol-constants")).CONSENSUS.BFT_TIME_GENESIS_MS + 1000;

// A cert with one tx; parents by (author, round).
function cert(dag, author, round, parents = []) {
  const hash = shake256(`align:${author}:${round}`);
  dag.saveCertificate({
    hash, round, author_node_id: author, signature: "00", acknowledgments: [], timestamp: BFT_T0 + round,
    batch: { round, author_node_id: author, txs: [{ tx_id: `tx-${author.slice(-2)}-${round}`, tx_type: "TEST", timestamp: BFT_T0 + round }], signature: "00" },
    parent_hashes: parents.map(([au, r]) => shake256(`align:${au}:${r}`)),
  });
  return hash;
}

describe("bullshark.alignToSnapshot", () => {
  test("a frontier past the snapshot is lowered: only the snapshot anchor's history stays ordered", () => {
    const { dag, bullshark } = setup();
    cert(dag, NODE, 147);
    cert(dag, NODE, 148, [[NODE, 147]]);
    cert(dag, NODE, 149, [[NODE, 148]]);            // the anchor committed at vote round 150
    cert(dag, NODE, 160, [[NODE, 149]]);
    bullshark.markOrderedUpTo(200);
    expect(bullshark.stats().orderedCertificates).toBe(4);

    bullshark.alignToSnapshot(150, 42);
    expect(bullshark.lastCommittedRound()).toBe(150);
    expect(bullshark.stats().orderedCertificates).toBe(3);   // 147..149, not 160
    expect(bullshark.stats().consensusIndex).toBe(42);
  });

  test("a frontier behind the snapshot moves up to it", () => {
    const { bullshark } = setup();
    bullshark.alignToSnapshot(300, 50);
    expect(bullshark.lastCommittedRound()).toBe(300);
    expect(bullshark.stats().consensusIndex).toBe(50);
  });

  test("after an install the next anchor orders only what the snapshot had not: no shipped cert twice, none skipped", () => {
    const N1 = "tip://node/n1", N2 = "tip://node/n2";
    const dag = initDAG({ dbPath: ":memory:" });
    const ordered = [];
    const bullshark = createBullshark({
      dag, getNodeIds: () => [N1, N2],
      onOrderedTxs: (txs) => { ordered.push(...txs.map(t => t.tx_id)); return { committed: txs.length, dropped: 0 }; },
    });
    const leader = (r) => bullshark.getLeader(r);
    const other = (r) => (leader(r) === N1 ? N2 : N1);
    // Shipped window (install): rounds 7..10. The anchor at 9 is committed by vote round 10.
    for (const au of [N1, N2]) cert(dag, au, 7);
    for (const au of [N1, N2]) cert(dag, au, 8, [[N1, 7], [N2, 7]]);
    cert(dag, leader(9), 9, [[N1, 8], [N2, 8]]);
    cert(dag, other(9), 9, [[N1, 8], [N2, 8]]);      // not in the anchor's history: ordered later
    for (const au of [N1, N2]) cert(dag, au, 10, [[N1, 9], [N2, 9]]);
    bullshark.alignToSnapshot(10, 5);
    // After the install: the next anchor (leader at 11) and its votes.
    cert(dag, leader(11), 11, [[N1, 10], [N2, 10]]);
    for (const au of [N1, N2]) cert(dag, au, 12, [[leader(11), 11]]);
    bullshark.driveCommit(12);

    const tag = (au, r) => `tx-${au.slice(-2)}-${r}`;
    expect(ordered.sort()).toEqual([tag(other(9), 9), tag(N1, 10), tag(N2, 10), tag(leader(11), 11)].sort());
    expect(bullshark.lastCommittedRound()).toBe(12);
  });
});
