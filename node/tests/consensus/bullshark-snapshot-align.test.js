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

describe("bullshark.alignToSnapshot", () => {
  test("a frontier past the snapshot is lowered and loses the ordered marks above it", () => {
    const { dag, bullshark } = setup();
    seedCert(dag, 140);
    seedCert(dag, 160);
    bullshark.markOrderedUpTo(200);
    expect(bullshark.stats().orderedCertificates).toBe(2);

    bullshark.alignToSnapshot(150, 42);
    expect(bullshark.lastCommittedRound()).toBe(150);
    expect(bullshark.stats().orderedCertificates).toBe(1);
    expect(bullshark.stats().consensusIndex).toBe(42);
  });

  test("a frontier behind the snapshot moves up to it", () => {
    const { bullshark } = setup();
    bullshark.alignToSnapshot(300, 50);
    expect(bullshark.lastCommittedRound()).toBe(300);
    expect(bullshark.stats().consensusIndex).toBe(50);
  });
});
