/**
 * @file tests/consensus/anchor-walk-committed-frontier.test.js
 * @description Regression: the anchored-cert ancestry walk must STOP at an
 * already-ordered cert (the committed frontier). Below that frontier old certs
 * are GC'd (pruneCertificatesBefore); descending into them records false
 * "missing parent" gaps that park the anchor commit forever. That park is the
 * sub-quorum halt observed when a single committee node is lost: every anchor
 * references settled, GC'd history, so no peer is ahead to resync from and the
 * surviving quorum wedges.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(SHARED + "/crypto");
const { initDAG } = require(path.join(SRC, "dag"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));

beforeAll(async () => { await initCrypto(); });

function cert(round, parentHashes = []) {
  return {
    hash: shake256(`cert-${round}`),
    round,
    author_node_id: "tip://node/n",
    signature: "00",
    batch: { txs: [], hash: shake256(`batch-${round}`) },
    parent_hashes: parentHashes,
    acknowledgments: [],
  };
}

function makeBullshark(dag) {
  return createBullshark({
    dag,
    getNodeIds: () => ["tip://node/n"],
    onOrderedTxs: () => { },
    proposer: null,
    onMissingCertsTimeout: () => { },
  });
}

describe("anchor walk stops at the committed frontier", () => {
  test("a GC'd cert below an already-ordered cert is NOT a missing gap", () => {
    const dag = initDAG({ inMemory: true });
    // Construct on an EMPTY dag so the constructor doesn't pre-order saved certs.
    const bs = makeBullshark(dag);

    const g = cert(8);                   // deep history, will be GC'd
    const a = cert(9, [g.hash]);         // a -> g
    const anchor = cert(10, [a.hash]);   // anchor -> a
    dag.saveCertificate(g);
    dag.saveCertificate(a);
    dag.saveCertificate(anchor);

    // Walk a's chain while g is present: it completes and marks a, g as ordered.
    const first = bs._walkAnchoredCertChain(a);
    expect(first.missingHashes.size).toBe(0);

    // GC g (round 8 < 9) — the certificate-GC that runs on every healthy node.
    dag.pruneCertificatesBefore(9);
    expect(dag.getCertificate(g.hash)).toBeNull();

    // Walk the anchor: it reaches a (already ordered) and MUST stop there, not
    // descend into the GC'd g. No false gap -> the commit is never parked.
    const walk = bs._walkAnchoredCertChain(anchor);
    expect(walk.missingHashes.size).toBe(0);
    expect([...walk.missingHashes]).not.toContain(g.hash);
  });

  test("a genuinely-missing FRONTIER parent (not yet ordered) is still reported", () => {
    // Guards the 15c2d28 case: an un-ordered missing parent must still surface
    // so the resync path can pull it. The frontier bound only stops descent at
    // ALREADY-ordered certs, never at live frontier gaps.
    const dag = initDAG({ inMemory: true });
    const bs = makeBullshark(dag);
    const anchor = cert(10, [shake256("never-saved")]);
    dag.saveCertificate(anchor);

    const walk = bs._walkAnchoredCertChain(anchor);
    expect(walk.missingHashes.size).toBe(1);
  });
});
