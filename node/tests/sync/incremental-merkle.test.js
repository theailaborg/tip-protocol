/**
 * @file tests/sync/incremental-merkle.test.js
 * @description Determinism guard for the incremental cert-DAG merkle (#1).
 * The persistent tree is maintained with add()/addBatch() per cert and
 * re-sourced on the GC tick (onCertsPruned). Its root MUST be byte-identical
 * to a full rebuild over the same live cert set, regardless of insert order,
 * and must re-align with the live set after a prune. The sorted-leaf invariant
 * guarantees this; these tests pin it so a future change can't silently diverge
 * the incremental root from the canonical one.
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
const { createSyncHandler } = require(path.join(SRC, "sync", "sync-handler"));
const { createMerkleTree } = require(path.join(SRC, "sync", "merkle-tree"));

beforeAll(async () => { await initCrypto(); });

function cert(round, i) {
  return {
    hash: shake256(`cert-${round}-${i}`),
    round,
    author_node_id: `tip://node/n${i}`,
    signature: "00",
    batch: { txs: [], hash: shake256(`batch-${round}-${i}`) },
    parent_hashes: [],
    acknowledgments: [],
  };
}

// The canonical root: a from-scratch tree over exactly the live cert set.
function fullRoot(dag) {
  return createMerkleTree({ initialHashes: dag.getAllCertificateHashes() }).root();
}

function makeHandler(dag) {
  return createSyncHandler({ dag, network: {}, isAuthorizedPeer: () => true });
}

describe("incremental cert-DAG merkle", () => {
  test("incremental add() yields the same root as a full rebuild", () => {
    const dag = initDAG({ inMemory: true });
    const sh = makeHandler(dag);
    for (let r = 1; r <= 10; r++) {
      for (let i = 0; i < 3; i++) {
        const c = cert(r, i);
        dag.saveCertificate(c);
        sh.onCertificateCommitted(c.hash);
      }
    }
    expect(sh.merkleRoot()).toBe(fullRoot(dag));
  });

  test("root is independent of add order (sorted-leaf invariant)", () => {
    const dag = initDAG({ inMemory: true });
    const sh = makeHandler(dag);
    const certs = [];
    for (let r = 1; r <= 8; r++) for (let i = 0; i < 2; i++) certs.push(cert(r, i));
    for (const c of certs) dag.saveCertificate(c);
    // add the leaves in REVERSE order — the sorted insert must still converge.
    for (const c of [...certs].reverse()) sh.onCertificateCommitted(c.hash);
    expect(sh.merkleRoot()).toBe(fullRoot(dag));
  });

  test("onCertsPruned re-aligns the root with the post-GC live set", () => {
    const dag = initDAG({ inMemory: true });
    const sh = makeHandler(dag);
    for (let r = 1; r <= 12; r++) {
      for (let i = 0; i < 2; i++) {
        const c = cert(r, i);
        dag.saveCertificate(c);
        sh.onCertificateCommitted(c.hash);
      }
    }
    const beforeRoot = sh.merkleRoot();

    // The bullshark GC prunes rounds < 8; the handler re-sources its tree.
    dag.pruneCertificatesBefore(8);
    sh.onCertsPruned();

    expect(dag.getAllCertificateHashes().length).toBe(2 * 5); // rounds 8..12
    expect(sh.merkleRoot()).toBe(fullRoot(dag));   // matches a fresh build
    expect(sh.merkleRoot()).not.toBe(beforeRoot);  // and is not the stale pre-prune root
  });
});
