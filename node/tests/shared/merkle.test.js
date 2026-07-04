/**
 * @file tests/shared/merkle.test.js
 * @description The unified merkle module: RFC-6962 discipline (L/N domain
 * separation, odd-node promotion), proof roundtrips at every size and
 * index, and the CVE-2012-2459 regression that odd-DUPLICATION would fail.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { leafHash, nodeHash, buildLevels, computeRoot, getProof, verifyProof, EMPTY_ROOT } =
  require(path.resolve(__dirname, "../../../shared/merkle"));
const { createMerkleTree } = require(path.resolve(__dirname, "../../src/sync/merkle-tree"));
const { computeTxsMerkleRoot, EMPTY_TXS_ROOT } =
  require(path.resolve(__dirname, "../../src/consensus/state-root"));

describe("shared/merkle core", () => {
  test("CVE-2012-2459 regression: [A,B,C] and [A,B,C,C] roots differ", () => {
    expect(computeRoot(["A", "B", "C"])).not.toBe(computeRoot(["A", "B", "C", "C"]));
  });

  test("domain separation: a leaf can never equal an internal node", () => {
    const a = leafHash("x");
    const b = leafHash("y");
    // the preimage of an internal node, fed as leaf DATA, must not forge it
    expect(leafHash(a + b)).not.toBe(nodeHash(a, b));
  });

  test("deterministic and order-sensitive", () => {
    expect(computeRoot(["a", "b", "c"])).toBe(computeRoot(["a", "b", "c"]));
    expect(computeRoot(["a", "b", "c"])).not.toBe(computeRoot(["c", "b", "a"]));
  });

  test("empty and singleton", () => {
    expect(computeRoot([])).toBe(EMPTY_ROOT());
    expect(computeRoot([], { emptyRoot: "custom" })).toBe("custom");
    expect(computeRoot(["only"])).toBe(leafHash("only"));
  });

  test("proof roundtrip: every index at sizes 1..9", () => {
    for (let n = 1; n <= 9; n++) {
      const items = Array.from({ length: n }, (_, i) => `item-${i}`);
      const levels = buildLevels(items.map(leafHash));
      const root = levels[levels.length - 1][0];
      for (let i = 0; i < n; i++) {
        const proof = getProof(levels, i);
        expect(proof).not.toBeNull();
        expect(verifyProof(items[i], proof, root)).toBe(true);
        expect(verifyProof("wrong-item", proof, root)).toBe(false);
      }
    }
  });

  test("tampered proof step fails", () => {
    const items = ["a", "b", "c", "d", "e"];
    const levels = buildLevels(items.map(leafHash));
    const root = levels[levels.length - 1][0];
    const proof = getProof(levels, 2);
    const tampered = proof.map((s, i) => (i === 0 ? { ...s, hash: leafHash("evil") } : s));
    expect(verifyProof(items[2], tampered, root)).toBe(false);
  });

  test("out-of-range proof requests return null", () => {
    const levels = buildLevels(["a", "b"].map(leafHash));
    expect(getProof(levels, -1)).toBeNull();
    expect(getProof(levels, 2)).toBeNull();
    expect(getProof([], 0)).toBeNull();
  });
});

describe("migrated consumers", () => {
  test("cert sync tree: proof roundtrip through the public API", () => {
    const tree = createMerkleTree();
    const certs = Array.from({ length: 7 }, (_, i) => `cert-hash-${i}`);
    tree.addBatch(certs);
    for (const c of certs) {
      const proof = tree.getProof(c);
      expect(proof).not.toBeNull();
      expect(tree.verifyProof(c, proof, tree.root())).toBe(true);
    }
    expect(tree.verifyProof("not-a-cert", tree.getProof(certs[0]), tree.root())).toBe(false);
  });

  test("cert sync tree: insertion order does not change the root (sorted leaves)", () => {
    const t1 = createMerkleTree();
    const t2 = createMerkleTree();
    t1.addBatch(["c", "a", "b"]);
    ["b", "c", "a"].forEach(h => t2.add(h));
    expect(t1.root()).toBe(t2.root());
  });

  test("txs root: promotion semantics, no duplication ambiguity", () => {
    const txs = (ids) => ids.map(tx_id => ({ tx_id }));
    expect(computeTxsMerkleRoot(txs(["t1", "t2", "t3"])))
      .not.toBe(computeTxsMerkleRoot(txs(["t1", "t2", "t3", "t3"])));
    expect(computeTxsMerkleRoot([])).toBe(EMPTY_TXS_ROOT);
    expect(computeTxsMerkleRoot(txs(["t1"]))).toBe(leafHash("t1"));
  });
});
