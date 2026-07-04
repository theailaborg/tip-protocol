/**
 * @file tests/shared/smt.test.js
 * @description Sparse merkle tree (#88 core): the root must be a pure
 * function of the key set , any insertion order, any deletion order, any
 * update path must converge to identical roots , and every key must yield
 * a verifiable inclusion proof while every absent key yields a verifiable
 * non-inclusion proof.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { createSMT, verifySMTProof, EMPTY_SMT_ROOT } =
  require(path.resolve(__dirname, "../../../shared/smt"));
const { shake256 } = require(path.resolve(__dirname, "../../../shared/crypto"));

// deterministic PRNG , reproducible fuzz
function lcg(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}

function shuffled(arr, rnd) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

const K = (s) => shake256(`key-${s}`);
const V = (s) => shake256(`val-${s}`);

describe("SMT , root is a pure function of the key set", () => {
  test("insertion order can never change the root (20 permutations of 50 keys)", () => {
    const entries = Array.from({ length: 50 }, (_, i) => [K(i), V(i)]);
    const rnd = lcg(42);
    const roots = new Set();
    for (let p = 0; p < 20; p++) {
      const t = createSMT();
      for (const [k, v] of shuffled(entries, rnd)) t.set(k, v);
      roots.add(t.root());
    }
    expect(roots.size).toBe(1);
  });

  test("delete is a true inverse: insert A∪B then delete B == insert A only", () => {
    const rnd = lcg(7);
    for (let round = 0; round < 10; round++) {
      const A = Array.from({ length: 30 }, (_, i) => [K(`a${round}-${i}`), V(i)]);
      const B = Array.from({ length: 20 }, (_, i) => [K(`b${round}-${i}`), V(i)]);

      const ref = createSMT();
      for (const [k, v] of A) ref.set(k, v);

      const t = createSMT();
      for (const [k, v] of shuffled([...A, ...B], rnd)) t.set(k, v);
      for (const [k] of shuffled(B, rnd)) expect(t.remove(k)).toBe(true);

      expect(t.root()).toBe(ref.root());
      expect(t.size()).toBe(A.length);
    }
  });

  test("value update changes the root; rewriting the same value does not", () => {
    const t = createSMT();
    t.set(K(1), V(1));
    t.set(K(2), V(2));
    const r1 = t.root();
    t.set(K(1), V("new"));
    expect(t.root()).not.toBe(r1);
    t.set(K(1), V(1));
    expect(t.root()).toBe(r1);
  });

  test("empty tree root is the sentinel; clear() restores it", () => {
    const t = createSMT();
    expect(t.root()).toBe(EMPTY_SMT_ROOT());
    t.set(K(1), V(1));
    t.clear();
    expect(t.root()).toBe(EMPTY_SMT_ROOT());
    expect(t.size()).toBe(0);
  });

  test("removing an absent key is a no-op and reports false", () => {
    const t = createSMT();
    t.set(K(1), V(1));
    const r = t.root();
    expect(t.remove(K("absent"))).toBe(false);
    expect(t.root()).toBe(r);
    expect(t.size()).toBe(1);
  });

  test("long-common-prefix keys: split chains build and collapse correctly", () => {
    // handcrafted keys sharing a 24-bit prefix , forces deep split chains
    const p = "abcdef";
    const keys = ["0", "1", "2", "3"].map(sfx => p + shake256(`tail${sfx}`).slice(6));
    const ref = createSMT();
    ref.set(keys[0], V(0));

    const t = createSMT();
    keys.forEach((k, i) => t.set(k, V(i)));
    for (let i = 3; i >= 1; i--) expect(t.remove(keys[i])).toBe(true);

    expect(t.root()).toBe(ref.root());
  });
});

describe("SMT proofs", () => {
  function build(n) {
    const t = createSMT();
    const entries = Array.from({ length: n }, (_, i) => [K(i), V(i)]);
    for (const [k, v] of entries) t.set(k, v);
    return { t, entries };
  }

  test("inclusion proof verifies for every key; wrong value fails", () => {
    const { t, entries } = build(40);
    const root = t.root();
    for (const [k, v] of entries) {
      const proof = t.getProof(k);
      expect(verifySMTProof(root, k, v, proof)).toBe(true);
      expect(verifySMTProof(root, k, V("forged"), proof)).toBe(false);
    }
  });

  test("non-inclusion proof verifies for absent keys (empty and mismatched-leaf terminals)", () => {
    const { t } = build(40);
    const root = t.root();
    let emptyTerminals = 0, leafTerminals = 0;
    for (let i = 0; i < 40; i++) {
      const absent = K(`absent-${i}`);
      const proof = t.getProof(absent);
      if (proof.terminal === null) emptyTerminals++; else leafTerminals++;
      expect(verifySMTProof(root, absent, null, proof)).toBe(true);
      expect(verifySMTProof(root, absent, V(1), proof)).toBe(false);   // can't claim inclusion
    }
    // both terminal shapes must be exercised or the test is weaker than it looks
    expect(emptyTerminals).toBeGreaterThan(0);
    expect(leafTerminals).toBeGreaterThan(0);
  });

  test("non-inclusion for a PRESENT key fails", () => {
    const { t, entries } = build(10);
    const [k] = entries[0];
    expect(verifySMTProof(t.root(), k, null, t.getProof(k))).toBe(false);
  });

  test("tampered sibling fails", () => {
    const { t, entries } = build(20);
    const [k, v] = entries[5];
    const proof = t.getProof(k);
    const tampered = {
      ...proof,
      siblings: proof.siblings.map((s, i) => (i === 0 ? { ...s, hash: shake256("evil") } : s)),
    };
    expect(verifySMTProof(t.root(), k, v, tampered)).toBe(false);
  });

  test("proof against a stale root fails after state changes", () => {
    const { t, entries } = build(15);
    const [k, v] = entries[3];
    const proof = t.getProof(k);
    const oldRoot = t.root();
    t.set(K("new-key"), V("new"));
    expect(verifySMTProof(t.root(), k, v, proof)).toBe(oldRoot === t.root());
  });
});
