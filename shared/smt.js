/**
 * @file @tip-protocol/shared/smt.js
 * @description Compressed sparse merkle tree for the state root (#88).
 * Keyed by 256-bit key hashes; subtrees holding a single leaf collapse to
 * that leaf, so depth is ~log2(n) and memory ~2n nodes. Structure is a
 * radix trie over key bits: a pure function of the key SET , insertion
 * and deletion order can never change the root. Updates rehash only the
 * O(depth) path; root reads are O(1).
 *
 * Hash discipline comes from shared/merkle.js:
 *   leaf node  = leafHash(keyHash + ":" + valueHash)     ("L" domain)
 *   internal   = nodeHash(leftHash, rightHash)           ("N" domain)
 *   empty tree = shake256("tip-smt-empty")
 *
 * Proofs: inclusion AND non-inclusion. A non-inclusion proof shows the
 * key's path terminates in empty space or at a DIFFERENT leaf , "this
 * TIP-ID is NOT registered" is as provable as membership.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256 } = require("./crypto");
const { leafHash, nodeHash } = require("./merkle");

const EMPTY_SMT_ROOT = () => shake256("tip-smt-empty");

// keyHash hex char -> 4 bits, MSB first
function _bit(keyHash, depth) {
  const nibble = parseInt(keyHash[depth >> 2], 16);
  return (nibble >> (3 - (depth & 3))) & 1;
}

function _leafNode(keyHash, valueHash) {
  return { leaf: true, keyHash, valueHash, hash: leafHash(keyHash + ":" + valueHash) };
}

function _internalNode(left, right, emptyHash) {
  const lh = left ? left.hash : emptyHash;
  const rh = right ? right.hash : emptyHash;
  return { leaf: false, left, right, hash: nodeHash(lh, rh) };
}

function createSMT() {
  const EMPTY = EMPTY_SMT_ROOT();
  let _root = null;
  let _size = 0;

  function _set(node, keyHash, valueHash, depth) {
    if (node === null) {
      _size++;
      return _leafNode(keyHash, valueHash);
    }
    if (node.leaf) {
      if (node.keyHash === keyHash) {
        return _leafNode(keyHash, valueHash);   // value update, size unchanged
      }
      // split: push the existing leaf down until the two keys diverge
      _size++;
      return _split(node, _leafNode(keyHash, valueHash), depth);
    }
    const bit = _bit(keyHash, depth);
    const left = bit === 0 ? _set(node.left ?? null, keyHash, valueHash, depth + 1) : node.left;
    const right = bit === 1 ? _set(node.right ?? null, keyHash, valueHash, depth + 1) : node.right;
    return _internalNode(left ?? null, right ?? null, EMPTY);
  }

  function _split(a, b, depth) {
    const abit = _bit(a.keyHash, depth);
    const bbit = _bit(b.keyHash, depth);
    if (abit !== bbit) {
      return _internalNode(abit === 0 ? a : b, abit === 0 ? b : a, EMPTY);
    }
    const child = _split(a, b, depth + 1);
    return abit === 0
      ? _internalNode(child, null, EMPTY)
      : _internalNode(null, child, EMPTY);
  }

  function _delete(node, keyHash, depth) {
    if (node === null) return { node: null, deleted: false };
    if (node.leaf) {
      if (node.keyHash !== keyHash) return { node, deleted: false };
      _size--;
      return { node: null, deleted: true };
    }
    const bit = _bit(keyHash, depth);
    const r = bit === 0
      ? _delete(node.left ?? null, keyHash, depth + 1)
      : _delete(node.right ?? null, keyHash, depth + 1);
    if (!r.deleted) return { node, deleted: false };
    const left = bit === 0 ? r.node : (node.left ?? null);
    const right = bit === 1 ? r.node : (node.right ?? null);
    // collapse: an internal with exactly one LEAF child and nothing else
    // becomes that leaf , keeps the structure canonical after deletes
    if (left === null && right !== null && right.leaf) return { node: right, deleted: true };
    if (right === null && left !== null && left.leaf) return { node: left, deleted: true };
    if (left === null && right === null) return { node: null, deleted: true };
    return { node: _internalNode(left, right, EMPTY), deleted: true };
  }

  /** Insert or update. keyHash: 64-hex; valueHash: any hex digest. */
  function set(keyHash, valueHash) {
    _root = _set(_root, keyHash, valueHash, 0);
  }

  /** Remove a key. No-op (and returns false) if absent. */
  function remove(keyHash) {
    const r = _delete(_root, keyHash, 0);
    _root = r.node;
    return r.deleted;
  }

  function root() {
    return _root === null ? EMPTY : _root.hash;
  }

  function size() {
    return _size;
  }

  function clear() {
    _root = null;
    _size = 0;
  }

  /**
   * Proof for a key , inclusion or non-inclusion, decided by what the
   * path terminates at. `siblings` are ordered root -> terminal.
   * @returns {{ siblings: Array<{hash: string, keyBit: 0|1}>,
   *             terminal: null | { keyHash: string, valueHash: string } }}
   */
  function getProof(keyHash) {
    const siblings = [];
    let node = _root;
    let depth = 0;
    while (node !== null && !node.leaf) {
      const bit = _bit(keyHash, depth);
      const sibling = bit === 0 ? (node.right ?? null) : (node.left ?? null);
      siblings.push({ hash: sibling ? sibling.hash : EMPTY, keyBit: bit });
      node = bit === 0 ? (node.left ?? null) : (node.right ?? null);
      depth++;
    }
    return {
      siblings,
      terminal: node === null ? null : { keyHash: node.keyHash, valueHash: node.valueHash },
    };
  }

  return { set, remove, root, size, clear, getProof };
}

/**
 * Verify a proof against a root.
 * - inclusion:      expectedValueHash = the value's hash
 * - non-inclusion:  expectedValueHash = null (proof must terminate in empty
 *                   space or at a leaf for a DIFFERENT key)
 */
function verifySMTProof(rootHash, keyHash, expectedValueHash, proof) {
  const EMPTY = EMPTY_SMT_ROOT();
  if (!proof || !Array.isArray(proof.siblings)) return false;

  const t = proof.terminal;
  if (expectedValueHash !== null) {
    if (!t || t.keyHash !== keyHash || t.valueHash !== expectedValueHash) return false;
  } else {
    if (t && t.keyHash === keyHash) return false;   // present => not a non-inclusion
  }
  // terminal leaf (if any) must lie on this key's path for the depth walked
  if (t) {
    for (let d = 0; d < proof.siblings.length; d++) {
      if (_bit(t.keyHash, d) !== _bit(keyHash, d)) return false;
    }
  }

  let h = t === null ? EMPTY : leafHash(t.keyHash + ":" + t.valueHash);
  for (let i = proof.siblings.length - 1; i >= 0; i--) {
    const { hash, keyBit } = proof.siblings[i];
    h = keyBit === 0 ? nodeHash(h, hash) : nodeHash(hash, h);
  }
  return h === rootHash;
}

module.exports = { createSMT, verifySMTProof, EMPTY_SMT_ROOT };
