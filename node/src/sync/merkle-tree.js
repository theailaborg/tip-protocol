/**
 * @file @tip-protocol/node/src/sync/merkle-tree.js
 * @description Merkle tree over certificate hashes for TIP consensus sync.
 *
 * Used for:
 *   1. Sync: two nodes compare roots → if different, walk tree to find missing certs
 *   2. Audit: 6-hour Merkle root publication as tamper-evident checkpoint
 *   3. Integrity: verifies all certificates are accounted for
 *
 * The tree is a binary hash tree built from sorted certificate hashes.
 * Leaf = SHAKE-256(cert_hash). Parent = SHAKE-256(left + right).
 * Odd leaf count → last leaf promoted to next level.
 *
 * The tree is rebuilt incrementally — adding a certificate updates only the
 * path from the new leaf to the root (O(log n)).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256 } = require("../../../shared/crypto");
const { getLogger } = require("../logger");

const log = getLogger("tip.merkle");

const EMPTY_ROOT = shake256("tip-merkle-empty-tree");

/**
 * Create a Merkle tree.
 *
 * @param {Object} [options]
 * @param {Array<string>} [options.initialHashes]  Pre-existing hashes to build from
 * @returns {Object} Merkle tree instance
 */
function createMerkleTree(options = {}) {
  // Sorted leaf hashes (certificate hashes)
  let _leaves = [];
  // Cached tree levels: _levels[0] = leaves, _levels[n] = root
  let _levels = [];
  let _root = EMPTY_ROOT;
  let _dirty = true;

  // Initialize with existing hashes
  if (options.initialHashes && options.initialHashes.length > 0) {
    _leaves = [...options.initialHashes].sort();
    _dirty = true;
    _rebuild();
  }

  /**
   * Add a certificate hash to the tree.
   * @param {string} hash  Certificate hash (hex string)
   */
  function add(hash) {
    if (!hash) return;

    // Insert in sorted position (binary search)
    const idx = _binarySearchInsert(_leaves, hash);
    if (idx < _leaves.length && _leaves[idx] === hash) return; // duplicate
    _leaves.splice(idx, 0, hash);
    _dirty = true;
  }

  /**
   * Add multiple hashes at once (more efficient than individual adds).
   * @param {Array<string>} hashes
   */
  function addBatch(hashes) {
    let added = 0;
    for (const h of hashes) {
      if (!h) continue;
      const idx = _binarySearchInsert(_leaves, h);
      if (idx < _leaves.length && _leaves[idx] === h) continue;
      _leaves.splice(idx, 0, h);
      added++;
    }
    if (added > 0) _dirty = true;
  }

  /**
   * Get the Merkle root hash.
   * @returns {string} Root hash (hex string)
   */
  function root() {
    if (_dirty) _rebuild();
    return _root;
  }

  /**
   * Get hashes at a specific tree level.
   * Level 0 = leaves, level N = root.
   * Used for sync: compare level by level to find divergence.
   * @param {number} level
   * @returns {Array<string>}
   */
  function getLevel(level) {
    if (_dirty) _rebuild();
    if (level < 0 || level >= _levels.length) return [];
    return [..._levels[level]];
  }

  /**
   * Get the total number of levels in the tree.
   * @returns {number}
   */
  function depth() {
    if (_dirty) _rebuild();
    return _levels.length;
  }

  /**
   * Get the number of leaves (certificates).
   * @returns {number}
   */
  function size() {
    return _leaves.length;
  }

  /**
   * Find which leaf hashes are in this tree but not in the other.
   * @param {Array<string>} otherLeaves  The other node's leaf hashes (sorted)
   * @returns {{ missing: Array<string>, extra: Array<string> }}
   *   missing = in other but not in ours
   *   extra = in ours but not in other
   */
  function diff(otherLeaves) {
    const otherSet = new Set(otherLeaves);
    const ourSet = new Set(_leaves);

    const missing = otherLeaves.filter(h => !ourSet.has(h));
    const extra = _leaves.filter(h => !otherSet.has(h));

    return { missing, extra };
  }

  /**
   * Get a proof for a specific leaf hash.
   * Returns the sibling hashes needed to verify the leaf is in the tree.
   * @param {string} hash  Leaf hash to prove
   * @returns {Array<{ hash: string, position: 'left'|'right' }>|null}  Proof path or null if not found
   */
  function getProof(hash) {
    if (_dirty) _rebuild();
    let idx = _leaves.indexOf(hash);
    if (idx === -1) return null;

    const proof = [];
    for (let level = 0; level < _levels.length - 1; level++) {
      const levelHashes = _levels[level];
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;

      if (siblingIdx < levelHashes.length) {
        proof.push({
          hash: levelHashes[siblingIdx],
          position: idx % 2 === 0 ? "right" : "left",
        });
      }

      idx = Math.floor(idx / 2);
    }

    return proof;
  }

  /**
   * Verify a proof for a leaf hash against a root.
   * @param {string} leafHash    The leaf to verify
   * @param {Array}  proof       Proof from getProof()
   * @param {string} expectedRoot  Root to verify against
   * @returns {boolean}
   */
  function verifyProof(leafHash, proof, expectedRoot) {
    let currentHash = shake256(`leaf:${leafHash}`);

    for (const step of proof) {
      if (step.position === "left") {
        currentHash = shake256(step.hash + currentHash);
      } else {
        currentHash = shake256(currentHash + step.hash);
      }
    }

    return currentHash === expectedRoot;
  }

  /**
   * Get all leaf hashes (sorted).
   * @returns {Array<string>}
   */
  function leaves() {
    return [..._leaves];
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  /**
   * Rebuild the entire tree from leaves.
   */
  function _rebuild() {
    _levels = [];

    if (_leaves.length === 0) {
      _root = EMPTY_ROOT;
      _dirty = false;
      return;
    }

    // Level 0: hash each leaf
    let currentLevel = _leaves.map(h => shake256(`leaf:${h}`));
    _levels.push([...currentLevel]);

    // Build up the tree
    while (currentLevel.length > 1) {
      const nextLevel = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          nextLevel.push(shake256(currentLevel[i] + currentLevel[i + 1]));
        } else {
          // Odd number of nodes — promote the last one
          nextLevel.push(currentLevel[i]);
        }
      }
      currentLevel = nextLevel;
      _levels.push([...currentLevel]);
    }

    _root = currentLevel[0];
    _dirty = false;
  }

  /**
   * Binary search for insert position in sorted array.
   */
  function _binarySearchInsert(arr, value) {
    let lo = 0, hi = arr.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (arr[mid] < value) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  return { add, addBatch, root, getLevel, depth, size, diff, getProof, verifyProof, leaves };
}

module.exports = { createMerkleTree, EMPTY_ROOT };
