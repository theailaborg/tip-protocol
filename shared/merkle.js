/**
 * @file @tip-protocol/shared/merkle.js
 * @description THE merkle implementation. Every list-shaped root in the
 * protocol (txs root, cert sync tree) builds on these primitives; #88's
 * state tree reuses leafHash/nodeHash. One hash discipline, one audit
 * surface.
 *
 * Construction (RFC-6962 style):
 *   leaf     = shake256("L" + data)
 *   internal = shake256("N" + left + right)
 *   odd last node is PROMOTED to the next level unchanged. Duplication
 *   (bitcoin-style) is banned: [A,B,C] and [A,B,C,C] must never share a
 *   root (CVE-2012-2459 ambiguity class).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256 } = require("./crypto");

const EMPTY_ROOT = () => shake256("tip-merkle-empty-tree");

function leafHash(data) {
  return shake256("L" + data);
}

function nodeHash(left, right) {
  return shake256("N" + left + right);
}

/**
 * Build all tree levels from pre-hashed leaves.
 * levels[0] = leaf hashes, levels[last] = [root]. Odd nodes promote.
 * @param {Array<string>} leafHashes
 * @returns {Array<Array<string>>}
 */
function buildLevels(leafHashes) {
  if (!leafHashes || leafHashes.length === 0) return [];
  const levels = [leafHashes.slice()];
  let level = levels[0];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) {
      next.push(nodeHash(level[i], level[i + 1]));
    }
    if (level.length % 2 === 1) next.push(level[level.length - 1]);
    levels.push(next);
    level = next;
  }
  return levels;
}

/**
 * Root over a list of raw items (hashed here) or pre-hashed leaves.
 * @param {Array<string>} items
 * @param {Object} [opts]
 * @param {boolean} [opts.alreadyHashed]  items are leaf hashes, skip leafHash()
 * @param {string}  [opts.emptyRoot]      sentinel for the empty list
 * @returns {string}
 */
function computeRoot(items, opts = {}) {
  if (!items || items.length === 0) return opts.emptyRoot ?? EMPTY_ROOT();
  const leaves = opts.alreadyHashed ? items : items.map(leafHash);
  const levels = buildLevels(leaves);
  return levels[levels.length - 1][0];
}

/**
 * Inclusion proof for the leaf at `index`.
 * With promotion, a lone odd node has no sibling at that level , the step
 * is simply absent and the hash carries upward unchanged.
 * @param {Array<Array<string>>} levels  from buildLevels()
 * @param {number} index                 leaf position
 * @returns {Array<{hash: string, position: "left"|"right"}>|null}
 */
function getProof(levels, index) {
  if (!levels.length || index < 0 || index >= levels[0].length) return null;
  const proof = [];
  let idx = index;
  for (let l = 0; l < levels.length - 1; l++) {
    const level = levels[l];
    const isLastOdd = level.length % 2 === 1 && idx === level.length - 1;
    if (isLastOdd) {
      idx = Math.floor(level.length / 2);   // promoted slot
      continue;
    }
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    proof.push({
      hash: level[siblingIdx],
      position: idx % 2 === 0 ? "right" : "left",
    });
    idx = Math.floor(idx / 2);
  }
  return proof;
}

/**
 * Verify an inclusion proof.
 * @param {string} data       raw leaf data (or leaf hash with alreadyHashed)
 * @param {Array}  proof      from getProof()
 * @param {string} expectedRoot
 * @param {Object} [opts]
 * @param {boolean} [opts.alreadyHashed]
 * @returns {boolean}
 */
function verifyProof(data, proof, expectedRoot, opts = {}) {
  if (!Array.isArray(proof)) return false;
  let h = opts.alreadyHashed ? data : leafHash(data);
  for (const step of proof) {
    if (!step || typeof step.hash !== "string") return false;
    h = step.position === "left" ? nodeHash(step.hash, h) : nodeHash(h, step.hash);
  }
  return h === expectedRoot;
}

module.exports = { leafHash, nodeHash, buildLevels, computeRoot, getProof, verifyProof, EMPTY_ROOT };
