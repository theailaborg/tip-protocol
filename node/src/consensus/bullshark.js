/**
 * @file @tip-protocol/node/src/consensus/bullshark.js
 * @description Bullshark ordering protocol for TIP consensus.
 *
 * Takes the certificate DAG produced by Narwhal and outputs a deterministic
 * total order of all transactions. Every node running the same algorithm on
 * the same certificate DAG produces the exact same transaction order.
 *
 * How it works:
 *   - Rounds are grouped into waves of 2 (odd = propose, even = vote)
 *   - Each wave has a leader (round-robin by sorted node IDs)
 *   - The leader's certificate in the odd round is the "anchor candidate"
 *   - If 2/3+ of even-round certificates reference the anchor → it's COMMITTED
 *   - Committed anchor → walk DAG backwards → collect all unreached txs → output in order
 *
 * The ordering is deterministic because:
 *   1. Leader selection: sorted node IDs, round-robin
 *   2. Commit rule: 2/3+ threshold (same on all nodes)
 *   3. DAG walk: BFS with deterministic ordering (by round, then author_node_id)
 *   4. Tx ordering within certificate: preserved from batch (mempool drain order)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { computeQuorum } = require("./certificate");
const { getLogger } = require("../logger");

const log = getLogger("tip.bullshark");

/**
 * Create the Bullshark ordering layer.
 *
 * @param {Object} options
 * @param {Object}   options.dag            DAG store (read certificates)
 * @param {Function} options.getNodeIds     () => sorted array of registered node IDs
 * @param {Function} options.onOrderedTxs   (txs, round) => called with deterministically ordered txs
 * @returns {Object} Bullshark instance
 */
function createBullshark({ dag, getNodeIds, onOrderedTxs }) {
  // Track which certificates have already been ordered (by hash)
  const _orderedCertHashes = new Set();

  // Track last committed round to avoid re-processing
  let _lastCommittedRound = 0;

  // Initialize from persisted state
  function _initFromDAG() {
    try {
      const latestRound = dag.getLatestRound();
      if (latestRound === 0) return;

      // Mark all existing certificates as ordered so they won't be re-collected.
      // On restart, Narwhal resumes from latestRound+1 — Bullshark only processes new rounds.
      _lastCommittedRound = latestRound;
      for (let r = 1; r <= latestRound; r++) {
        try {
          const certs = dag.getCertificatesByRound(r);
          for (const cert of certs) _orderedCertHashes.add(cert.hash);
        } catch (err) {
          log.warn(`Failed to load certificates for round ${r}: ${err.message}`);
        }
      }

      log.info(`Bullshark initialized: last committed round ${latestRound}, ${_orderedCertHashes.size} certificates`);
    } catch (err) {
      log.error(`Bullshark initialization failed: ${err.message}`);
    }
  }

  _initFromDAG();

  /**
   * Called by Narwhal when a round completes (2/3+ certificates collected).
   * Checks if this round triggers an anchor commit. If so, orders all
   * uncommitted txs reachable from the anchor.
   *
   * @param {Array} certificates   Certificates from the completed round
   * @param {number} round         The completed round number
   */
  function onRoundComplete(certificates, round) {
    if (!certificates || !Array.isArray(certificates) || round <= 0) {
      log.warn(`onRoundComplete: invalid args (round=${round}, certs=${certificates?.length})`);
      return;
    }

    if (round <= _lastCommittedRound) return;

    // Only check for anchor on even rounds (vote rounds)
    if (round % 2 !== 0) return;

    try {
      _checkAnchorCommit(round);
    } catch (err) {
      log.error(`Anchor check failed at round ${round}: ${err.message}`);
    }
  }

  /**
   * Check if the leader's certificate from the propose round is committed.
   */
  function _checkAnchorCommit(voteRound) {
    const proposeRound = voteRound - 1;
    const leader = _getLeader(proposeRound);
    if (!leader) {
      log.warn(`Round ${voteRound}: no leader for propose round ${proposeRound}`);
      return;
    }

    // Get leader's certificate
    let leaderCert;
    try {
      leaderCert = dag.getCertificateByAuthorRound(leader, proposeRound);
    } catch (err) {
      log.error(`Failed to read leader cert ${leader} round ${proposeRound}: ${err.message}`);
      return;
    }
    if (!leaderCert) {
      log.debug(`Round ${voteRound}: leader ${leader} has no cert in round ${proposeRound}`);
      return;
    }

    // Check commit rule: 2/3+ of vote round certs reference the leader's cert
    let voteCerts;
    try {
      voteCerts = dag.getCertificatesByRound(voteRound);
    } catch (err) {
      log.error(`Failed to read vote certs for round ${voteRound}: ${err.message}`);
      return;
    }

    const nodeIds = getNodeIds();
    if (!nodeIds || nodeIds.length === 0) {
      log.warn(`Round ${voteRound}: no registered nodes`);
      return;
    }
    const quorum = computeQuorum(nodeIds.length);

    let supportCount = 0;
    for (const voteCert of voteCerts) {
      if (_referencesAncestor(voteCert, leaderCert.hash, proposeRound)) {
        supportCount++;
      }
    }

    if (supportCount < quorum) {
      log.debug(`Round ${voteRound}: anchor ${leader} not committed (${supportCount}/${quorum} support)`);
      return;
    }

    // ANCHOR COMMITTED
    log.info(`Round ${voteRound}: anchor COMMITTED — leader ${leader}, support ${supportCount}/${nodeIds.length}`);

    const orderedTxs = _collectOrderedTxs(leaderCert);

    if (orderedTxs.length > 0 && onOrderedTxs) {
      log.info(`Round ${voteRound}: committing ${orderedTxs.length} ordered txs`);
      // Only advance committed round AFTER successful processing
      // If onOrderedTxs throws, we don't advance — will retry next round
      onOrderedTxs(orderedTxs, voteRound);
    }

    _lastCommittedRound = voteRound;
  }

  /**
   * Check if a certificate (or its ancestors) references a specific cert hash.
   * Iterative DFS with visited set — safe for deep DAGs, no stack overflow.
   *
   * @param {Object} cert        Certificate to check
   * @param {string} targetHash  Hash we're looking for
   * @param {number} targetRound Round of the target (stop searching below this)
   * @returns {boolean}
   */
  function _referencesAncestor(cert, targetHash, targetRound) {
    const visited = new Set();
    const stack = [cert];

    while (stack.length > 0) {
      const current = stack.pop();
      if (!current || !current.hash || visited.has(current.hash)) continue;
      visited.add(current.hash);

      const parents = current.parent_hashes || [];
      if (parents.includes(targetHash)) return true;

      // Don't descend below target round
      if (current.round <= targetRound) continue;

      for (const parentHash of parents) {
        if (visited.has(parentHash)) continue;
        try {
          const parentCert = dag.getCertificate(parentHash);
          if (parentCert) stack.push(parentCert);
        } catch (err) {
          log.warn(`Failed to read parent cert ${parentHash.slice(0, 16)}: ${err.message}`);
        }
      }
    }

    return false;
  }

  /**
   * Collect all txs from uncommitted certificates reachable from the anchor.
   * BFS walk of the certificate DAG, ordered deterministically.
   *
   * Order: by round (ascending), then by author_node_id (ascending)
   * Within a certificate: tx order preserved from batch
   */
  function _collectOrderedTxs(anchorCert) {
    const toVisit = [anchorCert];
    const visited = new Set();
    const collectedCerts = [];

    // BFS through the certificate DAG
    while (toVisit.length > 0) {
      const cert = toVisit.shift();
      if (!cert || !cert.hash || visited.has(cert.hash)) continue;
      visited.add(cert.hash);

      // Only collect if not already ordered in a previous anchor commit
      if (!_orderedCertHashes.has(cert.hash)) {
        collectedCerts.push(cert);
        _orderedCertHashes.add(cert.hash);
      }

      for (const parentHash of (cert.parent_hashes || [])) {
        if (visited.has(parentHash)) continue;
        try {
          const parentCert = dag.getCertificate(parentHash);
          if (parentCert) toVisit.push(parentCert);
        } catch (err) {
          log.warn(`Failed to read parent cert ${parentHash.slice(0, 16)}: ${err.message}`);
        }
      }
    }

    // Deterministic sort: round ASC, then author_node_id ASC
    collectedCerts.sort((a, b) => {
      if (a.round !== b.round) return a.round - b.round;
      return a.author_node_id.localeCompare(b.author_node_id);
    });

    // Extract txs in order
    const orderedTxs = [];
    for (const cert of collectedCerts) {
      for (const tx of (cert.batch?.txs || [])) {
        if (tx && tx.tx_id) orderedTxs.push(tx);
      }
    }

    return orderedTxs;
  }

  /**
   * Get the leader node for a given round (deterministic round-robin).
   * @param {number} round
   * @returns {string|null}
   */
  function _getLeader(round) {
    const nodeIds = getNodeIds();
    if (!nodeIds || nodeIds.length === 0) return null;
    return nodeIds[(round - 1) % nodeIds.length];
  }

  return {
    onRoundComplete,

    /** Get the leader for a specific round */
    getLeader: _getLeader,

    /** Get the last committed round */
    lastCommittedRound: () => _lastCommittedRound,

    /** Stats for monitoring */
    stats: () => ({
      lastCommittedRound: _lastCommittedRound,
      orderedCertificates: _orderedCertHashes.size,
      nodeCount: getNodeIds().length,
    }),
  };
}

module.exports = { createBullshark };
