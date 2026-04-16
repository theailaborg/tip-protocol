/**
 * @file @tip-protocol/node/src/consensus/participants.js
 * @description Active participant tracking for consensus quorum.
 *
 * Quorum is based on nodes actually participating (producing certificates),
 * not the full registry. This prevents registered-but-offline nodes from
 * inflating quorum and blocking consensus.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");
const { computeQuorum } = require("./certificate");
const { getLogger } = require("../logger");

const log = getLogger("tip.consensus");

/**
 * Get sorted active registered node IDs from the DAG.
 */
function getNodeIds(dag) {
  return dag.getAllNodes()
    .filter(n => n.status === "active")
    .map(n => n.node_id)
    .sort();
}

/**
 * Get total active registered node count.
 */
function getNodeCount(dag) {
  return dag.getAllNodes().filter(n => n.status === "active").length;
}

/**
 * Remove participants that haven't produced a certificate in the last N rounds.
 * Always keeps the local node.
 *
 * @param {Set}    activeParticipants  The active set to prune
 * @param {string} selfNodeId         This node's ID (never removed)
 * @param {Object} dag                DAG store
 */
function pruneInactive(activeParticipants, selfNodeId, dag) {
  const inactiveThreshold = CONSENSUS.PARTICIPANT_INACTIVE_ROUNDS;
  const latestRound = dag.getLatestRound();
  if (latestRound < inactiveThreshold) return;

  const recentAuthors = new Set();
  for (let r = Math.max(1, latestRound - inactiveThreshold + 1); r <= latestRound; r++) {
    try {
      const certs = dag.getCertificatesByRound(r);
      for (const cert of certs) recentAuthors.add(cert.author_node_id);
    } catch { /* ignore */ }
  }

  // Always keep self
  recentAuthors.add(selfNodeId);

  for (const participant of activeParticipants) {
    if (!recentAuthors.has(participant)) {
      activeParticipants.delete(participant);
      log.info(`Removed inactive participant: ${participant} (active: ${activeParticipants.size}, quorum: ${computeQuorum(activeParticipants.size)})`);
    }
  }
}

module.exports = { getNodeIds, getNodeCount, pruneInactive };
