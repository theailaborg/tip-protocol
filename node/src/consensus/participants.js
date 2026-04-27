/**
 * @file @tip-protocol/node/src/consensus/participants.js
 * @description Active committee derivation from DAG state.
 *
 * The active committee is a deterministic function of the DAG: every node
 * reading the same DAG computes the same committee, so leader rotation and
 * quorum thresholds match across the network.
 *
 * A node is in the committee iff:
 *   1. Registered and non-revoked (nodes table, status=active) — permission
 *   2. Produced at least one certificate in the last K rounds — liveness
 *
 * Registration alone is not enough: a permissioned-but-never-started node
 * would otherwise halt consensus. Liveness alone is not enough: an
 * unregistered peer couldn't have its certs accepted in the first place.
 *
 * Cold-start fallback: if no certs exist in the window (fresh genesis or
 * fully idle network), fall back to the registered set so consensus can
 * bootstrap or resume after deep idle.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");

/**
 * Get the active committee for a given round.
 *
 * Committee is stable within a wave (2 consecutive rounds = 1 wave: propose
 * + vote). Both rounds of wave W use the same committee, computed from
 * producers in the K rounds preceding wave W's first round. This aligns with
 * wave-based leader rotation and eliminates mid-wave races when a new node's
 * cert changes the rolling window between rounds.
 *
 * @param {Object} dag    DAG store
 * @param {number} round  Any round within the target wave
 * @param {number} [K]    Liveness window in rounds (defaults to CONSENSUS.COMMITTEE_WINDOW_K or 4)
 * @returns {string[]}    Sorted array of node IDs in the committee
 */
function getActiveCommittee(dag, round, K) {
  const windowRounds = K != null ? K : (CONSENSUS.COMMITTEE_WINDOW_K || 4);

  // Anchor the window to the wave's first round so both rounds of a wave
  // (propose + vote) see the same committee.
  const wave = Math.floor((round - 1) / 2);
  const waveStartRound = wave * 2 + 1;

  const registered = new Set();
  for (const n of dag.getAllNodes()) {
    if (n.status === "active" && !dag.isRevoked(n.node_id)) {
      registered.add(n.node_id);
    }
  }

  const producers = new Set();
  const fromRound = Math.max(1, waveStartRound - windowRounds);
  const toRound = waveStartRound - 1;
  for (let r = fromRound; r <= toRound; r++) {
    try {
      const certs = dag.getCertificatesByRound(r);
      for (const cert of certs) producers.add(cert.author_node_id);
    } catch { /* ignore */ }
  }

  const committee = [...producers].filter(id => registered.has(id));

  // Cold-start fallback: no activity in the window (fresh genesis or deep
  // idle) → use registered set so consensus can bootstrap or resume.
  if (committee.length === 0) {
    return [...registered].sort();
  }

  return committee.sort();
}

/**
 * Total registered (active, non-revoked) node count.
 * @param {Object} dag  DAG store
 * @returns {number}
 */
function getNodeCount(dag) {
  let count = 0;
  for (const n of dag.getAllNodes()) {
    if (n.status === "active" && !dag.isRevoked(n.node_id)) count++;
  }
  return count;
}

module.exports = { getActiveCommittee, getNodeCount };
