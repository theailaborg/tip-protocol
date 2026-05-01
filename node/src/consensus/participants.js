/**
 * @file @tip-protocol/node/src/consensus/participants.js
 * @description Active committee + node-count accessors for consensus.
 *
 * Two distinct concerns, two functions:
 *
 *   1. getActiveCommittee(dag, round)
 *      Hot path, called every round by Bullshark/Narwhal for leader
 *      rotation and quorum thresholds. Reads `committee_history` —
 *      the cryptographically-anchored chain of committees signed off
 *      by previous committees back to the genesis trust anchor (§4 + #34).
 *      No on-the-fly derivation; whatever the chain says IS the committee.
 *
 *   2. deriveLiveCommittee(dag, round, K)
 *      Used ONLY by the bullshark rotation-proposer (step 6) to compute
 *      the "would-be committee" — the committee that SHOULD be in effect
 *      based on current node-producing activity. Compared against
 *      committee_history's latest rotation; if they differ, the proposer
 *      builds a COMMITTEE_ROTATION tx to update the chain. This function
 *      is NOT consulted at consensus tick time.
 *
 * Wave stability: both rounds of a wave (propose + vote) see the same
 * committee. Anchored to the wave's first round, so a rotation that
 * lands mid-wave doesn't change the committee for that wave's vote
 * round. Same invariant pre- and post-§4.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");

/**
 * Get the active committee for a given round, reading from
 * `committee_history` (§4 + #34). Returns sorted node_ids — same shape
 * as the pre-§4 derivation function, so callers (leader rotation,
 * quorum count, leader-gated triggers) need no changes.
 *
 * Anchored to the wave's first round so propose + vote rounds of one
 * wave always see the same committee even if a rotation commits mid-wave.
 *
 * @param {Object} dag    DAG facade (must expose getCommitteeAtRound)
 * @param {number} round  Any round within the target wave
 * @param {number} [_K]   Legacy hysteresis param — IGNORED. Hysteresis
 *                        lives in `deriveLiveCommittee` (proposer side)
 *                        now. Kept in the signature only for backwards
 *                        compat with callers passing K.
 * @returns {string[]}    Sorted node_ids of the committee in effect at
 *                        this round.
 */
function getActiveCommittee(dag, round, _K) {
  // Anchor to wave's first round so both rounds of a wave see the same
  // committee.
  const wave = Math.floor((round - 1) / 2);
  const waveStartRound = wave * 2 + 1;

  const rotation = dag.getCommitteeAtRound(waveStartRound);

  if (!rotation || !rotation.committee || rotation.committee.length === 0) {
    // Should never fire in production — initDAG bootstraps rotation 0
    // unconditionally from genesis.founding_node, so committee_history
    // is never empty. Defensive fallback to registered set keeps
    // consensus alive if the table somehow gets emptied (corruption,
    // partial migration). Operationally surfaces via halt-gate if no
    // registered nodes either.
    const registered = [];
    for (const n of dag.getAllNodes()) {
      if (n.status === "active" && !dag.isRevoked(n.node_id)) {
        registered.push(n.node_id);
      }
    }
    return registered.sort();
  }

  // committee field is [{node_id, public_key}] — return just node_ids.
  // Callers needing pubkeys (chain-of-trust walker, future API) read
  // dag.getCommitteeAtRound directly.
  return rotation.committee.map(m => m.node_id).sort();
}

/**
 * Derive the "would-be committee" from current node-producing activity.
 * Used ONLY by the rotation proposer (bullshark.js, step 6) to detect
 * when committee_history needs an update.
 *
 * Logic — same as the pre-§4 getActiveCommittee, kept for the proposer's
 * diff-detection step:
 *   committee = registered_active ∩ producers_in_last_K_rounds
 *
 * Hysteresis K (default `committee_rotation_hysteresis_rounds`, ~10 min)
 * absorbs operational restarts so brief deploys don't trigger rotations.
 *
 * @param {Object} dag    DAG facade
 * @param {number} round  Anchor round for the K-window
 * @param {number} [K]    Hysteresis window in rounds (defaults to
 *                        CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS)
 * @returns {string[]}    Sorted node_ids of the would-be committee
 */
function deriveLiveCommittee(dag, round, K) {
  const windowRounds = K != null ? K : CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS;

  // Anchor the window to the wave's first round so the comparison
  // against latest_rotation.committee is wave-stable.
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

  // Cold-start fallback: no activity in the window (fresh genesis or
  // deep idle) → use registered set so the proposer doesn't shrink the
  // committee to zero on a quiet network.
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

module.exports = { getActiveCommittee, deriveLiveCommittee, getNodeCount };
