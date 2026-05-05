/**
 * @file @tip-protocol/node/src/consensus/participants.js
 * @description Active committee derivation under the #75 rotation-period model.
 *
 * Core property: committee membership is FIXED within a rotation period
 * and changes only at deterministic boundaries. Both `getActiveCommittee`
 * and the next-rotation computation read from BFT-attested state
 * (committee_history + rotation_participation), not from local
 * cert-history. This eliminates §4 / #72 / #74 divergence at the source.
 *
 * Two functions:
 *   - getActiveCommittee(round): pure lookup against committee_history.
 *     Returns the committee in effect at round R (= the latest rotation
 *     whose effective_round ≤ R). Bit-identical answer on every node.
 *
 *   - computeNextRotationCommittee(rotationNumber): called by bullshark at
 *     a rotation boundary. Reads rotation_participation tally for the
 *     just-finished rotation, applies threshold, returns the committee
 *     for the next rotation. Genesis members exempt from threshold.
 *
 * Determinism guarantees:
 *   - committee_history is BFT-committed via COMMITTEE_ROTATION tx
 *   - rotation_participation is incremented on every anchor commit, with
 *     bit-identical values across all nodes (because every node sees the
 *     same anchor cert at consensus_index N — same leader, same acks)
 *   - genesis_committee is fixed at genesis, identical on every node
 *   - threshold = ceil(INTERVAL_COMMITS * MIN_PARTICIPATION_PCT/100) is
 *     the same number on every node
 *   - Therefore: same input → same output, no flap, no divergence.
 *
 * What changed vs. pre-#75:
 *   - No more cert-history span check (was source of #74 GC-driven flap)
 *   - No more registered-set fallback (was source of #72 dead-peer ghost)
 *   - No more per-round derivation (was source of §4 mid-round quorum jump)
 *   - Committee_history is now the authoritative source — and it is
 *     populated deterministically by bullshark at rotation boundaries.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");
const { getGenesisCommittee } = require("../genesis");

/**
 * Active committee at the given round.
 *
 * Pure lookup: returns the `committee` field of the latest rotation in
 * `committee_history` whose `effective_round ≤ round`. Genesis seeds
 * rotation 0 with `effective_round = 0`, so any `round ≥ 0` resolves
 * to at least the genesis committee.
 *
 * Falls back to `genesis_committee ∩ registered_active` if no rotation
 * exists for the requested round (e.g. very early bootstrap before
 * initDAG has written rotation 0, or in unit tests with no DAG).
 *
 * @param {Object} dag    DAG facade with getCommitteeAtRound + getAllNodes + isRevoked
 * @param {number} round  Round to query
 * @param {number} [_K]   Unused (kept for API compatibility with pre-#75 callers)
 * @returns {string[]}    Sorted node_ids of the active committee
 */
function getActiveCommittee(dag, round, _K) {
  // Read the active rotation directly from committee_history. This is the
  // BFT-committed authoritative source — same answer on every node.
  let rotationCommittee = null;
  if (typeof dag.getCommitteeAtRound === "function") {
    const rec = dag.getCommitteeAtRound(round);
    if (rec && Array.isArray(rec.committee)) {
      rotationCommittee = rec.committee.map(m => m.node_id);
    }
  }

  if (rotationCommittee && rotationCommittee.length > 0) {
    // Filter against current registry: a rotation might list a node that
    // has subsequently been suspended/revoked. The chain-of-trust walker
    // verifies the rotation chain cryptographically; runtime quorum
    // additionally gates on current operational status.
    const registered = _registeredActiveSet(dag);
    return rotationCommittee.filter(id => registered.has(id)).sort();
  }

  // Fallback: chain hasn't bootstrapped rotation 0 yet, or unit-test
  // harness with no DAG. Use genesis ∩ registered_active.
  const genesis = getGenesisCommittee();
  const registered = _registeredActiveSet(dag);
  return [...genesis].filter(id => registered.has(id)).sort();
}

/**
 * Compute the committee for the next rotation, called by bullshark at
 * a rotation boundary.
 *
 * Reads `rotation_participation` for `finishingRotation` (the rotation
 * that just ended). For each author, the count is "how many of that
 * rotation's anchors had me as leader OR ack-signer." Authors meeting
 * the threshold OR in genesis_committee qualify, subject to current
 * registered+active status.
 *
 *   threshold = ceil(INTERVAL_COMMITS * MIN_PARTICIPATION_PCT / 100)
 *
 * @param {Object} dag                DAG facade
 * @param {number} finishingRotation  The rotation_number that just finished
 * @returns {Array<{node_id, public_key}>}  Sorted committee for the next rotation
 */
function computeNextRotationCommittee(dag, finishingRotation) {
  const intervalCommits = CONSENSUS.COMMITTEE_ROTATION_INTERVAL_COMMITS;
  const pct = CONSENSUS.COMMITTEE_ROTATION_PARTICIPATION_PCT_OF_INTERVAL;
  const threshold = Math.ceil((intervalCommits * pct) / 100);

  const tallies = (typeof dag.getRotationParticipation === "function")
    ? dag.getRotationParticipation(finishingRotation)
    : [];

  const registered = _registeredActiveSet(dag);
  const genesis = getGenesisCommittee();

  // Genesis members get a free pass (always in committee while
  // registered+active), matching the bootstrap chicken-and-egg argument:
  // someone has to be in the committee at chain start before anyone has
  // accumulated participation.
  const next = new Set();
  for (const id of genesis) {
    if (registered.has(id)) next.add(id);
  }

  // Late joiners admitted by participation threshold.
  for (const { node_id, count } of tallies) {
    if (count >= threshold && registered.has(node_id)) {
      next.add(node_id);
    }
  }

  // Resolve pubkeys from current nodes table for committee_history record.
  const out = [];
  for (const node_id of [...next].sort()) {
    const node = (typeof dag.getNode === "function") ? dag.getNode(node_id) : null;
    if (!node || !node.public_key) continue;  // can't include without pubkey
    out.push({ node_id, public_key: node.public_key });
  }
  return out;
}

function _registeredActiveSet(dag) {
  const out = new Set();
  if (typeof dag.getAllNodes !== "function") return out;
  for (const n of dag.getAllNodes()) {
    if (n.status === "active" && (typeof dag.isRevoked !== "function" || !dag.isRevoked(n.node_id))) {
      out.add(n.node_id);
    }
  }
  return out;
}

/**
 * Total registered (active, non-revoked) node count.
 * @param {Object} dag  DAG store
 * @returns {number}
 */
function getNodeCount(dag) {
  return _registeredActiveSet(dag).size;
}

/**
 * #75 atomic boundary — map a round number to its rotation_number.
 *
 *   epochOf(R) = floor(R / EPOCH_LENGTH_ROUNDS)
 *
 * Every node computes the same answer from `R` and the genesis-fixed
 * EPOCH_LENGTH_ROUNDS — no local-state ambiguity. Used by:
 *   - narwhal producer-pause (don't seal a cert until rotation for
 *     epochOf(round) is in local committee_history)
 *   - narwhal validator-park (park incoming certs whose epoch's rotation
 *     hasn't been applied locally yet)
 *   - bullshark proposer (effective_round = rotation_number * EPOCH_LENGTH_ROUNDS)
 *
 * @param {number} round
 * @returns {number} rotation_number that should be in effect at this round
 */
function epochOf(round) {
  if (typeof round !== "number" || !Number.isFinite(round) || round < 0) return 0;
  return Math.floor(round / CONSENSUS.EPOCH_LENGTH_ROUNDS);
}

module.exports = {
  getActiveCommittee,
  computeNextRotationCommittee,
  getNodeCount,
  epochOf,
};
