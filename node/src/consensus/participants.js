/**
 * @file @tip-protocol/node/src/consensus/participants.js
 * @description Active committee derivation from gossip-replicated DAG state.
 *
 * The active committee at round R is a deterministic function of the DAG's
 * cert history: every node reading the same DAG computes the same committee.
 * This is what makes leader rotation, quorum thresholds, and round advance
 * agree across nodes without needing an extra consensus pass.
 *
 * Membership rule (genesis-anchored):
 *   admit(id) := registered ∧ producing-in-K-window ∧ (
 *                  id ∈ genesis_committee     OR     span(id) ≥ K
 *                )
 *
 * Two classes of members:
 *   - GENESIS members (from `genesis.js`): admitted on their first cert,
 *     no K-wait. This solves the chicken-and-egg of needing a committee
 *     at round 1 before anyone has produced K rounds.
 *   - LATE joiners (anyone NOT in genesis): must produce for K rounds
 *     before being admitted. Span = lastInWindow − earliest_cert_anywhere.
 *     Robust under GC because lastInWindow keeps moving with the head.
 *
 * peer-352 protection (offline genesis members): the producers map only
 * tracks authors that produced IN the K-window, so a genesis member that
 * goes silent for K rounds drops out automatically — quorum doesn't
 * inflate around a non-producing seed.
 *
 * Empty-window fallback (no producers in K-window): return
 * `genesis_committee ∩ registered`. Covers true chain-genesis, sync
 * windows, ancient-round queries, and chain-halt recovery.
 *
 * Why cert-history (not committee_history) at runtime:
 *   committee_history is committed via Bullshark and has commit lag —
 *   different nodes commit the same rotation tx at different wall-clock
 *   times. Reading runtime committee from committee_history caused the
 *   §4 deadlock: founding's view jumped to quorum=2 before node 2's view
 *   did, founding rejected node 2's in-flight 1-ack certs, halt.
 *
 *   Gossip-replicated cert history has lag too, but at the millisecond
 *   scale (not Bullshark-round scale). Both nodes converge in well under
 *   one round period, so the K-window inclusion/exclusion fires on the
 *   same wave boundary on every node — no view divergence.
 *
 * Round-advance gates committee shrinking:
 *   The K-window is anchored to currentRound. currentRound only advances
 *   when current quorum is met (Narwhal). So a partition or disconnect
 *   that drops live producers below quorum cannot advance rounds, which
 *   cannot slide the K-window, which cannot drop offline members from
 *   the committee. Net effect: partition halts both sides; no split-brain.
 *
 * Wave stability: both rounds of a wave (propose + vote) see the same
 * committee. Anchored to the wave's first round, so a producer-set change
 * mid-wave doesn't change the committee for that wave's vote round.
 *
 * Chain-of-trust (committee_history): retained as a snapshot/audit
 * security overlay only. Snapshot syncers walk the chain back to genesis
 * to verify committee legitimacy. Not consulted at consensus tick time.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");
const { getGenesisCommittee } = require("../genesis");

/**
 * Active committee at the given round (genesis-anchored derivation).
 *
 *   admit(id) := registered ∧ producing-in-K-window ∧ (
 *                  id ∈ genesis_committee   OR   span(id) ≥ K
 *                )
 *
 * Genesis members are admitted on first cert. Late joiners must produce
 * for K rounds before joining (span = lastInWindow − earliest_in_dag).
 * Both classes are gated on producing-in-window (peer-352 protection).
 *
 * Anchored to the wave's first round so propose + vote rounds of the
 * same wave see the same committee. Both nodes derive identically from
 * the same gossip-replicated DAG + same genesis, so they agree at every
 * wave boundary.
 *
 * @param {Object} dag    DAG facade
 * @param {number} round  Any round within the target wave
 * @param {number} [K]    K-window in rounds. Defaults to
 *                        CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS.
 *                        Same K applies to inclusion (span ≥ K) and
 *                        exclusion (dropped after K rounds of silence).
 * @returns {string[]}    Sorted node_ids of the active committee.
 */
function getActiveCommittee(dag, round, K) {
  const windowRounds = K != null ? K : CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS;

  // Anchor the window to the wave's first round so both rounds of a wave
  // (propose + vote) see the same committee.
  const wave = Math.floor((round - 1) / 2);
  const waveStartRound = wave * 2 + 1;

  // Registered set — active + non-revoked nodes from the registry.
  const registered = new Set();
  for (const n of dag.getAllNodes()) {
    if (n.status === "active" && !dag.isRevoked(n.node_id)) {
      registered.add(n.node_id);
    }
  }

  // Genesis-anchored seed members. These are the only nodes admitted into
  // the committee during the first K rounds of the chain — late joiners
  // (anyone NOT in this set) must serve a K-round proven span before
  // joining. The set is fixed at genesis so every node computes the same
  // answer from the same `genesis.js`. Dead-peer registry rows are
  // excluded by construction (they're not in genesis and aren't producing
  // certs in the window).
  const genesis = getGenesisCommittee();

  // Producers in the K-round window — track the LATEST round each author
  // produced a cert in. Used by both the genesis-membership branch (admit
  // if id ∈ genesis) and the span-based proven branch (admit late joiners
  // once they've produced for K rounds).
  const producers = new Map();  // authorId → lastRoundSeenInWindow
  const fromRound = Math.max(1, waveStartRound - windowRounds);
  const toRound = waveStartRound - 1;
  for (let r = fromRound; r <= toRound; r++) {
    try {
      const certs = dag.getCertificatesByRound(r);
      for (const cert of certs) {
        const prev = producers.get(cert.author_node_id) || 0;
        if (r > prev) producers.set(cert.author_node_id, r);
      }
    } catch { /* ignore */ }
  }

  // Admission rule (single-pass over producers in window):
  //
  //   admit(id) := registered(id) ∧ producing-in-window(id) ∧ (
  //                  id ∈ genesis_committee   OR   span(id) ≥ K
  //                )
  //
  // - producing-in-window: implicit — only iterate the producers map. A
  //   registered node that hasn't produced in the K-window isn't in the
  //   committee. This is the peer-352 protection: silent-fail genesis
  //   members drop out automatically once their last cert ages out.
  //
  // - id ∈ genesis: founding-node IDs are seeded into the committee from
  //   round 1, no K-wait. Required for bootstrap (chicken-and-egg: at
  //   round 1 nobody has K rounds of span yet).
  //
  // - span ≥ K: late joiners (anyone NOT in genesis) are admitted only
  //   after producing for K rounds. earliest = first cert anywhere in
  //   the DAG; lastInWindow = latest cert in the K-window. Robust under
  //   GC: a continuously-producing late joiner's lastInWindow keeps
  //   moving forward at the same rate the GC cutoff does, so span ≥ K
  //   stays satisfied even after older certs are pruned.
  const committee = [];
  for (const [id, lastInWindow] of producers) {
    if (!registered.has(id)) continue;
    if (genesis.has(id)) {
      committee.push(id);
      continue;
    }
    // Late joiner — must have span ≥ K.
    let earliest;
    if (typeof dag.getEarliestCertRoundForAuthor === "function") {
      earliest = dag.getEarliestCertRoundForAuthor(id);
    } else {
      earliest = lastInWindow;  // legacy fallback — degrade to in-window-only
    }
    if (earliest > 0 && (lastInWindow - earliest) >= windowRounds) {
      committee.push(id);
    }
  }

  if (committee.length > 0) return committee.sort();

  // Empty-window fallback. Reached when `producers` is empty:
  //   - true chain genesis (round 1, DAG has no certs at all)
  //   - sync window (narwhal._currentRound stuck at 1 mid-sync)
  //   - historical/old-round query (round predates earliest cert in DAG)
  //   - catastrophic chain halt (entire committee offline > K rounds)
  //
  // In each case, returning genesis ∩ registered is the safe deterministic
  // answer: every node reads the same genesis.js, long-dead registry rows
  // are excluded by construction, and the response is consensus-safe (sync
  // mode doesn't ack/produce; historical queries are debug-only; the
  // chain-of-trust walker reads committee_history directly, not this
  // function). At true chain genesis this is exactly the bootstrap set.
  return [...genesis].filter(id => registered.has(id)).sort();
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

// Legacy alias — `deriveLiveCommittee` was the proposer-side derivation
// when `getActiveCommittee` was reading from committee_history. They've
// been merged: cert-history is now the single source of truth for both
// runtime quorum and proposer detection. Same function, exported under
// both names for callsite intent clarity.
const deriveLiveCommittee = getActiveCommittee;

module.exports = { getActiveCommittee, deriveLiveCommittee, getNodeCount };
