/**
 * @file @tip-protocol/node/src/consensus/participants.js
 * @description Active committee derivation from gossip-replicated DAG state.
 *
 * The active committee at round R is a deterministic function of the DAG's
 * cert history: every node reading the same DAG computes the same committee.
 * This is what makes leader rotation, quorum thresholds, and round advance
 * agree across nodes without needing an extra consensus pass.
 *
 * Membership rule:
 *   committee(R) = registered_active ∩ proven_producers_in_K_rounds_before(R)
 *
 * Where "proven" means SPAN-based: (last_cert_in_window - earliest_cert)
 * ≥ K. The node must have been producing certs across at least K rounds
 * — not merely "have an earliest cert that's K-old." A node that produced
 * briefly and stopped has span < K and is excluded even if its earliest
 * cert is now > K rounds old (live fingerprint: peer 352 case). A fresh
 * joiner that just produced its first cert has span=0, also excluded
 * until it has K rounds of continuous production. Same K is used for
 * offline detection (dropped after K rounds of silence) — symmetric.
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

/**
 * Active committee at the given round.
 *
 *   committee(round) = registered_active ∩ proven_producers_in_K_rounds
 *
 * "Proven" = span-based: `last_cert_in_window - earliest_cert ≥ K`.
 * Node must have been producing certs for at least K rounds. A fresh
 * joiner that just produced its first cert (span=0) is excluded; a
 * briefly-active joiner that produced for X rounds and stopped (span=X
 * for X < K) is excluded; a node continuously producing for ≥ K rounds
 * is admitted.
 *
 * Anchored to the wave's first round so propose + vote rounds of the
 * same wave see the same committee. Both nodes derive identically from
 * the same gossip-replicated DAG, so they agree at every wave boundary.
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

  const registered = new Set();
  for (const n of dag.getAllNodes()) {
    if (n.status === "active" && !dag.isRevoked(n.node_id)) {
      registered.add(n.node_id);
    }
  }

  // Producers in the K-round window — track the LATEST round each author
  // produced in (within the window). Used for the span-based proven check
  // below: a node is proven only when (last_cert - earliest_cert) >= K,
  // i.e. it has actually put in K rounds of work, not just "been around
  // for K rounds." A node that produced briefly and then stopped fails
  // this check even when its earliest cert is K-old, because its span
  // of activity is shorter than K.
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

  // Proven-node filter — span-based:
  //
  //   proven = (last_cert_in_window - earliest_cert) >= K
  //
  // The node must have been producing certs for AT LEAST K rounds
  // (continuous span). A node that produced for 100 rounds and stopped
  // has span=100, fails for K=300 — even if its earliest cert is now
  // 300+ rounds old, because the SPAN of its activity hasn't reached K.
  //
  // Live-fingerprint of why this matters (2026-05-02 federation halt):
  //   peer 352 produced certs at rounds 848..950 (span=102), then went
  //   offline. At round 1149, waveStart - earliest = 301 ≥ K=300 (the
  //   old check passed), so peer 352 was promoted into the committee.
  //   Quorum jumped from 1 to 2, peer 352 was offline, halt. With the
  //   span check: 950 - 848 = 102 < 300 → peer 352 stays out, no halt.
  //
  // Same property symmetrically: a fresh joiner producing only its
  // first cert has span=0, fails until it has continuously produced
  // for K rounds. The old "earliest cert is K-old" check satisfied
  // the same property for honest nodes that keep producing — but it
  // mis-fired on briefly-active joiners that died before reaching K.
  const proven = [];
  for (const [id, lastInWindow] of producers) {
    if (!registered.has(id)) continue;
    let earliest;
    if (typeof dag.getEarliestCertRoundForAuthor === "function") {
      earliest = dag.getEarliestCertRoundForAuthor(id);
    } else {
      earliest = lastInWindow;  // legacy fallback — degrade to in-window-only
    }
    if (earliest > 0 && (lastInWindow - earliest) >= windowRounds) {
      proven.push(id);
    }
  }

  if (proven.length > 0) return proven.sort();

  // First fallback (early-deployment): no node has demonstrated K rounds
  // yet, but some producers exist. Return registered ∩ producers — excludes
  // registered-but-not-running nodes that would inflate quorum and halt
  // consensus. This is the case during the first K rounds of a fresh
  // deployment, OR after a registration commit but before the new node
  // starts producing (registered without running).
  //
  // Without this filter: registering node 2 while founding is still in
  // its first K rounds would push committee to {founding, node2}, quorum=2,
  // unmeetable (node 2 not running) → halt. With the filter, node 2 is
  // excluded until it actually produces certs, and quorum stays at 1.
  const liveProducers = [...producers.keys()].filter(id => registered.has(id));
  if (liveProducers.length > 0) return liveProducers.sort();

  // Last-resort fallback: no certs exist anywhere yet (absolute genesis,
  // round 1 before founding's first cert lands). Return registered so
  // consensus can bootstrap. Only fires for the first round or two of
  // a fresh chain — once founding produces its first cert, the previous
  // branch takes over.
  return [...registered].sort();
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
