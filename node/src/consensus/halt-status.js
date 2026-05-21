/**
 * @file @tip-protocol/node/src/consensus/halt-status.js
 * @description Pure decision function for "is consensus halted?" (#30).
 *
 * Factored out of consensus/index.js so it can be tested deterministically
 * without a running orchestrator, and without nowMs() side-effects.
 * The orchestrator wraps this with the live narwhal stats + CONSENSUS
 * constants; tests drive `narwhalStats`, `now`, and `roundTimeoutMs`
 * directly.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs } = require("../../../shared/time");

/**
 * Classify a node's consensus state as halted / not-halted based on how
 * long it's been since the last round advance OR last sync progress.
 *
 * Not halted (with reason) while:
 *   - narwhal hasn't started yet                 → "narwhal_not_started"
 *   - narwhal is joining / syncing recently      → "join_state_<state>"
 *   - no rounds have advanced yet (grace window) → "no_activity_yet"
 *   - last advance within 3× round timeout       → "healthy"
 *
 * Halted:
 *   - running + ready + last advance older than 3× round timeout → "sub_quorum"
 *   - running + syncing for longer than 3× round timeout         → "stuck_syncing"
 *     (#78: a node pinned in `_joinState=syncing` due to repeated sync
 *     failures (#66 fingerprint) silently ignores all peer batches and is
 *     usually the actual cause of a federation halt — but the previous
 *     short-circuit on `joinState !== "ready"` returned not-halted, hiding
 *     it from Grafana while honest-but-blocked nodes appeared red. Pairs
 *     with #66's exit-sync watchdog: same threshold, two views.)
 *
 * The 3× factor is a local liveness knob — one round can legitimately take
 * longer than ROUND_TIMEOUT_MS during retry cycles without being "stuck".
 * Three consecutive failures is a strong signal of unreachable quorum or
 * dead-peer sync.
 *
 * @param {Object}   narwhalStats              Shape: narwhal.stats()
 * @param {boolean}  narwhalStats.running
 * @param {string}   narwhalStats.joinState    "ready" | "syncing"
 * @param {number}   narwhalStats.lastRoundAdvanceAt  Wall-clock ms
 * @param {number}   [narwhalStats.syncEnteredAt]     Wall-clock ms; 0 when not syncing
 * @param {number}   [narwhalStats.round]      Current round, for the error msg
 * @param {number}   [narwhalStats.certificatesThisRound]
 * @param {number}   [narwhalStats.quorum]
 * @param {Object}   opts
 * @param {number}   opts.roundTimeoutMs       Base round timeout from CONSENSUS
 * @param {Function} [opts.now]                Clock function (injectable for tests)
 * @returns {{ halted: boolean, reason: string, lastAdvanceAt: number, staleMs: number, message?: string }}
 */
function computeHaltStatus(narwhalStats, { roundTimeoutMs, now = Date.now } = {}) {
  if (!narwhalStats || !narwhalStats.running) {
    return { halted: false, reason: "narwhal_not_started", lastAdvanceAt: 0, staleMs: 0 };
  }
  // Byzantine-fork halt takes priority over all other conditions: it's a
  // safety event (we are the byzantine minority per ≥ f+1 peer agreement,
  // OR the operator manually flagged us). Surface it to the existing
  // halt-gate so the /metrics tip_consensus_halted gauge + Grafana "Halt
  // status" panel reflect this without dashboard changes. /v1/* writes
  // get 503 via consensus-gate middleware as soon as this fires.
  if (narwhalStats.byzantineForkHalt) {
    const h = narwhalStats.byzantineForkHalt;
    const since = h.since || now();
    return {
      halted: true,
      reason: "byzantine_fork",
      lastAdvanceAt: narwhalStats.lastRoundAdvanceAt || 0,
      staleMs: now() - since,
      message: `Byzantine-fork halt at round ${h.atRound} (${h.reason}). Operator must investigate state divergence and clearByzantineForkHalt() after resolving.`,
    };
  }
  const syncThreshold = (roundTimeoutMs || 2000) * 3;
  // catching_up is bandwidth-bound (cert tail closure) and legitimately
  // slower than initial install — give it 3× more headroom than syncing.
  const catchingUpThreshold = (roundTimeoutMs || 2000) * 10;
  const threshold = syncThreshold;
  if (narwhalStats.joinState === "syncing") {
    // Distinguish "briefly syncing" (healthy, expected) from "stuck in
    // syncing too long" (cause of federation halt). syncEnteredAt is the
    // wall-clock when narwhal flipped into syncing state.
    const syncStart = narwhalStats.syncEnteredAt || 0;
    if (syncStart > 0) {
      const stuckMs = now() - syncStart;
      if (stuckMs > syncThreshold) {
        return {
          halted: true,
          reason: "stuck_syncing",
          lastAdvanceAt: narwhalStats.lastRoundAdvanceAt || 0,
          staleMs: stuckMs,
          message: `Stuck in sync mode for ${Math.floor(stuckMs / 1000)}s — sync attempts likely failing in a loop. Operator action: check peer connectivity / restart this node.`,
        };
      }
    }
    return {
      halted: false,
      reason: "join_state_syncing",
      lastAdvanceAt: narwhalStats.lastRoundAdvanceAt || 0,
      staleMs: 0,
    };
  }
  if (narwhalStats.joinState === "catching_up") {
    // Catch-up tail is bandwidth-bound. Healthy when it converges within
    // the threshold; stuck when the cert tail isn't closing — peer GC'd
    // faster than we synced or peer dropped, ops should pick a different
    // peer or reset the joiner.
    const catchStart = narwhalStats.catchingUpEnteredAt || 0;
    if (catchStart > 0) {
      const stuckMs = now() - catchStart;
      if (stuckMs > catchingUpThreshold) {
        const target = narwhalStats.catchUpTarget || 0;
        const round  = narwhalStats.round ?? 0;
        return {
          halted: true,
          reason: "stuck_catching_up",
          lastAdvanceAt: narwhalStats.lastRoundAdvanceAt || 0,
          staleMs: stuckMs,
          message: `Stuck closing cert tail for ${Math.floor(stuckMs / 1000)}s (target=${target}, current=${round}) — peer likely GC'd past our snapshot. Operator action: pick a peer with a fresher commit horizon or reset this node.`,
        };
      }
    }
    return {
      halted: false,
      reason: "join_state_catching_up",
      lastAdvanceAt: narwhalStats.lastRoundAdvanceAt || 0,
      staleMs: 0,
    };
  }
  const lastAt = narwhalStats.lastRoundAdvanceAt || 0;
  if (lastAt === 0) {
    return { halted: false, reason: "no_activity_yet", lastAdvanceAt: 0, staleMs: 0 };
  }
  const staleMs = now() - lastAt;
  if (staleMs > threshold) {
    const round = narwhalStats.round ?? 0;
    const certs = narwhalStats.certificatesThisRound ?? 0;
    const quorum = narwhalStats.quorum ?? 0;
    return {
      halted: true,
      reason: "sub_quorum",
      lastAdvanceAt: lastAt,
      staleMs,
      message: `No consensus progress for ${Math.floor(staleMs / 1000)}s — quorum unreachable. ${certs}/${quorum} certs at round ${round}.`,
    };
  }
  return { halted: false, reason: "healthy", lastAdvanceAt: lastAt, staleMs };
}

module.exports = { computeHaltStatus };
