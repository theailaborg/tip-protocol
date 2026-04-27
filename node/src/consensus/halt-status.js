/**
 * @file @tip-protocol/node/src/consensus/halt-status.js
 * @description Pure decision function for "is consensus halted?" (#30).
 *
 * Factored out of consensus/index.js so it can be tested deterministically
 * without a running orchestrator, and without Date.now() side-effects.
 * The orchestrator wraps this with the live narwhal stats + CONSENSUS
 * constants; tests drive `narwhalStats`, `now`, and `roundTimeoutMs`
 * directly.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

/**
 * Classify a node's consensus state as halted / not-halted based on how
 * long it's been since the last round advance.
 *
 * Not halted (with reason) while:
 *   - narwhal hasn't started yet                 → "narwhal_not_started"
 *   - narwhal is joining / syncing               → "join_state_<state>"
 *   - no rounds have advanced yet (grace window) → "no_activity_yet"
 *   - last advance within 3× round timeout       → "healthy"
 *
 * Halted:
 *   - running + ready + last advance older than 3× round timeout → "sub_quorum"
 *
 * The 3× factor is a local liveness knob — one round can legitimately take
 * longer than ROUND_TIMEOUT_MS during retry cycles without being "stuck".
 * Three consecutive failures is a strong signal that quorum is unreachable.
 *
 * @param {Object}   narwhalStats              Shape: narwhal.stats()
 * @param {boolean}  narwhalStats.running
 * @param {string}   narwhalStats.joinState    "ready" | "syncing"
 * @param {number}   narwhalStats.lastRoundAdvanceAt  Wall-clock ms
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
  if (narwhalStats.joinState !== "ready") {
    return {
      halted: false,
      reason: `join_state_${narwhalStats.joinState}`,
      lastAdvanceAt: narwhalStats.lastRoundAdvanceAt || 0,
      staleMs: 0,
    };
  }
  const lastAt = narwhalStats.lastRoundAdvanceAt || 0;
  if (lastAt === 0) {
    return { halted: false, reason: "no_activity_yet", lastAdvanceAt: 0, staleMs: 0 };
  }
  const staleMs = now() - lastAt;
  const threshold = (roundTimeoutMs || 2000) * 3;
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
