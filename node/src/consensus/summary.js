/**
 * @file @tip-protocol/node/src/consensus/summary.js
 * @description Periodic consensus heartbeat summary.
 *
 * Per-round consensus events are chatty — they're logged at DEBUG level
 * and captured in debug.log for post-mortem analysis. The terminal and
 * info.log stay quiet. This module emits ONE INFO line per interval with
 * deltas from the last tick so operators get a heartbeat showing health
 * at a glance. Idle periods (no rounds, no retries, no fast-forwards)
 * produce no output — truly silent when there's nothing to say.
 *
 * Output example:
 *   consensus summary (60s): round=4821, +120 rounds, +60 anchors,
 *     +3 txs, 1 retries, mempool=0, peers=2
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs } = require("../../../shared/time");
const { safeSetInterval } = require("../safe-timer");

const { getLogger } = require("../logger");

const log = getLogger("tip.consensus");

/**
 * Create a consensus summary emitter.
 *
 * @param {Object} options
 * @param {Object} options.narwhal      Narwhal instance (provides stats())
 * @param {Object} options.bullshark    Bullshark instance (provides stats())
 * @param {number} options.intervalMs   Tick cadence
 * @returns {{ start: Function, stop: Function }}
 */
function createConsensusSummary({ narwhal, bullshark, intervalMs }) {
  let _timer = null;
  let _last = null;

  function _snapshot() {
    const n = narwhal.stats();
    const b = bullshark.stats();
    return {
      ts: nowMs(),
      round: n.round,
      mempoolSize: n.mempoolSize,
      participants: n.activeParticipants,
      rounds_advanced: n.metrics?.rounds_advanced || 0,
      anchors_committed: b.metrics?.anchors_committed || 0,
      txs_committed: b.metrics?.txs_committed || 0,
      fast_forwards: n.metrics?.fast_forwards || 0,
      retries: n.metrics?.retries || 0,
    };
  }

  function _tick() {
    const now = _snapshot();

    if (_last) {
      const dtSec = Math.max(1, Math.round((now.ts - _last.ts) / 1000));
      const dRounds = now.rounds_advanced - _last.rounds_advanced;
      const dAnchors = now.anchors_committed - _last.anchors_committed;
      const dTxs = now.txs_committed - _last.txs_committed;
      const dFastFwd = now.fast_forwards - _last.fast_forwards;
      const dRetries = now.retries - _last.retries;

      // Skip emission in pure steady-state quiet: no activity AND no trouble.
      const quiet = dRounds === 0 && dAnchors === 0 && dTxs === 0 &&
        dFastFwd === 0 && dRetries === 0;
      if (!quiet) {
        const trouble = [];
        if (dFastFwd) trouble.push(`${dFastFwd} fast-forwards`);
        if (dRetries) trouble.push(`${dRetries} retries`);
        const trailer = trouble.length ? `, ${trouble.join(", ")}` : "";
        log.info(
          `summary (${dtSec}s): round=${now.round}, ` +
          `+${dRounds} rounds, +${dAnchors} anchors, +${dTxs} txs${trailer}, ` +
          `mempool=${now.mempoolSize}, peers=${Math.max(0, now.participants - 1)}`
        );
      }
    }
    _last = now;
  }

  return {
    start() {
      if (_timer) return;
      _last = null;
      _timer = safeSetInterval(_tick, intervalMs, "consensus.summary");
      // Summary shouldn't keep the process alive on shutdown
      if (_timer.unref) _timer.unref();
    },
    stop() {
      if (_timer) { clearInterval(_timer); _timer = null; }
      _last = null;
    },
  };
}

module.exports = { createConsensusSummary };
