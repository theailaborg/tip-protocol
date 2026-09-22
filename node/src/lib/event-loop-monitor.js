/**
 * @file @tip-protocol/node/src/lib/event-loop-monitor.js
 * @description Windowed event-loop delay sampler for consensus observability.
 *
 * The node runs all consensus work on one thread. When that thread blocks
 * (synchronous crypto, large merkle rebuild, GC), libp2p keep-alives and
 * gossip miss their deadlines and peers drop, surfacing as the transient
 * "node goes offline for a bit" jitter. This exposes how long the loop was
 * blocked so a round-stall can be correlated against a loop-stall on the
 * same timeline instead of guessed at.
 *
 * A single perf_hooks histogram is snapshotted + reset every WINDOW_MS, so
 * sample() is non-destructive and safe for several readers at once (the
 * Prometheus scrape and a live tracer) without one stealing the other's
 * window. totals() does NOT share that guarantee: its utilization figure is
 * measured since the previous call, so two readers would split the interval
 * between them. Keep it to one caller. The cumulative fields it returns are
 * unaffected.
 *
 * The windowed figures answer "is it stalled right now". They cannot answer
 * "what was the average over the last hour", because each window overwrites
 * the last. Cumulative totals are carried alongside so a dashboard can divide
 * two rates and get the mean over whatever window it is drawing.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { monitorEventLoopDelay, performance } = require("perf_hooks");

const WINDOW_MS = 1000;

const _safe = (v) => (Number.isFinite(v) ? v : 0);

function createEventLoopMonitor() {
  const h = monitorEventLoopDelay({ resolution: 20 });
  h.enable();

  let _last = { max_ms: 0, p99_ms: 0, mean_ms: 0 };

  // Cumulative delay, for a rate-based mean over any window.
  let _delaySumMs = 0;
  let _delayCount = 0;

  // Event-loop utilization: the fraction of wall clock the single thread spent
  // doing work rather than waiting. Sustained high utilization is saturation,
  // which is what turns into missed deadlines and dropped peers. Node reports
  // it cumulatively, so a dashboard divides the two rates.
  let _eluSupported = typeof performance.eventLoopUtilization === "function";
  let _eluLast = _eluSupported ? performance.eventLoopUtilization() : null;

  function roll() {
    const mean = _safe(h.mean / 1e6);
    const count = _safe(h.count);
    _last = {
      max_ms: _safe(h.max / 1e6),
      p99_ms: _safe(h.percentile(99) / 1e6),
      mean_ms: mean,
    };
    if (count > 0) {
      _delaySumMs += mean * count;
      _delayCount += count;
    }
    h.reset();
  }

  const timer = setInterval(roll, WINDOW_MS);
  if (timer.unref) timer.unref();

  function sample() { return _last; }

  /**
   * Cumulative counters since process start.
   * @returns {{delay_sum_ms:number, delay_count:number, active_ms:number, idle_ms:number, utilization:number}}
   */
  function totals() {
    let active = 0;
    let idle = 0;
    let utilization = 0;
    if (_eluSupported) {
      try {
        const now = performance.eventLoopUtilization();
        active = _safe(now.active);
        idle = _safe(now.idle);
        // Utilization since the previous read, so the gauge tracks recent
        // saturation rather than flattening out over the process lifetime.
        const delta = performance.eventLoopUtilization(now, _eluLast);
        utilization = _safe(delta && delta.utilization);
        _eluLast = now;
      } catch { _eluSupported = false; }
    }
    return {
      delay_sum_ms: _delaySumMs,
      delay_count: _delayCount,
      active_ms: active,
      idle_ms: idle,
      utilization,
    };
  }

  return { sample, totals };
}

// Process-wide singleton: there is one event loop, so one monitor suffices.
const eventLoopMonitor = createEventLoopMonitor();

module.exports = { eventLoopMonitor, createEventLoopMonitor };
