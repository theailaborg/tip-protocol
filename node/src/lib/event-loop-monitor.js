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
 * window.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { monitorEventLoopDelay } = require("perf_hooks");

const WINDOW_MS = 1000;

const _safe = (v) => (Number.isFinite(v) ? v : 0);

function createEventLoopMonitor() {
  const h = monitorEventLoopDelay({ resolution: 20 });
  h.enable();

  let _last = { max_ms: 0, p99_ms: 0, mean_ms: 0 };

  function roll() {
    _last = {
      max_ms: _safe(h.max / 1e6),
      p99_ms: _safe(h.percentile(99) / 1e6),
      mean_ms: _safe(h.mean / 1e6),
    };
    h.reset();
  }

  const timer = setInterval(roll, WINDOW_MS);
  if (timer.unref) timer.unref();

  function sample() { return _last; }

  return { sample };
}

// Process-wide singleton: there is one event loop, so one monitor suffices.
const eventLoopMonitor = createEventLoopMonitor();

module.exports = { eventLoopMonitor, createEventLoopMonitor };
