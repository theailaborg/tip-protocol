/**
 * @file tests/consensus/anti-entropy-stale-peer-status.test.js
 * @description The resync guard must only trust peer status it observed recently.
 *
 * `_lastStatus` is never pruned. An isolated node therefore still holds entries
 * for peers that are long gone, frozen at the round it is itself stuck on. The
 * guard then reads its own round back, concludes nothing is ahead, and skips the
 * resync that would recover it. A partner node sat in exactly that state for
 * 9.7 hours, logging the same refusal every 4 seconds and never reconnecting.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

// Read before local-config loads: it resolves env at module load time.
process.env.TIP_PEER_STATUS_STALE_AFTER_MS = "20000";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { summarizeFreshPeers } = require(path.join(SRC, "consensus", "anti-entropy"));
const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));

const NOW = 1_700_000_000_000;

/** One cache entry as checkAndReconcile stores it. */
function entry(committed_round, observedAgoMs) {
  return { committed_round, _observedAtMs: NOW - observedAgoMs };
}

function cache(pairs) {
  return new Map(Object.entries(pairs));
}

describe("peer-status freshness", () => {
  test("the staleness window is a local constant and honours its env override", () => {
    expect(CONSENSUS.PEER_STATUS_STALE_AFTER_MS).toBe(20000);
  });

  test("a recently observed peer counts, and its committed round is reported", () => {
    const r = summarizeFreshPeers(cache({ a: entry(120, 1000) }), 20000, NOW);
    expect(r).toEqual({ fresh: 1, maxCommitted: 120 });
  });

  test("an observation older than the window is not evidence about that peer", () => {
    const r = summarizeFreshPeers(cache({ a: entry(120, 60000) }), 20000, NOW);
    expect(r).toEqual({ fresh: 0, maxCommitted: 0 });
  });

  test("the boundary is inclusive: an entry exactly at the window still counts", () => {
    const r = summarizeFreshPeers(cache({ a: entry(120, 20000) }), 20000, NOW);
    expect(r.fresh).toBe(1);
  });

  test("only fresh entries contribute the maximum committed round", () => {
    const r = summarizeFreshPeers(
      cache({ stale: entry(999, 60000), fresh: entry(120, 500) }),
      20000,
      NOW,
    );
    expect(r).toEqual({ fresh: 1, maxCommitted: 120 });
  });

  test("an entry with no observation timestamp is treated as stale", () => {
    const r = summarizeFreshPeers(cache({ a: { committed_round: 120 } }), 20000, NOW);
    expect(r).toEqual({ fresh: 0, maxCommitted: 0 });
  });

  test("a null entry is skipped rather than throwing", () => {
    const r = summarizeFreshPeers(cache({ a: null, b: entry(7, 100) }), 20000, NOW);
    expect(r).toEqual({ fresh: 1, maxCommitted: 7 });
  });

  test("an empty cache reports nothing fresh", () => {
    expect(summarizeFreshPeers(new Map(), 20000, NOW)).toEqual({ fresh: 0, maxCommitted: 0 });
  });

  // The failure this fix exists for. An isolated node keeps three cache entries
  // frozen at its own committed round. Counting them made the guard skip the
  // resync; counting only fresh ones leaves nothing to skip on.
  test("an isolated node holding only stale entries reports no fresh peers", () => {
    const selfCommitted = 13428108;
    const isolated = cache({
      p1: entry(selfCommitted, 9.7 * 3600 * 1000),
      p2: entry(selfCommitted, 9.7 * 3600 * 1000),
      p3: entry(selfCommitted, 9.7 * 3600 * 1000),
    });

    expect(isolated.size).toBe(3);   // the old size-based guard would have fired

    const r = summarizeFreshPeers(isolated, CONSENSUS.PEER_STATUS_STALE_AFTER_MS, NOW);

    expect(r.fresh).toBe(0);
    expect(r.maxCommitted).toBe(0);
    // fresh === 0 is what stops the guard short-circuiting to no_peer_ahead.
    expect(r.maxCommitted <= selfCommitted && r.fresh > 0).toBe(false);
  });
});
