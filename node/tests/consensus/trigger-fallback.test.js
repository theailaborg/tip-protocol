/**
 * @file tests/consensus/trigger-fallback.test.js
 * @description #126: the idle-cluster fallback timer must drive EVERY
 * time-based trigger, not just verdicts.
 *
 * On an idle cluster Bullshark's `orderedTxs.length > 0` guard stops
 * onOrderedTxs from firing, so the commit-handler never calls checkPending and
 * each trigger stalls. The fallback timer calls pollPendingTriggers on a short
 * interval; this locks in that it covers all four triggers (a regression guard
 * against the #106 bug where only verdictTrigger was polled).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { pollPendingTriggers } = require(path.resolve(__dirname, "../../src/consensus"));

// Four trigger doubles whose checkPending records its args. verdict also
// exposes size() (heap-backed; the only trigger with an O(1) pending count).
function mkTriggers({ verdictSize = 1 } = {}) {
  const calls = { verdict: [], clean: [], review: [], completion: [] };
  const triggers = {
    verdictTrigger: { size: () => verdictSize, checkPending: (...a) => calls.verdict.push(a) },
    cleanRecordTrigger: { checkPending: (...a) => calls.clean.push(a) },
    prescanReviewTrigger: { checkPending: (...a) => calls.review.push(a) },
    prescanCompletionTrigger: { checkPending: (...a) => calls.completion.push(a) },
  };
  return { triggers, calls };
}

describe("#126 pollPendingTriggers: idle-cluster fallback covers all four triggers", () => {
  test("one idle tick polls verdict + clean-record + prescan-review + prescan-completion", () => {
    const { triggers, calls } = mkTriggers({ verdictSize: 2 });
    pollPendingTriggers({ ...triggers, now: 1000, round: 7 });
    expect(calls.verdict).toEqual([[1000, 7]]);     // (now, round)
    expect(calls.clean).toEqual([[1000]]);          // clean-record takes only certTimestamp
    expect(calls.review).toEqual([[1000, 7]]);
    expect(calls.completion).toEqual([[1000, 7]]);
  });

  test("verdict is size-guarded: nothing pending skips it, but the other three still poll", () => {
    const { triggers, calls } = mkTriggers({ verdictSize: 0 });
    pollPendingTriggers({ ...triggers, now: 5, round: 1 });
    expect(calls.verdict).toEqual([]);              // size() === 0 -> skipped
    expect(calls.clean).toEqual([[5]]);
    expect(calls.review).toEqual([[5, 1]]);
    expect(calls.completion).toEqual([[5, 1]]);
  });

  test("a throwing trigger is isolated: the rest still fire", () => {
    const { triggers, calls } = mkTriggers();
    triggers.prescanReviewTrigger.checkPending = () => { throw new Error("boom"); };
    expect(() => pollPendingTriggers({ ...triggers, now: 9, round: 3 })).not.toThrow();
    expect(calls.verdict).toEqual([[9, 3]]);
    expect(calls.clean).toEqual([[9]]);
    expect(calls.completion).toEqual([[9, 3]]);     // ran despite review throwing
  });

  test("missing triggers are skipped (optional wiring, no throw)", () => {
    const calls = [];
    expect(() => pollPendingTriggers({
      cleanRecordTrigger: { checkPending: (...a) => calls.push(a) },
      now: 2, round: 4,
    })).not.toThrow();
    expect(calls).toEqual([[2]]);
  });
});
