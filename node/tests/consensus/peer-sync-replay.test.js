/**
 * @file tests/consensus/peer-sync-replay.test.js
 * @description Catch-up replay must judge a round with the same BFT time the
 * live path used (the committing anchor's cert.timestamp) and must not decide
 * rounds no anchor has committed yet.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { replaySyncedTxs, anchorTimestampFor } = require("../../src/consensus/peer-sync");

function fakeDag({ commits, certs }) {
  return {
    getCommitsFromRound: (r) => commits.filter(c => c.round >= r).sort((a, b) => a.round - b.round),
    getCertificate: (hash) => certs.find(c => c.hash === hash) || null,
    getCertificatesByRound: (r) => certs.filter(c => c.round === r),
  };
}

describe("replaySyncedTxs", () => {
  const certs = [
    { hash: "c1", round: 1, timestamp: 1000, batch: { txs: [{ tx_id: "t1" }] } },
    { hash: "c2", round: 2, timestamp: 2000, batch: { txs: [{ tx_id: "t2" }] } },
    { hash: "c3", round: 3, timestamp: 3000, batch: { txs: [{ tx_id: "t3" }] } },
    { hash: "c4", round: 4, timestamp: 4000, batch: { txs: [{ tx_id: "t4" }] } },
  ];
  // Anchor at round 2 committed rounds 1-2; rounds 3-4 are not committed yet.
  const commits = [{ round: 2, anchor_cert_hash: "c2" }];

  test("passes the committing anchor's time for every round of its wave", () => {
    const dag = fakeDag({ commits, certs });
    expect(anchorTimestampFor(dag, 1)).toBe(2000);
    expect(anchorTimestampFor(dag, 2)).toBe(2000);
    expect(anchorTimestampFor(dag, 3)).toBe(0);
  });

  test("replays committed rounds with that time and leaves uncommitted rounds to bullshark", () => {
    const calls = [];
    const commitHandler = { commitOrderedTxs: (txs, round, opts) => { calls.push({ ids: txs.map(t => t.tx_id), round, opts }); return { committed: txs.length, dropped: 0 }; } };
    const committed = replaySyncedTxs(fakeDag({ commits, certs }), commitHandler, 1, 4);
    expect(committed).toBe(2);
    expect(calls).toEqual([
      { ids: ["t1"], round: 1, opts: { certTimestamp: 2000 } },
      { ids: ["t2"], round: 2, opts: { certTimestamp: 2000 } },
    ]);
  });

  test("an anchor whose cert was pruned yields no time, so the round is skipped rather than guessed", () => {
    const dag = fakeDag({ commits: [{ round: 2, anchor_cert_hash: "gone" }], certs });
    const calls = [];
    replaySyncedTxs(dag, { commitOrderedTxs: (txs, round, opts) => { calls.push(opts); return { committed: 0, dropped: 0 }; } }, 1, 2);
    expect(calls).toEqual([]);
  });
});
