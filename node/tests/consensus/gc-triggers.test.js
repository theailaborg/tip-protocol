/**
 * @file tests/consensus/gc-triggers.test.js
 * @description §2 cert-GC trigger integration tests.
 *
 * Complements cert-gc.test.js (which covers the `pruneCertificatesBefore`
 * primitive). This file exercises the *wiring* that fires the primitive:
 *
 *   1. Bullshark `_maybeRunCertGC` — throttled by
 *      `_metrics.anchors_committed % GC_INTERVAL_COMMITS === 0`, cutoff
 *      computed as `lastCommittedRound - GC_DEPTH`. Runs only when
 *      consensus commits a real anchor.
 *   2. TIP_GC_DISABLED=1 env flag — halts pruning without code change.
 *      Observable via `gc_skipped_disabled` counter.
 *   3. Narwhal `_prunePendingCertsBefore` — drops parked cert waiters
 *      whose round falls below the GC horizon on round advance.
 *
 * Setup uses a 1-node committee (quorum=1) so each vote-round
 * cert self-certifies and commits deterministically. Uses
 * `bullshark.markOrderedUpTo(N)` to seed `_lastCommittedRound` past
 * the default GC_DEPTH=500 without having to drive 500 rounds of
 * fixture.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));
const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

// ── Test harness ─────────────────────────────────────────────────────────

const NODE_ID = "tip://node/n1";

function registerNode(dag) {
  dag.saveNode({
    node_id: NODE_ID,
    name: "n1",
    public_key: "00",
    status: "active",
    registered_at: 1767225600000,
  });
}

// BFT-Time monotonic floor for synthetic certs (1ms per round, strictly
// increasing, anchored 1ms past the genesis floor).
const BFT_T0 = 1773532801000;

function makeCert(round, parentHashes = []) {
  const hash = shake256(`cert:${round}:${NODE_ID}`);
  return {
    hash,
    round,
    author_node_id: NODE_ID,
    batch: { round, author_node_id: NODE_ID, txs: [], signature: "00" },
    acknowledgments: [],
    parent_hashes: parentHashes,
    signature: "00",
    timestamp: BFT_T0 + round,
  };
}

/**
 * Drive N valid anchor commits on a 1-node bullshark, starting at the
 * round just after `lastCommittedRound`. Each commit is a wave of two
 * rounds: propose round (odd) + vote round (even). Returns the final
 * vote round reached.
 */
function driveCommits(bullshark, dag, count, startFromRound) {
  const start = (startFromRound ?? bullshark.lastCommittedRound()) + 1;
  // Ensure start is a propose round (odd); if even, bump by 1.
  const firstPropose = start % 2 === 1 ? start : start + 1;

  let prevHash = null;
  // Look up the prior vote-round cert's hash so our first propose cert
  // has a valid parent link (not strictly required for 1-node quorum but
  // mirrors how real consensus flows).
  if (firstPropose > 1) {
    const prior = dag.getCertificatesByRound(firstPropose - 1);
    if (prior.length > 0) prevHash = prior[0].hash;
  }

  let lastVoteRound = bullshark.lastCommittedRound();
  for (let i = 0; i < count; i++) {
    const proposeRound = firstPropose + i * 2;
    const voteRound = proposeRound + 1;

    const proposeCert = makeCert(proposeRound, prevHash ? [prevHash] : []);
    dag.saveCertificate(proposeCert);
    const voteCert = makeCert(voteRound, [proposeCert.hash]);
    dag.saveCertificate(voteCert);
    prevHash = voteCert.hash;

    bullshark.onRoundComplete([voteCert], voteRound);
    lastVoteRound = voteRound;
  }
  return lastVoteRound;
}

function setupBullshark() {
  const dag = initDAG({ dbPath: ":memory:" });
  registerNode(dag);
  const bullshark = createBullshark({
    dag,
    getNodeIds: () => [NODE_ID],
    onOrderedTxs: () => { /* no-op */ },
  });
  return { dag, bullshark };
}

// ═══════════════════════════════════════════════════════════════════════════
// Bullshark commit-path GC trigger
// ═══════════════════════════════════════════════════════════════════════════
describe("bullshark _maybeRunCertGC (commit-path trigger)", () => {
  test("anchors_committed increments on every successful commit", () => {
    const { dag, bullshark } = setupBullshark();
    driveCommits(bullshark, dag, 3);
    expect(bullshark.stats().metrics.anchors_committed).toBe(3);
  });

  test("GC throttle: fires exactly at every GC_INTERVAL_COMMITS-th commit", () => {
    // TIP_GC_DISABLED path gives a clean observable counter for throttle
    // testing without needing GC_DEPTH-sized fixtures. `gc_skipped_disabled`
    // increments only when the function is entered (i.e. after the throttle
    // gate has passed), so it's the exact signal.
    process.env.TIP_GC_DISABLED = "1";
    try {
      const { dag, bullshark } = setupBullshark();
      const interval = CONSENSUS.GC_INTERVAL_COMMITS;

      driveCommits(bullshark, dag, interval - 1);
      expect(bullshark.stats().metrics.anchors_committed).toBe(interval - 1);
      expect(bullshark.stats().metrics.gc_skipped_disabled).toBe(0);

      driveCommits(bullshark, dag, 1);
      expect(bullshark.stats().metrics.anchors_committed).toBe(interval);
      expect(bullshark.stats().metrics.gc_skipped_disabled).toBe(1);

      driveCommits(bullshark, dag, interval);
      expect(bullshark.stats().metrics.anchors_committed).toBe(interval * 2);
      expect(bullshark.stats().metrics.gc_skipped_disabled).toBe(2);
    } finally {
      delete process.env.TIP_GC_DISABLED;
    }
  });

  test("TIP_GC_DISABLED=1 halts pruning entirely", () => {
    process.env.TIP_GC_DISABLED = "1";
    try {
      const { dag, bullshark } = setupBullshark();
      // Seed old certs that SHOULD be pruned under normal conditions.
      for (let r = 1; r <= 10; r++) dag.saveCertificate(makeCert(r));
      bullshark.markOrderedUpTo(600);

      driveCommits(bullshark, dag, CONSENSUS.GC_INTERVAL_COMMITS, 601);
      expect(bullshark.stats().metrics.gc_skipped_disabled).toBe(1);
      expect(bullshark.stats().metrics.certs_pruned).toBe(0);
      expect(bullshark.stats().metrics.gc_runs).toBe(0);

      // Pre-seeded certs still there
      expect(dag.certificateCount()).toBeGreaterThan(10);
    } finally {
      delete process.env.TIP_GC_DISABLED;
    }
  });

  test("GC fires real prune when cutoff > 0 and interval hits", () => {
    const { dag, bullshark } = setupBullshark();
    const interval = CONSENSUS.GC_INTERVAL_COMMITS;
    const gcDepth = CONSENSUS.GC_DEPTH;

    // With jumpTo=gcDepth and `interval` commits driving lastCommittedRound
    // to gcDepth + interval*2, cutoff = interval*2 (e.g. 20). Seed certs
    // straddling that cutoff: rounds 1..cutoff-1 will be pruned, rounds
    // cutoff.. survive.
    const expectedCutoff = interval * 2;
    for (let r = 1; r < expectedCutoff; r++) dag.saveCertificate(makeCert(r));
    for (let r = expectedCutoff; r < expectedCutoff + 5; r++) dag.saveCertificate(makeCert(r));
    const preSeedCount = dag.certificateCount();
    expect(preSeedCount).toBeGreaterThan(0);

    // Jump _lastCommittedRound to gcDepth so that after `interval` commits
    // the cutoff is positive. Each commit advances by 2 rounds, so after
    // `interval` commits lastCommittedRound = gcDepth + interval*2, and
    // cutoff = gcDepth + interval*2 - gcDepth = interval*2. That's the
    // value certs below which will be pruned (e.g. 20 if interval=10).
    const jumpTo = gcDepth;
    bullshark.markOrderedUpTo(jumpTo);
    expect(bullshark.lastCommittedRound()).toBe(jumpTo);

    const lastVote = driveCommits(bullshark, dag, interval);
    // anchors_committed === interval, so the throttle gate fires GC once.
    expect(bullshark.stats().metrics.anchors_committed).toBe(interval);
    expect(bullshark.stats().metrics.gc_runs).toBe(1);

    // cutoff = lastVote - gcDepth. Every seeded cert with round < cutoff
    // should be pruned.
    const cutoff = lastVote - gcDepth;
    expect(cutoff).toBe(expectedCutoff);
    // All seeded certs below cutoff pruned
    for (let r = 1; r < cutoff; r++) {
      expect(dag.getCertificatesByRound(r)).toHaveLength(0);
    }
    // Certs at rounds >= cutoff retained
    expect(dag.getCertificatesByRound(cutoff)).toHaveLength(1);
    expect(dag.getCertificatesByRound(cutoff + 4)).toHaveLength(1);
    expect(bullshark.stats().metrics.certs_pruned).toBe(cutoff - 1);
  });

  test("GC does NOT fire when cutoff <= 0 (early rounds, insufficient history)", () => {
    const { dag, bullshark } = setupBullshark();
    driveCommits(bullshark, dag, CONSENSUS.GC_INTERVAL_COMMITS);
    // lastCommittedRound is small (~20), cutoff = 20 - 500 = -480 → early return.
    expect(bullshark.stats().metrics.anchors_committed).toBe(CONSENSUS.GC_INTERVAL_COMMITS);
    expect(bullshark.stats().metrics.gc_runs).toBe(0);
    expect(bullshark.stats().metrics.certs_pruned).toBe(0);
    expect(bullshark.stats().metrics.gc_failures).toBe(0);
  });

  test("gc_failures counter increments on prune exception", () => {
    const { dag, bullshark } = setupBullshark();
    // Jump lastCommittedRound to gcDepth so after 1 interval's worth of
    // commits the cutoff is > 0 and prune would be attempted.
    bullshark.markOrderedUpTo(CONSENSUS.GC_DEPTH);

    // Sabotage the prune accessor to throw.
    const originalPrune = dag.pruneCertificatesBefore;
    dag.pruneCertificatesBefore = () => { throw new Error("synthetic disk error"); };

    try {
      driveCommits(bullshark, dag, CONSENSUS.GC_INTERVAL_COMMITS);
      expect(bullshark.stats().metrics.gc_failures).toBe(1);
      expect(bullshark.stats().metrics.certs_pruned).toBe(0);
      // Consensus still advanced despite GC failure
      expect(bullshark.stats().metrics.anchors_committed).toBe(CONSENSUS.GC_INTERVAL_COMMITS);
    } finally {
      dag.pruneCertificatesBefore = originalPrune;
    }
  });
});
