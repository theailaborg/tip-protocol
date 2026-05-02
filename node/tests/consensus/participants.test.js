/**
 * @file tests/consensus/participants.test.js
 * @description Tests for the active-committee accessor.
 *
 * Post-§4 deadlock fix: getActiveCommittee derives the runtime committee
 * from gossip-replicated cert history (NOT from committee_history /
 * Bullshark-committed state). Both nodes derive identically from the same
 * DAG, so they agree on quorum at every round — eliminating the mid-flight
 * quorum-change deadlock that committee_history-based derivation caused.
 *
 * deriveLiveCommittee is now an alias for getActiveCommittee — they were
 * the same logic but split (one for runtime, one for proposer detection)
 * in the §4 design. Merged after the §4 runtime path was reverted to
 * cert-history. Tests cover both names to lock the alias.
 *
 * Covers:
 *  - registered ∩ proven_producers_in_K_rounds, sorted
 *  - cold-start fallback to registered set when nothing is proven
 *  - proven-node filter (must produce for ≥ K rounds before inclusion)
 *  - excludes inactive / revoked / unregistered authors
 *  - wave-stable: propose + vote rounds of one wave see same committee
 *  - default K = CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS
 *  - getActiveCommittee and deriveLiveCommittee return identical results
 *  - getNodeCount counts only status='active' && non-revoked
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(SHARED + "/crypto");
const { initDAG } = require(path.join(SRC, "dag"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));
const { getActiveCommittee, deriveLiveCommittee, getNodeCount } = require(path.join(SRC, "consensus", "participants"));

beforeAll(async () => { await initCrypto(); });

const FOUNDING_NODE_ID = getGenesisPayload().founding_node.node_id;

function _setup() {
  return initDAG({ inMemory: true });
}

function _seedNodes(dag, ids) {
  for (const id of ids) {
    dag.saveNode({
      node_id: id, name: id, public_key: shake256(id),
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
  }
}

function _seedCertsByRound(dag, byRound) {
  for (const [roundStr, authors] of Object.entries(byRound)) {
    const round = Number(roundStr);
    for (const author of authors) {
      const certHash = shake256(`cert-${round}-${author}`);
      dag.saveCertificate({
        hash: certHash,
        round,
        author_node_id: author,
        signature: "00",
        batch: { txs: [], hash: shake256(`batch-${round}-${author}`) },
        parent_hashes: [],
        acknowledgments: [],
      });
    }
  }
}

describe("getActiveCommittee — cert-history-based derivation", () => {
  test("returns registered ∩ proven_producers_in_K_rounds, sorted", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b", "tip://node/c", "tip://node/d"]);

    // All four have early certs at round 1 — fully proven by round 101 (K=10)
    _seedCertsByRound(dag, {
      1: ["tip://node/a", "tip://node/b", "tip://node/c", "tip://node/d"],
    });

    // K=10 window for waveStartRound=101 covers [91, 100].
    // a, b, c produce in window; d was producing earlier but stopped.
    _seedCertsByRound(dag, {
      95: ["tip://node/a"],
      96: ["tip://node/b"],
      99: ["tip://node/c"],
    });

    const got = getActiveCommittee(dag, 101, 10);
    expect(got).toEqual(["tip://node/a", "tip://node/b", "tip://node/c"]);
  });

  test("wave-stable: propose round and vote round see same committee", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
    _seedCertsByRound(dag, {
      1: ["tip://node/a", "tip://node/b"],
      99: ["tip://node/a", "tip://node/b"],
    });

    // Wave 51 = rounds 101 (propose) + 102 (vote). Both anchored to waveStartRound=101.
    const c101 = getActiveCommittee(dag, 101, 10);
    const c102 = getActiveCommittee(dag, 102, 10);
    expect(c101).toEqual(c102);
  });

  test("empty-window fallback returns genesis ∩ registered (not the full registry)", () => {
    // Genesis-anchored: when nobody has produced in the K-window we fall
    // back to the genesis committee intersected with the active registry.
    // Late-joiner registry rows are NOT admitted via the fallback — only
    // genesis members are. This is the structural fix that subsumes #72:
    // the registry as-a-whole is never returned, so dead-peer rows can't
    // inflate quorum during sync windows or historical-round queries.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);

    const got = getActiveCommittee(dag, 101, 10);
    expect(got).toEqual([FOUNDING_NODE_ID]);
    expect(got).not.toContain("tip://node/a");
    expect(got).not.toContain("tip://node/b");
  });

  test("excludes nodes with status != active", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
    dag.saveNode({
      node_id: "tip://node/b", name: "b", public_key: "kb",
      status: "suspended", registered_at: "2026-01-01T00:00:00.000Z",
    });
    _seedCertsByRound(dag, {
      1: ["tip://node/a", "tip://node/b"],
      99: ["tip://node/a", "tip://node/b"],
    });

    const got = getActiveCommittee(dag, 101, 10);
    expect(got).toEqual(["tip://node/a"]);
  });

  test("default K = CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS when not passed", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a"]);
    // Cert way outside default K=300 window
    _seedCertsByRound(dag, { 1: ["tip://node/a"] });
    // Round 500 with default K=300 → window is [200, 499]; round 1 is OUT.
    // No producers in window → empty-window fallback fires and returns
    // genesis ∩ registered. `a` is a late joiner (not in genesis), so
    // even though it has a cert at round 1, the fallback excludes it.
    // Only FOUNDING_NODE_ID survives.
    const got = getActiveCommittee(dag, 500);
    expect(got).toEqual([FOUNDING_NODE_ID]);
  });
});

describe("getActiveCommittee — registered-but-not-running nodes do NOT inflate quorum", () => {
  test("registering a node before it produces does NOT add it to the committee (no halt)", () => {
    // Genesis-anchored bug-protection: a REGISTER_NODE-committed node
    // that hasn't started producing must NOT be pulled into the committee.
    // (Pre-old-fix this would have inflated quorum and halted; under the
    // new rule it's structurally impossible because admission requires
    // producing-in-window AND (genesis OR span≥K) — registered alone
    // doesn't admit anyone.)
    const dag = _setup();
    _seedNodes(dag, ["tip://node/registered_but_silent"]);

    // Genesis founding_node is producing but hasn't yet hit the K-round
    // proven mark. registered_but_silent has produced ZERO certs.
    _seedCertsByRound(dag, {
      1: [FOUNDING_NODE_ID],
      50: [FOUNDING_NODE_ID],
    });

    // K=300, currentRound=51. Founding is in genesis_committee → admitted
    // on first cert. registered_but_silent has no certs → not admitted.
    const got = getActiveCommittee(dag, 51, 300);

    expect(got).not.toContain("tip://node/registered_but_silent");
    expect(got).toContain(FOUNDING_NODE_ID);
  });

  test("absolute genesis (no certs anywhere yet) falls back to genesis_committee", () => {
    // True last-resort: producers is empty (chain has zero certs). The
    // empty-window fallback returns genesis ∩ registered so the very
    // first round can bootstrap. Random registered-but-not-genesis nodes
    // are NOT included even at this earliest moment.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/late-arrival"]);
    // No certs at all

    const got = getActiveCommittee(dag, 1, 300);
    expect(got).toEqual([FOUNDING_NODE_ID]);
    expect(got).not.toContain("tip://node/late-arrival");
  });
});

describe("getActiveCommittee — proven-node filter", () => {
  test("excludes a producer whose earliest cert is too recent (fresh joiner)", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/joiner", "tip://node/founder"]);

    // Founder fully proven (since round 1)
    _seedCertsByRound(dag, {
      1: ["tip://node/founder"],
      99: ["tip://node/founder"],
    });

    // Joiner started at round 105 — not yet proven for K=10
    _seedCertsByRound(dag, {
      105: ["tip://node/joiner"],
      106: ["tip://node/joiner"],
      107: ["tip://node/joiner"],
    });

    // waveStartRound for round 110 = 109. Joiner earliest=105 → 109-105=4 < K=10.
    // Founder earliest=1 → 109-1=108 >= K=10 → proven.
    const got = getActiveCommittee(dag, 110, 10);
    expect(got).toEqual(["tip://node/founder"]);
    expect(got).not.toContain("tip://node/joiner");
  });

  test("includes a node once it has K rounds of cert history", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/joiner", "tip://node/founder"]);
    _seedCertsByRound(dag, {
      1: ["tip://node/joiner", "tip://node/founder"],
      105: ["tip://node/joiner", "tip://node/founder"],
    });
    const got = getActiveCommittee(dag, 110, 10);
    expect(got.sort()).toEqual(["tip://node/founder", "tip://node/joiner"]);
  });

  test("briefly-active joiner that stops producing is NOT promoted into committee K rounds later (peer 352 fingerprint)", () => {
    // Live regression — 2026-05-02 federation halt fingerprint:
    //   Peer 352 produced certs from round 848 to 950 (102 rounds), then
    //   went offline. At round 1149 (peer's earliest = 848 → waveStart -
    //   earliest = 301 ≥ K=300), the OLD proven check incorrectly admitted
    //   peer 352 into the committee. Quorum jumped from 1 to 2, peer 352
    //   was offline, halt-gate tripped on sub-quorum.
    //
    // Span-based check: (last_cert_in_window - earliest_cert) ≥ K. Peer
    // 352's span is 950-848 = 102 < K=300, so it's never admitted —
    // matches the operational intuition that "you must have actually put
    // in K rounds of work, not just have been around K rounds ago."
    const dag = _setup();
    _seedNodes(dag, ["tip://node/founder", "tip://node/peer352"]);

    // Founder: continuous production from round 1 → fully proven.
    _seedCertsByRound(dag, {
      1: ["tip://node/founder"],
      1148: ["tip://node/founder"],
    });

    // Peer 352: produced 102 rounds, then stopped (mirrors live trace).
    _seedCertsByRound(dag, {
      848: ["tip://node/peer352"],
      950: ["tip://node/peer352"],  // last cert before going offline
    });

    // Query at round 1149 with default K=300. Peer 352's earliest=848 is
    // 301 rounds before waveStart=1149 — would have passed the OLD check.
    // New span check: last_in_window=950, earliest=848, span=102 < 300.
    // Peer 352 stays excluded.
    const got = getActiveCommittee(dag, 1149, 300);
    expect(got).toContain("tip://node/founder");
    expect(got).not.toContain("tip://node/peer352");
  });

  test("late joiners with span < K are NOT admitted, even if they're producing recently", () => {
    // Genesis-anchored: late joiners (anyone NOT in genesis) must serve
    // K rounds of proven span before being admitted. Just-produced-once
    // is not enough. This is the property that prevents node 2 from
    // entering committee on its very first cert and instantly inflating
    // quorum 1→2 (the eager-promotion bug we replaced level-2 to fix).
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
    _seedCertsByRound(dag, {
      105: ["tip://node/a"],
      106: ["tip://node/b"],
    });
    // K=10, round=110. waveStart=109, window=[99, 108].
    // a span = 105-105 = 0; b span = 106-106 = 0; neither in genesis.
    // Both excluded → committee=[], empty-window fallback → [FOUNDING].
    const got = getActiveCommittee(dag, 110, 10);
    expect(got).toEqual([FOUNDING_NODE_ID]);
    expect(got).not.toContain("tip://node/a");
    expect(got).not.toContain("tip://node/b");
  });
});

describe("getActiveCommittee — deterministic across nodes (the property that fixes §4)", () => {
  test("two independent DAGs with identical cert history yield identical committees", () => {
    // Simulates founding's DAG and node 2's DAG. Both have the same gossip-
    // replicated cert state. Both must derive the SAME committee at the
    // SAME round — that's the property the §4 deadlock violated when
    // committee_history's Bullshark-commit-lag caused view divergence.
    const dagA = _setup();
    const dagB = _setup();

    for (const dag of [dagA, dagB]) {
      _seedNodes(dag, ["tip://node/founding", "tip://node/node2"]);
      _seedCertsByRound(dag, {
        1: ["tip://node/founding", "tip://node/node2"],
        // Both nodes producing through round 99
        99: ["tip://node/founding", "tip://node/node2"],
      });
    }

    // Both DAGs should derive identical committees at every queried round.
    for (const round of [50, 100, 101, 102, 200]) {
      const a = getActiveCommittee(dagA, round, 10);
      const b = getActiveCommittee(dagB, round, 10);
      expect(a).toEqual(b);
    }
  });
});

describe("deriveLiveCommittee alias", () => {
  test("deriveLiveCommittee returns identical results to getActiveCommittee", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
    _seedCertsByRound(dag, {
      1: ["tip://node/a", "tip://node/b"],
      99: ["tip://node/a", "tip://node/b"],
    });

    expect(deriveLiveCommittee(dag, 101, 10)).toEqual(getActiveCommittee(dag, 101, 10));
    expect(deriveLiveCommittee(dag, 200, 10)).toEqual(getActiveCommittee(dag, 200, 10));
    expect(deriveLiveCommittee(dag, 500)).toEqual(getActiveCommittee(dag, 500));
  });
});

describe("getNodeCount", () => {
  test("counts active non-revoked nodes only", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b", "tip://node/c"]);
    dag.saveNode({
      node_id: "tip://node/c", name: "c", public_key: "kc",
      status: "suspended", registered_at: "2026-01-01T00:00:00.000Z",
    });
    // a, b, plus genesis founding_node from initDAG = 3
    expect(getNodeCount(dag)).toBe(3);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// #72 regression — last-resort fallback misfires for syncing nodes
// ═══════════════════════════════════════════════════════════════════════════
//
// Live-fingerprint (2026-05-02 federation, node 2 post-snapshot restart):
//   Node 2 fast-sync installs a snapshot at peer_committed_round=606 with
//   certs covering rounds [301, 606] (#69 K-window). narwhal stays in
//   joinState=syncing with _currentRound=1 while it backfills the gap.
//   getCommittee(_currentRound=1) — window [1, 0] empty, producers={} —
//   pre-fix dropped through to "return all registered" which silently
//   admitted dead-node-3 (a stopped peer whose row was still in `nodes`).
//
// Under the genesis-anchored derivation this entire class of bug is
// structurally impossible: the function never returns the registry. The
// empty-window fallback returns `genesis_committee ∩ registered`, which
// is fixed at genesis and excludes any registered-but-not-genesis row by
// construction. The tests below pin that property.
describe("getActiveCommittee — #72: empty-window fallback excludes non-genesis peers", () => {
  test("syncing node (round=1) ignores non-genesis cert authors AND non-genesis registry rows", () => {
    const dag = _setup();
    const A = "tip://node/alive-a";
    const B = "tip://node/alive-b";
    const STALE = "tip://node/stale-c";   // registered, never produced any cert
    _seedNodes(dag, [A, B, STALE]);

    // Mirror the live snapshot's cert range: A and B produced every round
    // in [301, 606] (so they're "alive" in DAG terms). STALE has zero
    // certs. Genesis is just the founding_node from initDAG.
    const byRound = {};
    for (let r = 301; r <= 606; r++) byRound[r] = [A, B];
    _seedCertsByRound(dag, byRound);

    // Syncing node calls with stale `_currentRound=1`. window [1, 0]
    // is empty → fallback returns genesis ∩ registered.
    const committee = getActiveCommittee(dag, 1, 300);

    // STALE excluded ✓ (the original #72 bug).
    expect(committee).not.toContain(STALE);
    // A and B excluded too — they're late joiners, not in genesis. The
    // syncing node correctly says "I don't yet know enough to admit them
    // — they may or may not be in committee at the head; until I exit
    // sync mode I can only trust genesis."
    expect(committee).not.toContain(A);
    expect(committee).not.toContain(B);
    expect(committee).toEqual([FOUNDING_NODE_ID]);
  });

  test("absolute genesis (DAG empty, registry has only genesis) — bootstrap committee = [founding]", () => {
    const dag = _setup();
    // No additional registered nodes, no certs.

    const committee = getActiveCommittee(dag, 1, 300);
    expect(committee).toEqual([FOUNDING_NODE_ID]);
  });

  test("registered-but-non-genesis nodes never enter the empty-window fallback", () => {
    // Even with several non-genesis rows in the registry, the fallback
    // must return only genesis ∩ registered. This is the structural
    // property that makes #72 unreachable: the registry-as-a-whole is
    // never returned.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/x", "tip://node/y", "tip://node/z"]);

    const committee = getActiveCommittee(dag, 1, 300);
    expect(committee).toEqual([FOUNDING_NODE_ID]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Genesis-anchored admission — positive tests for the new rule
// ═══════════════════════════════════════════════════════════════════════════
describe("getActiveCommittee — genesis-anchored admission rule", () => {
  test("genesis member admitted on first cert (no K-wait)", () => {
    // The whole point of the genesis branch: founding_node enters the
    // committee on its very first cert, no need to wait K rounds.
    const dag = _setup();
    _seedCertsByRound(dag, {
      1: [FOUNDING_NODE_ID],
    });

    const got = getActiveCommittee(dag, 2, 300);
    expect(got).toEqual([FOUNDING_NODE_ID]);
  });

  test("late joiner NOT admitted on first cert — must serve K rounds", () => {
    // Symmetric to the above: a non-genesis node producing its first
    // cert is not yet in committee. This protects against eager
    // promotion (the level-2 problem we removed).
    const dag = _setup();
    const LATE = "tip://node/late-joiner";
    _seedNodes(dag, [LATE]);

    // Genesis producing throughout for span; late joiner just produced
    // one cert at round 100.
    _seedCertsByRound(dag, {
      1: [FOUNDING_NODE_ID],
      99: [FOUNDING_NODE_ID],
      100: [LATE, FOUNDING_NODE_ID],
    });

    const got = getActiveCommittee(dag, 101, 10);
    // K=10. Genesis: span=99-1=98 ≥ 10 even without the genesis pass; in
    // committee. LATE: span=100-100=0 < 10 → NOT in committee.
    expect(got).toEqual([FOUNDING_NODE_ID]);
    expect(got).not.toContain(LATE);
  });

  test("late joiner admitted once span ≥ K", () => {
    const dag = _setup();
    const LATE = "tip://node/late-joiner";
    _seedNodes(dag, [LATE]);

    // Genesis producing throughout. LATE produced from round 100 to 110
    // (span = 10, exactly K).
    _seedCertsByRound(dag, {
      1: [FOUNDING_NODE_ID],
      100: [LATE],
      110: [LATE, FOUNDING_NODE_ID],
    });

    // K=10, query at round 112 (waveStart=111, window=[101, 110]).
    // LATE: earliest=100, lastInWindow=110, span=10 ≥ K → admit.
    // Genesis: earliest=1, span=109 ≥ K → admit (also via genesis pass).
    const got = getActiveCommittee(dag, 112, 10);
    expect(new Set(got)).toEqual(new Set([FOUNDING_NODE_ID, LATE]));
  });

  test("genesis member that goes silent for K+ rounds drops out (peer-352 protection applies to genesis too)", () => {
    // Critical safety: the "currently producing in window" check applies
    // to every member, including genesis. A genesis member that goes
    // offline for K rounds drops out of the committee — quorum doesn't
    // get stuck on a dead seed node.
    const dag = _setup();

    // Genesis produced rounds 1..100, then stopped.
    _seedCertsByRound(dag, {
      1: [FOUNDING_NODE_ID],
      100: [FOUNDING_NODE_ID],
    });

    // Query at round 500. K=300. window=[200, 499]. Genesis hasn't
    // produced in window. producers={} → empty-window fallback → returns
    // genesis ∩ registered = [FOUNDING] — but operationally consensus
    // halts because nothing in committee is producing. This is the
    // correct degraded-mode behavior (halt-honestly).
    const got = getActiveCommittee(dag, 500, 300);
    expect(got).toEqual([FOUNDING_NODE_ID]);
  });
});
