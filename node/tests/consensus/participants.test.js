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

  test("cold-start fallback: no proven producers → returns registered set", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);

    const got = getActiveCommittee(dag, 101, 10);
    // Includes genesis founding_node (always in nodes table after initDAG)
    expect(got.sort()).toEqual([FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"].sort());
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
    // Round 500 with default K → window is [200, 499]; round 1 is OUT
    const got = getActiveCommittee(dag, 500);
    // No producers in window → cold-start fallback to registered set
    expect(got.sort()).toEqual([FOUNDING_NODE_ID, "tip://node/a"].sort());
  });
});

describe("getActiveCommittee — registered-but-not-running nodes do NOT inflate quorum", () => {
  test("registering a node before it produces does NOT add it to the committee (no halt)", () => {
    // Bug fingerprint: pre-fix, the cold-start fallback returned the full
    // registered set when no producer was proven yet. If a node was
    // REGISTER_NODE-committed but hadn't started running, it'd get pulled
    // into the committee, push quorum to 2, become unmeetable (since the
    // not-running node can't ack), and halt founding. This test pins the
    // post-fix behavior: cold-start fallback returns registered ∩ producers,
    // which excludes registered-but-silent nodes.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/founding", "tip://node/registered_but_silent"]);

    // Founding is producing but hasn't yet hit the K-round proven mark.
    // Registered-but-silent has produced ZERO certs.
    _seedCertsByRound(dag, {
      1: ["tip://node/founding"],
      50: ["tip://node/founding"],
    });

    // K=300, currentRound=51. Founding's earliest=1, waveStart-earliest=50 < 300
    // → not proven yet → cold-start path.
    const got = getActiveCommittee(dag, 51, 300);

    // Must NOT include registered_but_silent — they have no certs.
    expect(got).not.toContain("tip://node/registered_but_silent");
    expect(got).toContain("tip://node/founding");
  });

  test("absolute genesis (no certs anywhere yet) falls back to registered set", () => {
    // True last-resort fallback: producers is empty, so registered ∩
    // producers is also empty. Returns registered so the very first
    // round can bootstrap (founding hasn't produced its first cert yet
    // at this exact moment).
    const dag = _setup();
    _seedNodes(dag, ["tip://node/founding"]);
    // No certs at all
    const got = getActiveCommittee(dag, 1, 300);
    expect(got).toContain("tip://node/founding");
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

  test("cold-start fallback returns registered ∩ producers (not full registered set)", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
    _seedCertsByRound(dag, {
      105: ["tip://node/a"],
      106: ["tip://node/b"],
    });
    // Neither proven for K=10 → cold-start fallback fires. Returns
    // registered ∩ producers — which excludes FOUNDING_NODE_ID because
    // it has no certs in this test setup. This is the post-fix behavior:
    // registered-but-not-running nodes are NOT included in the cold-start
    // committee, preventing the "register node 2 but it's not running →
    // halt" failure mode.
    const got = getActiveCommittee(dag, 110, 10);
    expect(got.sort()).toEqual(["tip://node/a", "tip://node/b"]);
    expect(got).not.toContain(FOUNDING_NODE_ID);
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
