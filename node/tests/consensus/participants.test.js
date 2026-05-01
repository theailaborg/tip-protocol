/**
 * @file tests/consensus/participants.test.js
 * @description Tests for the committee accessors after the §4 + #34
 * rewrite — getActiveCommittee reads from committee_history, while
 * deriveLiveCommittee keeps the old "registered ∩ producers_in_K_rounds"
 * derivation for use by the rotation proposer.
 *
 * Covers:
 *  - getActiveCommittee returns the committee from the rotation in
 *    effect at the queried round
 *  - getActiveCommittee is wave-stable (propose + vote rounds of one
 *    wave see same committee even if a rotation is committed mid-wave)
 *  - getActiveCommittee strips pubkeys, returns sorted node_ids
 *  - deriveLiveCommittee preserves pre-§4 behavior:
 *    * registered ∩ producers_in_last_K_rounds
 *    * cold-start fallback to registered set when no producers
 *  - deriveLiveCommittee uses CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS
 *    when K not passed
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

// Genesis founding_node is registered in `nodes` table by initDAG (and is
// the sole member of bootstrap rotation 0). Test expectations include it
// in any "registered nodes" set.
const FOUNDING_NODE_ID = getGenesisPayload().founding_node.node_id;

// Build an in-memory DAG and seed it with our own rotation history +
// nodes. Bypasses the genesis founding_node for clearer assertions.
function _setup() {
  const dag = initDAG({ inMemory: true });
  // Wipe genesis bootstrap rotation 0 by re-saving with our test data —
  // saveCommitteeRotation is INSERT OR IGNORE so we can't overwrite,
  // but we CAN add rotations 1, 2, ... For test purposes we'll keep
  // genesis rotation 0 (founding_node) and append rotations on top.
  return dag;
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
  // byRound: { roundNumber: [author_node_id, author_node_id, ...] }
  for (const [roundStr, authors] of Object.entries(byRound)) {
    const round = Number(roundStr);
    for (const author of authors) {
      const certHash = shake256(`cert-${round}-${author}`);
      dag.saveCertificate({
        hash: certHash,                          // dag uses cert.hash as PK
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

function _seedRotations(dag, rotations) {
  // rotations: [{ rotation_number, effective_round, committee: [{node_id, public_key}] }]
  for (const r of rotations) {
    dag.saveCommitteeRotation({
      rotation_number: r.rotation_number,
      effective_round: r.effective_round,
      committee: r.committee,
      prev_rotation: r.rotation_number - 1,
      signer_node_ids: r.signer_node_ids || [],
      signatures: r.signatures || [],
      payload_hash: r.payload_hash || shake256(JSON.stringify(r)),
      committed_at: "2026-01-01T00:00:00.000Z",
    });
  }
}

describe("getActiveCommittee — reads from committee_history (§4 + #34)", () => {
  test("returns sorted node_ids from rotation in effect at the queried round", () => {
    const dag = _setup();
    _seedRotations(dag, [
      {
        rotation_number: 1, effective_round: 100,
        committee: [
          { node_id: "tip://node/b", public_key: "kb" },
          { node_id: "tip://node/a", public_key: "ka" },
          { node_id: "tip://node/c", public_key: "kc" },
        ],
      },
    ]);

    // Round in rotation 1's window
    const got = getActiveCommittee(dag, 200);
    expect(got).toEqual(["tip://node/a", "tip://node/b", "tip://node/c"]);
  });

  test("wave-stable: propose round and vote round see same committee even if rotation lands mid-wave", () => {
    const dag = _setup();
    _seedRotations(dag, [
      {
        rotation_number: 1, effective_round: 102,  // commits during round 102 (vote round of wave 51)
        committee: [
          { node_id: "tip://node/a", public_key: "ka" },
          { node_id: "tip://node/b", public_key: "kb" },
        ],
      },
    ]);

    // Wave 51 = rounds 101 (propose) + 102 (vote). waveStartRound=101.
    // At round 101, getCommitteeAtRound(101) returns rotation 0 (genesis founding).
    // At round 102, getCommitteeAtRound(101) STILL returns rotation 0 because
    // we anchor to waveStartRound, even though rotation 1's effective_round=102.
    const c101 = getActiveCommittee(dag, 101);
    const c102 = getActiveCommittee(dag, 102);
    expect(c101).toEqual(c102);  // both anchored to waveStartRound=101

    // Wave 52 = rounds 103 + 104. waveStartRound=103.
    // getCommitteeAtRound(103) returns rotation 1 (effective_round=102 <= 103).
    const c103 = getActiveCommittee(dag, 103);
    const c104 = getActiveCommittee(dag, 104);
    expect(c103).toEqual(c104);
    expect(c103).toEqual(["tip://node/a", "tip://node/b"]);
  });

  test("strips public_keys — returns string[] of node_ids", () => {
    const dag = _setup();
    _seedRotations(dag, [
      {
        rotation_number: 1, effective_round: 1,
        committee: [
          { node_id: "tip://node/x", public_key: "longpubkeyx" },
          { node_id: "tip://node/y", public_key: "longpubkeyy" },
        ],
      },
    ]);

    const got = getActiveCommittee(dag, 100);
    expect(Array.isArray(got)).toBe(true);
    for (const item of got) {
      expect(typeof item).toBe("string");
      // No object leakage from internal {node_id, public_key} representation
      expect(item).not.toContain("public_key");
    }
  });

  test("ignores legacy K parameter (hysteresis lives in deriveLiveCommittee now)", () => {
    const dag = _setup();
    _seedRotations(dag, [
      {
        rotation_number: 1, effective_round: 1,
        committee: [{ node_id: "tip://node/a", public_key: "ka" }],
      },
    ]);

    // Different K values should yield identical results — K is ignored.
    const c1 = getActiveCommittee(dag, 100, 4);
    const c2 = getActiveCommittee(dag, 100, 999);
    const c3 = getActiveCommittee(dag, 100, undefined);
    expect(c1).toEqual(c2);
    expect(c1).toEqual(c3);
  });
});

describe("deriveLiveCommittee — proposer-side derivation (pre-§4 logic)", () => {
  test("returns registered ∩ producers_in_last_K_rounds, sorted", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b", "tip://node/c", "tip://node/d"]);

    // Wave 51 (rounds 101-102), K=10 → window covers rounds 91-100
    _seedCertsByRound(dag, {
      95: ["tip://node/a"],
      96: ["tip://node/b"],
      99: ["tip://node/c"],
      // d does NOT produce in the window — should be excluded
    });

    const got = deriveLiveCommittee(dag, 101, 10);
    expect(got).toEqual(["tip://node/a", "tip://node/b", "tip://node/c"]);
  });

  test("cold-start fallback: no producers in window → returns registered set", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
    // No certs at all

    const got = deriveLiveCommittee(dag, 101, 10);
    // Includes genesis founding_node (always in nodes table after initDAG)
    expect(got.sort()).toEqual([FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"].sort());
  });

  test("excludes nodes with status != active", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
    // Override b to inactive
    dag.saveNode({
      node_id: "tip://node/b", name: "b", public_key: "kb",
      status: "suspended", registered_at: "2026-01-01T00:00:00.000Z",
    });
    _seedCertsByRound(dag, {
      99: ["tip://node/a", "tip://node/b"],  // both produced, but b is suspended
    });

    const got = deriveLiveCommittee(dag, 101, 10);
    expect(got).toEqual(["tip://node/a"]);
  });

  test("uses CONSENSUS.COMMITTEE_ROTATION_HYSTERESIS_ROUNDS when K not passed", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a"]);
    // Cert way outside default K=300 window
    _seedCertsByRound(dag, {
      1: ["tip://node/a"],
    });
    // Round 500 with default K → window is [200, 499]; round 1 is OUT
    const got = deriveLiveCommittee(dag, 500);
    // Cold-start fallback to registered set (includes founding_node)
    expect(got.sort()).toEqual([FOUNDING_NODE_ID, "tip://node/a"].sort());
  });
});

describe("getNodeCount", () => {
  test("counts active non-revoked nodes only", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b", "tip://node/c"]);
    // Suspend one node
    dag.saveNode({
      node_id: "tip://node/c", name: "c", public_key: "kc",
      status: "suspended", registered_at: "2026-01-01T00:00:00.000Z",
    });

    const count = getNodeCount(dag);
    // a, b, plus genesis founding_node from initDAG = 3
    expect(count).toBe(3);
  });
});
