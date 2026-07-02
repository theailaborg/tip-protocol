/**
 * @file tests/consensus/participants.test.js
 * @description Committee derivation under the time-based rotation model.
 *
 *   admit(id) := registered_active AND (
 *                  id in genesis_committee
 *                  OR distinct_presence_buckets(id) >= threshold
 *                )
 *   threshold = max(1, ceil(maxBuckets_in_tally * PCT / 100))
 *
 * Presence is measured in distinct epoch time slices (buckets), not raw
 * increment counts, so burst participation cannot game admission.
 *
 * Functions tested:
 *   - getActiveCommittee(dag, round): pure lookup against committee_history,
 *     filtered by current registered+active status. Bit-identical across
 *     nodes reading the same committee_history.
 *   - computeNextRotationCommittee(dag, finishingRotation): reads the
 *     rotation_participation bucket tally, applies the presence threshold.
 *   - epochIndexOfTime(tsMs): time-based boundary index that drives the
 *     rotation trigger at anchor commit.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(SHARED + "/crypto");
const { CONSENSUS } = require(SHARED + "/protocol-constants");
const { initDAG } = require(path.join(SRC, "dag"));
const { getGenesisPayload, getGenesisCommittee } = require(path.join(SRC, "genesis"));
const {
  getActiveCommittee,
  computeNextRotationCommittee,
  getNodeCount,
  epochIndexOfTime,
} = require(path.join(SRC, "consensus", "participants"));

beforeAll(async () => { await initCrypto(); });

const FOUNDING_NODE_ID = getGenesisPayload().founding_nodes[0].node_id;
// The full genesis committee (every founding node), sorted. Genesis members
// are admitted from round 1 and are exempt from the presence threshold.
const GENESIS_IDS = [...getGenesisCommittee()].sort();

function _setup() {
  return initDAG({ inMemory: true });
}

function _seedNodes(dag, ids) {
  for (const id of ids) {
    dag.saveNode({
      node_id: id, name: id, public_key: shake256(id),
      status: "active", registered_at: 1767225600000,
    });
  }
}

function _seedRotation(dag, { rotation_number, effective_round, committee }) {
  const fullCommittee = committee.map(node_id => {
    const node = dag.getNode(node_id);
    return { node_id, public_key: node ? node.public_key : shake256(node_id) };
  });
  dag.saveCommitteeRotation({
    rotation_number,
    effective_round,
    committee: fullCommittee,
    prev_rotation: rotation_number === 0 ? null : rotation_number - 1,
    signer_node_ids: [],
    signatures: [],
    payload_hash: shake256(`rot-${rotation_number}`),
    committed_at: 1767225600000,
  });
}

// Presence seeding: byNode maps node_id -> number of DISTINCT buckets the
// node was seen in during the rotation (one credit per bucket 0..n-1).
function _seedPresence(dag, rotationNumber, byNode) {
  for (const [node_id, buckets] of Object.entries(byNode)) {
    for (let b = 0; b < buckets; b++) {
      dag.incrementRotationParticipation(node_id, rotationNumber, b);
    }
  }
}

// Burst seeding: many credits, all in ONE bucket. Raw count is high but
// distinct-bucket presence stays 1.
function _seedBurst(dag, rotationNumber, node_id, count, bucket = 0) {
  for (let i = 0; i < count; i++) {
    dag.incrementRotationParticipation(node_id, rotationNumber, bucket);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// getActiveCommittee: committee_history lookup
// ═══════════════════════════════════════════════════════════════════════════
describe("getActiveCommittee: committee_history lookup", () => {
  test("returns the committee from the latest rotation whose effective_round <= query round", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b", "tip://node/c"]);

    // initDAG already wrote rotation 0 (genesis). Add rotation 1 and 2.
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/a"],
    });
    _seedRotation(dag, {
      rotation_number: 2, effective_round: 200,
      committee: [FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"],
    });

    // Round 50 is before rotation 1's effective_round=100, so it falls
    // back to rotation 0 (the full genesis committee).
    expect(getActiveCommittee(dag, 50)).toEqual(GENESIS_IDS);
    expect(getActiveCommittee(dag, 100)).toEqual([FOUNDING_NODE_ID, "tip://node/a"].sort());
    expect(getActiveCommittee(dag, 150)).toEqual([FOUNDING_NODE_ID, "tip://node/a"].sort());
    expect(getActiveCommittee(dag, 200)).toEqual(
      [FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"].sort()
    );
    expect(getActiveCommittee(dag, 999)).toEqual(
      [FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"].sort()
    );
  });

  test("filters suspended/revoked nodes from the returned committee", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
    // Use rotation 1: initDAG already wrote rotation 0 (genesis) and
    // saveCommitteeRotation is INSERT OR IGNORE.
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 50,
      committee: [FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"],
    });

    // Suspend `b` after the rotation lands. The committee_history row
    // still contains b, but the runtime committee filters it out.
    dag.saveNode({
      node_id: "tip://node/b", name: "b", public_key: shake256("tip://node/b"),
      status: "suspended", registered_at: 1767225600000,
    });

    const got = getActiveCommittee(dag, 100);
    expect(got).toEqual([FOUNDING_NODE_ID, "tip://node/a"].sort());
    expect(got).not.toContain("tip://node/b");
  });

  test("falls back to genesis intersect registered when committee_history is empty", () => {
    // True absolute-genesis case before initDAG bootstraps rotation 0.
    // Non-genesis registry rows are NOT included.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);

    const got = getActiveCommittee(dag, 100);
    expect(got).toEqual(GENESIS_IDS);
    expect(got).not.toContain("tip://node/a");
    expect(got).not.toContain("tip://node/b");
  });

  test("wave-stable: any round within a rotation period returns the same committee", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a"]);
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/a"],
    });

    const r100 = getActiveCommittee(dag, 100);
    const r150 = getActiveCommittee(dag, 150);
    const r199 = getActiveCommittee(dag, 199);
    expect(r100).toEqual(r150);
    expect(r150).toEqual(r199);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// computeNextRotationCommittee: bucket-presence admission
// ═══════════════════════════════════════════════════════════════════════════
describe("computeNextRotationCommittee: bucket-presence admission", () => {
  test("genesis members are always admitted (regardless of participation)", () => {
    const dag = _setup();
    // Founding node is registered by initDAG. No participation seeded.
    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    expect(ids).toContain(FOUNDING_NODE_ID);
  });

  test("late joiner with distinct buckets >= threshold is admitted", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/late"]);

    // maxBuckets = 10 -> threshold = ceil(10 * 70/100) = 7
    _seedPresence(dag, 0, {
      [FOUNDING_NODE_ID]: 10,
      "tip://node/late": 8,
    });

    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    expect(ids).toContain("tip://node/late");
    expect(ids).toContain(FOUNDING_NODE_ID);
  });

  test("late joiner with few distinct buckets is NOT admitted (multi-node finishing rotation)", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/late", "tip://node/other"]);
    // Multi-node finishing rotation: bootstrap exception does not fire.
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/late", "tip://node/other"],
    });
    _seedPresence(dag, 1, {
      [FOUNDING_NODE_ID]: 10,
      "tip://node/late": 2,   // 2 buckets < threshold 7
      "tip://node/other": 8,
    });

    const next = computeNextRotationCommittee(dag, 1);
    const ids = next.map(m => m.node_id);
    expect(ids).not.toContain("tip://node/late");
    expect(ids).toContain(FOUNDING_NODE_ID);   // genesis always in
    expect(ids).toContain("tip://node/other"); // above threshold
  });

  test("raw count does not qualify: burst presence in one bucket is NOT admitted", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/burst", "tip://node/steady"]);
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/burst", "tip://node/steady"],
    });
    _seedPresence(dag, 1, {
      [FOUNDING_NODE_ID]: 10,
      "tip://node/steady": 8,
    });
    // 200 credits, all in bucket 0: count dwarfs everyone, buckets = 1.
    _seedBurst(dag, 1, "tip://node/burst", 200, 0);

    const next = computeNextRotationCommittee(dag, 1);
    const ids = next.map(m => m.node_id);
    expect(ids).not.toContain("tip://node/burst");
    expect(ids).toContain("tip://node/steady");
  });

  test("node with exactly threshold buckets is admitted (boundary inclusive)", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/edge"]);
    // maxBuckets = 10 -> threshold = ceil(10 * 70/100) = 7; edge has exactly 7.
    _seedPresence(dag, 0, {
      [FOUNDING_NODE_ID]: 10,
      "tip://node/edge": 7,
    });

    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    expect(ids).toContain("tip://node/edge");
  });

  test("outage-shortened epoch: threshold scales to best-observed presence", () => {
    // Network was up for only 3 buckets. The bar drops for everyone equally:
    // threshold = ceil(3 * 70/100) = 3.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"],
    });
    _seedPresence(dag, 1, {
      [FOUNDING_NODE_ID]: 3,
      "tip://node/a": 3,
      "tip://node/b": 2,
    });

    const next = computeNextRotationCommittee(dag, 1);
    const ids = next.map(m => m.node_id);
    expect(ids).toContain("tip://node/a");
    expect(ids).not.toContain("tip://node/b");
  });

  test("suspended node excluded even with full presence", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/active"]);
    _seedPresence(dag, 0, {
      [FOUNDING_NODE_ID]: 10,
      "tip://node/active": 10,
    });
    // Suspend after presence accumulates
    dag.saveNode({
      node_id: "tip://node/active", name: "active", public_key: shake256("tip://node/active"),
      status: "suspended", registered_at: 1767225600000,
    });

    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    expect(ids).not.toContain("tip://node/active");
  });

  test("returned committee is sorted by node_id", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/zzz", "tip://node/aaa", "tip://node/mmm"]);
    _seedPresence(dag, 0, {
      "tip://node/zzz": 10,
      "tip://node/aaa": 10,
      "tip://node/mmm": 10,
    });

    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    const sorted = [...ids].sort();
    expect(ids).toEqual(sorted);
  });

  test("includes public_key from nodes table for each committee member", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/x"]);
    _seedPresence(dag, 0, { "tip://node/x": 10 });

    const next = computeNextRotationCommittee(dag, 0);
    const x = next.find(m => m.node_id === "tip://node/x");
    expect(x).toBeDefined();
    expect(x.public_key).toBe(shake256("tip://node/x"));
  });

  test("excludes non-genesis nodes that have NO participation row (multi-node finishing rotation)", () => {
    // If a node did not participate AT ALL during the rotation, no row
    // exists in rotation_participation, so it is not admitted.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/silent", "tip://node/active"]);
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/silent", "tip://node/active"],
    });
    _seedPresence(dag, 1, {
      [FOUNDING_NODE_ID]: 10,
      "tip://node/active": 8,
    });
    // tip://node/silent has zero participation rows

    const next = computeNextRotationCommittee(dag, 1);
    const ids = next.map(m => m.node_id);
    expect(ids).not.toContain("tip://node/silent");
    expect(ids).toContain("tip://node/active");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Deterministic across nodes
// ═══════════════════════════════════════════════════════════════════════════
describe("rotation-period derivation: deterministic across nodes", () => {
  test("two independent DAGs with identical committee_history yield identical getActiveCommittee", () => {
    const dagA = _setup();
    const dagB = _setup();
    for (const dag of [dagA, dagB]) {
      _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
      _seedRotation(dag, {
        rotation_number: 1, effective_round: 50,
        committee: [FOUNDING_NODE_ID, "tip://node/a"],
      });
      _seedRotation(dag, {
        rotation_number: 2, effective_round: 100,
        committee: [FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"],
      });
    }

    for (const round of [50, 100, 150, 999]) {
      expect(getActiveCommittee(dagA, round)).toEqual(getActiveCommittee(dagB, round));
    }
  });

  test("two independent DAGs with identical presence tally yield identical computeNextRotationCommittee", () => {
    const dagA = _setup();
    const dagB = _setup();
    for (const dag of [dagA, dagB]) {
      _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
      // Multi-node finishing rotation: bootstrap exception must not fire.
      _seedRotation(dag, {
        rotation_number: 1, effective_round: 100,
        committee: [FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"],
      });
      _seedPresence(dag, 1, {
        [FOUNDING_NODE_ID]: 10,
        "tip://node/a": 8,
        "tip://node/b": 2,  // below threshold 7
      });
    }

    const a = computeNextRotationCommittee(dagA, 1);
    const b = computeNextRotationCommittee(dagB, 1);
    expect(a.map(m => m.node_id)).toEqual(b.map(m => m.node_id));
    // Both admit the genesis members (exempt) + a (above threshold), exclude b (below).
    expect(a.map(m => m.node_id)).toEqual([...GENESIS_IDS, "tip://node/a"].sort());
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Bootstrap exception: solo-mode finishing rotation admits all registered
// ═══════════════════════════════════════════════════════════════════════════
describe("computeNextRotationCommittee: bootstrap exception (solo finishing rotation)", () => {
  test("solo finishing rotation admits all registered+active nodes regardless of participation", () => {
    // In solo mode no non-genesis node can accumulate presence (the solo
    // anchor walk only visits the leader's own cert chain), so all
    // registered+active nodes are admitted to let the cluster expand.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/new1", "tip://node/new2"]);
    // Pin rotation 0 to a SOLO committee so _finishingSize === 1.
    _seedRotation(dag, { rotation_number: 0, effective_round: 0, committee: [FOUNDING_NODE_ID] });

    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    expect(ids).toContain(FOUNDING_NODE_ID);
    expect(ids).toContain("tip://node/new1");
    expect(ids).toContain("tip://node/new2");
  });

  test("multi-node finishing rotation does NOT trigger bootstrap exception", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b", "tip://node/silent"]);
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"],
    });
    _seedPresence(dag, 1, {
      [FOUNDING_NODE_ID]: 10,
      "tip://node/a": 8,
      // tip://node/b and tip://node/silent have zero participation
    });

    const next = computeNextRotationCommittee(dag, 1);
    const ids = next.map(m => m.node_id);
    expect(ids).toContain(FOUNDING_NODE_ID);
    expect(ids).toContain("tip://node/a");
    expect(ids).not.toContain("tip://node/b");
    expect(ids).not.toContain("tip://node/silent");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// epochIndexOfTime: time-based rotation boundary index
// ═══════════════════════════════════════════════════════════════════════════
describe("epochIndexOfTime: time-based boundary index", () => {
  const G = CONSENSUS.BFT_TIME_GENESIS_MS;
  const D = CONSENSUS.EPOCH_DURATION_MS;

  test("returns 0 at/before BFT genesis and for non-finite input", () => {
    expect(epochIndexOfTime(G)).toBe(0);
    expect(epochIndexOfTime(G - 1)).toBe(0);
    expect(epochIndexOfTime(0)).toBe(0);
    expect(epochIndexOfTime(-5)).toBe(0);
    expect(epochIndexOfTime(NaN)).toBe(0);
    expect(epochIndexOfTime(Infinity)).toBe(0);
    expect(epochIndexOfTime("nope")).toBe(0);
  });

  test("floor semantics: index = floor((T - genesis) / duration)", () => {
    expect(epochIndexOfTime(G + 1)).toBe(0);
    expect(epochIndexOfTime(G + D - 1)).toBe(0);
    expect(epochIndexOfTime(G + D)).toBe(1);
    expect(epochIndexOfTime(G + 2 * D - 1)).toBe(1);
    expect(epochIndexOfTime(G + 5 * D + 123)).toBe(5);
  });

  test("boundary trigger: rotation is due only when the anchor ts crosses into a later epoch", () => {
    // Latest rotation committed early in epoch 1.
    const committedAt = G + D + 10;
    // Anchor later in the SAME epoch: not due.
    expect(epochIndexOfTime(G + 2 * D - 1) > epochIndexOfTime(committedAt)).toBe(false);
    // First anchor of the NEXT epoch: due.
    expect(epochIndexOfTime(G + 2 * D) > epochIndexOfTime(committedAt)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// getNodeCount
// ═══════════════════════════════════════════════════════════════════════════
describe("getNodeCount", () => {
  test("counts active non-revoked nodes only", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b", "tip://node/c"]);
    dag.saveNode({
      node_id: "tip://node/c", name: "c", public_key: shake256("tip://node/c"),
      status: "suspended", registered_at: 1767225600000,
    });
    // a, b (active) + the genesis founding nodes from initDAG; c is suspended.
    expect(getNodeCount(dag)).toBe(2 + GENESIS_IDS.length);
  });
});
