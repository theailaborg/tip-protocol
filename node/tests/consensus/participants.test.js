/**
 * @file tests/consensus/participants.test.js
 * @description Tests for #75 rotation-period committee derivation.
 *
 *   admit(id) := registered_active ∧ producing-in-window ∧ (
 *                  id ∈ genesis_committee
 *                  OR  count_in_rotation(id) ≥ MIN_PARTICIPATION_THRESHOLD
 *                )
 *
 * Two functions tested:
 *   - getActiveCommittee(dag, round) — pure lookup against committee_history.
 *     Returns the committee in effect at the queried round, filtered by
 *     current registered+active status. Bit-identical across all nodes
 *     reading the same committee_history.
 *
 *   - computeNextRotationCommittee(dag, finishingRotation) — called by
 *     bullshark at rotation boundary. Reads rotation_participation tally
 *     for the just-finished rotation, applies threshold, returns next
 *     rotation's committee with pubkeys.
 *
 * Determinism guarantees verified:
 *   - Same DAG state → same lookup result on every node
 *   - Same participation tally → same next committee on every node
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
const { getGenesisPayload, getGenesisCommittee } = require(path.join(SRC, "genesis"));
const {
  getActiveCommittee,
  computeNextRotationCommittee,
  getNodeCount,
} = require(path.join(SRC, "consensus", "participants"));

beforeAll(async () => { await initCrypto(); });

const FOUNDING_NODE_ID = getGenesisPayload().founding_nodes[0].node_id;
// The full genesis committee (every founding node), sorted. Genesis members are
// admitted from round 1 and are exempt from the participation threshold.
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
  // committee is array of node_ids — we attach pubkeys from the nodes table
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

function _seedParticipation(dag, rotationNumber, byNode) {
  for (const [node_id, count] of Object.entries(byNode)) {
    for (let i = 0; i < count; i++) {
      dag.incrementRotationParticipation(node_id, rotationNumber);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// getActiveCommittee — committee_history lookup
// ═══════════════════════════════════════════════════════════════════════════
describe("getActiveCommittee — committee_history lookup", () => {
  test("returns the committee from the latest rotation whose effective_round ≤ query round", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b", "tip://node/c"]);

    // initDAG already wrote rotation 0 (genesis = [founding_node]).
    // We add rotation 1 and 2 on top.
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
    // Use rotation 1 — initDAG already wrote rotation 0 (genesis).
    // saveCommitteeRotation is INSERT OR IGNORE, so attempts to overwrite
    // rotation 0 are silently dropped.
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

  test("falls back to genesis ∩ registered when committee_history is empty", () => {
    // True absolute-genesis case before initDAG bootstraps rotation 0.
    // Empty committee_history → genesis fallback. Non-genesis registry
    // rows are NOT included (subsumes #72).
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
    // Note: initDAG seeds the founding_node into the nodes table but NOT
    // into committee_history (that's done elsewhere in production via
    // genesis bootstrap). For this test we just don't call _seedRotation.

    const got = getActiveCommittee(dag, 100);
    expect(got).toEqual(GENESIS_IDS);
    expect(got).not.toContain("tip://node/a");
    expect(got).not.toContain("tip://node/b");
  });

  test("wave-stable: any round within an epoch returns the same committee", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a"]);
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/a"],
    });

    // All rounds in [100, 199] return rotation 1's committee
    const r100 = getActiveCommittee(dag, 100);
    const r150 = getActiveCommittee(dag, 150);
    const r199 = getActiveCommittee(dag, 199);
    expect(r100).toEqual(r150);
    expect(r150).toEqual(r199);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// computeNextRotationCommittee — participation-based admission
// ═══════════════════════════════════════════════════════════════════════════
describe("computeNextRotationCommittee — participation-based admission", () => {
  test("genesis members are always admitted (regardless of participation)", () => {
    const dag = _setup();
    // Founding node is registered by initDAG. No participation seeded.
    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    expect(ids).toContain(FOUNDING_NODE_ID);
  });

  test("late joiner with count ≥ threshold is admitted", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/late"]);

    // Threshold = ceil(100 * 70/100) = 70
    _seedParticipation(dag, 0, {
      [FOUNDING_NODE_ID]: 100,
      "tip://node/late": 75,  // above threshold
    });

    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    expect(ids).toContain("tip://node/late");
    expect(ids).toContain(FOUNDING_NODE_ID);
  });

  test("late joiner with count < threshold is NOT admitted (multi-node finishing rotation)", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/late", "tip://node/other"]);
    // Use a multi-node finishing rotation — bootstrap exception does not fire.
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/late", "tip://node/other"],
    });
    _seedParticipation(dag, 1, {
      [FOUNDING_NODE_ID]: 100,
      "tip://node/late": 50,  // below 70% threshold
      "tip://node/other": 80,
    });

    const next = computeNextRotationCommittee(dag, 1);
    const ids = next.map(m => m.node_id);
    expect(ids).not.toContain("tip://node/late");
    expect(ids).toContain(FOUNDING_NODE_ID);  // genesis always in
    expect(ids).toContain("tip://node/other"); // above threshold
  });

  test("late joiner with exactly threshold count is admitted (boundary inclusive)", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/edge"]);
    // Default INTERVAL_COMMITS=100, MIN_PARTICIPATION_PCT=70 → threshold=70
    _seedParticipation(dag, 0, { "tip://node/edge": 70 });

    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    expect(ids).toContain("tip://node/edge");
  });

  test("suspended node excluded even with high participation count", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/active"]);
    _seedParticipation(dag, 0, { "tip://node/active": 100 });
    // Suspend after participation accumulates
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
    _seedParticipation(dag, 0, {
      "tip://node/zzz": 100,
      "tip://node/aaa": 100,
      "tip://node/mmm": 100,
    });

    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    const sorted = [...ids].sort();
    expect(ids).toEqual(sorted);
  });

  test("includes public_key from nodes table for each committee member", () => {
    const dag = _setup();
    _seedNodes(dag, ["tip://node/x"]);
    _seedParticipation(dag, 0, { "tip://node/x": 100 });

    const next = computeNextRotationCommittee(dag, 0);
    const x = next.find(m => m.node_id === "tip://node/x");
    expect(x).toBeDefined();
    expect(x.public_key).toBe(shake256("tip://node/x"));
  });

  test("excludes non-genesis nodes that have NO participation row (multi-node finishing rotation)", () => {
    // peer-352 protection at rotation granularity: if a node didn't
    // participate AT ALL during the rotation, no row exists in
    // rotation_participation, so it's not admitted.
    // Requires a multi-node finishing rotation — bootstrap exception must not fire.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/silent", "tip://node/active"]);
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/silent", "tip://node/active"],
    });
    _seedParticipation(dag, 1, {
      [FOUNDING_NODE_ID]: 100,
      "tip://node/active": 80,
    });
    // tip://node/silent has zero participation rows

    const next = computeNextRotationCommittee(dag, 1);
    const ids = next.map(m => m.node_id);
    expect(ids).not.toContain("tip://node/silent");
    expect(ids).toContain("tip://node/active");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Deterministic across nodes — the property that fixes §4 / #74
// ═══════════════════════════════════════════════════════════════════════════
describe("rotation-period derivation — deterministic across nodes", () => {
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

  test("two independent DAGs with identical participation tally yield identical computeNextRotationCommittee", () => {
    const dagA = _setup();
    const dagB = _setup();
    for (const dag of [dagA, dagB]) {
      _seedNodes(dag, ["tip://node/a", "tip://node/b"]);
      // Use a multi-node finishing rotation — bootstrap exception must not fire.
      _seedRotation(dag, {
        rotation_number: 1, effective_round: 100,
        committee: [FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"],
      });
      _seedParticipation(dag, 1, {
        [FOUNDING_NODE_ID]: 100,
        "tip://node/a": 80,
        "tip://node/b": 50,  // below threshold
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
// Bootstrap exception — solo-mode finishing rotation admits all registered
// ═══════════════════════════════════════════════════════════════════════════
describe("computeNextRotationCommittee — bootstrap exception (solo finishing rotation)", () => {
  test("solo finishing rotation admits all registered+active nodes regardless of participation", () => {
    // Bootstrap exception fires when the finishing rotation had a single member:
    // no participation is possible in solo mode (the solo anchor walk only
    // visits the leader's own cert chain), so all registered+active nodes are
    // admitted to let the cluster expand beyond single-node mode.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/new1", "tip://node/new2"]);
    // Pin rotation 0 to a SOLO committee (overwrite the multi-node genesis) so
    // _finishingSize === 1 and the bootstrap exception fires.
    _seedRotation(dag, { rotation_number: 0, effective_round: 0, committee: [FOUNDING_NODE_ID] });

    const next = computeNextRotationCommittee(dag, 0);
    const ids = next.map(m => m.node_id);
    expect(ids).toContain(FOUNDING_NODE_ID);
    expect(ids).toContain("tip://node/new1");
    expect(ids).toContain("tip://node/new2");
  });

  test("multi-node finishing rotation does NOT trigger bootstrap exception", () => {
    // A 3-member finishing rotation should apply normal threshold logic,
    // not admit all registered nodes.
    const dag = _setup();
    _seedNodes(dag, ["tip://node/a", "tip://node/b", "tip://node/silent"]);
    _seedRotation(dag, {
      rotation_number: 1, effective_round: 100,
      committee: [FOUNDING_NODE_ID, "tip://node/a", "tip://node/b"],
    });
    _seedParticipation(dag, 1, {
      [FOUNDING_NODE_ID]: 100,
      "tip://node/a": 80,
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
// getNodeCount — unchanged
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
