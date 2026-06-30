/**
 * @file tests/consensus/genesis-committee.test.js
 * @description Multi-node genesis committee. Rotation 0 is seeded from the full
 * `founding_nodes` list (not a single founding node), so a federation can launch
 * with an N-node BFT committee from round 0 instead of bootstrapping from 1.
 *
 * Covers:
 *   1. getGenesisCommittee() returns every founding_nodes id.
 *   2. initDAG bootstraps rotation 0 = the genesis committee (sorted by node_id,
 *      pubkeys inline, no signers/sigs, prev_rotation null).
 *   3. The genesis quorum is computeQuorum(committee size).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");
const SRC = path.resolve(__dirname, "../../src");
const { initDAG } = require(path.join(SRC, "dag"));
const { getGenesisCommittee, getGenesisPayload } = require(path.join(SRC, "genesis"));
const { computeQuorum } = require(path.join(SRC, "consensus", "certificate"));

let _n = 0;
function _tmpDbPath() {
  return path.join(os.tmpdir(), `tip-gen-committee-${process.pid}-${_n++}.db`);
}
function _cleanup(p) {
  for (const ext of ["", "-wal", "-shm"]) { try { fs.unlinkSync(p + ext); } catch { /* ignore */ } }
}

const FOUNDING = getGenesisPayload().founding_nodes || [];

describe("multi-node genesis committee", () => {
  test("getGenesisCommittee() returns every founding node id", () => {
    const gc = getGenesisCommittee();
    expect(gc.size).toBe(FOUNDING.length);
    for (const fn of FOUNDING) expect(gc.has(fn.node_id)).toBe(true);
  });

  test("the federation launches with at least 1 founding node (3 for AI Lab launch)", () => {
    expect(FOUNDING.length).toBeGreaterThanOrEqual(1);
  });

  describe("rotation 0 bootstrap", () => {
    let dag, dbPath;
    beforeAll(() => { dbPath = _tmpDbPath(); dag = initDAG({ dbPath }); });
    afterAll(() => { try { dag.close(); } catch { /* ignore */ } _cleanup(dbPath); });

    test("committee = the full genesis set, with pubkeys inline", () => {
      const rot0 = dag.getCommitteeRotation(0);
      expect(rot0).toBeTruthy();
      expect(rot0.committee.length).toBe(FOUNDING.length);
      const gc = getGenesisCommittee();
      for (const m of rot0.committee) {
        expect(gc.has(m.node_id)).toBe(true);
        expect(typeof m.public_key).toBe("string");
        expect(m.public_key.length).toBeGreaterThan(0);
      }
    });

    test("committee is sorted by node_id (deterministic payload_hash)", () => {
      const ids = dag.getCommitteeRotation(0).committee.map((m) => m.node_id);
      expect(ids).toEqual([...ids].sort());
    });

    test("genesis rotation is the trust root: prev_rotation null, no signers/sigs", () => {
      const rot0 = dag.getCommitteeRotation(0);
      expect(rot0.prev_rotation).toBeNull();
      expect((rot0.signer_node_ids || []).length).toBe(0);
      expect((rot0.signatures || []).length).toBe(0);
    });

    test("every founding node is registered active in the nodes table", () => {
      for (const fn of FOUNDING) {
        const node = dag.getNode(fn.node_id);
        expect(node).toBeTruthy();
        expect(node.status).toBe("active");
      }
    });

    test("genesis quorum = computeQuorum(committee size)", () => {
      const n = dag.getCommitteeRotation(0).committee.length;
      expect(computeQuorum(n)).toBe(Math.ceil((2 * n) / 3));
    });
  });
});
