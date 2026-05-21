/**
 * @file tests/dag/committee-history.test.js
 * @description Unit tests for the committee_history table + accessors
 * (§4 + #34 — chain-of-trust foundation).
 *
 * Covers:
 *  - Genesis bootstrap (rotation 0 written from genesis.founding_node)
 *  - Bootstrap idempotency (re-opening doesn't duplicate, backfills existing DBs)
 *  - Accessor correctness: save/get/at-round/latest/iterate
 *  - INSERT OR IGNORE semantics on duplicate rotation_number
 *  - MemoryStore ↔ SQLiteStore parity (same ops produce same results)
 *  - payload_hash determinism across stores
 *  - committee field schema: [{node_id, public_key}], pubkeys preserved
 *
 * Does NOT cover yet (deferred to later steps):
 *  - COMMITTEE_ROTATION tx validation in commit-handler (step 4)
 *  - Snapshot chain-of-trust walk (step 7)
 *  - participants.getActiveCommittee read-from-history (step 5)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, canonicalJson } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { getGenesisPayload, GENESIS_TIMESTAMP } = require(path.join(SRC, "genesis"));

beforeAll(async () => {
  await initCrypto();
});

function _tmpDbPath() {
  return path.join(os.tmpdir(), `tip-cot-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
}

function _cleanup(dbPath) {
  for (const ext of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
  }
}

// Rotation factory — produces a well-formed rotation row for tests.
function _rotation(rotationNumber, effectiveRound, committee, opts = {}) {
  return {
    rotation_number: rotationNumber,
    effective_round: effectiveRound,
    committee,
    prev_rotation: opts.prev_rotation === undefined ? rotationNumber - 1 : opts.prev_rotation,
    signer_node_ids: opts.signer_node_ids || [],
    signatures: opts.signatures || [],
    payload_hash: opts.payload_hash || shake256(canonicalJson({
      rotation_number: rotationNumber,
      effective_round: effectiveRound,
      committee,
    })),
    committed_at: opts.committed_at || Date.now(),
  };
}

describe("committee_history — genesis bootstrap (rotation 0)", () => {
  test("MemoryStore: bootstrap writes rotation 0 from genesis.founding_node", () => {
    const dag = initDAG({ inMemory: true });
    const rot0 = dag.getCommitteeRotation(0);

    expect(rot0).not.toBeNull();
    expect(rot0.rotation_number).toBe(0);
    expect(rot0.effective_round).toBe(0);
    expect(rot0.prev_rotation).toBeNull();
    expect(rot0.signer_node_ids).toEqual([]);
    expect(rot0.signatures).toEqual([]);

    // Committee carries [{node_id, public_key}] — pubkeys must be present
    // for the chain-of-trust walker to verify rotation 1 against genesis.
    expect(rot0.committee).toHaveLength(1);
    expect(rot0.committee[0]).toHaveProperty("node_id");
    expect(rot0.committee[0]).toHaveProperty("public_key");

    const founding = getGenesisPayload().founding_node;
    expect(rot0.committee[0].node_id).toBe(founding.node_id);
    expect(rot0.committee[0].public_key).toBe(founding.public_key);

    expect(rot0.committed_at).toBe(GENESIS_TIMESTAMP);
  });

  test("SQLiteStore: bootstrap writes rotation 0 from genesis.founding_node", () => {
    const dbPath = _tmpDbPath();
    try {
      const dag = initDAG({ dbPath });
      const rot0 = dag.getCommitteeRotation(0);
      const founding = getGenesisPayload().founding_node;

      expect(rot0).not.toBeNull();
      expect(rot0.committee[0].node_id).toBe(founding.node_id);
      expect(rot0.committee[0].public_key).toBe(founding.public_key);
      dag.close();
    } finally {
      _cleanup(dbPath);
    }
  });

  test("payload_hash is deterministic + matches shake256(canonicalJson)", () => {
    const memDag = initDAG({ inMemory: true });
    const rot0 = memDag.getCommitteeRotation(0);

    const expected = shake256(canonicalJson({
      rotation_number: 0,
      effective_round: 0,
      committee: rot0.committee,
    }));
    expect(rot0.payload_hash).toBe(expected);
  });

  test("payload_hash matches between MemoryStore and SQLiteStore", () => {
    const memDag = initDAG({ inMemory: true });
    const dbPath = _tmpDbPath();
    try {
      const sqlDag = initDAG({ dbPath });
      const memHash = memDag.getCommitteeRotation(0).payload_hash;
      const sqlHash = sqlDag.getCommitteeRotation(0).payload_hash;
      expect(memHash).toBe(sqlHash);
      sqlDag.close();
    } finally {
      _cleanup(dbPath);
    }
  });

  test("re-opening a SQLite DB is idempotent — no duplicate rotation 0", () => {
    const dbPath = _tmpDbPath();
    try {
      // First open: bootstrap writes rotation 0
      const first = initDAG({ dbPath });
      const initialChain = [...first.getRotationsFromGenesis()];
      expect(initialChain).toHaveLength(1);
      first.close();

      // Reopen: bootstrap should be a no-op
      const second = initDAG({ dbPath });
      const reopenChain = [...second.getRotationsFromGenesis()];
      expect(reopenChain).toHaveLength(1);
      // Same rotation 0 row, byte-for-byte
      expect(reopenChain[0].payload_hash).toBe(initialChain[0].payload_hash);
      second.close();
    } finally {
      _cleanup(dbPath);
    }
  });

  test("backfills an existing DB that pre-dates committee_history", () => {
    // Simulate a DB that has identities/content/etc. but no committee_history
    // rows yet (either the table didn't exist, or a deploy gap meant it was
    // created but never populated). Bootstrap must fire on next initDAG.
    const dbPath = _tmpDbPath();
    try {
      // Phase 1: first boot creates everything including rotation 0
      const dag1 = initDAG({ dbPath });
      const Database = require("better-sqlite3");
      dag1.close();

      // Phase 2: simulate a missing rotation 0 by deleting the row directly
      // (a real prior-version DB wouldn't have written it at all).
      const raw = new Database(dbPath);
      raw.prepare("DELETE FROM committee_history").run();
      const before = raw.prepare("SELECT COUNT(*) as n FROM committee_history").get();
      expect(before.n).toBe(0);
      raw.close();

      // Phase 3: re-open via initDAG. Bootstrap must fire, backfilling rotation 0.
      const dag2 = initDAG({ dbPath });
      const after = [...dag2.getRotationsFromGenesis()];
      expect(after).toHaveLength(1);
      expect(after[0].rotation_number).toBe(0);
      dag2.close();
    } finally {
      _cleanup(dbPath);
    }
  });
});

describe("committee_history — accessors", () => {
  function _seed(dag) {
    // Seed a 3-rotation chain on top of bootstrap rotation 0.
    // Rotation 1: add node-a, node-b at round 100
    // Rotation 2: add node-c at round 500
    // Rotation 3: remove node-a at round 1000
    const founding = getGenesisPayload().founding_node;
    const rot1Committee = [
      { node_id: founding.node_id, public_key: founding.public_key },
      { node_id: "node-a", public_key: "pubkey_a" },
      { node_id: "node-b", public_key: "pubkey_b" },
    ];
    const rot2Committee = [
      ...rot1Committee,
      { node_id: "node-c", public_key: "pubkey_c" },
    ];
    const rot3Committee = rot2Committee.filter(m => m.node_id !== "node-a");

    dag.saveCommitteeRotation(_rotation(1, 100, rot1Committee, {
      signer_node_ids: [founding.node_id],
      signatures: ["sig1"],
    }));
    dag.saveCommitteeRotation(_rotation(2, 500, rot2Committee, {
      signer_node_ids: [founding.node_id, "node-a"],
      signatures: ["sig2a", "sig2b"],
    }));
    dag.saveCommitteeRotation(_rotation(3, 1000, rot3Committee, {
      signer_node_ids: [founding.node_id, "node-b"],
      signatures: ["sig3a", "sig3b"],
    }));
  }

  test.each([
    ["MemoryStore", () => initDAG({ inMemory: true }), () => null],
    ["SQLiteStore", (dbPath) => initDAG({ dbPath }), (dag, dbPath) => { dag.close(); _cleanup(dbPath); }],
  ])("%s: getCommitteeAtRound returns the rotation in effect at the queried round", (_name, mk, cleanup) => {
    const dbPath = _tmpDbPath();
    const dag = mk(dbPath);
    try {
      _seed(dag);

      // Round 50: only rotation 0 is in effect (rotation 1 starts at 100)
      const at50 = dag.getCommitteeAtRound(50);
      expect(at50.rotation_number).toBe(0);

      // Round 100 & 200: rotation 1 just took effect
      expect(dag.getCommitteeAtRound(100).rotation_number).toBe(1);
      expect(dag.getCommitteeAtRound(200).rotation_number).toBe(1);

      // Round 499: still rotation 1
      expect(dag.getCommitteeAtRound(499).rotation_number).toBe(1);

      // Round 500-999: rotation 2
      expect(dag.getCommitteeAtRound(500).rotation_number).toBe(2);
      expect(dag.getCommitteeAtRound(999).rotation_number).toBe(2);

      // Round 1000+: rotation 3 (current)
      expect(dag.getCommitteeAtRound(1000).rotation_number).toBe(3);
      expect(dag.getCommitteeAtRound(99999).rotation_number).toBe(3);
    } finally {
      cleanup(dag, dbPath);
    }
  });

  test.each([
    ["MemoryStore", () => initDAG({ inMemory: true }), () => null],
    ["SQLiteStore", (dbPath) => initDAG({ dbPath }), (dag, dbPath) => { dag.close(); _cleanup(dbPath); }],
  ])("%s: getLatestRotation returns the highest rotation_number", (_name, mk, cleanup) => {
    const dbPath = _tmpDbPath();
    const dag = mk(dbPath);
    try {
      // Before seeding extra rotations, latest should be rotation 0
      expect(dag.getLatestRotation().rotation_number).toBe(0);

      _seed(dag);
      expect(dag.getLatestRotation().rotation_number).toBe(3);
    } finally {
      cleanup(dag, dbPath);
    }
  });

  test.each([
    ["MemoryStore", () => initDAG({ inMemory: true }), () => null],
    ["SQLiteStore", (dbPath) => initDAG({ dbPath }), (dag, dbPath) => { dag.close(); _cleanup(dbPath); }],
  ])("%s: getRotationsFromGenesis iterates in rotation_number order", (_name, mk, cleanup) => {
    const dbPath = _tmpDbPath();
    const dag = mk(dbPath);
    try {
      _seed(dag);
      const chain = [...dag.getRotationsFromGenesis()];
      expect(chain.map(r => r.rotation_number)).toEqual([0, 1, 2, 3]);
    } finally {
      cleanup(dag, dbPath);
    }
  });

  test.each([
    ["MemoryStore", () => initDAG({ inMemory: true }), () => null],
    ["SQLiteStore", (dbPath) => initDAG({ dbPath }), (dag, dbPath) => { dag.close(); _cleanup(dbPath); }],
  ])("%s: saveCommitteeRotation is idempotent on duplicate rotation_number (INSERT OR IGNORE)", (_name, mk, cleanup) => {
    const dbPath = _tmpDbPath();
    const dag = mk(dbPath);
    try {
      const founding = getGenesisPayload().founding_node;
      const rot1 = _rotation(1, 100, [{ node_id: founding.node_id, public_key: founding.public_key }]);

      dag.saveCommitteeRotation(rot1);
      // Second save with different content but same rotation_number — should NOT overwrite
      const tampered = { ...rot1, payload_hash: "different_hash" };
      dag.saveCommitteeRotation(tampered);

      const stored = dag.getCommitteeRotation(1);
      expect(stored.payload_hash).toBe(rot1.payload_hash);   // first wins
      expect(stored.payload_hash).not.toBe("different_hash");

      // Chain length unchanged
      const chain = [...dag.getRotationsFromGenesis()];
      expect(chain).toHaveLength(2);
    } finally {
      cleanup(dag, dbPath);
    }
  });

  test.each([
    ["MemoryStore", () => initDAG({ inMemory: true }), () => null],
    ["SQLiteStore", (dbPath) => initDAG({ dbPath }), (dag, dbPath) => { dag.close(); _cleanup(dbPath); }],
  ])("%s: round-trip preserves committee pubkeys + signer arrays + payload_hash", (_name, mk, cleanup) => {
    const dbPath = _tmpDbPath();
    const dag = mk(dbPath);
    try {
      const committee = [
        { node_id: "node-x", public_key: "x_pub" },
        { node_id: "node-y", public_key: "y_pub" },
      ];
      const rec = _rotation(7, 700, committee, {
        signer_node_ids: ["s1", "s2", "s3"],
        signatures: ["sig_one", "sig_two", "sig_three"],
        prev_rotation: 6,
        committed_at: 1777507200000,
      });
      dag.saveCommitteeRotation(rec);

      const got = dag.getCommitteeRotation(7);
      expect(got.committee).toEqual(committee);
      expect(got.signer_node_ids).toEqual(["s1", "s2", "s3"]);
      expect(got.signatures).toEqual(["sig_one", "sig_two", "sig_three"]);
      expect(got.prev_rotation).toBe(6);
      expect(got.committed_at).toBe(1777507200000);
      expect(got.payload_hash).toBe(rec.payload_hash);
    } finally {
      cleanup(dag, dbPath);
    }
  });

  test.each([
    ["MemoryStore", () => initDAG({ inMemory: true }), () => null],
    ["SQLiteStore", (dbPath) => initDAG({ dbPath }), (dag, dbPath) => { dag.close(); _cleanup(dbPath); }],
  ])("%s: getCommitteeRotation returns null for unknown rotation_number", (_name, mk, cleanup) => {
    const dbPath = _tmpDbPath();
    const dag = mk(dbPath);
    try {
      expect(dag.getCommitteeRotation(99999)).toBeNull();
    } finally {
      cleanup(dag, dbPath);
    }
  });
});

describe("committee_history — store parity", () => {
  test("MemoryStore and SQLiteStore produce identical chain after same ops", () => {
    const memDag = initDAG({ inMemory: true });
    const dbPath = _tmpDbPath();
    try {
      const sqlDag = initDAG({ dbPath });

      // Apply same sequence of writes to both
      const founding = getGenesisPayload().founding_node;
      const rotations = [
        _rotation(1, 100, [
          { node_id: founding.node_id, public_key: founding.public_key },
          { node_id: "n1", public_key: "k1" },
        ], { signer_node_ids: [founding.node_id], signatures: ["sigA"] }),
        _rotation(2, 250, [
          { node_id: founding.node_id, public_key: founding.public_key },
          { node_id: "n1", public_key: "k1" },
          { node_id: "n2", public_key: "k2" },
        ], { signer_node_ids: [founding.node_id, "n1"], signatures: ["sigB", "sigC"] }),
      ];
      for (const r of rotations) {
        memDag.saveCommitteeRotation(r);
        sqlDag.saveCommitteeRotation(r);
      }

      // Compare the full chain — payload_hash, committee, signers, sigs
      const memChain = [...memDag.getRotationsFromGenesis()];
      const sqlChain = [...sqlDag.getRotationsFromGenesis()];
      expect(memChain.length).toBe(sqlChain.length);
      for (let i = 0; i < memChain.length; i++) {
        expect(memChain[i].rotation_number).toBe(sqlChain[i].rotation_number);
        expect(memChain[i].payload_hash).toBe(sqlChain[i].payload_hash);
        expect(memChain[i].committee).toEqual(sqlChain[i].committee);
        expect(memChain[i].signer_node_ids).toEqual(sqlChain[i].signer_node_ids);
        expect(memChain[i].signatures).toEqual(sqlChain[i].signatures);
        expect(memChain[i].prev_rotation).toBe(sqlChain[i].prev_rotation);
      }

      sqlDag.close();
    } finally {
      _cleanup(dbPath);
    }
  });
});
