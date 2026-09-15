/**
 * @file tests/consensus/state-root.test.js
 * @description Unit tests for §14 state-root + txs-root primitives.
 *
 * Consensus-stability properties:
 *   - state_merkle_root is a pure function of canonical derived state
 *     (identical DAG state → identical root, independent of construction order)
 *   - mutating any canonical field changes the root
 *   - createStateRootBuilder (incremental, used by snapshot client) and
 *     computeStateMerkleRoot (bulk, used by Bullshark commit) agree
 *   - txs_merkle_root has a known empty sentinel, is order-sensitive,
 *     and distinguishes content
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../../../shared/time");

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const {
  computeStateMerkleRoot, computeTxsMerkleRoot, createStateRootBuilder, verifyStateRootConsistency,
  verifyStateRootConsistencyAsync,
  EMPTY_STATE_ROOT, EMPTY_TXS_ROOT,
} = require(path.join(SRC, "consensus", "state-root"));

beforeAll(async () => { await initCrypto(); });

describe("state_merkle_root", () => {
  test("is identical across two independent DAGs bootstrapped from the same genesis", () => {
    const a = initDAG({ dbPath: ":memory:" });
    const b = initDAG({ dbPath: ":memory:" });
    expect(computeStateMerkleRoot(a)).toBe(computeStateMerkleRoot(b));
  });

  test("changes when any canonical state row is added", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const before = computeStateMerkleRoot(dag);
    dag.saveNode({
      node_id: "NODE_X", name: "x", public_key: "deadbeef",
      status: "active", registered_at: 1767225600000,
    });
    expect(computeStateMerkleRoot(dag)).not.toBe(before);
  });

  test("changes when an identity is revoked (status transitions to 'revoked')", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    dag.saveIdentity({
      tip_id: "tip:dev:us:abc", region: "US",
      public_key: "beef", vp_id: "vp:founding",
      verification_tier: "T1", founding: false, status: "active",
      registered_at: 1767225600000, tx_id: "t1",
    });
    const before = computeStateMerkleRoot(dag);
    dag.addRevocation("tip:dev:us:abc", "REVOKE_VOLUNTARY", 1769904000000, "tx-revoke");
    expect(computeStateMerkleRoot(dag)).not.toBe(before);
  });

  test("verifyStateRootConsistency: consistent on a healthy DAG, detects a stale incremental SMT + names the table", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    dag.saveNode({ node_id: "N1", name: "n1", public_key: "abc", status: "active", registered_at: 1767225600000 });

    // Healthy: the committed incremental root equals the reference walk.
    const ok = verifyStateRootConsistency(dag);
    expect(ok.consistent).toBe(true);
    expect(ok.perTable).toBeNull();
    expect(ok.incremental).toBe(ok.reference);

    // Now simulate the drift class (dedup bug shape): a canonical mutation lands
    // in the state (reference walk sees it) but the incremental SMT never synced
    // its leaf, so stateRoot() is stale. verifyStateRootConsistency must catch it
    // and computeStateMerkleRootPerTable must pinpoint the diverging table.
    const staleRoot = dag.stateRoot();
    dag.saveNode({ node_id: "N2", name: "n2", public_key: "def", status: "active", registered_at: 1767225600001 });
    const drifted = {
      stateRoot: () => staleRoot,                                  // incremental never advanced
      iterateCanonicalState: (o) => dag.iterateCanonicalState(o),  // canonical walk did
    };
    const bad = verifyStateRootConsistency(drifted);
    expect(bad.consistent).toBe(false);
    expect(bad.incremental).toBe(staleRoot);
    expect(bad.reference).not.toBe(staleRoot);
    expect(bad.perTable).not.toBeNull();
    expect(bad.perTable.some(t => t.table === "nodes")).toBe(true);
  });

  test("verifyStateRootConsistencyAsync: agrees with the sync walk and detects the same drift", async () => {
    const dag = initDAG({ dbPath: ":memory:" });
    dag.saveNode({ node_id: "N1", name: "n1", public_key: "abc", status: "active", registered_at: 1767225600000 });

    const ok = await verifyStateRootConsistencyAsync(dag, { yieldEvery: 2 });
    expect(ok.skipped).toBe(false);
    expect(ok.consistent).toBe(true);
    expect(ok.reference).toBe(verifyStateRootConsistency(dag).reference);

    const staleRoot = dag.stateRoot();
    dag.saveNode({ node_id: "N2", name: "n2", public_key: "def", status: "active", registered_at: 1767225600001 });
    const drifted = {
      stateRoot: () => staleRoot,
      iterateCanonicalState: (o) => dag.iterateCanonicalState(o),
    };
    const bad = await verifyStateRootConsistencyAsync(drifted, { yieldEvery: 2 });
    expect(bad.skipped).toBe(false);
    expect(bad.consistent).toBe(false);
    expect(bad.perTable.some(t => t.table === "nodes")).toBe(true);
  });

  test("verifyStateRootConsistencyAsync: skips (no verdict) when state mutates mid-walk", async () => {
    const dag = initDAG({ dbPath: ":memory:" });
    for (let i = 0; i < 10; i++) {
      dag.saveNode({ node_id: `M${i}`, name: `m${i}`, public_key: "aa", status: "active", registered_at: 1767225600000 + i });
    }
    // Mutate DURING the walk via the first yield: the incremental root moves
    // between the pre- and post-walk reads, so the cycle must be discarded.
    let mutated = false;
    const origSetImmediate = global.setImmediate;
    const p = verifyStateRootConsistencyAsync(dag, { yieldEvery: 2 });
    await new Promise((r) => origSetImmediate(r));
    if (!mutated) {
      mutated = true;
      dag.saveNode({ node_id: "MID_WALK", name: "mw", public_key: "bb", status: "active", registered_at: 1767225700000 });
    }
    const res = await p;
    expect(res.skipped).toBe(true);
    expect(res.consistent).toBe(true);   // skip is not a failure verdict
  });

  test("createStateRootBuilder and computeStateMerkleRoot agree on the same DAG", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    dag.saveNode({
      node_id: "N1", name: "n1", public_key: "abc",
      status: "active", registered_at: 1767225600000,
    });
    const bulk = computeStateMerkleRoot(dag);
    const b = createStateRootBuilder();
    for (const { table, row } of dag.iterateCanonicalState()) {
      b.addRowObject(table, row);
    }
    expect(b.finalize()).toBe(bulk);
  });

  test("empty canonical state hashes to EMPTY_STATE_ROOT sentinel", () => {
    // A dag with no iterateCanonicalState output — simulate by using a
    // fresh builder directly (initDAG writes genesis state so its iterator
    // is non-empty). This tests the sentinel path only.
    const b = createStateRootBuilder();
    expect(b.finalize()).toBe(EMPTY_STATE_ROOT);
  });

  test("finalize() throws if called twice (builder is single-use)", () => {
    const b = createStateRootBuilder();
    b.finalize();
    expect(() => b.finalize()).toThrow(/already called/);
  });

  test("SQLite and in-memory stores compute identical state_merkle_root", () => {
    // Consensus-critical: our two store implementations (SQLite + in-mem)
    // MUST hash to the same root for the same writes. If they diverge,
    // a mixed-store network forks silently on the first commit.
    const fs = require("fs");
    const os = require("os");
    const dbPath = path.join(os.tmpdir(), `tip-state-root-parity-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);

    let sqliteDag, memDag;
    try {
      sqliteDag = initDAG({ dbPath });                // real SQLite file
      memDag    = initDAG({ dbPath: ":memory:" });    // MemoryStore

      // Apply the exact same writes to both stores in the same order.
      const writes = [
        () => {
          const rec = {
            tip_id: "tip:dev:us:alpha", region: "US",
            public_key: "aa", root_public_key: "bb",
            vp_id: "vp:founding", verification_tier: "T1",
            founding: false, status: "active",
            registered_at: 1767225600000, tx_id: "tx-alpha",
            biometric_commit: "d".repeat(64),
          };
          sqliteDag.saveIdentity(rec); memDag.saveIdentity(rec);
        },
        () => {
          const rec = {
            node_id: "NODE_P", name: "peer node",
            public_key: "cc", status: "active",
            registered_at: 1767225600000,
          };
          sqliteDag.saveNode(rec); memDag.saveNode(rec);
        },
        () => {
          sqliteDag.addDedupHash("dh-1", 1735689600);
          memDag.addDedupHash("dh-1", 1735689600);
        },
        () => {
          sqliteDag.addRevocation("tip:dev:us:alpha", "REVOKE_VOLUNTARY",
            1769904000000, "tx-revoke");
          memDag.addRevocation("tip:dev:us:alpha", "REVOKE_VOLUNTARY",
            1769904000000, "tx-revoke");
        },
      ];
      for (const w of writes) w();

      expect(computeStateMerkleRoot(sqliteDag)).toBe(computeStateMerkleRoot(memDag));
    } finally {
      // Cleanup: SQLite handle + file + WAL/SHM siblings.
      try { sqliteDag?.close?.(); } catch { /* ignore */ }
      try { memDag?.close?.(); } catch { /* ignore */ }
      for (const ext of ["", "-wal", "-shm"]) {
        try { fs.unlinkSync(dbPath + ext); } catch { /* not present */ }
      }
    }
  });

  test("biometric_commit is bound into state_merkle_root (differs-in-field ⇒ differs-in-root)", () => {
    // Consensus-binding guard: two identities that differ ONLY in
    // biometric_commit MUST hash to different roots, and present-vs-absent MUST
    // differ. If biometric_commit were dropped from _canonIdentity, all three
    // canonical rows would be identical and this test would fail — catching a
    // silent un-binding of the field from consensus that the store-parity and
    // snapshot tests cannot (they only check the two stores agree with each
    // other, which stays true even if the field is dropped from the shaper).
    const base = {
      tip_id: "tip:dev:us:biom", region: "US",
      public_key: "aa", vp_id: "vp:founding", verification_tier: "T1",
      founding: false, status: "active",
      registered_at: 1767225600000, tx_id: "tx-biom",
    };
    let withA, withB, without;
    try {
      withA   = initDAG({ dbPath: ":memory:" });
      withB   = initDAG({ dbPath: ":memory:" });
      without = initDAG({ dbPath: ":memory:" });
      withA.saveIdentity({ ...base, biometric_commit: "a".repeat(64) });
      withB.saveIdentity({ ...base, biometric_commit: "b".repeat(64) });
      without.saveIdentity({ ...base }); // no biometric_commit → OMITTED from the canonical row
      const rootA = computeStateMerkleRoot(withA);
      const rootB = computeStateMerkleRoot(withB);
      const rootNone = computeStateMerkleRoot(without);
      expect(rootA).not.toBe(rootB);     // differ only in biometric_commit value
      expect(rootA).not.toBe(rootNone);  // present vs absent must differ
    } finally {
      for (const d of [withA, withB, without]) { try { d?.close?.(); } catch { /* ignore */ } }
    }
  });

  test("absent biometric_commit is OMITTED from the canonical identity row (live-chain byte-compat)", () => {
    // The rolling-upgrade safety guarantee: an identity that never bound a commit
    // must canonicalize EXACTLY as it did before the field existed — the key is
    // OMITTED, not emitted as null. If it were `|| null`, the pre-existing rows'
    // leaves (and thus state_merkle_root) would change on deploy and old-vs-new
    // nodes would fork. This asserts the strip-when-absent behavior at the byte level
    // (mutation guard: reverting _canonIdentity to `|| null` fails the first expect).
    const { canonicalJson } = require(path.join(SHARED, "crypto"));
    const base = {
      tip_id: "tip:dev:us:oldid", region: "US", public_key: "aa",
      vp_id: "vp:founding", verification_tier: "T1", founding: false,
      status: "active", registered_at: 1767225600000, tx_id: "tx-old",
    };
    let d;
    try {
      d = initDAG({ dbPath: ":memory:" });
      d.saveIdentity({ ...base });                                          // no commit → omitted
      d.saveIdentity({ ...base, tip_id: "tip:dev:us:newid",
                       biometric_commit: "c".repeat(64) });                 // commit → present
      const canon = {};
      for (const { table, row } of d.iterateCanonicalState()) {
        if (table === "identities") canon[row.tip_id] = canonicalJson(row);
      }
      expect(canon["tip:dev:us:oldid"]).not.toContain("biometric_commit");  // old: key absent
      expect(canon["tip:dev:us:newid"]).toContain("biometric_commit");      // new: key present
    } finally {
      try { d?.close?.(); } catch { /* ignore */ }
    }
  });
});

describe("txs_merkle_root", () => {
  test("empty array returns EMPTY_TXS_ROOT sentinel", () => {
    expect(computeTxsMerkleRoot([])).toBe(EMPTY_TXS_ROOT);
  });

  test("same input produces same root (deterministic)", () => {
    const txs = [{ tx_id: "a".repeat(64) }, { tx_id: "b".repeat(64) }, { tx_id: "c".repeat(64) }];
    expect(computeTxsMerkleRoot(txs)).toBe(computeTxsMerkleRoot([...txs]));
  });

  test("order matters (reordering txs changes root — block-inclusion proofs)", () => {
    const a = { tx_id: "a".repeat(64) };
    const b = { tx_id: "b".repeat(64) };
    const c = { tx_id: "c".repeat(64) };
    expect(computeTxsMerkleRoot([a, b, c])).not.toBe(computeTxsMerkleRoot([b, a, c]));
  });

  test("odd-count inputs duplicate the last leaf (Bitcoin-style padding)", () => {
    // Implementation detail worth pinning: odd-level width is evened by
    // duplicating the final node. Two+duplicate and single should NOT
    // collide — leaf is H("L" || tx_id), internal is H("N" || left || right),
    // so domain separation prevents the classic second-preimage issue.
    const one = [{ tx_id: "a".repeat(64) }];
    const three = [
      { tx_id: "a".repeat(64) },
      { tx_id: "b".repeat(64) },
      { tx_id: "c".repeat(64) },
    ];
    expect(computeTxsMerkleRoot(one)).not.toBe(computeTxsMerkleRoot(three));
  });
});
