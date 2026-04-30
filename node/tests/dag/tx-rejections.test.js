/**
 * @file tests/dag/tx-rejections.test.js
 * @description Tests for the `tx_rejections` table — the per-node
 * observation log that seals the no-loss invariant (#64 follow-up).
 *
 * Drives every assertion against BOTH stores (MemoryStore + real SQLite)
 * so the SQL and JS implementations stay in lockstep. A regression in
 * one store is silent for the other; describe.each catches both.
 *
 * Contract under test (see dag.js `saveTxRejection`):
 *   - INSERT OR IGNORE on tx_id PK — first observation wins, returns
 *     true on insert, false on collision. Original (most-informative)
 *     reason is preserved across peer re-broadcast.
 *   - Optional fields default to null, not undefined or '' — ensures
 *     the column shape matches between stores (SQLite is strict).
 *   - getTxRejectionsByReason filters on reason + since (epoch ms),
 *     orders DESC by rejected_at_ms, respects limit.
 *   - countTxRejections gives a fast cardinality probe (used by ops
 *     dashboards / health endpoint).
 *
 * NOT under test here (covered by the wiring tests in mempool /
 * narwhal / commit-handler suites):
 *   - which sites call saveTxRejection — that's the wiring layer.
 *   - the GET /v1/dag/tx/:txId/outcome endpoint — separate route test.
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

const { initCrypto } = require(path.join(SHARED, "crypto"));
const { TX_REJECTION_REASON } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));

beforeAll(async () => {
  await initCrypto();
});

// ─── Store scenarios ────────────────────────────────────────────────────────
// Same dual-store pattern as clean-record-eligibility.test.js — every
// test runs once per store. Real SQLite uses a tmpfile that the test
// cleans up on its way out so we don't accumulate /tmp clutter.
const SCENARIOS = [
  ["MemoryStore (in-memory)", () => initDAG({ dbPath: ":memory:" })],
  ["SQLiteStore (real DB)", () => {
    const dbPath = path.join(os.tmpdir(), `tip-rej-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    const dag = initDAG({ dbPath });
    return { dag, _cleanup: () => { try { fs.unlinkSync(dbPath); } catch { /* ignore */ } } };
  }],
];

const NODE_ID = "tip://node/test";

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeRej(overrides = {}) {
  return {
    tx_id:           overrides.tx_id || `tip://tx/${Math.random().toString(36).slice(2)}`,
    reason:          overrides.reason || TX_REJECTION_REASON.MEMPOOL_FULL,
    reason_detail:   overrides.reason_detail,
    rejected_at_ms:  overrides.rejected_at_ms,
    rejected_at_round: overrides.rejected_at_round,
    dropper_node_id: overrides.dropper_node_id || NODE_ID,
    tx_type:         overrides.tx_type,
    origin_node_id:  overrides.origin_node_id,
  };
}

function withDag(makeStore, fn) {
  const made = makeStore();
  const dag = made.dag || made;
  try {
    fn(dag);
  } finally {
    if (made._cleanup) made._cleanup();
    if (typeof dag.close === "function") dag.close();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Constants surface — make sure the reason enum was exported
// ═══════════════════════════════════════════════════════════════════════════

describe("TX_REJECTION_REASON enum surface", () => {
  test("exports the expected reason codes (wire-stable strings)", () => {
    // If a future refactor renames a value, this test red-flags it BEFORE
    // it ships and breaks deployed nodes that have the old strings on disk.
    expect(TX_REJECTION_REASON.MEMPOOL_FULL).toBe("mempool_full");
    expect(TX_REJECTION_REASON.MEMPOOL_TTL_EXPIRED).toBe("mempool_ttl_expired");
    expect(TX_REJECTION_REASON.BATCH_BEYOND_HORIZON).toBe("batch_beyond_horizon");
    expect(TX_REJECTION_REASON.BATCH_EQUIVOCATION).toBe("batch_equivocation");
    expect(TX_REJECTION_REASON.IDENTITY_ALREADY_REGISTERED).toBe("identity_already_registered");
    expect(TX_REJECTION_REASON.REVALIDATION_FAILED).toBe("revalidation_failed");
  });

  test("enum is frozen — refactor can't accidentally mutate at runtime", () => {
    expect(Object.isFrozen(TX_REJECTION_REASON)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. saveTxRejection / getTxRejection — happy path + idempotence
// ═══════════════════════════════════════════════════════════════════════════

describe.each(SCENARIOS)("dag.saveTxRejection / getTxRejection — %s", (_label, makeStore) => {
  test("saves and reads back a rejection with all fields populated", () => {
    withDag(makeStore, (dag) => {
      const rec = makeRej({
        tx_id: "tip://tx/full",
        reason: TX_REJECTION_REASON.BATCH_BEYOND_HORIZON,
        reason_detail: "round 5 < currentRound 100 - horizon 5",
        rejected_at_ms: 1_700_000_000_000,
        rejected_at_round: 100,
        tx_type: "REGISTER_IDENTITY",
        origin_node_id: "tip://node/peerB",
      });

      expect(dag.saveTxRejection(rec)).toBe(true);

      const got = dag.getTxRejection("tip://tx/full");
      expect(got).toMatchObject({
        tx_id:             "tip://tx/full",
        reason:            "batch_beyond_horizon",
        reason_detail:     "round 5 < currentRound 100 - horizon 5",
        rejected_at_ms:    1_700_000_000_000,
        rejected_at_round: 100,
        dropper_node_id:   NODE_ID,
        tx_type:           "REGISTER_IDENTITY",
        origin_node_id:    "tip://node/peerB",
      });
    });
  });

  test("optional fields default to null (not undefined or '')", () => {
    withDag(makeStore, (dag) => {
      // Minimal rejection — only the required fields. The shape must be
      // null-padded so the SQLite store and MemoryStore agree on what
      // "absent" looks like (otherwise downstream code that compares
      // rec.tx_type === null would behave differently per store).
      dag.saveTxRejection({
        tx_id: "tip://tx/minimal",
        reason: TX_REJECTION_REASON.MEMPOOL_FULL,
        dropper_node_id: NODE_ID,
      });

      const got = dag.getTxRejection("tip://tx/minimal");
      expect(got.reason_detail).toBeNull();
      expect(got.rejected_at_round).toBeNull();
      expect(got.tx_type).toBeNull();
      expect(got.origin_node_id).toBeNull();
      // rejected_at_ms must be auto-stamped (not null) when caller omits it.
      expect(typeof got.rejected_at_ms).toBe("number");
      expect(got.rejected_at_ms).toBeGreaterThan(0);
    });
  });

  test("returns null for unknown tx_id", () => {
    withDag(makeStore, (dag) => {
      expect(dag.getTxRejection("tip://tx/never-saved")).toBeNull();
    });
  });

  test("tx_data round-trips through both stores as a parsed object", () => {
    // Locks the contract that drives operator replay tooling: the full
    // tx body must come back out shaped exactly as it went in. If a
    // future refactor stops parsing the JSON string on read, replay
    // tooling silently breaks (it'd see a string, not an object) — this
    // test catches that drift.
    withDag(makeStore, (dag) => {
      const tx = {
        tx_id: "tip://tx/with-body",
        tx_type: "REGISTER_IDENTITY",
        timestamp: "2026-04-30T08:00:00.000Z",
        prev: ["a", "b"],
        signature: "deadbeef",
        data: { tip_id: "tip://id/X", region: "US", nested: { k: 1 } },
      };
      dag.saveTxRejection({
        tx_id: tx.tx_id,
        reason: TX_REJECTION_REASON.MEMPOOL_FULL,
        dropper_node_id: NODE_ID,
        tx_type: tx.tx_type,
        tx_data: tx,
      });

      const got = dag.getTxRejection(tx.tx_id);
      expect(got.tx_data).toEqual(tx);  // structural match — parsed object
      expect(typeof got.tx_data).toBe("object");
      expect(got.tx_data.data.nested).toEqual({ k: 1 });
    });
  });

  test("tx_data null when omitted (drop site has tx_id only)", () => {
    withDag(makeStore, (dag) => {
      dag.saveTxRejection({
        tx_id: "tip://tx/no-body",
        reason: TX_REJECTION_REASON.MEMPOOL_FULL,
        dropper_node_id: NODE_ID,
      });
      expect(dag.getTxRejection("tip://tx/no-body").tx_data).toBeNull();
    });
  });

  test("idempotent on tx_id PK — first observation wins, second is a no-op", () => {
    withDag(makeStore, (dag) => {
      // Same tx is observed at two drop sites (e.g. mempool TTL evict on
      // node 1, then beyond-horizon on node 2 if peer re-broadcast sneaks
      // in). On a single node the first reason recorded must persist.
      const first = makeRej({
        tx_id: "tip://tx/dup",
        reason: TX_REJECTION_REASON.MEMPOOL_FULL,
        reason_detail: "first observation",
        rejected_at_ms: 1000,
      });
      const second = makeRej({
        tx_id: "tip://tx/dup",
        reason: TX_REJECTION_REASON.BATCH_BEYOND_HORIZON,
        reason_detail: "second observation — should not overwrite",
        rejected_at_ms: 2000,
      });

      expect(dag.saveTxRejection(first)).toBe(true);
      expect(dag.saveTxRejection(second)).toBe(false);  // no-op

      const got = dag.getTxRejection("tip://tx/dup");
      expect(got.reason).toBe("mempool_full");
      expect(got.reason_detail).toBe("first observation");
      expect(got.rejected_at_ms).toBe(1000);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. getTxRejectionsByReason — filter, order, limit, since
// ═══════════════════════════════════════════════════════════════════════════

describe.each(SCENARIOS)("dag.getTxRejectionsByReason — %s", (_label, makeStore) => {
  function seed(dag) {
    // Three mempool_full at t=1000, 2000, 3000
    for (let i = 1; i <= 3; i++) {
      dag.saveTxRejection(makeRej({
        tx_id: `tip://tx/full-${i}`,
        reason: TX_REJECTION_REASON.MEMPOOL_FULL,
        rejected_at_ms: i * 1000,
      }));
    }
    // Two beyond_horizon at t=4000, 5000
    for (let i = 1; i <= 2; i++) {
      dag.saveTxRejection(makeRej({
        tx_id: `tip://tx/horizon-${i}`,
        reason: TX_REJECTION_REASON.BATCH_BEYOND_HORIZON,
        rejected_at_ms: 3000 + i * 1000,
      }));
    }
  }

  test("filters by reason — only matching rows returned", () => {
    withDag(makeStore, (dag) => {
      seed(dag);
      const fulls = dag.getTxRejectionsByReason(TX_REJECTION_REASON.MEMPOOL_FULL);
      expect(fulls.map(r => r.tx_id).sort()).toEqual([
        "tip://tx/full-1", "tip://tx/full-2", "tip://tx/full-3",
      ]);
    });
  });

  test("orders by rejected_at_ms DESC (most-recent first)", () => {
    withDag(makeStore, (dag) => {
      seed(dag);
      const fulls = dag.getTxRejectionsByReason(TX_REJECTION_REASON.MEMPOOL_FULL);
      expect(fulls.map(r => r.rejected_at_ms)).toEqual([3000, 2000, 1000]);
    });
  });

  test("respects `since` (inclusive lower bound on rejected_at_ms)", () => {
    withDag(makeStore, (dag) => {
      seed(dag);
      const recent = dag.getTxRejectionsByReason(
        TX_REJECTION_REASON.MEMPOOL_FULL,
        { since: 2000 }
      );
      expect(recent.map(r => r.rejected_at_ms)).toEqual([3000, 2000]);
    });
  });

  test("respects `limit` after sorting", () => {
    withDag(makeStore, (dag) => {
      seed(dag);
      const top = dag.getTxRejectionsByReason(
        TX_REJECTION_REASON.MEMPOOL_FULL,
        { limit: 1 }
      );
      // Top result must be the most recent (sorted DESC, limited to 1).
      expect(top).toHaveLength(1);
      expect(top[0].rejected_at_ms).toBe(3000);
    });
  });

  test("returns [] for a reason with no rows (no error, no surprises)", () => {
    withDag(makeStore, (dag) => {
      seed(dag);
      const empty = dag.getTxRejectionsByReason(TX_REJECTION_REASON.IDENTITY_ALREADY_REGISTERED);
      expect(empty).toEqual([]);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. countTxRejections — fast cardinality probe
// ═══════════════════════════════════════════════════════════════════════════

describe.each(SCENARIOS)("dag.countTxRejections — %s", (_label, makeStore) => {
  test("returns 0 on a fresh dag", () => {
    withDag(makeStore, (dag) => {
      expect(dag.countTxRejections()).toBe(0);
    });
  });

  test("increments on insert, ignores duplicates", () => {
    withDag(makeStore, (dag) => {
      dag.saveTxRejection(makeRej({ tx_id: "tip://tx/a" }));
      dag.saveTxRejection(makeRej({ tx_id: "tip://tx/b" }));
      dag.saveTxRejection(makeRej({ tx_id: "tip://tx/a" }));  // dup
      expect(dag.countTxRejections()).toBe(2);
    });
  });
});
