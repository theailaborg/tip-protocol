/**
 * @file tests/dag/migration-subject-tip-id.test.js
 * @description Regression test for the subject_tip_id schema migration
 * that hit live federation node 2 on first restart. Symptom:
 *
 *   WARN  SQLite init failed (no such column: subject_tip_id) —
 *         using in-memory store
 *
 * Root cause: `CREATE INDEX ... ON transactions(subject_tip_id)` was
 * placed inside the main migration `db.exec()` block alongside the
 * `CREATE TABLE IF NOT EXISTS`. For an existing DB the table already
 * exists (no-op), but the column doesn't — so the index creation
 * threw and cascaded to MemoryStore fallback, dropping all persisted
 * state. The node then re-bootstrapped from genesis, lost its node
 * registry, and got rejected from peer handshakes.
 *
 * Fix: index creation moved AFTER the `ALTER TABLE ADD COLUMN`
 * conditional in `_migrate`. This test seeds an on-disk DB with the
 * pre-migration schema (no subject_tip_id columns) and verifies that
 * re-opening it via initDAG completes successfully — column appears,
 * indexes appear, persisted rows survive.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../../../shared/time");

const path = require("path");
const os = require("os");
const fs = require("fs");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));

beforeAll(async () => {
  await initCrypto();
});

// Drop in a tmpfile path; cleaned up on test exit.
function _tmpDbPath() {
  return path.join(os.tmpdir(), `tip-mig-subj-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
}

function _cleanup(dbPath) {
  for (const ext of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
  }
}

describe("dag migration — subject_tip_id (pre-migration → migrated DB)", () => {
  test("re-opening a DB without subject_tip_id columns succeeds + adds column + index", () => {
    const dbPath = _tmpDbPath();

    // ── Phase 1: build a pre-migration schema by hand ────────────────
    // Mirrors the layout that lived on node 2's disk before this
    // commit: the three target tables exist but lack the column.
    const Database = require("better-sqlite3");
    const seedDb = new Database(dbPath);
    seedDb.exec(`
      CREATE TABLE transactions (
        tx_id          TEXT PRIMARY KEY,
        tx_type        TEXT NOT NULL,
        data           TEXT NOT NULL,
        timestamp      TEXT NOT NULL,
        prev           TEXT NOT NULL DEFAULT '[]',
        signature      TEXT,
        created_at     INTEGER NOT NULL DEFAULT (unixepoch())
      );
      CREATE TABLE mempool (
        tx_id           TEXT PRIMARY KEY,
        tx_data         TEXT NOT NULL,
        received_at     INTEGER NOT NULL DEFAULT (unixepoch())
      );
      CREATE TABLE tx_rejections (
        tx_id              TEXT PRIMARY KEY,
        reason             TEXT NOT NULL,
        reason_detail      TEXT,
        rejected_at_ms     INTEGER NOT NULL,
        rejected_at_round  INTEGER,
        dropper_node_id    TEXT NOT NULL,
        tx_type            TEXT,
        origin_node_id     TEXT,
        tx_data            TEXT
      );
    `);
    // Plant a row in each table so the migration also exercises the
    // backfill path. The transaction body has a tip_id so subjectTipId
    // resolves to a non-null value.
    seedDb.prepare(
      "INSERT INTO transactions (tx_id,tx_type,data,timestamp,prev,signature) VALUES (?,?,?,?,?,?)"
    ).run(
      "a".repeat(64), "REGISTER_IDENTITY",
      JSON.stringify({ tip_id: "tip://id/US-1234567890abcdef", region: "US" }),
      1777507200000, "[]", null
    );
    seedDb.prepare("INSERT INTO mempool (tx_id, tx_data) VALUES (?,?)").run(
      "b".repeat(64),
      JSON.stringify({
        tx_id: "b".repeat(64), tx_type: "SCORE_UPDATE",
        timestamp: 1777510800000,
        data: { tip_id: "tip://id/US-fedcba9876543210", delta: 1, reason: "test" },
      })
    );
    seedDb.prepare(
      "INSERT INTO tx_rejections (tx_id,reason,rejected_at_ms,dropper_node_id,tx_type,tx_data) VALUES (?,?,?,?,?,?)"
    ).run(
      "c".repeat(64), "mempool_full", 1_700_000_000_000, "tip://node/x", "REGISTER_CONTENT",
      JSON.stringify({
        tx_id: "c".repeat(64), tx_type: "REGISTER_CONTENT",
        data: { signer_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa" },
      })
    );
    seedDb.close();

    try {
      // ── Phase 2: open via initDAG — must NOT fall back to memory ──
      // Pre-fix this throws on the unconditional CREATE INDEX over the
      // missing subject_tip_id column. Post-fix migration succeeds.
      const dag = initDAG({ dbPath });

      // The store should be SQLite-backed (the persisted row count
      // should match what we seeded — MemoryStore fallback would have
      // re-bootstrapped from genesis at 6 txs).
      const total = dag.count();
      expect(total).toBeGreaterThan(0);
      // Our seeded tx is still there.
      expect(dag.getTx("a".repeat(64))).not.toBeNull();

      // ── Phase 3: column + index actually present ──────────────────
      // Re-open the underlying file directly to verify the migration
      // wrote the column and index — initDAG doesn't expose pragmas.
      dag.close();
      const verify = new Database(dbPath);
      try {
        for (const table of ["transactions", "mempool", "tx_rejections"]) {
          const cols = verify.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
          expect(cols).toContain("subject_tip_id");
        }
        for (const idx of ["idx_txs_subject", "idx_mempool_subject", "idx_tx_rej_subject"]) {
          const row = verify.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name=?").get(idx);
          expect(row).toBeDefined();
        }

        // ── Phase 4: backfill populated subject_tip_id on existing rows ──
        // The seeded REGISTER_IDENTITY tx has tip_id, so its
        // subject_tip_id should now be backfilled (not NULL).
        const seededRow = verify.prepare("SELECT subject_tip_id FROM transactions WHERE tx_id=?").get("a".repeat(64));
        expect(seededRow.subject_tip_id).toBe("tip://id/US-1234567890abcdef");

        const seededMempool = verify.prepare("SELECT subject_tip_id FROM mempool WHERE tx_id=?").get("b".repeat(64));
        expect(seededMempool.subject_tip_id).toBe("tip://id/US-fedcba9876543210");

        const seededRej = verify.prepare("SELECT subject_tip_id FROM tx_rejections WHERE tx_id=?").get("c".repeat(64));
        expect(seededRej.subject_tip_id).toBe("tip://id/US-aaaaaaaaaaaaaaaa");
      } finally {
        verify.close();
      }
    } finally {
      _cleanup(dbPath);
    }
  });

  test("re-opening a fresh DB (no pre-existing tables) is also clean", () => {
    // Sanity case — fresh DB hits the CREATE TABLE WITH subject_tip_id
    // path AND the unconditional CREATE INDEX. No regressions either way.
    const dbPath = _tmpDbPath();
    try {
      const dag = initDAG({ dbPath });
      expect(dag.count()).toBeGreaterThan(0);  // genesis was written
      dag.close();
    } finally {
      _cleanup(dbPath);
    }
  });
});
