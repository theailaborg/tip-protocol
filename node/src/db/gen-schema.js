"use strict";

/**
 * @file src/db/gen-schema.js
 * @description Regenerates src/db/schema.sql from the Knex baseline migration.
 *
 * The migration files (src/db/migrations/*.js) are the SINGLE authored schema.
 * This script runs them against a throwaway SQLite DB, dumps the resulting DDL,
 * and writes it to schema.sql, which the synchronous SQLiteStore `_migrate()`
 * execs for :memory: / file-SQLite. So there is one schema you ever edit (the
 * migration); schema.sql is a generated artifact, a "schema lockfile".
 *
 * Run after any migration change:   npm run gen:schema
 *
 * The drift-guard test (tests/db/migration-baseline-schema.test.js) fails if
 * schema.sql is stale, so it can never silently fall out of sync with the
 * migration in CI.
 *
 * Statements get `IF NOT EXISTS` because on a file-SQLite node the Knex
 * migration (initDAGAsync -> _runSqliteMigrations) creates the tables first and
 * then the SQLiteStore constructor execs this schema again, idempotently.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

const path = require("path");
const fs = require("fs");
const os = require("os");
const Database = require("better-sqlite3");
const knexLib = require("knex");

const MIGRATIONS_DIR = path.join(__dirname, "migrations");
const OUT = path.join(__dirname, "schema.sql");

// Indexes intentionally EXCLUDED from schema.sql because dag.js `_migrate()`
// creates them AFTER its conditional ALTER backfills. They index columns
// (subject_tip_id) that may be added via ALTER on a DB that predates the
// column; emitting the CREATE INDEX here would throw "no such column" when
// schema.sql is exec'd on such a pre-existing DB and cascade to the in-memory
// fallback (a live-observed incident). On a fresh DB the trailing
// CREATE INDEX IF NOT EXISTS still creates them, so coverage is unchanged.
const DEFERRED_INDEXES = new Set([
  "idx_txs_subject",
  "idx_mempool_subject",
  "idx_tx_rej_subject",
]);

function addIfNotExists(sql) {
  return sql
    .replace(/^CREATE TABLE /i, "CREATE TABLE IF NOT EXISTS ")
    .replace(/^CREATE (UNIQUE )?INDEX /i, (m, u) => `CREATE ${u || ""}INDEX IF NOT EXISTS `)
    .replace(/^CREATE TRIGGER /i, "CREATE TRIGGER IF NOT EXISTS ")
    .replace(/^CREATE VIEW /i, "CREATE VIEW IF NOT EXISTS ");
}

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-gen-schema-"));
  const dbFile = path.join(tmpDir, "schema.db");
  const knex = knexLib({
    client: "better-sqlite3",
    connection: { filename: dbFile },
    useNullAsDefault: true,
    migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
  });
  try {
    await knex.migrate.latest();
  } finally {
    await knex.destroy();
  }

  const db = new Database(dbFile, { readonly: true });
  // Tables first (FK targets resolve at DML time, so table order is free),
  // then indexes/triggers/views which reference an existing table. Deterministic
  // ordering keeps schema.sql diffs minimal across regenerations.
  const rows = db
    .prepare(
      "SELECT type, name, sql FROM sqlite_master " +
      "WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'knex_%' " +
      "ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 " +
      "WHEN 'trigger' THEN 2 WHEN 'view' THEN 3 ELSE 4 END, name"
    )
    .all();
  db.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });

  const stmts = rows
    .filter((r) => !(r.type === "index" && DEFERRED_INDEXES.has(r.name)))
    .map((r) => addIfNotExists(r.sql.trim()) + ";");
  const header =
    "-- GENERATED FILE. DO NOT EDIT.\n" +
    "-- Source of truth: src/db/migrations/*.js (Knex baseline).\n" +
    "-- Regenerate with: npm run gen:schema\n" +
    "-- Verified current by tests/db/migration-baseline-schema.test.js.\n\n";
  fs.writeFileSync(OUT, header + stmts.join("\n\n") + "\n");
  console.log(`schema.sql written: ${stmts.length} statements -> ${OUT}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
