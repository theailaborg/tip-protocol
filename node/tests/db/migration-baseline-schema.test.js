/**
 * @file tests/db/migration-baseline-schema.test.js
 * @description #117 schema-drift guard.
 *
 * The SQLite store keeps TWO schema authorities: the inline CREATE TABLE block
 * in dag.js `_migrate()` (the path that runs for :memory: / direct initDAG
 * callers, i.e. the test suite) AND the Knex baseline migration 000_baseline.js
 * (the path that runs for file-SQLite + Postgres in production via
 * initDAGAsync). They MUST define the same schema. If a column or table is
 * added to one but not the other, production (migration) silently diverges from
 * the tests (inline) — the exact juror_consent-missing-on-Postgres class of bug.
 *
 * This test builds a SQLite DB through each path and asserts the table set and
 * per-table column set are identical, so any future drift fails CI here.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const Database = require("better-sqlite3");
const knexLib = require("knex");
const { SQLiteStore } = require("../../src/dag");

const MIGRATIONS_DIR = path.join(__dirname, "../../src/db/migrations");

// Introspect a SQLite handle into { table -> sorted column names }. Excludes
// SQLite internals and the knex_migrations / knex_migrations_lock tracker.
function introspect(db) {
  const tables = db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' " +
        "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'knex_%' ORDER BY name"
    )
    .all()
    .map((r) => r.name);
  const schema = {};
  for (const t of tables) {
    schema[t] = db.pragma(`table_info(${t})`).map((c) => c.name).sort();
  }
  return schema;
}

let inlineSchema;
let migrationSchema;
let tmpDir;

beforeAll(async () => {
  // (a) Inline path: the SQLiteStore constructor runs dag.js `_migrate()`.
  const inline = new SQLiteStore(":memory:");
  inlineSchema = introspect(inline.db);
  inline.db.close();

  // (b) Migration path: run the Knex baseline against a fresh file, reopen it
  // with a plain better-sqlite3 handle, and introspect identically.
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-mig-schema-"));
  const dbFile = path.join(tmpDir, "migrated.db");
  const k = knexLib({
    client: "better-sqlite3",
    connection: { filename: dbFile },
    useNullAsDefault: true,
    migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
  });
  try {
    await k.migrate.latest();
  } finally {
    await k.destroy();
  }
  const migDb = new Database(dbFile);
  migrationSchema = introspect(migDb);
  migDb.close();
});

afterAll(() => {
  if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("#117 schema-drift guard: inline SQLite schema === Knex baseline migration", () => {
  test("both paths define the same set of tables", () => {
    expect(Object.keys(inlineSchema).sort()).toEqual(Object.keys(migrationSchema).sort());
  });

  test("every table has identical columns in both paths", () => {
    // Per-table deep-equal so a failure names the offending table + columns.
    expect(inlineSchema).toEqual(migrationSchema);
  });
});
