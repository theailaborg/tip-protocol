/**
 * @file tests/db/migration-baseline-schema.test.js
 * @description #117 schema-drift guard (exhaustive).
 *
 * The SQLite store keeps TWO schema authorities: the inline CREATE TABLE block
 * in dag.js `_migrate()` (the path that runs for :memory: / direct initDAG
 * callers, i.e. the test suite) AND the Knex baseline migration 000_baseline.js
 * (the path that runs for file-SQLite + Postgres in production via
 * initDAGAsync). They MUST define the same schema. If ANY schema feature is
 * added to one but not the other, production (the migration) silently diverges
 * from the tests (inline) — the juror_consent-missing-on-Postgres,
 * mempool-received_at-defaults-to-0, missing-index class of bug.
 *
 * This guard introspects a SQLite DB built through each path and asserts the
 * two are identical across EVERY schema dimension SQLite can express:
 *   - table set + view set
 *   - per-column: name, type affinity, NOT NULL, default, primary-key ORDINAL
 *     (composite-key column order), generated/hidden flag
 *   - per-table flags: AUTOINCREMENT, WITHOUT ROWID, CHECK constraints
 *   - per-index: kind (PK/UNIQUE/INDEX), columns with sort-order + collation,
 *     partial flag + WHERE predicate
 *   - per-foreign-key: from/table/to, on_delete, on_update, match
 *   - triggers: name, table, normalised body
 *
 * If you add anything to dag.js `_migrate()` or to a migration, mirror it in
 * the other or this test fails. A column-name-only check (an earlier version)
 * was too weak: it passed while the migration was missing two indexes and
 * defaulting seven timestamp columns to 0 instead of unixepoch()*1000.
 *
 * Normalisation (so cosmetic, behaviour-identical spellings don't flag):
 *   - type affinity, not raw type ("varchar(512)" ≡ "TEXT", both TEXT).
 *   - default: strip a layer of outer parens, unquote pure-numeric literals
 *     ('0' ≡ 0), collapse whitespace ("(unixepoch() * 1000)" ≡ "unixepoch()*1000").
 *   - an INTEGER PRIMARY KEY column is treated NOT NULL regardless of the
 *     pragma flag: "INTEGER PRIMARY KEY [AUTOINCREMENT]" (rowid alias,
 *     notnull=0) and bigIncrements (notnull=1) are equivalent auto-id PKs.
 *   - DDL fragments (CHECK, partial WHERE, trigger/view bodies) are lowercased,
 *     unquoted, and whitespace-collapsed before comparison.
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

// Collapse a declared SQLite type to its storage affinity so cosmetic type
// spellings (varchar(512) vs TEXT, bigint vs INTEGER) compare equal.
function affinity(t) {
  t = (t || "").toUpperCase();
  if (t.includes("INT")) return "INTEGER";
  if (t.includes("CHAR") || t.includes("CLOB") || t.includes("TEXT")) return "TEXT";
  if (t.includes("BLOB") || t === "") return "BLOB";
  if (t.includes("REAL") || t.includes("FLOA") || t.includes("DOUB")) return "REAL";
  return "NUMERIC";
}

// Normalise a column default so behaviour-identical spellings compare equal
// but a real change (unixepoch()*1000 vs 0) still differs.
function normDefault(d) {
  if (d === null || d === undefined) return "NULL";
  let s = String(d).trim();
  while (s.startsWith("(") && s.endsWith(")")) s = s.slice(1, -1).trim();
  const numeric = s.match(/^'(-?\d+(?:\.\d+)?)'$/);
  if (numeric) s = numeric[1];
  return s.replace(/\s+/g, "");
}

// Normalise a raw DDL fragment (CHECK clause, partial-index WHERE, trigger /
// view body) so hand-written and Knex-generated spellings compare equal.
function normSql(s) {
  return String(s || "").toLowerCase().replace(/"/g, "").replace(/\s+/g, " ").trim();
}

// Extract normalised CHECK(...) clauses from a CREATE TABLE statement
// (tolerates one level of nested parens, e.g. CHECK(status IN ('a','b'))).
function extractChecks(sql) {
  const m = (sql || "").match(/check\s*\((?:[^()]|\([^()]*\))*\)/gi) || [];
  return m.map(normSql).sort();
}

function introspect(db) {
  const master = db
    .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE sql IS NOT NULL")
    .all();
  const tableSql = {};
  const indexSql = {};
  for (const r of master) {
    if (r.type === "table") tableSql[r.name] = r.sql;
    if (r.type === "index") indexSql[r.name] = r.sql;
  }

  const tableNames = db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' " +
      "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'knex_%' ORDER BY name"
    )
    .all()
    .map((r) => r.name);

  const tables = {};
  for (const t of tableNames) {
    const ddl = (tableSql[t] || "").toUpperCase();

    // Columns — table_xinfo also surfaces generated/hidden columns table_info omits.
    const columns = db
      .pragma(`table_xinfo(${t})`)
      .map((c) => {
        const aff = affinity(c.type);
        const notnull = c.pk && aff === "INTEGER" ? 1 : c.notnull;
        return {
          name: c.name,
          aff,
          notnull,
          dflt: normDefault(c.dflt_value),
          pk: c.pk, // ORDINAL (1-based position in the PK; 0 if not a PK column)
          hidden: c.hidden, // 0 normal, 2 virtual-generated, 3 stored-generated
        };
      })
      .sort((a, b) => a.name.localeCompare(b.name));

    const flags = {
      autoincrement: /AUTOINCREMENT/.test(ddl),
      withoutRowid: /WITHOUT\s+ROWID/.test(ddl),
      checks: extractChecks(tableSql[t]),
    };

    const indexes = db
      .pragma(`index_list(${t})`)
      .map((i) => {
        const cols = db
          .pragma(`index_xinfo(${i.name})`)
          .filter((x) => x.cid >= 0) // drop the implicit rowid entry (cid=-1)
          .map((x) => `${x.name}:${x.desc ? "DESC" : "ASC"}:${x.coll}`)
          .join(",");
        const kind = i.origin === "pk" ? "PK" : i.unique ? "UNIQUE" : "INDEX";
        const where = i.partial
          ? normSql((indexSql[i.name] || "").replace(/^[\s\S]*?\bwhere\b/i, ""))
          : "";
        return `${kind}[${cols}]partial=${i.partial ? 1 : 0}${where ? " WHERE:" + where : ""}`;
      })
      .sort();

    const fks = db
      .pragma(`foreign_key_list(${t})`)
      .map((f) => `${f.from}->${f.table}.${f.to}:del=${f.on_delete}:upd=${f.on_update}:match=${f.match}`)
      .sort();

    tables[t] = { columns, flags, indexes, fks };
  }

  const triggers = db
    .prepare("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name")
    .all()
    .map((r) => ({ name: r.name, table: r.tbl_name, sql: normSql(r.sql) }));

  const views = db
    .prepare("SELECT name, sql FROM sqlite_master WHERE type='view' ORDER BY name")
    .all()
    .map((r) => ({ name: r.name, sql: normSql(r.sql) }));

  return { tables, triggers, views };
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
    expect(Object.keys(inlineSchema.tables).sort()).toEqual(
      Object.keys(migrationSchema.tables).sort()
    );
  });

  test("every table has identical columns (name, affinity, NOT NULL, default, pk ordinal, generated)", () => {
    for (const t of Object.keys(inlineSchema.tables)) {
      expect({ table: t, columns: inlineSchema.tables[t]?.columns }).toEqual({
        table: t,
        columns: migrationSchema.tables[t]?.columns,
      });
    }
  });

  test("every table has identical table-level flags (AUTOINCREMENT, WITHOUT ROWID, CHECK)", () => {
    for (const t of Object.keys(inlineSchema.tables)) {
      expect({ table: t, flags: inlineSchema.tables[t]?.flags }).toEqual({
        table: t,
        flags: migrationSchema.tables[t]?.flags,
      });
    }
  });

  test("every table has identical indexes (kind, columns, sort-order, collation, partial + WHERE)", () => {
    for (const t of Object.keys(inlineSchema.tables)) {
      expect({ table: t, indexes: inlineSchema.tables[t]?.indexes }).toEqual({
        table: t,
        indexes: migrationSchema.tables[t]?.indexes,
      });
    }
  });

  test("every table has identical foreign keys (target, on_delete, on_update, match)", () => {
    for (const t of Object.keys(inlineSchema.tables)) {
      expect({ table: t, fks: inlineSchema.tables[t]?.fks }).toEqual({
        table: t,
        fks: migrationSchema.tables[t]?.fks,
      });
    }
  });

  test("both paths define identical triggers (name, table, body)", () => {
    expect(inlineSchema.triggers).toEqual(migrationSchema.triggers);
  });

  test("both paths define identical views (name, body)", () => {
    expect(inlineSchema.views).toEqual(migrationSchema.views);
  });
});
