/**
 * @file tests/regression/timestamp-discipline.test.js
 * @description Regression guardrail for the ms-everywhere timestamp policy.
 *
 * Two layers of protection:
 *
 *   1. Source discipline — production code under `node/src` and `shared`
 *      must route every timestamp call through `shared/time.js`. The raw
 *      JS Date and parse APIs (`new Date(...)`, `Date.now()`,
 *      `Date.parse(...)`, `.toISOString()`) are forbidden everywhere
 *      except inside `shared/time.js` itself, where they're implemented.
 *
 *   2. Schema discipline — every timestamp-named column in every SQLite
 *      table must be declared INTEGER. Mixing TEXT and INTEGER timestamp
 *      storage was the silent root cause of the state_merkle_root
 *      divergence we hit during the migration (scores.last_updated
 *      stored "1773532800000.0" as TEXT/REAL on one store, 1773532800000
 *      as Number on the other). Knex-side parity is enforced by a
 *      mirror check against `db/knex-adapter.js`.
 *
 * If either describe block fails, a regression has slipped past review
 * — the failing message names the offending file:line so the reviewer
 * can target the fix without grepping.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const os = require("os");

const PC = require("../../../shared/protocol-constants");
const { GENESIS_PAYLOAD } = require("../../src/genesis");
PC.init(GENESIS_PAYLOAD.protocol_constants);

const { initDAG } = require("../../src/dag");

const REPO_ROOT = path.resolve(__dirname, "../../..");
const NODE_SRC = path.join(REPO_ROOT, "node", "src");
const SHARED_DIR = path.join(REPO_ROOT, "shared");

// shared/time.js IS the timestamp helper module — it's the one place
// raw JS Date APIs are allowed.
const SOURCE_ALLOWLIST = new Set([
  path.join(SHARED_DIR, "time.js"),
]);

// Patterns that must not appear in production source. Each entry has a
// human-readable name (for the failure message) and the regex.
const FORBIDDEN_SOURCE_PATTERNS = [
  { name: "new Date(", regex: /new\s+Date\s*\(/ },
  { name: ".toISOString()", regex: /\.toISOString\s*\(\s*\)/ },
  { name: "Date.parse(", regex: /\bDate\.parse\s*\(/ },
  { name: "Date.now()", regex: /\bDate\.now\s*\(\s*\)/ },
];

// Walk a directory and yield every .js file. Skips node_modules and
// hidden directories so the scan stays within first-party code.
function _walkJsFiles(root, out = []) {
  if (!fs.existsSync(root)) return out;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
    const p = path.join(root, entry.name);
    if (entry.isDirectory()) _walkJsFiles(p, out);
    else if (entry.isFile() && p.endsWith(".js")) out.push(p);
  }
  return out;
}

// Strip line and block comments so a JSDoc reference to `Date.now()` for
// historical/documentation reasons doesn't trip the check. We're scanning
// for actual code callsites, not prose.
//
// Critically, newlines inside block comments are PRESERVED so that
// post-strip line numbers still correspond to the original source —
// the violation message cites file:line and would be useless otherwise.
function _stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))  // /* ... */
    .replace(/\/\/[^\n]*/g, (m) => " ".repeat(m.length));            // // ...
}

// Column names that semantically carry a timestamp. The schema invariant
// asserts every column matching this pattern is INTEGER in SQLite (and
// bigInteger in knex via the source-level check below).
const TIMESTAMP_COLUMN_NAME = /^(timestamp|cert_timestamp|last_updated|.*_at|.*_at_ms)$/;

// Columns that match the timestamp-name pattern but are NOT timestamps:
//   - *_at_round           → round counters (integer round number)
//   - ack_signed_ats       → JSON-encoded array of int64 ms (container is TEXT,
//                            values inside are ms; intentional)
const TIMESTAMP_NAME_EXEMPT = (col) =>
  /_at_round$/.test(col.name) || col.name === "ack_signed_ats";


// ═══════════════════════════════════════════════════════════════════════════
// 1. Source discipline
// ═══════════════════════════════════════════════════════════════════════════
describe("timestamp discipline — production source routes through shared/time.js", () => {
  const sourceFiles = [
    ..._walkJsFiles(NODE_SRC),
    ..._walkJsFiles(SHARED_DIR),
  ];

  for (const { name, regex } of FORBIDDEN_SOURCE_PATTERNS) {
    test(`no \`${name}\` outside shared/time.js`, () => {
      const violations = [];
      for (const file of sourceFiles) {
        if (SOURCE_ALLOWLIST.has(file)) continue;
        const raw = fs.readFileSync(file, "utf8");
        const code = _stripComments(raw);
        if (!regex.test(code)) continue;
        // Re-scan raw lines to produce a useful file:line hit for the message.
        const rawLines = raw.split("\n");
        const codeLines = code.split("\n");
        for (let i = 0; i < codeLines.length; i++) {
          if (regex.test(codeLines[i])) {
            violations.push(`  ${path.relative(REPO_ROOT, file)}:${i + 1}  ${rawLines[i].trim()}`);
          }
        }
      }
      if (violations.length > 0) {
        throw new Error(
          `Found ${violations.length} forbidden \`${name}\` callsite(s) in production source.\n` +
          `Use the helpers exported from shared/time.js (nowMs, nowIso, nowPlusMs, toIso, fromIso, isValidMs).\n\n` +
          violations.slice(0, 20).join("\n") +
          (violations.length > 20 ? `\n  ... and ${violations.length - 20} more` : ""),
        );
      }
      expect(violations).toEqual([]);
    });
  }
});


// ═══════════════════════════════════════════════════════════════════════════
// 2. Schema discipline — SQLite tables
// ═══════════════════════════════════════════════════════════════════════════
describe("timestamp schema invariants — SQLite tables", () => {
  let dbPath;
  let dag;
  let rawDb;

  beforeAll(() => {
    dbPath = path.join(os.tmpdir(), `tip-ts-schema-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    dag = initDAG({ dbPath });
    rawDb = new Database(dbPath, { readonly: true });
  });

  afterAll(() => {
    try { dag.close?.(); } catch { /* ignore */ }
    try { rawDb.close(); } catch { /* ignore */ }
    for (const ext of ["", "-wal", "-shm"]) {
      try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
    }
  });

  test("every timestamp-named column is declared INTEGER", () => {
    const tables = rawDb.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    ).all();
    expect(tables.length).toBeGreaterThan(0);

    const violations = [];
    for (const { name: table } of tables) {
      const cols = rawDb.prepare(`PRAGMA table_info(${table})`).all();
      for (const col of cols) {
        if (!TIMESTAMP_COLUMN_NAME.test(col.name)) continue;
        if (TIMESTAMP_NAME_EXEMPT(col)) continue;
        if (col.type !== "INTEGER") {
          violations.push(`  ${table}.${col.name} is ${col.type || "<no-type>"} (expected INTEGER)`);
        }
      }
    }
    if (violations.length > 0) {
      throw new Error(
        `Found ${violations.length} timestamp-named column(s) not declared INTEGER:\n` +
        violations.join("\n") +
        `\n\nEvery timestamp is integer epoch ms throughout the codebase. ` +
        `Update the CREATE TABLE in node/src/dag.js — and the matching ` +
        `t.bigInteger(...) declaration in node/src/db/knex-adapter.js.`,
      );
    }
    expect(violations).toEqual([]);
  });
});


// ═══════════════════════════════════════════════════════════════════════════
// 3. Schema discipline — Knex parity (source-level check)
// ═══════════════════════════════════════════════════════════════════════════
describe("timestamp schema invariants — Knex parity", () => {
  test("no t.string(...) declarations on timestamp-named columns", () => {
    const knexSrc = fs.readFileSync(path.join(NODE_SRC, "db", "knex-adapter.js"), "utf8");
    // Match `t.string("colName", ...)` — flag any whose column name
    // looks like a timestamp. Knex `string` maps to VARCHAR — should
    // be bigInteger for ms timestamps.
    const re = /t\.string\(\s*["']([a-z_][a-z0-9_]*)["']/gi;
    const violations = [];
    let m;
    while ((m = re.exec(knexSrc)) !== null) {
      const col = m[1];
      if (!TIMESTAMP_COLUMN_NAME.test(col)) continue;
      if (TIMESTAMP_NAME_EXEMPT({ name: col })) continue;
      // Compute line number for the hit
      const line = knexSrc.slice(0, m.index).split("\n").length;
      violations.push(`  db/knex-adapter.js:${line}  ${col} declared as t.string(...) — expected t.bigInteger(...)`);
    }
    if (violations.length > 0) {
      throw new Error(
        `Found ${violations.length} timestamp-named column(s) declared as t.string(...) in knex schema:\n` +
        violations.join("\n"),
      );
    }
    expect(violations).toEqual([]);
  });
});


// ═══════════════════════════════════════════════════════════════════════════
// 4. Cross-store drift — SQLite INTEGER timestamps must match Knex bigInteger
// ═══════════════════════════════════════════════════════════════════════════
//
// Catches the regression class where a new timestamp column is added to one
// store and forgotten in the other (e.g. a future revocation_renewal_at on
// the SQLite revocations table without the matching bigInteger declaration in
// the knex schema). Both directions checked — adds to either store without
// the mirror trip the test.

// Parse `await ensure("<table>", t => { ... })` blocks in the knex source
// and return a Map<tableName, Set<columnName>> of every bigInteger column.
function _parseKnexBigIntegerColumns() {
  const src = fs.readFileSync(path.join(NODE_SRC, "db", "knex-adapter.js"), "utf8");
  const result = new Map();
  const ensureRe = /await\s+ensure\(\s*["']([a-z_][a-z0-9_]*)["']\s*,\s*\(?t\)?\s*=>\s*\{/g;
  let m;
  while ((m = ensureRe.exec(src)) !== null) {
    const tableName = m[1];
    // Walk forward matching braces to find the end of this block.
    let depth = 1;
    let i = ensureRe.lastIndex;
    while (i < src.length && depth > 0) {
      if (src[i] === "{") depth++;
      else if (src[i] === "}") depth--;
      i++;
    }
    const blockSrc = src.slice(ensureRe.lastIndex, i);
    const cols = new Set();
    const colRe = /t\.bigInteger\(\s*["']([a-z_][a-z0-9_]*)["']/g;
    let cm;
    while ((cm = colRe.exec(blockSrc)) !== null) cols.add(cm[1]);
    result.set(tableName, cols);
  }
  return result;
}

// Tables that exist only in one store by design. Drift across these is fine.
// votes_seen + rotation_participation are SQLite-only (in-memory mirror only,
// not persisted via knex). consensus_meta is a k/v map with no timestamp
// columns either way.
const STORE_ONLY_TABLES = new Set(["votes_seen", "consensus_meta"]);

describe("timestamp schema invariants — cross-store drift", () => {
  let dbPath;
  let dag;
  let rawDb;

  beforeAll(() => {
    dbPath = path.join(os.tmpdir(), `tip-ts-drift-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    dag = initDAG({ dbPath });
    rawDb = new Database(dbPath, { readonly: true });
  });

  afterAll(() => {
    try { dag.close?.(); } catch { /* ignore */ }
    try { rawDb.close(); } catch { /* ignore */ }
    for (const ext of ["", "-wal", "-shm"]) {
      try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
    }
  });

  test("every SQLite INTEGER timestamp column has a matching knex bigInteger", () => {
    const knexCols = _parseKnexBigIntegerColumns();
    const tables = rawDb.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    ).all();

    const missingInKnex = [];
    for (const { name: table } of tables) {
      if (STORE_ONLY_TABLES.has(table)) continue;
      const cols = rawDb.prepare(`PRAGMA table_info(${table})`).all();
      for (const col of cols) {
        if (!TIMESTAMP_COLUMN_NAME.test(col.name)) continue;
        if (TIMESTAMP_NAME_EXEMPT(col)) continue;
        if (col.type !== "INTEGER") continue;        // already enforced by test 2
        const knexSetForTable = knexCols.get(table);
        if (!knexSetForTable) {
          missingInKnex.push(`  ${table}.${col.name}  (table not found in knex source)`);
          continue;
        }
        if (!knexSetForTable.has(col.name)) {
          missingInKnex.push(`  ${table}.${col.name}  (no matching t.bigInteger("${col.name}") in knex)`);
        }
      }
    }
    if (missingInKnex.length > 0) {
      throw new Error(
        `Found ${missingInKnex.length} timestamp column(s) present in SQLite but missing from knex schema:\n` +
        missingInKnex.join("\n") +
        `\n\nAdd t.bigInteger("<col>").notNullable() to the matching await ensure() block in db/knex-adapter.js.`,
      );
    }
    expect(missingInKnex).toEqual([]);
  });

  test("every knex bigInteger timestamp column has a matching SQLite INTEGER", () => {
    const knexCols = _parseKnexBigIntegerColumns();

    // Build the SQLite side as Map<table, Set<column>> for fast lookup.
    const sqliteCols = new Map();
    const tables = rawDb.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    ).all();
    for (const { name: table } of tables) {
      const cols = rawDb.prepare(`PRAGMA table_info(${table})`).all();
      sqliteCols.set(table, new Set(cols.filter(c => c.type === "INTEGER").map(c => c.name)));
    }

    const missingInSqlite = [];
    for (const [table, cols] of knexCols) {
      if (STORE_ONLY_TABLES.has(table)) continue;
      for (const col of cols) {
        if (!TIMESTAMP_COLUMN_NAME.test(col)) continue;
        if (TIMESTAMP_NAME_EXEMPT({ name: col })) continue;
        const sqliteSetForTable = sqliteCols.get(table);
        if (!sqliteSetForTable) {
          missingInSqlite.push(`  ${table}.${col}  (table not found in SQLite schema)`);
          continue;
        }
        if (!sqliteSetForTable.has(col)) {
          missingInSqlite.push(`  ${table}.${col}  (no matching INTEGER column in SQLite)`);
        }
      }
    }
    if (missingInSqlite.length > 0) {
      throw new Error(
        `Found ${missingInSqlite.length} timestamp column(s) present in knex schema but missing from SQLite:\n` +
        missingInSqlite.join("\n") +
        `\n\nAdd <col> INTEGER NOT NULL to the matching CREATE TABLE in node/src/dag.js.`,
      );
    }
    expect(missingInSqlite).toEqual([]);
  });
});
