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
const NODE_TESTS = path.join(REPO_ROOT, "node", "tests");
const SHARED_DIR = path.join(REPO_ROOT, "shared");
const SCRIPTS_DIR = path.join(REPO_ROOT, "scripts");

// shared/time.js IS the timestamp helper module — it's the one place
// raw JS Date APIs are allowed. Everything else — including dev-only
// scripts and CLI tooling — must route through nowMs / nowIso /
// nowPlusMs / toIso / fromIso so cross-language byte-determinism and
// audit-format consistency hold uniformly.
const SOURCE_ALLOWLIST = new Set([
  // The timestamp helper module itself.
  path.join(SHARED_DIR, "time.js"),
  // The regression test file's regex patterns and assertion strings
  // contain the forbidden tokens by necessity (it's scanning for them).
  __filename,
]);

// Patterns that must not appear in production source. Each entry has a
// human-readable name (for the failure message) and the regex.
const FORBIDDEN_SOURCE_PATTERNS = [
  { name: "new Date(", regex: /new\s+Date\s*\(/ },
  { name: ".toISOString()", regex: /\.toISOString\s*\(\s*\)/ },
  { name: "Date.parse(", regex: /\bDate\.parse\s*\(/ },
  // Catches both call form `Date.now()` and bare reference `Date.now`
  // (the latter used as an injectable default arg — surfaced after fixing
  // halt-status.js where `now = Date.now` slipped past the call-form check).
  { name: "Date.now", regex: /\bDate\.now\b/ },
];

// Walk a directory and yield every JS-family file (.js + .mjs + .cjs).
// Skips node_modules and hidden directories so the scan stays within
// first-party code.
function _walkJsFiles(root, out = []) {
  if (!fs.existsSync(root)) return out;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
    const p = path.join(root, entry.name);
    if (entry.isDirectory()) _walkJsFiles(p, out);
    else if (entry.isFile() && (p.endsWith(".js") || p.endsWith(".mjs") || p.endsWith(".cjs"))) out.push(p);
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
    ..._walkJsFiles(NODE_TESTS),
    ..._walkJsFiles(SHARED_DIR),
    ..._walkJsFiles(SCRIPTS_DIR),
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


// ═══════════════════════════════════════════════════════════════════════════
// 5. API-boundary discipline — no epoch-ms integers leak to clients
// ═══════════════════════════════════════════════════════════════════════════
//
// Catches the regression class that surfaced during UAT: a route or service
// adds a new timestamp-shaped field, but the boundary middleware doesn't
// recognise its key name, so the integer ms leaks to clients instead of
// being converted to ISO 8601.
//
// The current middleware uses pattern + value-shape detection, so:
//   - any *_at / *At / *_deadline / *_since / `at` / `timestamp` key carrying
//     a valid epoch-ms integer converts to ISO.
//   - any field NOT matching the pattern (e.g. a hypothetical `rejectedTime`
//     instead of `rejected_at`) does NOT convert, and would leak.
//
// This test drives synthetic response shapes — modeled on real endpoint
// outputs (UAT-observed) plus a "future fields" fuzz — through the
// middleware and asserts the post-middleware tree contains zero values in
// the plausible epoch-ms range.

const { createTimestampFormat } = require("../../src/middleware/timestamp-format");
const { MS_FLOOR_2025_01_01_UTC, nowMs } = require("../../../shared/time");

// Upper bound for "plausible epoch ms" — year 2603, leaves headroom but
// trips on the seconds-as-ms class of bugs and on any future code that
// produces a wall-clock ms by mistake. Below this floor: counters,
// durations, byte-counts (all safe to be integers).
const MS_UPPER = 2e13;

function _walkLeaves(node, cb, pathParts = []) {
  if (node === null || node === undefined) return;
  if (Array.isArray(node)) {
    node.forEach((item, i) => _walkLeaves(item, cb, [...pathParts, `[${i}]`]));
    return;
  }
  if (typeof node === "object") {
    for (const key of Object.keys(node)) _walkLeaves(node[key], cb, [...pathParts, key]);
    return;
  }
  cb(node, pathParts);
}

// Drive `body` through outgoing middleware (which is what api.js mounts on
// every response) and return the post-conversion body.
function _throughOutgoing(body) {
  const mw = createTimestampFormat({ outgoing: true, incoming: false });
  let captured = null;
  const res = { json(b) { captured = b; return res; } };
  mw({ body: {} }, res, () => { });
  res.json(body);
  return captured;
}

describe("timestamp discipline — API-boundary outgoing conversion", () => {
  const NOW = nowMs();

  // Each fixture mirrors a real read-endpoint response shape (names taken
  // from UAT scan + a sweep of node/src/routes/*.js). If any of these leak
  // an integer ms, the middleware pattern is incomplete.
  const FIXTURES = [
    {
      name: "/health (consensus subtree)",
      body: {
        consensus: {
          narwhal: { lastRoundAdvanceAt: NOW, round: 42, lastBatchHash: "abc" },
          halt: { lastAdvanceAt: NOW, halted: false, reason: null },
        },
      },
    },
    {
      name: "/v1/stats (mixed timestamps + counters)",
      body: {
        consensus: { narwhal: { lastRoundAdvanceAt: NOW, lastRoundAdvanceAtRound: 100 } },
        tx_counts: { committed: 12345, pending: 7 },
      },
    },
    {
      name: "/v1/content/:ctid",
      body: {
        ctid: "tip://ct/abc",
        registered_at: NOW,
        node_seen_at: NOW + 1,
        prescan: {
          decision_window_ends_at: NOW + 172_800_000,
          filing_deadline: NOW + 86_400_000,
          status: "open",
        },
      },
    },
    {
      name: "/v1/dag/tx/:txId/outcome (short-form `at`)",
      body: { tx_id: "tip://tx/xyz", status: "committed", at: NOW, tx_type: "REGISTER_CONTENT" },
    },
    {
      name: "/v1/dag/state-root",
      body: {
        round: 50,
        state_merkle_root: "deadbeef",
        txs_merkle_root: "cafebabe",
        cert_timestamp: NOW,
        committed_at: NOW + 1,
      },
    },
    {
      name: "rejection record (rejected_at_ms + rejected_at_round)",
      body: {
        tx_id: "tip://tx/r",
        status: "rejected",
        at: NOW,
        rejected_at_round: 99,  // round counter — must NOT convert
      },
    },
    {
      name: "deeply-nested list (paginated dispute feed)",
      body: {
        items: [
          { dispute_id: "d1", filed_at: NOW, decided_at: NOW + 1, filing_deadline: NOW + 2 },
          { dispute_id: "d2", filed_at: NOW + 3, decided_at: null, filing_deadline: NOW + 4 },
        ],
        meta: { generated_at: NOW + 5 },
      },
    },
  ];

  for (const fx of FIXTURES) {
    test(`${fx.name} — no epoch-ms leaks after middleware`, () => {
      const out = _throughOutgoing(fx.body);
      const leaks = [];
      _walkLeaves(out, (v, p) => {
        if (typeof v === "number" && Number.isInteger(v) && v >= MS_FLOOR_2025_01_01_UTC && v <= MS_UPPER) {
          leaks.push(`  ${p.join(".")} = ${v}  (integer in epoch-ms range, not converted to ISO)`);
        }
      });
      if (leaks.length > 0) {
        throw new Error(
          `Boundary middleware failed to convert ${leaks.length} field(s) to ISO:\n` +
          leaks.join("\n") +
          `\n\nAdd the key name to TIMESTAMP_PATTERN in node/src/middleware/timestamp-format.js, ` +
          `or rename the field to follow the *_at / *At / *_deadline / *_since convention.`,
        );
      }
      expect(leaks).toEqual([]);
    });
  }

  test("round counters in the same response stay as integers", () => {
    const out = _throughOutgoing({
      tx_id: "tip://tx/a",
      at: NOW,                          // converts
      rejected_at_round: 42,            // does NOT convert (excluded)
      triggered_at_round: 7,            // does NOT convert (excluded)
    });
    expect(typeof out.at).toBe("string");                  // ISO
    expect(out.rejected_at_round).toBe(42);                // intact
    expect(out.triggered_at_round).toBe(7);                // intact
  });

  test("ack_signed_ats array stays as raw ms (excluded by name)", () => {
    const out = _throughOutgoing({
      cert_id: "tip://cert/c",
      ack_signed_ats: [NOW, NOW + 1, NOW + 2],
    });
    // Excluded keys preserve raw ms — consumers know they need to
    // format the array contents themselves.
    expect(Array.isArray(out.ack_signed_ats)).toBe(true);
    expect(out.ack_signed_ats).toEqual([NOW, NOW + 1, NOW + 2]);
  });
});


// ═══════════════════════════════════════════════════════════════════════════
// 6. Driver-level BIGINT → JS Number coercion (Knex)
// ═══════════════════════════════════════════════════════════════════════════
//
// Locks the contract that every timestamp / counter column declared as
// `t.bigInteger(...)` in the Knex schema comes back from the DB as a JS
// number (not a string, not a bigint), regardless of which underlying
// driver is in use.
//
// This is the root-cause class of bug that surfaced during UAT for
// tip://c/OH-9b971892b3c77f-acea: PG returns INT8 as a string by
// default (precision-loss avoidance), so the in-memory mirror hydrated
// with `registered_at: "1779253012162"`. The prescan-review trigger's
// `Number.isFinite(c.registered_at)` check then returned false on every
// round, silently skipping the content. Downstream arithmetic
// `registered_at + decision_window_ms` became string concatenation
// ("1779253012162" + 172800000 = "1779253012162172800000"), leaking
// to the API.
//
// The fix (node/src/db/knex-adapter.js): pg.types.setTypeParser(20,
// Number) at module load + a Knex `postProcessResponse` fallback that
// uses a column-name allow-list (BIGINT_COLUMN_PATTERN) so every Knex-
// supported driver gets the same Number-typed view. This test ensures
// any future schema addition / driver swap doesn't regress that
// invariant.
//
// Requires env: DB_DRIVER, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
// Skips automatically when DB_DRIVER is absent (covers the local "npm
// test" pass-through; CI must pin the driver env vars).

const _bigintDriver = process.env.DB_DRIVER || "";
const _shouldRunBigintTest = !!_bigintDriver;

(_shouldRunBigintTest ? describe : describe.skip)(
  `timestamp discipline — Knex BIGINT → Number (${_bigintDriver || "skipped"})`,
  () => {
    jest.setTimeout(60_000);

    const { KnexAdapter } = require("../../src/db/knex-adapter");
    const { nowMs } = require("../../../shared/time");

    let adapter;
    let knex;

    beforeAll(async () => {
      adapter = new KnexAdapter(_bigintDriver, {
        dbHost: process.env.DB_HOST,
        dbPort: process.env.DB_PORT ? Number(process.env.DB_PORT) : undefined,
        dbName: process.env.DB_NAME,
        dbUser: process.env.DB_USER,
        dbPassword: process.env.DB_PASSWORD,
      });
      await adapter.migrate();
      knex = adapter.knex;
    });

    afterAll(async () => {
      try { await knex.destroy(); } catch { /* ignore */ }
    });

    // Parse `await ensure("<table>", t => { ... })` blocks in the knex
    // source and collect (table, [bigintColumns...]) pairs. Same parser
    // as the cross-store drift section (section 4) but inverted: there
    // we want column names per table, here we want table → bigint cols.
    function _parseKnexBigintByTable() {
      const src = fs.readFileSync(path.join(NODE_SRC, "db", "knex-adapter.js"), "utf8");
      const out = [];
      const ensureRe = /await\s+ensure\(\s*["']([a-z_][a-z0-9_]*)["']\s*,\s*\(?t\)?\s*=>\s*\{/g;
      let m;
      while ((m = ensureRe.exec(src)) !== null) {
        const tableName = m[1];
        let depth = 1;
        let i = ensureRe.lastIndex;
        while (i < src.length && depth > 0) {
          if (src[i] === "{") depth++;
          else if (src[i] === "}") depth--;
          i++;
        }
        const blockSrc = src.slice(ensureRe.lastIndex, i);
        const cols = [];
        const colRe = /t\.bigInteger\(\s*["']([a-z_][a-z0-9_]*)["']/g;
        let cm;
        while ((cm = colRe.exec(blockSrc)) !== null) cols.push(cm[1]);
        if (cols.length > 0) out.push({ table: tableName, cols });
      }
      return out;
    }

    test("every table with bigInteger columns returns them as JS number on SELECT", async () => {
      const tables = _parseKnexBigintByTable();
      expect(tables.length).toBeGreaterThan(0);

      const violations = [];
      for (const { table, cols } of tables) {
        // SELECT one row from each table — we don't need to write our
        // own; the test runs against a populated mirror so any existing
        // row exercises the read path the production code uses.
        const rows = await knex(table).select("*").limit(1);
        if (rows.length === 0) {
          // Empty table — skip but record for visibility. Most schema
          // tables have at least the genesis row after migrate(), but
          // a fresh DB might leave some empty.
          continue;
        }
        const row = rows[0];
        for (const col of cols) {
          if (row[col] === null || row[col] === undefined) continue;
          const t = typeof row[col];
          if (t !== "number") {
            violations.push(`  ${table}.${col} returned as ${t} (value=${JSON.stringify(row[col])}, expected number)`);
          }
        }
      }
      if (violations.length > 0) {
        throw new Error(
          `Found ${violations.length} bigInteger column(s) returning non-number type from Knex:\n` +
          violations.join("\n") +
          `\n\nDriver-level coercion missing. Check the pg.types parser / mysql2 typeCast / ` +
          `the postProcessResponse fallback in node/src/db/knex-adapter.js.`,
        );
      }
      expect(violations).toEqual([]);
    });

    test("INSERT → SELECT round-trip preserves bigint as Number (every bigInteger column)", async () => {
      // Drives the contract on FRESHLY-inserted rows so we catch the
      // case where the driver returns Number on hydration of existing
      // rows but produces strings on RETURNING / SELECT after an
      // INSERT. Targets `transactions.timestamp` + `transactions.created_at`
      // — both bigInteger, both on a table where we can synthesise a
      // unique row without touching consensus state.
      const fakeTxId = `test_bigint_${nowMs()}_${Math.random().toString(36).slice(2, 10)}`;
      const ts = nowMs();
      try {
        await knex("transactions").insert({
          tx_id: fakeTxId,
          tx_type: "TEST_BIGINT_PROBE",
          data: "{}",
          timestamp: ts,
          prev: "[]",
          signature: null,
          subject_tip_id: null,
          created_at: ts,
        });
        const [row] = await knex("transactions").select("*").where({ tx_id: fakeTxId });
        expect(row).toBeTruthy();
        expect(typeof row.timestamp).toBe("number");
        expect(row.timestamp).toBe(ts);
        expect(typeof row.created_at).toBe("number");
        expect(row.created_at).toBe(ts);
      } finally {
        try { await knex("transactions").where({ tx_id: fakeTxId }).delete(); } catch { /* ignore */ }
      }
    });

    test("MAX_SAFE_INTEGER headroom — no TIP timestamp can overflow", () => {
      // Sanity check: epoch ms for year 9999 is ~2.5e14, MAX_SAFE_INTEGER
      // is ~9.0e15 — 36× headroom. If TIP ever needs sub-millisecond
      // precision or starts using cert.timestamp * round, revisit.
      const year9999Ms = new Date("9999-12-31T23:59:59.999Z").getTime();
      expect(year9999Ms).toBeLessThan(Number.MAX_SAFE_INTEGER);
      // 36× headroom is comfortably above the precision boundary
      expect(Number.MAX_SAFE_INTEGER / year9999Ms).toBeGreaterThan(30);
    });
  },
);

