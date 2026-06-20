/**
 * @file tests/db/knex-adapter-pg-reserved.test.js
 * @description Static guard: the KnexAdapter (the Postgres / MySQL / etc. path)
 * must never define a user column with a PostgreSQL RESERVED SYSTEM COLUMN name.
 *
 * Postgres gives every table system columns (`ctid`, `xmin`, `xmax`, `cmin`,
 * `cmax`, `tableoid`) and rejects `CREATE TABLE ... (ctid ...)` outright. The
 * adapter therefore names the content-id column `tip_ctid` and maps
 * tip_ctid <-> ctid at the method boundary.
 *
 * SQLite / better-sqlite3 ALLOW a `ctid` column, so the SQLite-backed unit + most
 * integration tests CANNOT catch this — they pass while Postgres init crashes
 * and silently falls back (the whole perceptual index was disabled this way:
 * `perceptual_fingerprint(ctid ...)` failed knex schema-init on Postgres).
 * This static scan is the cheap guard that runs without a live Postgres.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const path = require("path");

// Strip comments so prose that mentions "ctid" (explaining this very rule)
// doesn't trip the scan; we only care about actual code (column defs, key
// arrays, query column names).
const code = fs.readFileSync(path.resolve(__dirname, "../../src/db/knex-adapter.js"), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "")  // block comments
  .replace(/\/\/.*$/gm, "");         // line comments

const PG_RESERVED = ["ctid", "xmin", "xmax", "cmin", "cmax", "tableoid"];

describe("KnexAdapter — no PostgreSQL reserved column names", () => {
  for (const col of PG_RESERVED) {
    test(`schema/queries never use a quoted "${col}" identifier (use tip_${col})`, () => {
      const m = code.match(new RegExp(`["']${col}["']`));
      expect(m ? `found ${m[0]} in knex-adapter — Postgres reserves it; use a non-reserved name` : null).toBeNull();
    });
  }
});
