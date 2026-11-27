/**
 * @file tests/db/migration-018-site-pages.test.js
 * @description Migration 018 creates the node-local site_page and site_ingest
 * tables (off-DAG index of site snapshots), rolls back cleanly, re-applies, and
 * does not crash a boot where schema.sql already created them.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");
const knexLib = require("knex");

const MIGRATIONS_DIR = path.resolve(__dirname, "../../src/db/migrations");
const SCHEMA_SQL = path.resolve(__dirname, "../../src/db/schema.sql");
const NAME = "018_site_pages.js";

let tmpDir;
beforeAll(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-mig-018-")); });
afterAll(() => { if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true }); });

function open(file) {
  return knexLib({
    client: "better-sqlite3",
    connection: { filename: path.join(tmpDir, file) },
    useNullAsDefault: true,
    migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
  });
}

async function indexes(knex, table) {
  return (await knex.raw(`PRAGMA index_list('${table}')`)).map(r => r.name).filter(n => n.startsWith("idx_")).sort();
}

test("up creates site_page and site_ingest with their indexes; down drops both; up again restores them", async () => {
  const k = open("fresh.db");
  try {
    await k.migrate.latest();
    expect(await indexes(k, "site_page")).toEqual(["idx_site_page_index_key", "idx_site_page_snapshot"]);   // the first from 022
    expect(await indexes(k, "site_ingest")).toEqual(["idx_site_ingest_state"]);
    await k.migrate.down({ name: NAME });
    expect(await k.schema.hasTable("site_page")).toBe(false);
    expect(await k.schema.hasTable("site_ingest")).toBe(false);
    await k.migrate.up({ name: NAME });
    expect(await indexes(k, "site_page")).toEqual(["idx_site_page_snapshot"]);
  } finally {
    await k.destroy();
  }
});

test("a database where schema.sql already created the tables migrates without error", async () => {
  const k = open("schema-first.db");
  try {
    const sql = fs.readFileSync(SCHEMA_SQL, "utf8");
    for (const stmt of sql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean)) await k.raw(stmt);
    await k.migrate.latest();
    expect(await indexes(k, "site_ingest")).toEqual(["idx_site_ingest_state"]);
  } finally {
    await k.destroy();
  }
});
