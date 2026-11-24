/**
 * @file tests/db/migration-023-index-ctid-lookup.test.js
 * @description Migration 023 adds tip_ctid indexes to minhash_band and
 * document_passage (pruning deletes by ctid), rolls back, re-applies, and
 * tolerates a boot where schema.sql already made them.
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

let tmpDir;
beforeAll(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-mig-023-")); });
afterAll(() => { if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true }); });

function open(file) {
  return knexLib({
    client: "better-sqlite3",
    connection: { filename: path.join(tmpDir, file) },
    useNullAsDefault: true,
    migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
  });
}

const has = async (k, table, name) => (await k.raw(`PRAGMA index_list('${table}')`)).some((r) => r.name === name);

test("up adds both ctid indexes; down drops them; up again restores them", async () => {
  const k = open("fresh.db");
  try {
    await k.migrate.latest();
    expect(await has(k, "minhash_band", "idx_minhash_band_ctid")).toBe(true);
    expect(await has(k, "document_passage", "idx_document_passage_ctid")).toBe(true);
    await k.migrate.down({ name: "023_index_ctid_lookup.js" });
    expect(await has(k, "minhash_band", "idx_minhash_band_ctid")).toBe(false);
    expect(await has(k, "document_passage", "idx_document_passage_ctid")).toBe(false);
    await k.migrate.up({ name: "023_index_ctid_lookup.js" });
    expect(await has(k, "minhash_band", "idx_minhash_band_ctid")).toBe(true);
  } finally {
    await k.destroy();
  }
});

test("a boot where schema.sql already made the indexes runs the migration without error", async () => {
  const k = open("schema-first.db");
  try {
    const sql = fs.readFileSync(SCHEMA_SQL, "utf8");
    for (const stmt of sql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean)) await k.raw(stmt);
    await k.migrate.latest();
    expect(await has(k, "document_passage", "idx_document_passage_ctid")).toBe(true);
  } finally {
    await k.destroy();
  }
});
