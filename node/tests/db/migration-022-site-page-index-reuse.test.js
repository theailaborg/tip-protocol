/**
 * @file tests/db/migration-022-site-page-index-reuse.test.js
 * @description Migration 022 adds site_page.index_key / index_hash with an index
 * on index_key, keeps existing pages (null, compared as changed once), rolls back,
 * re-applies, and tolerates a boot where schema.sql already made the columns.
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
const IDX = "idx_site_page_index_key";
const hex = (c) => c.repeat(64);

let tmpDir;
beforeAll(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-mig-022-")); });
afterAll(() => { if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true }); });

function open(file) {
  return knexLib({
    client: "better-sqlite3",
    connection: { filename: path.join(tmpDir, file) },
    useNullAsDefault: true,
    migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
  });
}

const hasIndex = async (k) => (await k.raw("PRAGMA index_list('site_page')")).some((r) => r.name === IDX);

const page = {
  page_key: `site:${hex("1")}:0123456789abcdef`, snapshot_tx: hex("1"), domain: "theailab.org", seq: 1,
  url: "https://theailab.org/", text_hash: hex("a"), page_hash: hex("b"), offsite: 0, changed: null, kept: null,
  paragraph_keys: "", proof: null, created_at: 1794672700000,
};

test("from 021: 022 keeps existing pages with null index columns; down and up again", async () => {
  const k = open("upgrade.db");
  try {
    await k.migrate.latest();
    await k.migrate.down();
    expect(await k.schema.hasColumn("site_page", "index_key")).toBe(false);
    await k("site_page").insert(page);

    await k.migrate.up();
    expect(await hasIndex(k)).toBe(true);
    const row = await k("site_page").first();
    expect([row.page_key, row.index_key, row.index_hash]).toEqual([page.page_key, null, null]);

    await k.migrate.down();
    expect(await k.schema.hasColumn("site_page", "index_hash")).toBe(false);
    expect(await hasIndex(k)).toBe(false);
    await k.migrate.latest();
    expect(await k.schema.hasColumn("site_page", "index_key")).toBe(true);
  } finally {
    await k.destroy();
  }
});

test("a boot where schema.sql already made the columns runs the migration without error", async () => {
  const k = open("schema-first.db");
  try {
    const sql = fs.readFileSync(SCHEMA_SQL, "utf8");
    for (const stmt of sql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean)) await k.raw(stmt);
    await k.migrate.latest();
    expect(await k.schema.hasColumn("site_page", "index_key")).toBe(true);
    expect(await hasIndex(k)).toBe(true);
  } finally {
    await k.destroy();
  }
});
