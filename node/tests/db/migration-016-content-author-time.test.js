/**
 * @file tests/db/migration-016-content-author-time.test.js
 * @description Migration 016 adds idx_content_author_time on content
 * (author_tip_id, registered_at, tip_ctid), rolls back cleanly, re-applies,
 * and does not crash a boot where schema.sql already created the index (the
 * SQLite path runs schema.sql on every start, before any knex migration).
 * Content rows are untouched, so state_merkle_root is unchanged.
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
const IDX = "idx_content_author_time";

let tmpDir;
beforeAll(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-mig-016-")); });
afterAll(() => { if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true }); });

function open(file) {
  return knexLib({
    client: "better-sqlite3",
    connection: { filename: path.join(tmpDir, file) },
    useNullAsDefault: true,
    migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
  });
}
async function indexColumns(knex) {
  const rows = await knex.raw(`PRAGMA index_info('${IDX}')`);
  return rows.sort((a, b) => a.seqno - b.seqno).map((r) => r.name);
}
async function plan(knex) {
  const rows = await knex.raw("EXPLAIN QUERY PLAN SELECT * FROM content WHERE author_tip_id = ? AND registered_at >= ? ORDER BY registered_at DESC, tip_ctid DESC LIMIT 21", ["tip://id/US-aaaaaaaaaaaaaaaa", 0]);
  return rows.map((r) => r.detail).join(" | ");
}

test("up adds the index the My Content query uses; down removes it; up again restores it", async () => {
  const k = open("fresh.db");
  try {
    await k.migrate.latest();
    expect(await indexColumns(k)).toEqual(["author_tip_id", "registered_at", "tip_ctid"]);
    // An author's newest-first page with a date floor is an index range scan, no sort.
    const p = await plan(k);
    expect(p).toContain(IDX);
    expect(p).not.toMatch(/TEMP B-TREE/);

    await k("content").insert({
      tip_ctid: "tip://c/OH-00000000000001-aaaa", origin_code: "OH", content_hash: "c".repeat(64),
      author_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa", signer_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa",
      cna_version: "CNA-2.2", registered_at: 1783036800000,
    });
    const [, pendingBefore] = await k.migrate.list();
    expect(pendingBefore).toHaveLength(0);

    await k.migrate.down();                       // 016 is the newest migration
    expect(await indexColumns(k)).toEqual([]);
    await k.migrate.up();
    expect(await indexColumns(k)).toEqual(["author_tip_id", "registered_at", "tip_ctid"]);
    // The row is untouched by either direction.
    const [{ n }] = await k("content").count({ n: "*" });
    expect(Number(n)).toBe(1);
  } finally {
    await k.destroy();
  }
});

test("a database where schema.sql already made the index still migrates (idempotent)", async () => {
  const k = open("preexisting.db");
  try {
    // The SQLite boot path: schema.sql first, with no knex_migrations rows.
    const sql = fs.readFileSync(SCHEMA_SQL, "utf8");
    expect(sql).toContain(`CREATE INDEX IF NOT EXISTS \`${IDX}\``);
    for (const stmt of sql.split(/;\s*\n/).map((s) => s.trim()).filter(Boolean)) await k.raw(stmt);
    expect(await indexColumns(k)).toEqual(["author_tip_id", "registered_at", "tip_ctid"]);
    await expect(k.migrate.latest()).resolves.toBeDefined();
    expect(await indexColumns(k)).toEqual(["author_tip_id", "registered_at", "tip_ctid"]);
  } finally {
    await k.destroy();
  }
});
