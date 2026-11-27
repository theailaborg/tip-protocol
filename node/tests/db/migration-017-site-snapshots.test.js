/**
 * @file tests/db/migration-017-site-snapshots.test.js
 * @description Migration 017 creates site_snapshots (canonical state) with the
 * unique (domain, seq) index, rolls back cleanly, re-applies, and does not
 * crash a boot where schema.sql already created the table (the SQLite path
 * runs schema.sql on every start, before any knex migration).
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
const NAME = "017_site_snapshots.js";
const IDX = "idx_site_snapshots_domain_seq";

let tmpDir;
beforeAll(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-mig-017-")); });
afterAll(() => { if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true }); });

function open(file) {
  return knexLib({
    client: "better-sqlite3",
    connection: { filename: path.join(tmpDir, file) },
    useNullAsDefault: true,
    migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
  });
}

const row = (seq, txChar) => ({
  tx_id: txChar.repeat(64), domain: "theailab.org", seq, prev_snapshot_tx: seq === 1 ? null : "1".repeat(64),
  root: "a".repeat(64), page_count: 30, template_hash: "b".repeat(64), profile: "cf-web-1",
  wacz_hash: "c".repeat(64), pack_hash: "d".repeat(64), ai_signals_hash: "e".repeat(64),
  captured_at: 1794672650000, signer_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa", witness_vp_id: null,
  registered_at: 1794672700000,
});

async function indexInfo(knex) {
  const list = await knex.raw("PRAGMA index_list('site_snapshots')");
  const idx = list.find(r => r.name === IDX);
  if (!idx) return null;
  const cols = await knex.raw(`PRAGMA index_info('${IDX}')`);
  return { unique: idx.unique === 1, columns: cols.sort((a, b) => a.seqno - b.seqno).map(r => r.name) };
}

test("up creates site_snapshots with a unique (domain, seq); down drops it; up again restores it", async () => {
  const k = open("fresh.db");
  try {
    await k.migrate.latest();
    expect(await indexInfo(k)).toEqual({ unique: true, columns: ["domain", "seq"] });

    await k("site_snapshots").insert(row(1, "1"));
    let dup = null;
    try { await k("site_snapshots").insert(row(1, "2")); } catch (e) { dup = e; }
    expect(String(dup && dup.message)).toMatch(/UNIQUE constraint failed: site_snapshots\.domain, site_snapshots\.seq/);
    await k("site_snapshots").insert(row(2, "2"));
    const [{ n }] = await k("site_snapshots").count({ n: "*" });
    expect(Number(n)).toBe(2);

    await k.migrate.down({ name: NAME });
    expect(await k.schema.hasTable("site_snapshots")).toBe(false);
    await k.migrate.up({ name: NAME });
    expect(await indexInfo(k)).toEqual({ unique: true, columns: ["domain", "seq"] });
  } finally {
    await k.destroy();
  }
});

test("a database where schema.sql already created the table migrates without error", async () => {
  const k = open("schema-first.db");
  try {
    const sql = fs.readFileSync(SCHEMA_SQL, "utf8");
    for (const stmt of sql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean)) await k.raw(stmt);
    expect(await indexInfo(k)).toEqual({ unique: true, columns: ["domain", "seq"] });
    await k.migrate.latest();
    expect(await indexInfo(k)).toEqual({ unique: true, columns: ["domain", "seq"] });
  } finally {
    await k.destroy();
  }
});
