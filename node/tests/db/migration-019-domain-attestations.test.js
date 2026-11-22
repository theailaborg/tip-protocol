/**
 * @file tests/db/migration-019-domain-attestations.test.js
 * @description Migration 019 creates domain_attestations (canonical state) keyed
 * (domain, node_id) with the claim index, rolls back cleanly, re-applies, and does
 * not crash a boot where schema.sql already created the table.
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
const NAME = "019_domain_attestations.js";
const IDX = "idx_domain_attestations_claim";

let tmpDir;
beforeAll(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-mig-019-")); });
afterAll(() => { if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true }); });

function open(file) {
  return knexLib({
    client: "better-sqlite3",
    connection: { filename: path.join(tmpDir, file) },
    useNullAsDefault: true,
    migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
  });
}

const row = (node, txChar) => ({
  domain: "a.example", node_id: node, tip_id: "tip://id/US-aaaaaaaaaaaaaaaa", claimed_at: 1794672650000,
  claimed_method: "dns", verified_at: 1794672700000, tx_id: txChar.repeat(64),
});

async function shape(knex) {
  const cols = await knex.raw("PRAGMA table_info('domain_attestations')");
  const pk = cols.filter(c => c.pk > 0).sort((a, b) => a.pk - b.pk).map(c => c.name);
  const list = await knex.raw("PRAGMA index_list('domain_attestations')");
  const idx = list.find(r => r.name === IDX);
  const idxCols = idx ? (await knex.raw(`PRAGMA index_info('${IDX}')`)).sort((a, b) => a.seqno - b.seqno).map(r => r.name) : null;
  return { pk, idxCols };
}

test("up creates domain_attestations keyed (domain, node_id); down drops it; up again restores it", async () => {
  const k = open("fresh.db");
  try {
    await k.migrate.latest();
    expect(await shape(k)).toEqual({ pk: ["domain", "node_id"], idxCols: ["domain", "tip_id", "claimed_at"] });
    await k("domain_attestations").insert(row("tip://node/n1", "1"));
    await k("domain_attestations").insert(row("tip://node/n2", "2"));
    let dup = null;
    try { await k("domain_attestations").insert(row("tip://node/n1", "3")); } catch (e) { dup = e; }
    expect(String(dup && dup.message)).toMatch(/UNIQUE constraint failed: domain_attestations\.domain, domain_attestations\.node_id/);

    await k.migrate.down({ name: NAME });
    expect(await k.schema.hasTable("domain_attestations")).toBe(false);
    await k.migrate.up({ name: NAME });
    expect(await shape(k)).toEqual({ pk: ["domain", "node_id"], idxCols: ["domain", "tip_id", "claimed_at"] });
  } finally {
    await k.destroy();
  }
});

test("a database where schema.sql already created the table migrates without error", async () => {
  const k = open("schema-first.db");
  try {
    const sql = fs.readFileSync(SCHEMA_SQL, "utf8");
    for (const stmt of sql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean)) await k.raw(stmt);
    expect(await shape(k)).toEqual({ pk: ["domain", "node_id"], idxCols: ["domain", "tip_id", "claimed_at"] });
    await k.migrate.latest();
    expect(await shape(k)).toEqual({ pk: ["domain", "node_id"], idxCols: ["domain", "tip_id", "claimed_at"] });
  } finally {
    await k.destroy();
  }
});
