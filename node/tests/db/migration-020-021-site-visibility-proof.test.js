/**
 * @file tests/db/migration-020-021-site-visibility-proof.test.js
 * @description Migration 020 adds the nullable site_snapshots.visibility
 * column (existing public rows stay null) and 021 adds site_page.proof,
 * clearing pages indexed without one so the ingest job rebuilds them. Both
 * roll back, re-apply, and tolerate a boot where schema.sql made the columns.
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
const hex = (c) => c.repeat(64);

let tmpDir;
beforeAll(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-mig-020-")); });
afterAll(() => { if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true }); });

function open(file) {
  return knexLib({
    client: "better-sqlite3",
    connection: { filename: path.join(tmpDir, file) },
    useNullAsDefault: true,
    migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
  });
}

const snapshot = {
  tx_id: hex("1"), domain: "theailab.org", seq: 1, prev_snapshot_tx: null, root: hex("a"), page_count: 30,
  template_hash: hex("b"), profile: "cf-web-1", wacz_hash: hex("c"), pack_hash: hex("d"), ai_signals_hash: hex("e"),
  captured_at: 1794672650000, signer_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa", witness_vp_id: null, registered_at: 1794672700000,
};
const page = {
  page_key: `site:${hex("1")}:0123456789abcdef`, snapshot_tx: hex("1"), domain: "theailab.org", seq: 1,
  url: "https://theailab.org/", text_hash: hex("a"), page_hash: hex("b"), offsite: 0, changed: null, kept: null,
  paragraph_keys: "", created_at: 1794672700000,
};
const ingest = { snapshot_tx: hex("1"), domain: "theailab.org", seq: 1, state: "done", attempts: 1, next_attempt_at: 0, pages: 1, updated_at: 1794672700000 };

test("from 019: 020 keeps old snapshots public, 021 adds proofs and clears pages to re-index; down and up again", async () => {
  const k = open("upgrade.db");
  try {
    await k.migrate.latest();
    await k.migrate.down();   // 021
    await k.migrate.down();   // 020
    expect(await k.schema.hasColumn("site_snapshots", "visibility")).toBe(false);
    expect(await k.schema.hasColumn("site_page", "proof")).toBe(false);
    await k("site_snapshots").insert(snapshot);
    await k("site_page").insert(page);
    await k("site_ingest").insert(ingest);

    await k.migrate.up();     // 020
    expect((await k("site_snapshots").first()).visibility).toBeNull();
    await k("site_snapshots").insert({ ...snapshot, tx_id: hex("2"), domain: "private.example", visibility: "private" });
    expect((await k("site_snapshots").where({ tx_id: hex("2") }).first()).visibility).toBe("private");
    expect(await k("site_page").count({ n: "*" })).toEqual([{ n: 1 }]);

    await k.migrate.up();     // 021
    expect(await k.schema.hasColumn("site_page", "proof")).toBe(true);
    expect(await k("site_page").count({ n: "*" })).toEqual([{ n: 0 }]);
    expect(await k("site_ingest").count({ n: "*" })).toEqual([{ n: 0 }]);
    expect(await k("site_snapshots").count({ n: "*" })).toEqual([{ n: 2 }]);

    await k.migrate.down();
    await k.migrate.down();
    expect(await k.schema.hasColumn("site_snapshots", "visibility")).toBe(false);
    expect(await k.schema.hasColumn("site_page", "proof")).toBe(false);
    await k.migrate.latest();
    expect(await k.schema.hasColumn("site_snapshots", "visibility")).toBe(true);
    expect(await k.schema.hasColumn("site_page", "proof")).toBe(true);
  } finally {
    await k.destroy();
  }
});

test("a boot where schema.sql already made both columns runs the migrations without error", async () => {
  const k = open("schema-first.db");
  try {
    const sql = fs.readFileSync(SCHEMA_SQL, "utf8");
    for (const stmt of sql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean)) await k.raw(stmt);
    await k.migrate.latest();
    expect(await k.schema.hasColumn("site_snapshots", "visibility")).toBe(true);
    expect(await k.schema.hasColumn("site_page", "proof")).toBe(true);
  } finally {
    await k.destroy();
  }
});
