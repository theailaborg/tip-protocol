/**
 * @file tests/db/knex-adapter-bulk-dedup.test.js
 * @description Snapshot bulk install: repeated writes to one key inside a
 * merge buffer (stream row + install-progress markers, e.g. consensus_meta's
 * last_committed_round) must collapse to the LAST write before the chunked
 * INSERT. Postgres rejects a single INSERT..ON CONFLICT DO UPDATE that
 * touches the same key twice ("cannot affect row a second time") , live
 * incident 2026-07-10: node3 fail-stopped in a crash loop on every snapshot
 * resync attempt, wedging the whole cluster below quorum.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const { KnexAdapter } = require("../../src/db/knex-adapter");

const logStub = { info() { }, warn() { }, debug() { }, error() { } };

describe("bulk install merge buffers dedup by pk (last write wins)", () => {
  let a;
  let tmpDir;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-bulk-"));
    a = new KnexAdapter("better-sqlite3", { dbName: path.join(tmpDir, "bulk.db") }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { await a.knex.destroy(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("repeated consensus_meta writes flush as one row per key with the last value", async () => {
    a.beginBulkInstall();
    a.setConsensusMeta("last_committed_round", 100);
    a.setConsensusMeta("last_committed_round", 101);
    a.setConsensusMeta("last_committed_round", 102);
    a.setConsensusMeta("snapshot_source", "peer-a");

    // Capture every INSERT statement's row set as it goes to the DB.
    const inserted = [];
    const origK = a._k.bind(a);
    a._k = (table) => {
      const qb = origK(table);
      const origInsert = qb.insert.bind(qb);
      qb.insert = (rows) => { inserted.push({ table, rows }); return origInsert(rows); };
      return qb;
    };
    await a._flushBulkBuffers();
    a._k = origK;
    a.endBulkInstall();

    const metaChunks = inserted.filter(c => c.table === "consensus_meta");
    expect(metaChunks.length).toBeGreaterThan(0);
    for (const { rows } of metaChunks) {
      const keys = rows.map(r => r.key);
      expect(new Set(keys).size).toBe(keys.length);   // no key twice in one statement
    }

    const flushed = metaChunks.flatMap(c => c.rows);
    expect(flushed.find(r => r.key === "last_committed_round").value).toBe("102");
    expect(flushed.find(r => r.key === "snapshot_source").value).toBe("peer-a");

    const dbRow = await a.knex("consensus_meta").where({ key: "last_committed_round" }).first();
    expect(dbRow.value).toBe("102");
  });

  test("ignore buffers keep duplicates path unchanged (insert-only tables)", async () => {
    a.beginBulkInstall();
    const tx = { tx_id: "bulk-dedup-tx-1", tx_type: "TEST_EVENT", data: { n: 1 }, timestamp: 5, prev: [] };
    a.saveTx(tx);
    a.saveTx(tx);
    await a._flushBulkBuffers();
    a.endBulkInstall();

    const rows = await a.knex("transactions").where({ tx_id: "bulk-dedup-tx-1" });
    expect(rows.length).toBe(1);
  });
});
