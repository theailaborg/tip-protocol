/**
 * @file tests/db/knex-adapter-bulk-writes.test.js
 * @description In bulk-install mode every queued write still reaches the database: a delete returns a
 * lazy Knex builder, which used to be discarded unrun, leaving the mirror and Postgres apart.
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

describe("knex adapter: writes queued during a bulk install", () => {
  let a;
  let tmpDir;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-bulk-writes-"));
    a = new KnexAdapter("better-sqlite3", { dbName: path.join(tmpDir, "bulk-writes.db") }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { await a.knex.destroy(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("a delete issued in bulk mode is executed by flush, like the mirror's", async () => {
    a.saveMempoolTx({ tx_id: "mp-1", tx_type: "REGISTER_CONTENT", data: {}, timestamp: 1767225600000 });
    a.saveMempoolTx({ tx_id: "mp-2", tx_type: "REGISTER_CONTENT", data: {}, timestamp: 1767225600000 });
    await a.flush();

    a.beginBulkInstall();
    a.deleteMempoolTxs(["mp-1"]);
    await a.flush();
    a.endBulkInstall();

    const rows = (await a.knex("mempool").select("tx_id").orderBy("tx_id")).map(r => r.tx_id);
    expect(rows).toEqual(["mp-2"]);
    expect(a.getMempoolTxs().map(t => t.tx_id)).toEqual(["mp-2"]);
  });
});
