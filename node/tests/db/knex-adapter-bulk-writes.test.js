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

  const tx = (id) => ({ tx_id: id, tx_type: "CONTENT_REGISTER", data: { id }, timestamp: 1778025600000, prev: [], signature: "00" });
  const dbTxIds = async (prefix) => (await a.knex("transactions").select("tx_id").where("tx_id", "like", `${prefix}%`)).map(r => r.tx_id).sort();

  test("rows buffered while a flush is writing are kept for the next flush, not cleared with its batch", async () => {
    a.beginBulkInstall();
    for (let i = 0; i < 400; i++) a.saveTx(tx(`during-${String(i).padStart(3, "0")}`));
    const orig = a._k.bind(a);
    let injected = false;
    a._k = (table) => {
      // Another writer lands while the bulk insert of the 400 rows is in flight.
      if (table === "transactions" && !injected) { injected = true; a.saveTx(tx("during-400")); a.saveTx(tx("during-401")); }
      return orig(table);
    };
    try {
      await a.flush();
    } finally {
      a._k = orig;
    }
    await a.flush();
    a.endBulkInstall();
    expect(injected).toBe(true);
    expect(await dbTxIds("during-")).toHaveLength(402);
  });

  test("concurrent flushes write every row once and in order, and a merged row keeps its last value", async () => {
    a.beginBulkInstall();
    for (let i = 0; i < 1200; i++) a.saveTx(tx(`conc-${String(i).padStart(4, "0")}`));
    a.setConsensusMeta("bulk-order", "v1");
    const p1 = a.flush();
    const p2 = a.flush();                      // a background job flushing at the same time
    a.setConsensusMeta("bulk-order", "v2");
    for (let i = 1200; i < 1500; i++) a.saveTx(tx(`conc-${String(i).padStart(4, "0")}`));
    await p1;
    const p3 = a.flush();                      // the install's next batch
    await Promise.all([p2, p3]);
    a.endBulkInstall();
    expect(await dbTxIds("conc-")).toHaveLength(1500);
    const meta = await a.knex("consensus_meta").where("key", "bulk-order").first();
    expect(meta.value).toBe("v2");
  });

  test("an insert then a delete of the same row in one bulk window land in that order", async () => {
    a.beginBulkInstall();
    a.saveMempoolTx({ tx_id: "mp-order", tx_type: "REGISTER_CONTENT", data: {}, timestamp: 1767225600000 });
    a.deleteMempoolTxs(["mp-order"]);
    await a.flush();
    a.endBulkInstall();
    await a.flush();
    expect(await a.knex("mempool").where("tx_id", "mp-order").first()).toBeUndefined();
    expect(a.getMempoolTxs().map(t => t.tx_id)).not.toContain("mp-order");
  });

  test("a delete issued in bulk mode while a transaction is mid-flush runs on the pool, not that transaction", async () => {
    a.saveMempoolTx({ tx_id: "mp-trx", tx_type: "REGISTER_CONTENT", data: {}, timestamp: 1767225600000 });
    await a.flush();
    let finished = null;
    await a.knex.transaction(async (trx) => { finished = trx; });
    const exit = jest.spyOn(process, "exit").mockImplementation(() => { });
    try {
      a._activeTrx = finished;                 // a runInTransaction flush still holding the slot
      a.beginBulkInstall();
      a.deleteMempoolTxs(["mp-trx"]);
      a._activeTrx = null;
      await a.flush();
      a.endBulkInstall();
      await a.flush();
      expect(exit).not.toHaveBeenCalled();
      expect(await a.knex("mempool").where("tx_id", "mp-trx").first()).toBeUndefined();
    } finally {
      a._activeTrx = null;
      exit.mockRestore();
    }
  });

  test("rows still buffered when bulk mode ends reach the database instead of being dropped", async () => {
    a.beginBulkInstall();
    a.saveTx(tx("left-1"));
    a.saveTx(tx("left-2"));
    a.endBulkInstall();
    await a.flush();
    expect(await dbTxIds("left-")).toEqual(["left-1", "left-2"]);
    expect(a.getTx("left-2")).toBeTruthy();
  });
});
