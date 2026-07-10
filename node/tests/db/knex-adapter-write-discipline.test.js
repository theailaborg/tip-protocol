/**
 * @file tests/db/knex-adapter-write-discipline.test.js
 * @description Persistence-safety contracts from the 2026-07-10 incident.
 *
 * 1. Source discipline: every fire-and-forget WRITE must route through
 *    this._k() (transaction-aware), never this.knex() (raw pool). A raw-pool
 *    write inside a commit batch waits on the batch's own row lock while the
 *    batch waits on the flush , a client-side deadlock Postgres cannot see.
 * 2. persistenceStats: queue depth / oldest-pending age expose the memory-
 *    to-disk distance that every mirror-reading metric is blind to.
 * 3. Parity probe: with the write chain drained, DB row counts must equal
 *    the mirror exactly; divergence fail-stops.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const { KnexAdapter } = require("../../src/db/knex-adapter");

const logStub = { info() { }, warn() { }, error() { } };

describe("write discipline , no raw-pool writes in the persistence chain", () => {
  test("no _ff or chained thunk uses this.knex() directly", () => {
    const src = fs.readFileSync(path.join(__dirname, "../../src/db/knex-adapter.js"), "utf8");
    const violations = [];
    src.split("\n").forEach((line, i) => {
      if (/_ff\(\(\) => this\.knex\(/.test(line) || /\.then\(\(\) => this\.knex\("/.test(line)) {
        violations.push(`${i + 1}: ${line.trim()}`);
      }
    });
    expect(violations).toEqual([]);
  });
});

describe("persistenceStats + parity probe", () => {
  let a;
  let tmpDir;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-parity-"));
    a = new KnexAdapter("better-sqlite3", { dbName: path.join(tmpDir, "parity.db") }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { a.close(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("stats track a hanging write and recover when it settles", async () => {
    expect(a.persistenceStats().queue_depth).toBe(0);
    let release;
    a._ff(() => new Promise(r => { release = r; }));
    a._ff(() => Promise.resolve());
    expect(a.persistenceStats().queue_depth).toBe(2);
    await new Promise(r => setTimeout(r, 30));
    expect(a.persistenceStats().oldest_pending_ms).toBeGreaterThanOrEqual(20);
    release();
    await a._ffChain;
    expect(a.persistenceStats().queue_depth).toBe(0);
    expect(a.persistenceStats().oldest_pending_ms).toBe(0);
  });

  test("parity probe passes when mirror and DB agree", async () => {
    a.saveContent({
      ctid: "parity-ct", origin_code: "OH", content_hash: "h",
      author_tip_id: "x", signer_tip_id: "x", cna_version: "CNA-2.2",
      status: "registered", registered_at: 1,
    });
    await a._ffChain;
    const exit = jest.spyOn(process, "exit").mockImplementation(() => { throw new Error("exit called"); });
    try {
      a._enqueueParityProbe();
      await a._ffChain;
      expect(exit).not.toHaveBeenCalled();
    } finally {
      exit.mockRestore();
    }
  });

  test("parity probe fail-stops when a DB row silently disappears", async () => {
    await a.knex("content").where("tip_ctid", "parity-ct").del();   // simulate a lost write
    const exit = jest.spyOn(process, "exit").mockImplementation(() => { throw new Error("exit-78"); });
    try {
      a._enqueueParityProbe();
      await a._ffChain.catch(() => { });
      expect(exit).toHaveBeenCalledWith(78);
    } finally {
      exit.mockRestore();
      // restore parity for any later assertions
      a.mirror._content.delete("parity-ct");
    }
  });
});
