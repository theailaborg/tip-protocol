/**
 * @file tests/dag/content-by-hash-index.test.js
 * @description getContentByHash on MemoryStore (also the Postgres mirror)
 * reads a content_hash index kept in step with every write to the content
 * map, so it never walks every record. Same answers, in the same order, as
 * SQLite's indexed query.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");
const SRC = path.resolve(__dirname, "../../src");
const { nowMs } = require(path.resolve(__dirname, "../../../shared/time"));
const { initDAG, MemoryStore } = require(path.join(SRC, "dag"));

const H1 = "11".repeat(32);
const H2 = "22".repeat(32);
const AUTHOR = "tip://id/US-aaaaaaaaaaaaaaaa";

let n = 0;
function record(hash, extra = {}) {
  n += 1;
  return {
    ctid: `tip://c/OH-${String(n).padStart(14, "0")}-0001`, origin_code: "OH", content_hash: hash,
    author_tip_id: AUTHOR, signer_tip_id: AUTHOR, authors: [], attribution_mode: "self", extras: {},
    cna_version: "CNA-2.2", status: "registered", override: false, registered_at: 1790000000000 + n,
    registered_urls: [], tx_id: `tx_${n}`, ...extra,
  };
}
const ctidsOf = (rows) => rows.map((r) => r.ctid);

const STORES = [
  ["MemoryStore", () => ({ dag: initDAG({ dbPath: ":memory:" }), cleanup: () => {} })],
  ["SQLiteStore", () => {
    const dbPath = path.join(os.tmpdir(), `tip-hash-index-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
    return { dag: initDAG({ dbPath }), cleanup: () => { try { fs.unlinkSync(dbPath); } catch { /* gone */ } } };
  }],
];

describe.each(STORES)("getContentByHash on %s", (_label, make) => {
  test("every record with the hash, oldest write first, and nothing else", () => {
    const { dag, cleanup } = make();
    try {
      const a = record(H1);
      const b = record(H2);
      const c = record(H1);
      for (const r of [a, b, c]) dag.saveContent(r);
      expect(ctidsOf(dag.getContentByHash(H1))).toEqual([a.ctid, c.ctid]);
      expect(ctidsOf(dag.getContentByHash(H2))).toEqual([b.ctid]);
      expect(dag.getContentByHash("33".repeat(32))).toEqual([]);
      expect(dag.getContentByHash("")).toEqual([]);
    } finally { cleanup(); }
  });

  test("status, origin, link and counter updates return the current row, once", () => {
    const { dag, cleanup } = make();
    try {
      const a = record(H1);
      const b = record(H1);
      dag.saveContent(a);
      dag.saveContent(b);
      dag.updateContentStatus(a.ctid, "retracted");
      dag.updateContentOrigin(b.ctid, "AA", "registered");
      dag.updateContentUrls(a.ctid, ["https://example.com/p"]);
      dag.incrementContentCounter(b.ctid, "verification_count");
      const rows = dag.getContentByHash(H1);
      expect(ctidsOf(rows)).toEqual([a.ctid, b.ctid]);
      expect(rows[0].status).toBe("retracted");
      expect(rows[0].registered_urls).toEqual(["https://example.com/p"]);
      expect(rows[1].origin_code).toBe("AA");
    } finally { cleanup(); }
  });
});

describe("MemoryStore index follows deletes and clears", () => {
  test("deleteCanonicalRow drops only that record; clearCanonicalState empties the index", () => {
    const store = new MemoryStore();
    const a = record(H1);
    const b = record(H1);
    store.saveContent(a);
    store.saveContent(b);
    expect(store.deleteCanonicalRow("content", a)).toBe(true);
    expect(ctidsOf(store.getContentByHash(H1))).toEqual([b.ctid]);
    store.clearCanonicalState();
    expect(store.getContentByHash(H1)).toEqual([]);
    store.saveContent(a);
    expect(ctidsOf(store.getContentByHash(H1))).toEqual([a.ctid]);
  });

  test("a hash shared by several records grows and shrinks in write order", () => {
    const store = new MemoryStore();
    const [a, b, c] = [record(H1), record(H1), record(H1)];
    for (const r of [a, b, c]) store.saveContent(r);
    expect(ctidsOf(store.getContentByHash(H1))).toEqual([a.ctid, b.ctid, c.ctid]);
    store.deleteCanonicalRow("content", a);
    store.deleteCanonicalRow("content", b);
    expect(ctidsOf(store.getContentByHash(H1))).toEqual([c.ctid]);
    store.saveContent(a);
    store.updateContentStatus(c.ctid, "retracted");
    expect(ctidsOf(store.getContentByHash(H1))).toEqual([c.ctid, a.ctid]);
    store.deleteCanonicalRow("content", c);
    store.deleteCanonicalRow("content", a);
    expect(store.getContentByHash(H1)).toEqual([]);
  });

  test("a lookup never walks the content map", () => {
    const store = new MemoryStore();
    for (let i = 0; i < 50; i++) store.saveContent(record(i % 2 ? H1 : H2));
    const walk = jest.spyOn(store._content, "values");
    expect(store.getContentByHash(H1)).toHaveLength(25);
    expect(walk).not.toHaveBeenCalled();
  });
});
