/**
 * @file tests/db/knex-adapter-site-snapshots.test.js
 * @description site_snapshots through the KnexAdapter, the path mainnet runs
 * (Postgres behind Knex): writes land in the DB in the mirror's canonical
 * shape, a repeat save changes nothing, the parity probe agrees, and a restart
 * hydrates the rows and the per-domain head so the chain rule and the state
 * root survive a reboot.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const { KnexAdapter } = require("../../src/db/knex-adapter");
const { computeStateMerkleRoot } = require("../../src/consensus/state-root");

const logStub = { info() { }, warn() { }, error() { } };
const T0 = 1794672650000;
const hex = (c) => c.repeat(64);

function snap(domain, seq, prev, txId, over = {}) {
  return {
    tx_id: txId, domain, seq, prev_snapshot_tx: prev, root: hex("a"), page_count: 30,
    template_hash: hex("b"), profile: "cf-web-1", wacz_hash: hex("c"), pack_hash: hex("d"),
    ai_signals_hash: hex("e"), captured_at: T0 + seq, signer_tip_id: "tip://id/US-aaaaaaaaaaaaaaaa",
    witness_vp_id: null, registered_at: T0 + 1000 * seq, ...over,
  };
}

describe("site_snapshots on the KnexAdapter", () => {
  let tmpDir, dbFile, a;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-site-"));
    dbFile = path.join(tmpDir, "site.db");
    a = new KnexAdapter("better-sqlite3", { dbName: dbFile }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { a.close(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("writes land in the DB in canonical shape; a repeat save changes nothing", async () => {
    a.saveSiteSnapshot(snap("theailab.org", 1, null, hex("1")));
    a.saveSiteSnapshot(snap("theailab.org", 2, hex("1"), hex("2"), { witness_vp_id: "tip://vp/US-0e7db4040667073a" }));
    a.saveSiteSnapshot(snap("theailab.org", 2, hex("1"), hex("2"), { root: hex("f") }));
    await a.flush();
    const rows = await a.knex("site_snapshots").orderBy("seq").select("*");
    expect(rows.map(r => [r.tx_id, Number(r.seq), r.prev_snapshot_tx, r.root, r.witness_vp_id, Number(r.registered_at)])).toEqual([
      [hex("1"), 1, null, hex("a"), null, T0 + 1000],
      [hex("2"), 2, hex("1"), hex("a"), "tip://vp/US-0e7db4040667073a", T0 + 2000],
    ]);
    expect(a.getLatestSiteSnapshot("theailab.org").tx_id).toBe(hex("2"));
    expect(a.getSiteSnapshot(hex("2")).root).toBe(hex("a"));
  });

  test("parity probe agrees on site_snapshots row counts", async () => {
    await a._ffChain;
    const exit = jest.spyOn(process, "exit").mockImplementation(() => { throw new Error("exit called"); });
    try {
      expect(a._paritySnapshot().site_snapshots).toBe(2);
      a._enqueueParityProbe();
      await a._ffChain;
      expect(exit).not.toHaveBeenCalled();
    } finally {
      exit.mockRestore();
    }
  });

  test("site pages and ingest state (off-DAG) go straight to the DB and read back from it", async () => {
    a.saveSitePages([{
      page_key: `site:${hex("2")}:0123456789abcdef`, snapshot_tx: hex("2"), domain: "theailab.org", seq: 2,
      url: "https://theailab.org/about", text_hash: hex("a"), page_hash: hex("b"), offsite: false,
      changed: true, kept: 0.75, paragraph_keys: "aa bb cc", created_at: T0,
    }]);
    a.saveSiteIngest({ snapshot_tx: hex("2"), domain: "theailab.org", seq: 2, state: "failed", attempts: 1, next_attempt_at: T0, last_error: "pack_unavailable: x", updated_at: T0 });
    await a.flush();
    const page = await a.getSitePage(`site:${hex("2")}:0123456789abcdef`);
    expect([page.url, Number(page.changed), Number(page.kept), page.paragraph_keys]).toEqual(["https://theailab.org/about", 1, 0.75, "aa bb cc"]);
    expect((await a.listSitePages(hex("2"))).map(r => r.page_key)).toEqual([`site:${hex("2")}:0123456789abcdef`]);
    expect((await a.listSiteIngestsDue(T0)).map(r => r.snapshot_tx)).toEqual([hex("2")]);
    a.saveSiteIngest({ snapshot_tx: hex("2"), domain: "theailab.org", seq: 2, state: "done", attempts: 2, next_attempt_at: 0, pages: 30, offsite: 0, source: "https://archive.test", updated_at: T0 + 1 });
    await a.flush();
    expect(await a.getSiteIngest(hex("2"))).toEqual(expect.objectContaining({ state: "done", source: "https://archive.test" }));
    expect(await a.listSiteIngestsDue(T0 + 10)).toEqual([]);
    expect(a.listSiteSnapshotsAfter("", 10).map(r => r.seq)).toEqual([1, 2]);
  });

  test("rows, the per-domain head and the state root survive an adapter restart", async () => {
    await a.flush();
    const rootBefore = computeStateMerkleRoot(a);
    a.close();

    const b = new KnexAdapter("better-sqlite3", { dbName: dbFile }, logStub);
    await b.migrate();
    try {
      expect(b.getLatestSiteSnapshot("theailab.org")).toEqual(snap("theailab.org", 2, hex("1"), hex("2"), { witness_vp_id: "tip://vp/US-0e7db4040667073a" }));
      expect(b.listSiteSnapshots("theailab.org", { limit: 5 }).map(r => r.seq)).toEqual([2, 1]);
      expect(computeStateMerkleRoot(b)).toBe(rootBefore);
    } finally {
      b.close();
    }
    a = new KnexAdapter("better-sqlite3", { dbName: dbFile }, logStub);
    await a.migrate();
  });
});
