/**
 * @file tests/db/knex-adapter-owner-chain.test.js
 * @description KnexAdapter pending-owner-head primitives.
 *
 * _buildDagHandle wires prevFor/noteSealedTx as _computePrevFor(store)/
 * _noteSealedTx(store) against the RAW store, and those helpers probe
 * store.getPendingOwnerHead/notePendingOwnerHead directly , with a silent
 * no-op fallback when missing. The adapter lacked both primitives, so on
 * Postgres every seal fell back to the committed head: whole bursts became
 * siblings and lanes committed one tx per round (live repro 2026-07-12,
 * 88 rebuild generations for a single prescan completion). These tests pin
 * the handle-level path against the adapter.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");

const { KnexAdapter } = require("../../src/db/knex-adapter");
const { _computePrevFor, _noteSealedTx } = require("../../src/dag");

const logStub = { info() { }, warn() { }, debug() { }, error() { } };

const NODE = "tip://node/kx-chain-test";
const LANE = `node:${NODE}`;
const TT = "PRESCAN_COMPLETED";   // NODE-signed: owner resolves from data.node_id alone

describe("KnexAdapter pending-owner-head primitives (handle-level burst chaining)", () => {
  let a;
  let tmpDir;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-oc-"));
    a = new KnexAdapter("better-sqlite3", { dbName: path.join(tmpDir, "oc.db") }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { await a.knex.destroy(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("same-owner seals CHAIN through the handle path (not sibling fallback)", () => {
    _noteSealedTx(a, TT, { node_id: NODE, ctid: "c1" }, "T1");
    expect(_computePrevFor(a, TT, { node_id: NODE, ctid: "c2" })[0]).toBe("T1");
    _noteSealedTx(a, TT, { node_id: NODE, ctid: "c2" }, "T2");
    expect(_computePrevFor(a, TT, { node_id: NODE, ctid: "c3" })[0]).toBe("T2");
  });

  test("a committed head supersedes the pending base it confirms", () => {
    a.setOwnerHead(LANE, "T2");
    // T2's pending entry is cleared on commit; the next seal chains onto the
    // committed head , same tip, no sibling fork.
    expect(a.getPendingOwnerHead(LANE)).toBe(null);
    expect(_computePrevFor(a, TT, { node_id: NODE, ctid: "c4" })[0]).toBe("T2");
  });

  test("pruneSupersededContentTxs drops non-canonical same-ctid history rows (install-union artifact)", () => {
    const CT = "tip://c/OH-prunetest000000-0001";
    // Superseded copy T1 and canonical T2 (content.tx_id points at T2).
    a.mirror._txs.set("T1", { tx_id: "T1", tx_type: "REGISTER_CONTENT", data: { ctid: CT }, prev: [], timestamp: 1 });
    a.mirror._txs.set("T2", { tx_id: "T2", tx_type: "REGISTER_CONTENT", data: { ctid: CT }, prev: [], timestamp: 2 });
    a.mirror.saveContent({ ctid: CT, origin_code: "OH", content_hash: "aa", author_tip_id: "tip://id/US-x", signer_tip_id: "tip://id/US-x", status: "registered", registered_at: 2, tx_id: "T2" });

    const pruned = a.pruneSupersededContentTxs();
    expect(pruned).toEqual(["T1"]);
    expect(a.mirror._txs.has("T1")).toBe(false);
    expect(a.mirror._txs.has("T2")).toBe(true);
    // Idempotent: second call finds nothing.
    expect(a.pruneSupersededContentTxs()).toEqual([]);
  });

  test("resetPendingOwnerHead rebases the lane onto the committed head", () => {
    _noteSealedTx(a, TT, { node_id: NODE, ctid: "c5" }, "T5");
    expect(a.getPendingOwnerHead(LANE)).toBe("T5");
    a.resetPendingOwnerHead(LANE);
    expect(a.getPendingOwnerHead(LANE)).toBe(null);
    expect(_computePrevFor(a, TT, { node_id: NODE, ctid: "c6" })[0]).toBe("T2");
  });
});
