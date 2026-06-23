/**
 * @file tests/db/knex-adapter-transaction.test.js
 * @description #91 (C-2): KnexAdapter.runInTransaction must be ATOMIC.
 *
 * The server (Knex) write path queues DB writes fire-and-forget via _ff().
 * runInTransaction(fn) must batch the writes queued during fn() and flush them
 * as ONE transaction, so a crash or a mid-batch failure can never leave a
 * partially-written round / snapshot on the DB. A partial write rehydrates a
 * divergent mirror on restart -> state_merkle_root fork -> byzantine halt
 * (#91 / #58). The earlier version of this file documented the no-op as the
 * contract; this version asserts real atomicity.
 *
 * Runs locally against file-SQLite-via-Knex (real transactions), exercising the
 * exact production write path without a server. Postgres/MySQL/MSSQL/Oracle are
 * covered in CI by knex-adapter-committee.test.js.
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

function rot(n, effectiveRound) {
  return {
    rotation_number: n,
    effective_round: effectiveRound,
    committee: [{ node_id: `n${n}`, public_key: `pk${n}` }],
    prev_rotation: n - 1,
    signer_node_ids: ["n0"],
    signatures: ["sig"],
    payload_hash: `hash-${n}`,
    committed_at: 1777939200000,
  };
}

describe("#91 KnexAdapter.runInTransaction atomicity (file-SQLite via Knex)", () => {
  let a;
  let tmpDir;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-tx-"));
    a = new KnexAdapter("better-sqlite3", { dbName: path.join(tmpDir, "tx.db") }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { await a.knex.destroy(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // Let the buffered transaction flush (commit or roll back).
  async function drain() {
    await a._ffChain;
    await new Promise((r) => setTimeout(r, 50));
    await a._ffChain;
  }

  test("returns fn()'s result and calls it exactly once", () => {
    const sentinel = Symbol("r");
    let calls = 0;
    const result = a.runInTransaction(() => { calls++; return sentinel; });
    expect(result).toBe(sentinel);
    expect(calls).toBe(1);
  });

  test("a successful runInTransaction persists all of its writes", async () => {
    a.runInTransaction(() => {
      a.saveCommitteeRotation(rot(1, 100));
      a.saveCommitteeRotation(rot(2, 200));
    });
    await drain();
    const rows = await a.knex("committee_history").whereIn("rotation_number", [1, 2]).select("*");
    expect(rows).toHaveLength(2);
  });

  test("a synchronous throw from fn propagates and writes nothing", async () => {
    expect(() =>
      a.runInTransaction(() => {
        a.saveCommitteeRotation(rot(5, 500));
        throw new Error("boom");
      })
    ).toThrow("boom");
    await drain();
    const rows = await a.knex("committee_history").where("rotation_number", 5).select("*");
    expect(rows).toHaveLength(0);
  });

  test("a mid-batch failure rolls back the WHOLE batch (no partial write)", async () => {
    // rotation 9 would persist on its own; the forced failure must abort the
    // transaction so it does NOT land. The old no-op runInTransaction fired
    // rotation 9 fire-and-forget independently -> it persisted -> 1 row.
    a.runInTransaction(() => {
      a.saveCommitteeRotation(rot(9, 900));
      a._ff(() => { throw new Error("forced mid-batch failure"); });
    });
    await drain();
    const rows = await a.knex("committee_history").where("rotation_number", 9).select("*");
    expect(rows).toHaveLength(0);
  });
});
