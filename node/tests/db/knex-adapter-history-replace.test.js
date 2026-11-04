/**
 * @file tests/db/knex-adapter-history-replace.test.js
 * @description Snapshot install replaces the commit history and prunes the tx history in the mirror and
 * the database alike, inside bulk-install mode. A joiner's own rows reuse consensus indexes the attested
 * history needs (UNIQUE(consensus_index)); an insert-or-ignore left the mirror ahead of the DB and the
 * parity probe fail-stopped the node in a resync loop.
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

function commit(round, consensusIndex, root) {
  return {
    round, anchor_cert_hash: `cert-${round}`, anchor_batch_hash: `batch-${round}`, leader_node_id: "tip://node/a",
    committee: ["tip://node/a"], support_count: 1, consensus_index: consensusIndex, committed_at: 1767225600000 + round,
    state_merkle_root: root, txs_merkle_root: `txs-${round}`, ack_signer_ids: [], ack_signatures: [], ack_signed_ats: [],
    cert_timestamp: 1767225600000 + round * 1000,
  };
}

function tx(id) {
  return { tx_id: id, tx_type: "REGISTER_CONTENT", data: { ctid: `tip://content/${id}` }, timestamp: 1767225600000, signature: "00" };
}

describe("knex adapter: snapshot history replace and prune", () => {
  let a;
  let tmpDir;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-knex-history-"));
    a = new KnexAdapter("better-sqlite3", { dbName: path.join(tmpDir, "history.db") }, logStub);
    await a.migrate();
  });

  afterAll(async () => {
    try { await a.knex.destroy(); } catch { /* ignore */ }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("attested history replaces local rows that collide on consensus_index; mirror and DB agree", async () => {
    a.saveCommit(commit(10, 7, "own-10"));
    a.saveCommit(commit(12, 8, "own-12"));
    a.saveTx(tx("keep-1"));
    a.saveTx(tx("stale-1"));
    await a.flush();

    a.beginBulkInstall();
    a.saveTx(tx("keep-2"));
    const pruned = await a.pruneTransactionsExcept(new Set(["keep-1", "keep-2"]));
    await a.replaceCommits([commit(9, 7, "net-9"), commit(10, 8, "net-10")]);
    await a.flush();
    a.endBulkInstall();

    expect(pruned).toEqual(["stale-1"]);
    const dbCommits = await a.knex("commits").select("round", "consensus_index", "state_merkle_root").orderBy("round");
    expect(dbCommits).toEqual([
      { round: 9, consensus_index: 7, state_merkle_root: "net-9" },
      { round: 10, consensus_index: 8, state_merkle_root: "net-10" },
    ]);
    expect(a.mirror._commits.size).toBe(dbCommits.length);
    expect(a.getLatestCommit().state_merkle_root).toBe("net-10");

    const dbTxs = (await a.knex("transactions").select("tx_id").orderBy("tx_id")).map(r => r.tx_id);
    expect(dbTxs).toEqual(["keep-1", "keep-2"]);
    expect(a.mirror._txs.size).toBe(dbTxs.length);
  });
});
