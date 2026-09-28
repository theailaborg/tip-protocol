/**
 * @file tests/db/migration-010-prescan-probability.test.js
 * @description Migration 010 restores each content row's prescan_probability
 * from the value its PRESCAN_COMPLETED transaction carried, rounded to the
 * basis points the state root hashes at. On mainnet the float4 column had
 * turned 0.37174999999999997 (leaf 3717) into 0.37175 (leaf 3718), so every
 * restarted node diverged from the fleet.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");
const knexLib = require("knex");
const { nowMs } = require("../../../shared/time");
const { quantizeProbability } = require("../../../shared/prescan-probability");

const MIGRATIONS_DIR = path.resolve(__dirname, "../../src/db/migrations");
const TARGET = "010_content_prescan_probability_double.js";

function _tmpDbPath() {
  return path.join(os.tmpdir(), `tip-mig-010-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
}

function _openKnex(dbPath) {
  return knexLib({
    client: "better-sqlite3",
    connection: { filename: dbPath },
    useNullAsDefault: true,
    migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
  });
}

// Run every migration before TARGET so the seed lands on the pre-010 schema.
async function _migrateUpTo(knex, target) {
  while (true) {
    const [, pending] = await knex.migrate.list();
    const next = pending[0] && (pending[0].file || pending[0]);
    if (!next || next === target) return;
    await knex.migrate.up();
  }
}

function contentRow(ctid, probability) {
  return {
    tip_ctid: ctid,
    origin_code: "OH",
    content_hash: "c".repeat(64),
    author_tip_id: "tip://id/US-abcdef0123456789",
    signer_tip_id: "tip://id/US-abcdef0123456789",
    cna_version: "CNA-2.2",
    prescan_probability: probability,
    prescan_tier: "low",
    registered_at: 1783036800000,
  };
}

function verdictTx(txId, ctid, probability, timestamp) {
  return {
    tx_id: txId,
    tx_type: "PRESCAN_COMPLETED",
    data: JSON.stringify({ ctid, probability, tier: "low", node_id: "tip://node/1122334455667788" }),
    timestamp,
  };
}

describe("migration 010: prescan_probability restored from the verdict at basis points", () => {
  let dbPath;
  let knex;

  beforeEach(async () => {
    dbPath = _tmpDbPath();
    knex = _openKnex(dbPath);
    await _migrateUpTo(knex, TARGET);
  });

  afterEach(async () => {
    await knex.destroy();
    for (const ext of ["", "-wal", "-shm"]) {
      try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
    }
  });

  test("an edge row lands on the leaf the live fleet holds, not the float4 reading", async () => {
    await knex("content").insert(contentRow("tip://c/OH-edge-0001", 0.37175));
    await knex("transactions").insert(verdictTx("a".repeat(64), "tip://c/OH-edge-0001", 0.37174999999999997, 1783036900000));

    await knex.migrate.up();

    const [row] = await knex("content").where("tip_ctid", "tip://c/OH-edge-0001").select("prescan_probability");
    expect(row.prescan_probability).toBe(0.3717);
    expect(quantizeProbability(row.prescan_probability)).toBe(quantizeProbability(0.37174999999999997));
  });

  test("the latest verdict wins when a content item was scanned more than once", async () => {
    await knex("content").insert(contentRow("tip://c/OH-twice-0001", 0.9));
    await knex("transactions").insert([
      verdictTx("b".repeat(64), "tip://c/OH-twice-0001", 0.9, 1783036900000),
      verdictTx("d".repeat(64), "tip://c/OH-twice-0001", 0.22220000000000004, 1783036950000),
    ]);

    await knex.migrate.up();

    const [row] = await knex("content").where("tip_ctid", "tip://c/OH-twice-0001").select("prescan_probability");
    expect(row.prescan_probability).toBe(0.2222);
  });

  test("content without a verdict and rows already at basis points are left alone", async () => {
    await knex("content").insert([contentRow("tip://c/OH-none-0001", 0.5), contentRow("tip://c/OH-clean-0001", 0.2736)]);
    await knex("transactions").insert(verdictTx("e".repeat(64), "tip://c/OH-clean-0001", 0.2736, 1783036900000));

    await knex.migrate.up();

    const rows = await knex("content").whereIn("tip_ctid", ["tip://c/OH-none-0001", "tip://c/OH-clean-0001"])
      .orderBy("tip_ctid").select("tip_ctid", "prescan_probability");
    expect(rows.map(r => r.prescan_probability)).toEqual([0.2736, 0.5]);
  });

  test("runs twice without error and rolls back", async () => {
    await knex.migrate.up();
    await knex.migrate.down();
    await knex.migrate.up();
    const [, pending] = await knex.migrate.list();
    expect(pending).toHaveLength(0);
  });
});
