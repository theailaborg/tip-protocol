/**
 * @file tests/db/migration-011-attested-correction.test.js
 * @description Migration 011 puts the one mainnet content row back on the value
 * every live node hashes (4249), which migration 010 had rebuilt from its
 * transaction (4248), and touches nothing else.
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
const TARGET = "011_content_attested_prescan_correction.js";
const CTID = "tip://c/OH-3d67495bf3a9f6-50b7";

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

function verdictTx(txId, ctid, probability) {
  return {
    tx_id: txId,
    tx_type: "PRESCAN_COMPLETED",
    data: JSON.stringify({ ctid, probability, tier: "low", node_id: "tip://node/1122334455667788" }),
    timestamp: 1783036900000,
  };
}

async function probabilityOf(knex, ctid) {
  const [row] = await knex("content").where("tip_ctid", ctid).select("prescan_probability");
  return row && row.prescan_probability;
}

describe("migration 011: attested correction of the mainnet edge row", () => {
  let dbPath;
  let knex;

  beforeEach(async () => {
    dbPath = path.join(os.tmpdir(), `tip-mig-011-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
    knex = knexLib({
      client: "better-sqlite3",
      connection: { filename: dbPath },
      useNullAsDefault: true,
      migrations: { directory: MIGRATIONS_DIR, loadExtensions: [".js"] },
    });
    await _migrateUpTo(knex, TARGET);
  });

  afterEach(async () => {
    await knex.destroy();
    for (const ext of ["", "-wal", "-shm"]) {
      try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
    }
  });

  test("the row migration 010 rebuilt as 0.4248 lands on the attested 4249", async () => {
    await knex("content").insert(contentRow(CTID, 0.4248));
    await knex("transactions").insert(verdictTx("a".repeat(64), CTID, 0.42484999999999995));

    await knex.migrate.up();

    expect(await probabilityOf(knex, CTID)).toBe(0.4249);
    expect(quantizeProbability(await probabilityOf(knex, CTID))).toBe(4249);
  });

  test("a later verdict for the same content leaves the row alone", async () => {
    await knex("content").insert(contentRow(CTID, 0.61));
    await knex("transactions").insert(verdictTx("b".repeat(64), CTID, 0.61));

    await knex.migrate.up();

    expect(await probabilityOf(knex, CTID)).toBe(0.61);
  });

  test("a database without that row is untouched", async () => {
    await knex("content").insert(contentRow("tip://c/OH-other-0001", 0.4248));
    await knex("transactions").insert(verdictTx("d".repeat(64), "tip://c/OH-other-0001", 0.42484999999999995));

    await knex.migrate.up();

    expect(await probabilityOf(knex, "tip://c/OH-other-0001")).toBe(0.4248);
  });
});
