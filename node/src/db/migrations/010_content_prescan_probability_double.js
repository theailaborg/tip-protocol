// Consensus-affecting: no. Leaf values do not change: the backfill rounds to the
// basis points the state root already hashes at, so a rolling deploy is safe.
//
// content.prescan_probability was declared t.float, which Postgres stores as
// float4. A blend such as 0.37174999999999997 hashes as 3717 live but reads back
// as 0.37175 after the float4 round-trip and hashes as 3718 at boot, so every
// restarted node diverged from the fleet and had to snapshot-recover. Widen the
// column and restore each row from the value its PRESCAN_COMPLETED transaction
// carried, rounded the way new verdicts now are at the aggregator.
"use strict";

const { roundProbability } = require("../../../../shared/prescan-probability");

const TABLE = "content";
const COLUMN = "prescan_probability";

// SQLite REAL is already 8 bytes; knex would rebuild the table to "alter" it.
function _widensColumn(knex) {
  return knex.client.dialect !== "sqlite3";
}

async function _latestVerdicts(knex) {
  const rows = await knex("transactions")
    .where("tx_type", "PRESCAN_COMPLETED")
    .select("data", "timestamp")
    .orderBy("timestamp", "desc");
  const byCtid = new Map();
  for (const row of rows) {
    let d;
    try { d = JSON.parse(row.data); } catch { continue; }
    if (!d || typeof d.ctid !== "string" || byCtid.has(d.ctid)) continue;
    if (typeof d.probability !== "number" || !Number.isFinite(d.probability)) continue;
    byCtid.set(d.ctid, roundProbability(d.probability));
  }
  return byCtid;
}

exports.up = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE)) || !(await knex.schema.hasColumn(TABLE, COLUMN))) return;
  if (_widensColumn(knex)) {
    await knex.schema.alterTable(TABLE, t => t.double(COLUMN).notNullable().defaultTo(0).alter());
  }
  if (!(await knex.schema.hasTable("transactions"))) return;
  for (const [ctid, probability] of await _latestVerdicts(knex)) {
    await knex(TABLE).where("tip_ctid", ctid).update({ [COLUMN]: probability });
  }
};

exports.down = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE)) || !(await knex.schema.hasColumn(TABLE, COLUMN))) return;
  if (_widensColumn(knex)) {
    await knex.schema.alterTable(TABLE, t => t.float(COLUMN).notNullable().defaultTo(0).alter());
  }
};
