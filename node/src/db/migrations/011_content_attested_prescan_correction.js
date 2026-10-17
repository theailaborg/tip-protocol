// Consensus-affecting: no. Every live mainnet node hashes this row as 4249, the
// float4 read-back its restarts spread through snapshots; 010 rebuilt it from the
// transaction (4248) and the restarted node halted (2026-09-28). No-op elsewhere.
"use strict";

const CTID = "tip://c/OH-3d67495bf3a9f6-50b7";
const TX_PROBABILITY = 0.42484999999999995;
const ATTESTED_PROBABILITY = 0.4249;

async function _latestVerdict(knex) {
  const rows = await knex("transactions")
    .where("tx_type", "PRESCAN_COMPLETED")
    .andWhere("data", "like", `%${CTID}%`)
    .select("data", "timestamp")
    .orderBy("timestamp", "desc");
  for (const row of rows) {
    let d;
    try { d = JSON.parse(row.data); } catch { continue; }
    if (d && d.ctid === CTID) return d;
  }
  return null;
}

exports.up = async (knex) => {
  if (!(await knex.schema.hasTable("content")) || !(await knex.schema.hasTable("transactions"))) return;
  const verdict = await _latestVerdict(knex);
  if (!verdict || verdict.probability !== TX_PROBABILITY) return;
  await knex("content").where("tip_ctid", CTID).update({ prescan_probability: ATTESTED_PROBABILITY });
};

exports.down = async () => {};
