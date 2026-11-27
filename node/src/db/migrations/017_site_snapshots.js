// consensus-affecting: site_snapshots is canonical state (in state_merkle_root).
// One row per committed SITE_SNAPSHOT, keyed by its tx_id and chained per
// domain by seq; rows are never rewritten.

"use strict";

const TABLE_NAME = "site_snapshots";
const IDX_DOMAIN_SEQ = "idx_site_snapshots_domain_seq";

async function _tableExists(knex, name) {
  return knex.schema.hasTable(name);
}

async function _indexExists(knex, name) {
  const client = knex.client.config.client;
  try {
    if (client === "better-sqlite3" || client === "sqlite3") {
      const r = await knex.raw(
        "SELECT 1 AS x FROM sqlite_master WHERE type='index' AND name = ?",
        [name],
      );
      return Array.isArray(r) ? r.length > 0 : !!(r && r.length);
    }
    if (client === "pg") {
      const r = await knex.raw("SELECT 1 FROM pg_class WHERE relkind='i' AND relname = ?", [name]);
      return r.rowCount > 0 || (r.rows && r.rows.length > 0);
    }
    if (client === "mysql2" || client === "mysql") {
      const r = await knex.raw(
        "SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND index_name = ?",
        [name],
      );
      const rows = Array.isArray(r) ? r[0] : r;
      return !!(rows && rows.length);
    }
    if (client === "mssql") {
      const r = await knex.raw("SELECT 1 AS x FROM sys.indexes WHERE name = ?", [name]);
      const rows = r && (r.rows || r);
      return !!(rows && rows.length);
    }
    if (client === "oracledb") {
      const r = await knex.raw("SELECT 1 FROM user_indexes WHERE index_name = ?", [name.toUpperCase()]);
      const rows = r && (r.rows || r);
      return !!(rows && rows.length);
    }
  } catch {
    // fall through
  }
  return false;
}

exports.up = async (knex) => {
  if (!(await _tableExists(knex, TABLE_NAME))) {
    await knex.schema.createTable(TABLE_NAME, t => {
      t.string("tx_id", 64).primary();
      t.string("domain", 253).notNullable();
      t.bigInteger("seq").notNullable();
      t.string("prev_snapshot_tx", 64).nullable();
      t.string("root", 64).notNullable();
      t.integer("page_count").notNullable();
      t.string("template_hash", 64).notNullable();
      t.string("profile", 32).notNullable();
      t.string("wacz_hash", 64).notNullable();
      t.string("pack_hash", 64).notNullable();
      t.string("ai_signals_hash", 64).notNullable();
      t.bigInteger("captured_at").notNullable();
      t.string("signer_tip_id", 512).notNullable();
      t.string("witness_vp_id", 512).nullable();
      t.bigInteger("registered_at").notNullable();
    });
  }
  if (!(await _indexExists(knex, IDX_DOMAIN_SEQ))) {
    await knex.schema.table(TABLE_NAME, t => { t.unique(["domain", "seq"], { indexName: IDX_DOMAIN_SEQ }); });
  }
};

exports.down = async (knex) => {
  if (await _tableExists(knex, TABLE_NAME)) {
    await knex.schema.dropTable(TABLE_NAME);
  }
};
