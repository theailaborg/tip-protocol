// consensus-affecting: domain_attestations is canonical state (in state_merkle_root).
// Each node's latest BIND_DOMAIN attestation per domain, keyed (domain, node_id) and
// upserted, so a binding or renewal applies once a committee quorum has checked it.

"use strict";

const TABLE_NAME = "domain_attestations";
const IDX_CLAIM = "idx_domain_attestations_claim";

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
      t.string("domain", 253).notNullable();
      t.string("node_id", 512).notNullable();
      t.string("tip_id", 512).notNullable();
      t.bigInteger("claimed_at").notNullable();
      t.string("claimed_method", 8).notNullable();
      t.bigInteger("verified_at").notNullable();
      t.string("tx_id", 64).notNullable();
      t.primary(["domain", "node_id"]);
    });
  }
  if (!(await _indexExists(knex, IDX_CLAIM))) {
    await knex.schema.table(TABLE_NAME, t => { t.index(["domain", "tip_id", "claimed_at"], IDX_CLAIM); });
  }
};

exports.down = async (knex) => {
  if (await _tableExists(knex, TABLE_NAME)) {
    await knex.schema.dropTable(TABLE_NAME);
  }
};
