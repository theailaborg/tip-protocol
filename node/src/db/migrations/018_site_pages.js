// node-local: site_page and site_ingest are the off-DAG index of committed site
// snapshots (filled from each fingerprint pack after commit). Not in
// state_merkle_root; nodes apply this independently and can rebuild the rows.

"use strict";

const PAGE = "site_page";
const INGEST = "site_ingest";
const IDX_PAGE_SNAPSHOT = "idx_site_page_snapshot";
const IDX_INGEST_STATE = "idx_site_ingest_state";

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
  if (!(await knex.schema.hasTable(PAGE))) {
    await knex.schema.createTable(PAGE, t => {
      t.string("page_key", 96).primary();          // site:<snapshot tx_id>:<16 hex of SHAKE-256(url)>
      t.string("snapshot_tx", 64).notNullable();
      t.string("domain", 253).notNullable();
      t.bigInteger("seq").notNullable();
      t.text("url").notNullable();
      t.string("text_hash", 64).notNullable();
      t.string("page_hash", 64).notNullable();
      t.integer("offsite").notNullable().defaultTo(0);
      t.integer("changed").nullable();
      t.double("kept").nullable();   // double: Postgres stores t.float as float4
      t.text("paragraph_keys").notNullable();
      t.bigInteger("created_at").notNullable();
    });
  }
  if (!(await _indexExists(knex, IDX_PAGE_SNAPSHOT))) {
    await knex.schema.table(PAGE, t => { t.index("snapshot_tx", IDX_PAGE_SNAPSHOT); });
  }
  if (!(await knex.schema.hasTable(INGEST))) {
    await knex.schema.createTable(INGEST, t => {
      t.string("snapshot_tx", 64).primary();
      t.string("domain", 253).notNullable();
      t.bigInteger("seq").notNullable();
      t.string("state", 16).notNullable();
      t.integer("attempts").notNullable().defaultTo(0);
      t.bigInteger("next_attempt_at").notNullable().defaultTo(0);
      t.text("last_error").nullable();
      t.integer("pages").nullable();
      t.integer("offsite").nullable();
      t.text("source").nullable();
      t.bigInteger("updated_at").notNullable();
    });
  }
  if (!(await _indexExists(knex, IDX_INGEST_STATE))) {
    await knex.schema.table(INGEST, t => { t.index(["state", "next_attempt_at"], IDX_INGEST_STATE); });
  }
};

exports.down = async (knex) => {
  if (await knex.schema.hasTable(INGEST)) await knex.schema.dropTable(INGEST);
  if (await knex.schema.hasTable(PAGE)) await knex.schema.dropTable(PAGE);
};
