// consensus-affecting: org_members is canonical state (in state_merkle_root).
// One row per invite, keyed by the ORG_MEMBER_INVITED tx_id; the row walks
// invited -> active -> removed through ORG_MEMBER_ADDED / ORG_MEMBER_REMOVED.
// Expiry of an unaccepted invite is derived from invited_at at read time, so
// no row is ever rewritten by a sweep.

"use strict";

const TABLE_NAME = "org_members";
const IDX_ORG = "idx_org_members_org_status";
const IDX_MEMBER = "idx_org_members_member_status";
const IDX_ADD_TX = "idx_org_members_add_tx_id";

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
      t.string("invite_tx_id", 512).primary();
      t.string("org_tip_id", 512).notNullable();
      t.string("member_tip_id", 512).notNullable();
      t.string("role", 64).notNullable();
      t.string("status", 16).notNullable().defaultTo("invited");
      t.bigInteger("invited_at").notNullable();
      t.bigInteger("accepted_at").nullable();
      t.string("add_tx_id", 512).nullable();
      t.bigInteger("removed_at").nullable();
      t.string("remove_tx_id", 512).nullable();
      t.string("removed_by", 512).nullable();
    });
  }
  if (!(await _indexExists(knex, IDX_ORG))) {
    await knex.schema.table(TABLE_NAME, t => { t.index(["org_tip_id", "status"], IDX_ORG); });
  }
  if (!(await _indexExists(knex, IDX_MEMBER))) {
    await knex.schema.table(TABLE_NAME, t => { t.index(["member_tip_id", "status"], IDX_MEMBER); });
  }
  if (!(await _indexExists(knex, IDX_ADD_TX))) {
    await knex.schema.table(TABLE_NAME, t => { t.index("add_tx_id", IDX_ADD_TX); });
  }
};

exports.down = async (knex) => {
  if (await _tableExists(knex, TABLE_NAME)) {
    await knex.schema.dropTable(TABLE_NAME);
  }
};
