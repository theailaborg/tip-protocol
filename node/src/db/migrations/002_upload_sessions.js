// node-local: ephemeral chunked upload sessions.
// No consensus impact; table is node-local bookkeeping only.

"use strict";

const TABLE_NAME = "upload_sessions";
const IDX_EXPIRES = "idx_upload_sessions_expires_at";

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
      t.string("session_id", 64).primary();
      t.string("upload_id", 256).notNullable();
      t.string("s3_key", 512).notNullable();
      t.string("content_hash", 64).notNullable();
      t.string("mime", 128).notNullable();
      t.bigInteger("size").notNullable();
      t.string("signer_tip_id", 512).notNullable();
      t.bigInteger("timestamp").notNullable();
      t.text("signature").notNullable();
      t.text("parts_json").notNullable().defaultTo("[]");
      t.bigInteger("completed_size").notNullable().defaultTo(0);
      t.bigInteger("created_at").notNullable();
      t.bigInteger("expires_at").notNullable();
    });
  }
  if (!(await _indexExists(knex, IDX_EXPIRES))) {
    await knex.schema.table(TABLE_NAME, t => {
      t.index("expires_at", IDX_EXPIRES);
    });
  }
};

exports.down = async (knex) => {
  if (await _tableExists(knex, TABLE_NAME)) {
    await knex.schema.dropTable(TABLE_NAME);
  }
};
