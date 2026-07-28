// parent_url: where a response-type content lives (comment -> post, reply ->
// comment). Nullable, never exclusivity-checked, so many rows share one value;
// the index serves the parent_url lookup on GET /v1/content.

"use strict";

const TABLE_NAME = "content";
const COLUMN_NAME = "parent_url";
const IDX_PARENT_URL = "idx_content_parent_url";

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
  if (!(await knex.schema.hasColumn(TABLE_NAME, COLUMN_NAME))) {
    await knex.schema.table(TABLE_NAME, t => {
      t.string(COLUMN_NAME, 2048).nullable();
    });
  }
  if (!(await _indexExists(knex, IDX_PARENT_URL))) {
    await knex.schema.table(TABLE_NAME, t => {
      t.index(COLUMN_NAME, IDX_PARENT_URL);
    });
  }
};

exports.down = async (knex) => {
  if (await _indexExists(knex, IDX_PARENT_URL)) {
    await knex.schema.table(TABLE_NAME, t => {
      t.dropIndex(COLUMN_NAME, IDX_PARENT_URL);
    });
  }
  if (await knex.schema.hasColumn(TABLE_NAME, COLUMN_NAME)) {
    await knex.schema.table(TABLE_NAME, t => {
      t.dropColumn(COLUMN_NAME);
    });
  }
};
