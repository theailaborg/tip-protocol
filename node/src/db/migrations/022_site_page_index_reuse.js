// Node-local, off-DAG. A page whose indexed content (and site owner) is unchanged
// from the previous snapshot points at that version's index rows (index_key)
// instead of writing them again; index_hash is what the comparison uses. Rows
// from before this column are compared as changed once, then reused.

"use strict";

const TABLE_NAME = "site_page";
const IDX = "idx_site_page_index_key";

async function _indexExists(knex, name) {
  const client = knex.client.config.client;
  try {
    if (client === "better-sqlite3" || client === "sqlite3") {
      const r = await knex.raw("SELECT 1 AS x FROM sqlite_master WHERE type='index' AND name = ?", [name]);
      return Array.isArray(r) ? r.length > 0 : !!(r && r.length);
    }
    if (client === "pg") {
      const r = await knex.raw("SELECT 1 FROM pg_class WHERE relkind='i' AND relname = ?", [name]);
      return r.rowCount > 0 || (r.rows && r.rows.length > 0);
    }
    if (client === "mysql2" || client === "mysql") {
      const r = await knex.raw("SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND index_name = ?", [name]);
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
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  if (!(await knex.schema.hasColumn(TABLE_NAME, "index_key"))) {
    await knex.schema.table(TABLE_NAME, t => {
      t.string("index_key", 96).nullable();
      t.string("index_hash", 64).nullable();
    });
  }
  if (!(await _indexExists(knex, IDX))) {
    await knex.schema.table(TABLE_NAME, t => { t.index("index_key", IDX); });
  }
};

exports.down = async (knex) => {
  if (!(await knex.schema.hasTable(TABLE_NAME))) return;
  if (await _indexExists(knex, IDX)) {
    await knex.schema.table(TABLE_NAME, t => { t.dropIndex("index_key", IDX); });
  }
  if (await knex.schema.hasColumn(TABLE_NAME, "index_key")) {
    await knex.schema.table(TABLE_NAME, t => {
      t.dropColumn("index_key");
      t.dropColumn("index_hash");
    });
  }
};
