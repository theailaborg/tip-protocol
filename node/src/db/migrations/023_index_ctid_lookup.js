// Node-local, off-DAG. Pruning an old snapshot's index deletes its similar-index rows
// by tip_ctid; minhash_band and document_passage lead their keys with other columns,
// so without these indexes each delete would scan the whole table.

"use strict";

const INDEXES = [
  ["minhash_band", "idx_minhash_band_ctid"],
  ["document_passage", "idx_document_passage_ctid"],
];

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
  for (const [table, name] of INDEXES) {
    if (!(await knex.schema.hasTable(table))) continue;
    if (await _indexExists(knex, name)) continue;
    await knex.schema.table(table, t => { t.index("tip_ctid", name); });
  }
};

exports.down = async (knex) => {
  for (const [table, name] of INDEXES) {
    if (!(await knex.schema.hasTable(table))) continue;
    if (!(await _indexExists(knex, name))) continue;
    await knex.schema.table(table, t => { t.dropIndex("tip_ctid", name); });
  }
};
