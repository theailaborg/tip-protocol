// node-local (index-only DDL on `content`: no new columns, no data changes,
// state_merkle_root is unaffected — nodes can apply this independently)

"use strict";

// Register-time near-duplicate warning, step 0 (exact match): the register
// path looks up existing content by exact normalized content_hash to warn
// when byte-different but normalization-identical content is already
// registered ("I am Vishal" vs "i am VISHAL." both normalize to "iamvishal").
// The ctid primary key can't serve this lookup — the ctid embeds
// origin_code + signer, so the same content registered by a different
// author or under a different origin always has a different ctid.

const INDEX_NAME = "idx_content_content_hash";

// True if idx_content_content_hash already exists. Idempotency guard for up():
// on a file-SQLite node the SQLiteStore constructor execs the generated
// schema.sql (CREATE INDEX IF NOT EXISTS) — so the index can pre-exist WITHOUT
// a knex_migrations row for this migration (e.g. a DB first opened through the
// sync initDAG path, or the Knex-init-failure SQLite fallback). Re-running the
// bare `t.index()` there would throw "index already exists" and, since
// _runSqliteMigrations has no catch, crash-loop the boot. Checking first also
// makes a re-run safe on the non-transactional-DDL engines (mysql/oracle).
// Catalog query is per-dialect; unknown clients fall through to "not present"
// so the create still attempts (matches prior behavior).
async function _indexExists(knex) {
  const client = knex.client.config.client;
  try {
    if (client === "better-sqlite3" || client === "sqlite3") {
      const r = await knex.raw(
        "SELECT 1 AS x FROM sqlite_master WHERE type='index' AND name = ?",
        [INDEX_NAME],
      );
      return Array.isArray(r) ? r.length > 0 : !!(r && r.length);
    }
    if (client === "pg") {
      const r = await knex.raw("SELECT 1 FROM pg_class WHERE relkind='i' AND relname = ?", [INDEX_NAME]);
      return r.rowCount > 0 || (r.rows && r.rows.length > 0);
    }
    if (client === "mysql2" || client === "mysql") {
      const r = await knex.raw(
        "SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND index_name = ?",
        [INDEX_NAME],
      );
      const rows = Array.isArray(r) ? r[0] : r;
      return !!(rows && rows.length);
    }
    if (client === "mssql") {
      const r = await knex.raw("SELECT 1 AS x FROM sys.indexes WHERE name = ?", [INDEX_NAME]);
      const rows = r && (r.rows || r);
      return !!(rows && rows.length);
    }
    if (client === "oracledb") {
      // Oracle folds unquoted identifiers to upper-case in the catalog.
      const r = await knex.raw("SELECT 1 FROM user_indexes WHERE index_name = ?", [INDEX_NAME.toUpperCase()]);
      const rows = r && (r.rows || r);
      return !!(rows && rows.length);
    }
  } catch {
    // Catalog probe failed (permissions / unexpected dialect shape) — fall
    // through and let the create attempt run as it did before this guard.
  }
  return false;
}

exports.up = async (knex) => {
  if (await _indexExists(knex)) return; // idempotent — see _indexExists
  await knex.schema.alterTable("content", t => {
    t.index(["content_hash"], INDEX_NAME);
  });
};

exports.down = async (knex) => {
  if (!(await _indexExists(knex))) return;
  await knex.schema.alterTable("content", t => {
    t.dropIndex(["content_hash"], INDEX_NAME);
  });
};
