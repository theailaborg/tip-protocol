/**
 * @file @tip-protocol/node/src/db/index.js
 * @description DB adapter factory. Returns a KnexAdapter for server-side DBs
 * (postgres, mariadb, mssql, oracle) or null to let dag.js use its built-in
 * SQLite/MemoryStore path.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const KNEX_DRIVERS = new Set(["postgres", "mariadb", "mysql", "mssql", "sqlserver", "oracle"]);

function resolveDriver(config) {
  const d = ((config && config.dbDriver) || process.env.DB_DRIVER || "").toLowerCase().trim();
  if (d) return d;
  const env = (process.env.NODE_ENV || "development").toLowerCase();
  return (env === "production" || env === "staging") ? "postgres" : "sqlite";
}

function createStore(config, log) {
  const driver = resolveDriver(config);
  if (!KNEX_DRIVERS.has(driver)) return null;
  try {
    const { KnexAdapter } = require("./knex-adapter");
    return new KnexAdapter(driver, config, log);
  } catch (err) {
    if (log) log.warn(`createStore: KnexAdapter unavailable (${err.message}) — SQLite/memory fallback`);
    return null;
  }
}

module.exports = { createStore, resolveDriver };
