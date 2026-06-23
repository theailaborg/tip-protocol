'use strict';

// Mirrors the connection-building logic in knex-adapter.js so that
//   npx knex --knexfile knexfile.js migrate:latest
// uses exactly the same DB_DRIVER / DB_HOST / DB_* env vars as the running app.
//
// Named environments (--env flag):
//   npx knex --knexfile knexfile.js --env sqlite   migrate:latest
//   npx knex --knexfile knexfile.js --env pg        migrate:latest
//   npx knex --knexfile knexfile.js --env mariadb   migrate:latest
//   npx knex --knexfile knexfile.js --env mssql     migrate:latest
//   npx knex --knexfile knexfile.js --env oracle    migrate:latest
//
// Default (no --env): reads DB_DRIVER from the environment (same as the app).

const path = require('path');

const MIGRATIONS_DIR = path.join(__dirname, 'src/db/migrations');

const CLIENT_MAP = {
  sqlite:    'better-sqlite3',
  postgres:  'pg',
  pg:        'pg',
  mariadb:   'mysql2',
  mysql:     'mysql2',
  mysql2:    'mysql2',
  mssql:     'mssql',
  sqlserver: 'mssql',
  oracle:    'oracledb',
  oracledb:  'oracledb',
};

function _defaultPort(driver) {
  if (driver === 'postgres' || driver === 'pg') return 5432;
  if (driver === 'mssql' || driver === 'sqlserver') return 1433;
  return 3306;
}

function _buildConfig(driver) {
  const client = CLIENT_MAP[driver] || driver;
  const migrations = { directory: MIGRATIONS_DIR, loadExtensions: ['.js'] };

  if (client === 'better-sqlite3') {
    return {
      client: 'better-sqlite3',
      connection: {
        filename: process.env.TIP_DB_PATH || process.env.TIP_SQLITE_PATH || './tip_protocol.sqlite',
      },
      useNullAsDefault: true,
      migrations,
    };
  }

  let connection;
  if (driver === 'oracle' || driver === 'oracledb') {
    const host = process.env.DB_HOST || 'localhost';
    const port = Number(process.env.DB_PORT || 1521);
    const svc  = process.env.DB_NAME || 'FREEPDB1';
    connection = {
      connectString: `${host}:${port}/${svc}`,
      user:     process.env.DB_USER     || 'tip',
      password: process.env.DB_PASSWORD || '',
    };
  } else {
    connection = {
      host:     process.env.DB_HOST     || 'localhost',
      port:     Number(process.env.DB_PORT || _defaultPort(driver)),
      database: process.env.DB_NAME     || 'tip_protocol',
      user:     process.env.DB_USER     || 'tip',
      password: process.env.DB_PASSWORD || '',
    };
    if (process.env.DB_SSL === 'true') {
      connection.ssl = {
        rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false',
      };
    }
  }

  return { client, connection, migrations };
}

// Default environment reads DB_DRIVER — same env var the app uses.
const _driver = (process.env.DB_DRIVER || 'sqlite').toLowerCase();

module.exports = {
  // Default: `npx knex migrate:latest` (no --env) uses DB_DRIVER
  development: _buildConfig(_driver),

  // Named environments for explicit --env selection
  sqlite:  _buildConfig('sqlite'),
  pg:      _buildConfig('postgres'),
  mariadb: _buildConfig('mariadb'),
  mssql:   _buildConfig('mssql'),
  oracle:  _buildConfig('oracle'),
};
