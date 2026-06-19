'use strict';

const path = require('path');

const migrationsDir = path.join(__dirname, 'src/db/migrations');

const sqlite = {
  client: 'better-sqlite3',
  connection: {
    filename: process.env.TIP_SQLITE_PATH || './tip_protocol.sqlite',
  },
  useNullAsDefault: true,
  migrations: {
    directory: migrationsDir,
  },
};

const pg = {
  client: 'pg',
  connection: process.env.TIP_DATABASE_URL || {
    host: process.env.TIP_PG_HOST || 'localhost',
    port: Number(process.env.TIP_PG_PORT) || 5432,
    database: process.env.TIP_PG_DATABASE || 'tip_protocol',
    user: process.env.TIP_PG_USER || 'tipuser',
    password: process.env.TIP_PG_PASSWORD || '',
  },
  migrations: {
    directory: migrationsDir,
  },
};

module.exports = { sqlite, pg };
