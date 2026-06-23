# DB Migrations

Each schema change gets its own numbered migration file (`001_add_foo.js`, `002_drop_bar.js`, …).
Never edit an existing migration after it has been applied to any node.
Never inline `ALTER TABLE` or `CREATE TABLE` in store code — all DDL lives here.

## Tagging migrations

Add a comment at the top of each migration file:
- `// consensus-affecting` — changes a table that is included in `state_merkle_root`.
  All nodes in the federation must apply this migration before the round that first
  writes the new column/table, or state roots will diverge.
- `// node-local` — changes a node-local table (mempool, tx_rejections, prescan_jobs,
  votes_seen, pending_domain_claims, dispute_details, consensus_meta).
  Nodes can apply this independently; no federation coordination required.

## Running migrations

Run from the `node/` directory. The default environment reads `DB_DRIVER` from
the environment (same var the app uses), so the npm scripts work against whatever
DB your `.env` points at:

```
npm run db:migrate     # apply all pending migrations (migrate:latest)
npm run db:status      # list completed + pending migrations
npm run db:rollback    # undo the last batch
npm run db:fresh       # roll everything back, then re-apply from empty
```

Knex has no `migrate:fresh` (that is a Laravel command); `db:fresh` is the
knex-native equivalent — `migrate:rollback --all` followed by `migrate:latest`,
which relies on every migration having a correct `down`.

To target a specific engine regardless of `DB_DRIVER`, pass `--env` (the named
environments are defined in `node/knexfile.js`): `sqlite`, `pg`, `mariadb`,
`mssql`, `oracle`.

```
# SQLite (dev / test)
npx knex --knexfile knexfile.js --env sqlite migrate:latest

# Postgres (production)
npx knex --knexfile knexfile.js --env pg migrate:latest

# Fresh re-run (roll everything back, then re-apply from empty)
npx knex --knexfile knexfile.js --env pg migrate:rollback --all
npx knex --knexfile knexfile.js --env pg migrate:latest
```

Note: select the engine with `--env`, not `--client`. `--client` overrides the
driver name and fails (knex tries to load a `sqlite3` package that isn't
installed; this repo uses `better-sqlite3`).

## Adding a new migration

1. Create `node/src/db/migrations/NNN_description.js` (zero-padded 3-digit number,
   created by hand). Do not use `knex migrate:make` — it generates a
   timestamp-prefixed filename (`20260623_...`) that breaks the `NNN_` ordering
   convention; if you do run it, rename the file to the next 3-digit number.
2. Export `up` and `down` functions (a working `down` keeps rollback and fresh
   re-runs healthy).
3. Tag it consensus-affecting or node-local at the top.
4. Never touch `000_baseline.js`.
