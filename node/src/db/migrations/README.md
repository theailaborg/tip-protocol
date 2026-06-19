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

```
# SQLite (dev / test)
npx knex --knexfile knexfile.js --client sqlite migrate:latest

# Postgres (production)
npx knex --knexfile knexfile.js --client pg migrate:latest
```

## Adding a new migration

1. Create `node/src/db/migrations/NNN_description.js` (zero-padded 3-digit number).
2. Export `up` and `down` functions.
3. Tag it consensus-affecting or node-local at the top.
4. Never touch `000_baseline.js`.
