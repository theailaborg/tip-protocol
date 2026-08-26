# Testing Runbook

What to test, how to run it, and what "pass" means. Written for both humans
and AI agents picking up this repo with no session memory: follow this file
and you can validate any change end to end.

## 1. Unit and integration suites (jest)

Run from `node/`:

```bash
# full suite (~6 min on an idle machine)
cd node && npm test

# one suite / directory (preferred while iterating)
node --experimental-vm-modules ../node_modules/.bin/jest --runInBand --forceExit tests/consensus/
node --experimental-vm-modules ../node_modules/.bin/jest --runInBand --forceExit tests/consensus/mempool.test.js

# one test by name
node --experimental-vm-modules ../node_modules/.bin/jest --runInBand --forceExit tests/consensus/commit-handler-owner-chain.test.js -t "burst chaining"
```

Layout:

| Directory | Covers |
|---|---|
| `tests/consensus/` | mempool (lane-aware chain-following drain, tombstones), commit-handler (owner-chain prev, multi-pass, dup-hold, sterile-round budget), pre-verify drift seal, bullshark, narwhal, rotation, anti-entropy |
| `tests/db/` | KnexAdapter parity with MemoryStore/SQLiteStore: owner-chain primitives, write discipline, transactions, snapshot, committee |
| `tests/sync/` | sync handler framing, GC horizon, incremental merkle |
| `tests/integration/` | prescan flood regression, prescan review flow, end-to-end flows |
| `tests/services/`, `tests/api/` | request validation, service logic |

Rules that matter:

- **Fix code, not tests.** A red test means the production code is wrong until
  proven otherwise. Never weaken an assertion to go green.
- **Flakes:** a handful of timing-sensitive suites (multinode-rotation,
  tip-protocol, prescan-review-flow) fail under CPU contention. If the full
  suite fails, rerun ONLY the failing suite in isolation on an idle machine
  before concluding anything. Never run the full suite while docker builds or
  cluster bursts are running.
- **Unit-green is not prod-green.** Units run SQLite/MemoryStore; production
  runs Postgres through KnexAdapter. Shared dag.js helpers probe store
  primitives with SILENT no-op fallbacks, so a primitive missing on the
  adapter passes every unit and dies live (this killed burst chaining once).
  Any new store primitive needs a KnexAdapter delegate plus a test in
  `tests/db/` at the handle-call level.

## 2. Live-cluster scripts (scripts/)

| Script | Purpose |
|---|---|
| `scripts/loss-audit.mjs` | THE acceptance gate. Submits N registrations, records every 202 ctid (client receipt), then polls until every ctid resolves on every node over HTTP. Exit 0 = zero loss. |
| `scripts/seed-temp-users.js` | Registers N temp identities via the API (multi-owner tests). Keys land in `genesis-data/temp-users/keys/`. |
| `scripts/bench-content-register.mjs`, `scripts/concurrent-content-register.mjs` | Submission benchmarks. |

Loss audit usage:

```bash
# local cluster, defaults (500 txs, 3 nodes)
node scripts/loss-audit.mjs

# full gauntlet form
COUNT=2000 CONC=8 node scripts/loss-audit.mjs

# against prod
SUBMIT_URL=http://<node1>:4000 AUDIT_URLS=http://<n1>:4000,http://<n2>:4000,http://<n3>:4000 node scripts/loss-audit.mjs
```

For a restart-under-load test, start the audit and `docker restart tip-node2`
about 15-20s in. PASS is unchanged: every accepted ctid on every node.

## 3. Local cluster operations

The local cluster is 3 nodes (tip-node1..3, API ports 4000/4100/4200) against
a shared Postgres (`shared-postgres` container, DBs `tip_node1..3`).

```bash
# rebuild + deploy , containers pin their image, so ALWAYS recreate, never
# just docker start after a build; verify the code actually landed
docker compose -f docker-compose.local.yml build node1
docker stop tip-node1 tip-node2 tip-node3
# wipe (only with explicit owner approval , NEVER seed:fresh, it mints new node identities)
for n in 1 2 3; do
  docker exec shared-postgres psql -U tip -d postgres -c "DROP DATABASE IF EXISTS tip_node$n"
  docker exec shared-postgres psql -U tip -d postgres -c "CREATE DATABASE tip_node$n OWNER tip"
done
docker compose -f docker-compose.local.yml up -d --no-deps --force-recreate node1 node2 node3
docker exec tip-node1 grep -c "<some marker from your change>" /app/node/src/...   # prove the build landed
```

Order matters: stop nodes BEFORE wiping DBs (a running node half-rewrites a
fresh DB and byzantine-halts the cluster at round 0). `--no-deps` avoids the
tip-postgres port clash with shared-postgres. Recreating also clears container
logs (restart does not).

Health and convergence checks:

```bash
curl -s localhost:4000/health | python3 -c 'import sys,json;d=json.load(sys.stdin)["data"];print(d["status"], d["dag_count"])'
# same-round root comparison , THE convergence check
R=$(docker exec shared-postgres psql -U tip -d tip_node1 -tAc "SELECT max(round) FROM commits")
for n in 1 2 3; do docker exec shared-postgres psql -U tip -d tip_node$n -tAc \
  "SELECT (SELECT count(*) FROM content)||' '||left(state_merkle_root,14) FROM commits WHERE round=$R"; done
# cross-node history identity (id + prev checksums must match)
docker exec shared-postgres psql -U tip -d tip_node1 -tAc \
  "SELECT count(*)||' '||md5(string_agg(tx_id,',' ORDER BY tx_id))||' '||md5(string_agg(prev,',' ORDER BY tx_id)) FROM transactions"
# churn check , should stay ~0 on a healthy build
docker exec shared-postgres psql -U tip -d tip_node1 -tAc "SELECT reason, count(*) FROM tx_rejections GROUP BY 1"
```

## 4. Pitfalls that have burned us (verify before trusting a result)

- **`tip_ctid`, not `ctid`.** Postgres reserves `ctid` as a system column
  (physical tuple id). A query using `j.ctid` on a table without that user
  column silently compares tuple ids and returns garbage. Every content-id
  column in this schema is `tip_ctid`.
- **`TIP_LOG_LEVEL=warn`** in cluster env files suppresses all INFO logs.
  Absence of an info line proves nothing; instrument at warn or check env
  before concluding code doesn't run.
- **Container logs persist across `docker restart`** , counts from
  `docker logs` may span several experiments. Recreate for clean logs, or
  scope with `--since`.
- **Prod `/metrics` needs a bearer token** , query via the Prometheus
  container on the metrics host instead.
- `grep tip_narwhal_join_state` matches HELP/TYPE comment lines , anchor
  with `^tip_narwhal_join_state_ready`.
- The mempool metric oscillating during bursts is in-flight batching, not
  loss , judge loss ONLY by the loss-audit script.

## 5. Acceptance gates by change type

| Change touches | Required before merge |
|---|---|
| Any consensus-path code (mempool, commit-handler, bullshark, narwhal, anti-entropy, sync, dag stores) | Full jest suite green, `scripts/loss-audit.mjs` PASS on a fresh local cluster, burst 2000 with a mid-drain node restart converging with identical roots, tx_rejections near zero |
| Store/adapter surface | `tests/db/` green plus a KnexAdapter-level test for the new primitive |
| API/service only | Affected suites plus full suite |
| Prod deploy | Rolling recreate one node at a time with in-container marker check, then loss-audit against prod (small COUNT), same-round root check across all nodes |

## 6. Prod validation

Nodes: see `my-notes/mainnet-prod/ACCESS.md` (SSH key, IPs; never commit that
directory). Per node: `git pull`, `sudo docker compose build tip-node`,
`sudo docker compose up -d --force-recreate tip-node`, verify a marker inside
the container, wait for `/health` ok, then next node. Finish with the
loss-audit script pointed at prod and a same-round root comparison via each
node's `tip-postgres` container (DB names `tip_node1..3` per host).
