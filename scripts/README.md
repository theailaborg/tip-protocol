# scripts/

Dev-time tooling. None of these run in production. Genesis bootstrap
(`seed.js`, `register-node.js`, `zk-setup.js`) is documented in
`docs/DEPLOYMENT.md`; this README focuses on the two scripts you'll
use most often when iterating on dispute-flow work.

---

## `seed-temp-users.js` — populate a dev cluster with test identities

Registers N synthetic identities at varied scores so jury selection
has a realistic pool to draw from. Without this, every brand-new
identity sits at `INITIAL_IDENTITY=500` and you can't run a Stage-2
flow at all (jury threshold is 700).

### Quick start

```bash
# default: 50 users, 70% jury-eligible (700-1000), 30% below threshold (500-699)
node scripts/seed-temp-users.js

# bigger pool for stress testing
node scripts/seed-temp-users.js --count 100

# narrower country distribution (default spreads across 10 regions)
node scripts/seed-temp-users.js --regions US,DE,JP

# point at a non-default node
node scripts/seed-temp-users.js --node-url http://localhost:4001
```

### What it does

1. Reads the founding-VP keys (the VP that will attest each new identity).
2. For each user: generates an ML-DSA-65 keypair, computes a dedup
   hash, builds a `REGISTER_IDENTITY` tx signed by the VP, POSTs it
   to the node.
3. After all identities commit, runs a `UPDATE scores SET score = ?`
   directly against every node's database to bump scores into the
   configured bands (the protocol has no admin path to set scores —
   real activity would take ~20 days of cluster time).
4. Writes:
   - `genesis-data/temp-users/temp-users-latest.json` — pointer to the
     newest run (used by `drive-jury.js` to look up keypairs)
   - `genesis-data/temp-users/temp-users-<timestamp>.json` —
     timestamped backup of the same data
   - `genesis-data/temp-users/keys/<tip_id>.json` — per-identity
     private keys

### After running

The score bump writes directly to the DB; the in-memory mirror that
the API reads from doesn't pick up SQL UPDATEs. **Restart every node
in the cluster after seeding** so the mirror re-hydrates from the
table. Compose:

```bash
docker compose restart tip-node
```

### Options

| Flag | Default | Notes |
|---|---|---|
| `--count N` | 50 | Number of users to create |
| `--node-url URL` | `http://localhost:4000` | Submission target |
| `--high-pct N` | 70 | % at jury-eligible scores |
| `--high-min N` / `--high-max N` | 700 / 1000 | Jury-eligible band |
| `--low-min N` / `--low-max N` | 500 / 699 | Below-threshold band |
| `--regions A,B,C` | `US,BR,DE,JP,IN,GB,FR,AU,CA,MX` | Countries to spread across |
| `--region X` | — | Single-region (back-compat) |
| `--name-prefix STR` | `TempUser` | Display-name prefix; final = `STR-NNN` |
| `--no-score-bump` | — | Skip the SQL update step (leaves all users at 500) |
| `--force-prod` | — | Bypass the `NODE_ENV=production` guard. Don't. |

### Safety

- Refuses to run when `NODE_ENV=production` unless `--force-prod` is passed.
- Refuses to run when the target node is consensus-halted (submitting
  txs into a halted node was the cause of an early state-divergence
  bug — keep the guard).
- Idempotent: if an identity is already registered (e.g. the previous
  run timed out client-side but committed server-side), it skips and
  continues. Re-running the script is safe.

---

## `drive-jury.js` — auto commit + reveal for an in-flight dispute

Once a dispute is filed, 7 jurors are summoned. Walking through 7
sets of commit + 7 sets of reveal by hand is painful. This script
loads each summoned juror's keypair from the temp-users seed, picks a
vote per the bias you choose, and submits commit-then-reveal in the
right order.

### Quick start

```bash
# auto-detect phase (commit window vs reveal window) and drive accordingly
node scripts/drive-jury.js --ctid tip://c/AA-3356172f3297aa-4c0b

# bias the verdict: most jurors vote MISMATCH → Stage-2 UPHELD
node scripts/drive-jury.js --ctid <CTID> --vote-bias UPHELD

# bias the other way → Stage-2 DISMISSED
node scripts/drive-jury.js --ctid <CTID> --vote-bias DISMISSED

# uniform-random votes — useful for tie-vote / NO_QUORUM tests
node scripts/drive-jury.js --ctid <CTID> --vote-bias RANDOM

# stay running and poll for the verdict
node scripts/drive-jury.js --ctid <CTID> --watch
```

### What it does

1. Reads the dispute case via `GET /v1/content/:ctid/dispute-case` —
   pulls the list of summoned jurors and the current phase.
2. For each summoned juror:
   - Loads the keypair from `genesis-data/temp-users/keys/`.
   - Picks a vote (`MATCH` / `MISMATCH` / `ABSTAIN`) per `--vote-bias`.
   - Generates a 32-byte salt and computes
     `commitment = shake256(vote + ":" + salt)`.
   - Submits `POST jury/commit` if commit window is open,
     `POST jury/reveal` if reveal window is open.
3. Caches each juror's `(vote, salt)` in
   `genesis-data/temp-users/jury-secrets-<ctid-slug>.json`. The reveal
   phase REQUIRES this cache (matches the protocol — losing the salt
   means you can't reveal).
4. Skips jurors who already committed/revealed (idempotent re-runs).

### Options

| Flag | Default | Notes |
|---|---|---|
| `--ctid CTID` | required | Dispute target |
| `--node-url URL` | `http://localhost:4000` | Submission target |
| `--vote-bias BIAS` | `UPHELD` | `UPHELD` (mostly MISMATCH), `DISMISSED` (mostly MATCH), `RANDOM` |
| `--confirmed-origin CODE` | dispute's `claimed_origin` | Origin code for MISMATCH votes |
| `--phase COMMIT\|REVEAL` | auto-detected | Force a phase (auto-detect uses wall-clock deadlines) |
| `--watch` | off | Poll dispute-case until verdict lands |
| `--watch-timeout SEC` | 30 | Max seconds to watch |
| `--dry-run` | off | Print the plan, don't submit |

### Fast-forwarding the vote windows

The commit/reveal deadlines are on-chain values; there is no bypass flag.
To drive a dispute quickly in dev, rewind the summons deadlines directly
in the node's DB (dev DBs only), then run both phases with `--phase`.

---

## End-to-end: file a dispute and drive it to a verdict

```bash
# 1. one-time setup: bootstrap genesis (if you haven't already)
node scripts/seed.js

# 2. start the node cluster
docker compose up -d

# 3. seed jurors and restart so scores hydrate
node scripts/seed-temp-users.js --count 50
docker compose restart tip-node

# 4. file a dispute (via the UI or directly via curl) — note the CTID

# 5. drive both phases (fast-forward the windows via DB if needed, see above)
node scripts/drive-jury.js --ctid <CTID> --phase COMMIT
node scripts/drive-jury.js --ctid <CTID> --phase REVEAL --watch

# 6. inspect the verdict
curl http://localhost:4000/v1/content/<CTID>/dispute-case | jq .data.verdict
```
