# TIP Protocol Deployment Guide

This document is for operators who want to run a TIP Protocol node: what a
node is, and step-by-step instructions for getting from zero to a live node
in under 30 minutes.

---

## One Node Type

Every TIP node is a **full node**: it validates transactions, stores the DAG,
serves the REST API and takes part in consensus and gossip. There is no other
node type today; `TIP_NODE_TYPE` stays `full` (the value is only echoed in the
boot log and `/health`).

Issuing TIP-IDs to verified humans is **not** a node role. It is done by the
Verification Provider application (`tip-vp`, a separate repository and service
run by The AI Lab), which submits `REGISTER_IDENTITY` transactions to a node
like any other client. Running a node never involves a VP keypair or a
biometric pipeline.

---

## Prerequisites

| Item | |
|------|---|
| Node.js 24+ | Required |
| Docker and Docker Compose | Recommended (Option A) |
| Static public IP address | Required for a federation node (peers store it) |
| Open ports 4000 (REST) and 4001 (gossip) | Required for a federation node |
| PostgreSQL | Required for production (the compose stack provides it) |

---

## Option A: Docker Compose (Recommended, Under 30 Minutes)

This is the fastest path to a running node with PostgreSQL.

### Step 1: Clone the repository

```bash
git clone https://github.com/theailaborg/tip-protocol.git
cd tip-protocol
```

### Step 2: Configure your environment

Which `.env` you use depends on what you are running:

- **Joining mainnet as a partner:** use the `node.env` the AI Lab team delivered
  in your credentials bundle (`cp <bundle>/node.env .env`). It is generated from
  `.env.example` with every federation value already set (bootstrap peers,
  classifier URL and key, metrics token, CORS, rate limits, production mode) and
  it points at your registered node key, which is the only key the network will
  peer with. Do not start from `.env.example`: a key you mint yourself is not on
  chain and the node will never find a peer. Skip the rest of this step and
  follow [Joining an Existing Federation](#joining-an-existing-federation-partner-node).
- **Your own development node** (local, not connected to mainnet): start from
  the template and set the values below; the node key is minted by the seed in
  Step 5.

```bash
cp .env.example .env
```

Open `.env` and set the following. Everything else can stay as the default
for a development node. The chain id and genesis are carried by the baked
`genesis-data/genesis.json`, not by env vars.

```bash
NODE_ENV=production                # development for a dev node
# Node identity: a .tip.json holding the node keypair (founding nodes are minted
# by scripts/seed.js; new nodes register via scripts/register-node.js).
TIP_NODE_ID=tip://node/<id>
TIP_NODE_CREDENTIALS_FILE=genesis-data/backups/tip-node-<id>.tip.json

# Network
TIP_PUBLIC_IP=<your public/Elastic IP>          # for peer dial-back
# TIP_BOOTSTRAP_PEERS=/ip4/<seed-ip>/tcp/4001/p2p/<seed-peer-id>   # empty on the seed
# TIP_PUBLIC_URL=https://your-node-hostname.com
```

Database credentials in `.env` (each node has its own local postgres):

```bash
DB_DRIVER=postgres
DB_HOST=postgres
DB_NAME=tip_node1                  # tip_node2 / tip_node3 on the other nodes
DB_USER=tip
DB_PASSWORD=<choose_a_strong_password>
```

### Step 3: Start the stack

```bash
docker compose up -d
```

This starts the TIP node and PostgreSQL together. The node waits for
PostgreSQL to be healthy before starting.

### Step 4: Verify the node is running

```bash
curl http://localhost:4000/health
```

Expected response (every API answer is wrapped in `ok` / `status` / `data`):

```json
{
  "ok": true,
  "status": 200,
  "data": {
    "status": "ok",
    "node_id": "tip://node/<id>",
    "node_type": "full",
    "dag_count": 0,
    "version": "2.7.9",
    "protocol": "2.0.0",
    "peers": { "connected": 0, "peer_ids": [] }
  }
}
```

`/health` does not return `genesis_hash` or a chain id. To confirm which chain
the image carries, read the baked genesis directly:

```bash
python3 -c "import json;print(json.load(open('genesis-data/genesis.json'))['genesis_hash'][:16])"
```

### Step 5: Seed the genesis block (FOUNDING node only)

> **Do not run this if you are joining an existing network.** Seeding mints a
> new genesis and a new founding VP. A node that seeds has a different
> `genesis_hash` from the fleet, so the p2p handshake rejects it, it peers with
> nobody, and it sits at `join_state: syncing` forever. There is no clean
> "wrong network" error and `scripts/seed.js` will not stop you. Partners
> joining mainnet skip straight to Step 6: the genesis is already baked into
> the image and state arrives by sync.

```bash
docker compose exec tip-node node scripts/seed.js
```

This mints the genesis block, registers the founding VP, and writes the
genesis ring members to the DAG. Only the first node of a **brand new** chain
does this.

After seeding:

```bash
curl http://localhost:4000/health
# dag_count should now be greater than 0

curl http://localhost:4000/v1/dag/stats
# Should show identity_count, content_count, vp_count
```

### Step 6: View logs

```bash
docker compose logs -f tip-node
```

---

## Option B: Manual Setup (Node.js)

Use this if you prefer to manage the process yourself with pm2, systemd,
or another process manager.

### Step 1: Install dependencies

```bash
git clone https://github.com/theailaborg/tip-protocol.git
cd tip-protocol
cd node && npm install
```

### Step 2: Configure

```bash
cd ..
cp .env.example .env
# Edit .env as described in Option A Step 2
```

### Step 3: Start the node

```bash
cd node
npm start
```

For production with automatic restart:

```bash
npm install -g pm2
pm2 start src/index.js --name tip-node
pm2 save
pm2 startup
```

### Step 4: Seed (development node only)

Only for a node of its own, on its own chain. Never on a node joining mainnet or
the test cluster: seeding mints a new genesis and the node peers with nobody.

```bash
cd ..
npm run seed
```

---

## Production Federation Deploy (0 to live)

The reproducible steps used for the mainnet launch: fresh cloud hosts to a
live, converged federation, plus observability. The container runs as **uid
1001** (`tipnode`); every file it reads/writes must be owned by `1001`. The
genesis is **baked into the image**, so rebuild after any genesis change.
Deploy code with **git**, never a code copy.

Prereqs: one Ubuntu host per node (4-core / 8 GB, stable Elastic IP), one obs
host, the genesis already minted and merged to `main`, and the per-node key
files `genesis-data/backups/tip-node-<id>.tip.json` (gitignored).

**1. Install Docker (every host)**

```bash
curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker ubuntu
```

**2. Clone via git (every node)**: `main` already carries the baked genesis.

```bash
git clone https://x-access-token:<TOKEN>@github.com/theailaborg/tip-protocol.git ~/tip-protocol
git -C ~/tip-protocol remote set-url origin https://github.com/theailaborg/tip-protocol.git
```

**3. Node identity + env (every node)**: owner must be uid 1001.

```bash
scp tip-node-<id>.tip.json ubuntu@<node-ip>:~/tip-protocol/genesis-data/backups/
sudo chown 1001:1001 ~/tip-protocol/genesis-data/backups/tip-node-<id>.tip.json
sudo chmod 600      ~/tip-protocol/genesis-data/backups/tip-node-<id>.tip.json
scp <node>.env ubuntu@<node-ip>:~/tip-protocol/.env   # per node; see Step 2 above
```

Keep `.env` at parity with `.env.example`; missing keys silently fall back to
protocol defaults. Prod values: `NODE_ENV=production`, `TIP_CORS_ORIGINS`
listing every browser client (the VP app; NOT `*`), a shared `TIP_METRICS_TOKEN`
identical on all nodes, `TIP_CRYPTO_POOL_SIZE=2` on 4-core hosts.

**Media storage (S3)**: the node writes media bytes to S3 (SSE-KMS) and hands
the classifier presigned URLs. Provision the bucket + KMS key + IAM role once
and set `TIP_MEDIA_BACKEND=s3`, `TIP_MEDIA_S3_BUCKET`, `TIP_MEDIA_S3_REGION`,
`TIP_MEDIA_S3_KMS_KEY_ID` in each node's `.env`. Full step-by-step (Terraform or
console/CLI, IAM policy, VPC endpoint, smoke tests): **[`PROD_S3_SETUP.md`](PROD_S3_SETUP.md)**.
Credentials come from the instance role (EC2) / IRSA (EKS), never a long-lived
`AWS_ACCESS_KEY_ID` in the env.

**4. Log directory permissions (GOTCHA)**: the compose bind-mounts
`./logs/node-1`, which docker creates root-owned, so the container cannot write
its per-level log files. Fix before first boot:

```bash
mkdir -p ~/tip-protocol/logs && sudo chown -R 1001:1001 ~/tip-protocol/logs
```

Skip this and the log dir stays empty (logs only reach docker stdout) and Loki
never gets the `level` label.

**5. Build (every node)**: bakes the genesis into the image.

```bash
cd ~/tip-protocol && sudo docker compose build tip-node
```

**6. Bring up, seed node first.** The seed (node1) has empty
`TIP_BOOTSTRAP_PEERS`; the others dial its libp2p multiaddr (stable across
reboots).

```bash
# node1 (seed):
cd ~/tip-protocol && sudo docker compose up -d
curl -s http://<node1-ip>:4000/health | grep -o '"bootstrap_addr":"[^"]*"'   # -> multiaddr
# set TIP_BOOTSTRAP_PEERS on node2/3 to that multiaddr, then `docker compose up -d`
```

> Re-deploying an existing chain? STOP tip-node on ALL nodes before wiping any
> DB, then DROP/CREATE each DB, then bring up node1 first. A running node
> half-rewrites a fresh DB and byzantine-halts at round 0.

**6b. Schema migrations run automatically on first boot.** Knex applies
anything in `node/src/db/migrations/` that the node's `knex_migrations` table
has not seen, before consensus starts. A deploy is therefore a schema change
whenever new migrations have landed since that node last booted. They are
additive and fast (nullable columns on small tables), but on the first node of
a rollout watch the boot logs and confirm the expected set applied:

```bash
docker exec tip-postgres psql -U tip -d "$DB_NAME" -tAc \
  "SELECT name FROM knex_migrations ORDER BY id;"
```

**7. Validate** across all nodes: `/health` shows `byzantineForkHalt=none`,
`joinState=ready`, `peers=<N-1>`, rounds advancing; the same
`state_merkle_root` at the same round from `/v1/state-root` (`/health` does not
return `genesis_hash`),
identities = genesis ring size, and the same committed tx count (converged).

**8. Observability** (obs host: Prometheus + Grafana + Loki + Caddy)

Full step-by-step (monitoring host, per-node agent, verify, operations) is the
runbook at **[`infra/observability/prod/README.md`](../infra/observability/prod/README.md)**.
The load-bearing gotchas to not relearn the hard way:

- **Metrics**: `infra/observability/prod/prometheus.yml` (gitignored), job
  `tip-federation` (do NOT rename), targets = the nodes' **private** IPs `:4000`,
  `Bearer` = the shared `TIP_METRICS_TOKEN`, and `chmod 644` the file (a `sudo`
  edit that leaves it `root:600` crash-loops Prometheus). Verify
  `count(up{job="tip-federation"}==1)` returns N.
- **Logs**: promtail per node (`infra/observability/agent/`), requires Step 4.
  `promtail.env`: `LOKI_URL=logs.<domain>`, `LOKI_PASSWORD=<plaintext>`,
  `NODE_LABEL=node<n>`; then `docker compose -f docker-compose.promtail.yml up -d`.
  It tags `node` + derives `level` from the per-level filenames. Set the Loki
  basic-auth (`LOKI_BASIC_AUTH_HASH` via `caddy hash-password`) in the obs `.env`.
- **DNS (GOTCHA)**: `logs.<domain>` must be **DNS-only (grey cloud), NOT
  Cloudflare-proxied**: Caddy owns TLS + basic-auth for the push; a proxy in
  front breaks the ACME challenge and the push times out. `grafana.<domain>`
  proxied is fine (browser UI).

---

## Joining an Existing Federation (partner node)

The section above is a **cold start** for a brand new chain. A partner joining
mainnet is a different job: the chain already exists, so the node mints nothing
and instead proves it agrees with everyone else. We register the node and issue
the credentials bundle first, per
[`REGISTRATION_AND_KEY_DISTRIBUTION.md`](./REGISTRATION_AND_KEY_DISTRIBUTION.md).

The one rule that matters: **never run `scripts/seed.js`**. It mints a fresh
genesis, and a node whose `genesis_hash` differs cannot complete the p2p
handshake with anybody. The symptom is not an error, it is zero peers and
`join_state: syncing` forever.

**1. Clone and place the credentials.** The zip is flat; the key has to be moved
to where `node.env` points it and handed to uid 1001, the container user.

```bash
git clone https://github.com/theailaborg/tip-protocol.git ~/tip-protocol
cd ~/tip-protocol

cp <bundle>/NODE-KEY__tip-node-<id>.tip.json genesis-data/backups/tip-node-<id>.tip.json
cp <bundle>/node.env .env                     # compose reads .env, not node.env

mkdir -p data logs/node-1
sudo chown -R 1001:1001 genesis-data/backups data logs
sudo chmod 600 genesis-data/backups/tip-node-<id>.tip.json
```

The `ORG-IDENTITY__*.tip.json` from the same bundle does **not** belong on this
host. It signs as the company, not as the node; keep it offline.

Host notes from real deployments: Docker Engine without Docker Desktop also
needs the `docker-buildx` plugin for `compose build`; on a host without `sudo`,
create `data/` and `logs/node-1/` yourself before the first start so the
container user can write them.

**2. Confirm the chain before starting anything.**

```bash
python3 -c "import json;print(json.load(open('genesis-data/genesis.json'))['genesis_hash'][:16])"
```

It must match the federation's genesis prefix. If it does not, you are on the
wrong branch or a stale clone, and nothing below will work.

**3. Edit only what is yours in `.env`.** The delivered file is complete except
for the values only you can know:

| line | what to do |
|---|---|
| `DB_PASSWORD=CHANGE_ME_STRONG_DB_PASSWORD` | always: choose a strong password; the compose stack creates the database with it |
| `TIP_PUBLIC_IP`, `TIP_PUBLIC_URL`, `TIP_API_ENDPOINT` | only if they still read `CHANGE_ME`: your static public IP and `https://<your-node-domain>` |
| `TIP_CLASSIFIER_CALLBACK_SECRET` | only if the AI Lab gave you one; empty means the node polls for verdicts, which also works |

Leave everything else as delivered: `TIP_BOOTSTRAP_PEERS`, `TIP_CLASSIFIER_URL`
and `TIP_CLASSIFIER_KEY`, `TIP_METRICS_TOKEN`, `TIP_CORS_ORIGINS`,
`TIP_CLASSIFIER_FALLBACK=0`, `TIP_CLASSIFIER_SCAN_NON_OH=true`, the ports and
`NODE_ENV=production`. Do not add any `TIP_*_ACTIVATION_MS` line: the code
defaults are the mainnet epochs, and a different value forks your node.

**4. Build and start.** No seed step.

```bash
sudo docker compose build tip-node
sudo docker compose up -d
docker compose logs -f tip-node
```

**No static IP or no inbound 4001?** The node still works, outbound-only: it
dials the federation, nobody can dial it, and the API reaches the internet
through a tunnel (Cloudflare Tunnel to `localhost:4000`, as one partner runs).
Then `TIP_PUBLIC_IP` stays empty and `TIP_BOOTSTRAP_PEERS` **must list all three
founding nodes**, otherwise the two it did not dial never learn it exists. This
is a degraded setup (`NODE_REQUIREMENTS.md` asks for a static IP and open
4000/4001); agree it with the AI Lab team before choosing it.

**5. Watch it sync.** A joining node downloads a snapshot before it can
participate, which takes minutes on a live chain. Progress, not speed, is what
to watch:

```bash
curl -s http://localhost:4000/ready | python3 -m json.tool
```

`join_state` moves `syncing` → `catching_up` → `ready`. Snapshot installs are
not resumable today, so a dropped transfer restarts it; repeated restarts
usually mean an unstable link rather than a broken node.

**6. Verify, in this order.** Each proves something different:

```bash
# reachable and not halted
curl -s http://localhost:4000/ready      | python3 -m json.tool   # ready:true, halted:false

# on the right chain: the handshake authorises peers against the genesis-scoped
# on-chain registry, so a non-zero peer count IS proof of the correct genesis
curl -s http://localhost:4000/health     | python3 -m json.tool   # peers.connected >= 1

# the definitive check: identical state at the same round
curl -s http://localhost:4000/v1/state-root
curl -s https://node.theailab.org/v1/state-root
```

Equal `state_merkle_root` at equal `round` means the node's entire state is
byte-identical to the rest of the federation. Rounds advance every ~2s, so
compare matching round numbers rather than two snapshots taken seconds apart.

The same checks, kept green on one page: open `https://<your-node-host>/status`
(or `http://localhost:4000/status`). It shows every connected peer with its
round and state root, whether a genesis node is among them, and a checklist
that is only all-green when the node is reachable, caught up, not halted,
connected, in agreement on the state root and announcing its endpoint. It reads
only the public endpoints above, so there is nothing to configure.

**7. Put TLS in front, then announce the endpoint.** Your node domain must
serve `https://<your-node-domain>/health`, `/metrics` and `/status`
(terminating TLS in front of `:4000` with a reverse proxy or a tunnel): the
federation stores that URL on chain, the AI Lab scrapes `/metrics` through it
with the token already in your `.env`, and users open `/status`. Once DNS
resolves to it, announce it. It is optional at registration and can be re-run
any time, signed by the node's own key with no council re-approval:

```bash
curl -X POST http://localhost:4000/v1/node/endpoint/announce
```

The node probes its own domain first. If that fails with `fetch failed` right
after you created the DNS record, the container has cached the earlier
"no such name" answer; wait for it to expire or recreate the container, then
announce again. Success shows your URL as `api_endpoint` in
`https://node.theailab.org/v1/nodes`.

**8. Media storage before real traffic.** The delivered env ships
`TIP_MEDIA_BACKEND=fs`, which writes media bytes to the node disk. Production
nodes use S3 with SSE-KMS, in one of two ways:

- *Your own bucket* (recommended): provision bucket, KMS key and instance role
  per [`PROD_S3_SETUP.md`](./PROD_S3_SETUP.md), then set
  `TIP_MEDIA_BACKEND=s3`, `TIP_MEDIA_S3_BUCKET`, `TIP_MEDIA_S3_REGION`,
  `TIP_MEDIA_S3_KMS_KEY_ID`. No AWS keys in the env: the instance role signs.
- *A Lab-provided bucket*: the AI Lab team creates an IAM user scoped to the
  `media/` prefix of one of its buckets and hands you an access key; set the
  same four values plus `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, and
  rotate that key every 90 days.

Recreate the container (`docker compose up -d --force-recreate tip-node`),
upload one image through the VP app or extension against your node, and confirm
the object appears under `media/` in the bucket with `0` S3 errors in the logs.
Also tell the AI Lab team the bucket host, so the classifier is allowed to
download from it.

**9. Ship logs.** Follow
[`PARTNER_LOG_SHIPPING.md`](./PARTNER_LOG_SHIPPING.md): create
`infra/observability/agent/promtail.env` with `LOKI_URL=logs.theailab.org`, the
`NODE_LABEL` and the `LOKI_PASSWORD` the AI Lab team gave you with the bundle,
then

```bash
cd infra/observability/agent && docker compose -f docker-compose.promtail.yml up -d
```

Your node appears under its label in the federation dashboard within a minute;
a `401` in `docker logs tip-promtail` means the password does not match. On a
macOS Docker host, drop the Docker-socket and container-log mounts from the
agent compose file (they live inside Docker's VM there) and ship the four node
log files only.

**10. Metrics** need nothing from you beyond step 7: the AI Lab team adds
`<your-node-domain>:443` to its Prometheus targets and scrapes `/metrics` with
the token in your `.env`.

**11. Upgrades** follow [Upgrading a Running Federation](#upgrading-a-running-federation-rolling)
below: pull, build, stop, run the root gate (`scripts/check-boot-root.js`)
against an untouched founding node, start only on `MATCH`. On a macOS Docker
host add `-e NODE_OPTIONS=--dns-result-order=ipv4first` to the gate command, or
its peer fetch fails on IPv6-first DNS.

---

## Upgrading a Running Federation (rolling)

The section above is a cold start. Upgrading a live chain is different: the
chain must keep quorum throughout, so nodes go one at a time and each is
verified before the next is touched. With 3 nodes quorum is 2, so exactly one
node may be down at a time. Never two.

Per node, in order (leave the seed until last so peers always have a bootstrap
target):

```bash
# 1. back up genesis BEFORE touching git; a checkout can clobber a local edit
cp genesis-data/genesis.json /tmp/genesis-backup.json

# 2. move to the target commit, keeping the local genesis
git stash push -q genesis-data/genesis.json
git fetch origin && git checkout <sha>
git stash pop -q
diff -q genesis-data/genesis.json /tmp/genesis-backup.json   # MUST be identical

# 3. rebuild (genesis is baked into the image); the running container keeps its image
docker compose build tip-node

# 4. gate: stop this node, apply the new migrations, and prove its database
#    rebuilds to the live root of an untouched peer. Exit 0 means MATCH.
docker compose stop tip-node
docker compose run --rm --no-deps -T --entrypoint node tip-node \
  scripts/check-boot-root.js --migrate --peer https://<untouched-peer>

# 5. only on MATCH: recreate this node
docker compose up -d --no-deps --force-recreate tip-node
```

On MISMATCH, do not start the node on the new version: it would halt at boot and
depend on a peer's single snapshot slot to recover. The script prints per-table
roots; the table that differs from the peer's is where the database drifted.

Then verify **before** moving on:

- `/ready` returns `ready:true, db_ok:true, halted:false`
- `RestartCount` is still 0 and no `persistence lost, fail-stop` in the logs
- `/v1/state-root` matches the untouched nodes at the same round
- expected migrations applied (step 6b)

Give it a few minutes rather than seconds. A node that comes up and then dies
on its second cycle looks healthy at t+30s.

Nodes on different commits reporting **identical** state roots is normal: the
canonical projections used for hashing are explicit whitelists, so a column added
by a new migration does not enter the root. Mixed versions agree by design.

A `HALT (byzantine_fork)` after boot is **not** normal, even when it clears itself
through a snapshot. It means this node's database rebuilt to a different root than
the fleet holds. It was read as harmless for months and hid a real drift until a
restart found no peer able to serve a snapshot (2026-09-28). Stop the rollout and
run the gate against the node's database.

Anything else, stop and investigate before touching the next node.

## Production Checklist

Before exposing your node to the public internet or connecting to the
mainnet bootstrap peers, complete this checklist.

**Security**

- [ ] The node key (`genesis-data/backups/tip-node-<id>.tip.json`) and the log
  dir (`logs/`) are owned by **uid 1001** (the container user)
- [ ] `.env` and `genesis-data/backups/*.tip.json` are gitignored and never committed
- [ ] `DB_PASSWORD` is strong; `TIP_METRICS_TOKEN` is a random shared secret
- [ ] `TIP_CORS_ORIGINS` is an explicit allowlist (not `*`) including the VP app
- [ ] Ports 4000 and 4001 are behind a firewall; only open to intended traffic
- [ ] TLS is configured (Let's Encrypt or AWS Certificate Manager) for port 4000
- [ ] The node process runs as a non-root user (handled automatically by Docker)

**Network**

- [ ] `TIP_PUBLIC_URL` is set to your node's public HTTPS URL
- [ ] `TIP_BOOTSTRAP_PEERS` points to the mainnet bootstrap peers
- [ ] Port 4001 (gossip) is open for TCP from any IP
- [ ] Port 4000 (REST API) is behind a reverse proxy (nginx, Caddy, or Cloudflare)

**Chain**

- [ ] The image was built from the correct `genesis-data/genesis.json` (the chain
  id and genesis are baked into the image, not set via env vars)
- [ ] Every node reports the **same `state_merkle_root` at the same round** on `/v1/state-root`
- [ ] The genesis founding identities are present (identities count = ring size)
  and consensus is advancing with `byzantineForkHalt=none`

**Monitoring**

- [ ] Uptime monitoring configured (alert if `/health` stops responding)
- [ ] Log aggregation configured (CloudWatch, Grafana Loki, or equivalent)
- [ ] Disk space monitoring on the data volume (DAG grows over time)

---

## Verify Your Node Is Participating in the Network

Once your node is running and connected to bootstrap peers:

```bash
# Check peer connections
curl http://localhost:4000/v1/node/peers

# Check DAG synchronisation status
curl http://localhost:4000/v1/dag/stats

# Check your node identity
curl http://localhost:4000/v1/node/info
```

Your node is fully operational when `tx_count` matches (or is close to)
the count on other network nodes.

---

## Troubleshooting

**`dag_count` is 0 after startup**
Run the seed script: `node scripts/seed.js` (or `docker compose exec tip-node node scripts/seed.js`).
The node does not automatically seed itself on first boot.

**Node starts but peers do not connect**
Check `TIP_BOOTSTRAP_PEERS` in your `.env`. Verify port 4001 is open.
Bootstrap peer addresses are published at theailab.org/genesis.

**`POST /v1/identity/register` returns 403 "VP not found"**
The VP ID in `vp_id` field must match a VP already registered in the DAG.
Run the seed script first to register the founding VP.

**Docker compose fails with `better-sqlite3` build error**
The `build` stage in `Dockerfile` installs native build tools. If you are
pulling a pre-built image from a registry, this should not occur. If
building locally, ensure Docker has internet access during the build.

**Node can't read its key (EACCES) or the log dir is empty**
The container runs as uid 1001; a scp'd key lands owned by `ubuntu` and a
bind-mounted log dir is created root-owned. `sudo chown 1001:1001` the node
key and `sudo chown -R 1001:1001 ~/tip-protocol/logs`, then restart the node.
An empty log dir also means Loki gets no `level` label.

---

## Getting Help

| Channel | Contact |
|---------|---------|
| General questions | chairman@theailab.org |
| VP accreditation | accreditation@theailab.org |
| Security issues | security@theailab.org |
| Bug reports | github.com/theailaborg/tip-protocol/issues |
| Documentation | docs: see docs/ directory in this repository |

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc.*
*Authored by Dinesh Mendhe. Licensed under TIPCL-1.0.*
