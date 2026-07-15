# TIP Protocol Deployment Guide

This document is for operators who want to run a TIP Protocol node. It
covers all three node types, the difference between a full node and a VP
node, and step-by-step instructions for getting from zero to a live node
in under 30 minutes.

---

## Three Node Types

| Type | Who Runs It | What It Does | Requires Accreditation? |
|------|-------------|-------------|------------------------|
| **Full Node** | Anyone | Validates transactions, stores the DAG, serves the REST API, participates in gossip | No |
| **VP Node** | Accredited Verification Providers | Everything a full node does, plus issues TIP-IDs to verified humans | Yes |
| **Archive Node** | Research institutions, compliance teams | Full node plus complete historical snapshots and long-term data retention | No |

**If you are running a node for the first time, you are running a full node.**
That is the default. A VP node is a full node running with additional
configuration (`TIP_NODE_TYPE=vp`, `TIP_VP_ID=...`) and an external
biometric pipeline that you build and operate separately.

---

## Full Node vs VP Node: The Critical Difference

The source code is identical. The same repository, the same `npm start`,
the same Docker image runs both.

What makes a VP node different is not the software. It is:

1. **An accredited VP keypair** issued by The AI Lab Intelligence Unobscured,
   Inc. at accreditation. Without this keypair, the node cannot sign
   `REGISTER_IDENTITY` transactions and cannot issue TIP-IDs.

2. **An external biometric verification pipeline** that you build and operate.
   The TIP Protocol reference implementation does not include biometric
   hardware or software. It provides the REST endpoint that receives the
   *output* of your biometric pipeline. Your pipeline must:
   - Verify government ID documents (OCR, NFC chip, tamper detection)
   - Run 3D facial liveness detection
   - Complete FIDO2/WebAuthn device binding
   - Compute the peppered dedup hash inside a device secure enclave
   - Generate the ZK uniqueness proof
   - Sign the resulting payload with the VP keypair
   - Call `POST /v1/identity/register` on the TIP node

3. **VP accreditation** from The AI Lab Intelligence Unobscured, Inc.
   Contact: accreditation@theailab.org

If you are running a full node, none of the above applies. You sync the
DAG, serve the REST API, and participate in the network. That is it.

---

## Prerequisites

| Item | Full Node | VP Node |
|------|-----------|---------|
| Node.js 20+ or Python 3.12+ | Required | Required |
| Docker and Docker Compose (optional) | Recommended | Recommended |
| Public IP address | Recommended for gossip | Required |
| Open ports 4000 (REST) and 4001 (gossip) | Recommended | Required |
| PostgreSQL | Recommended for production | Required |
| VP keypair from The AI Lab | Not needed | Required |
| Biometric hardware and pipeline | Not needed | Required |
| TIP VP accreditation | Not needed | Required |

---

## Option A: Docker Compose (Recommended, Under 30 Minutes)

This is the fastest path to a running node with PostgreSQL.

### Step 1: Clone the repository

```bash
git clone https://github.com/theailaborg/tip-protocol.git
cd tip-protocol
```

### Step 2: Configure your environment

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

Expected response:

```json
{
  "status": "ok",
  "version": "2.0.0",
  "chain_id": "tip-devnet-v2",
  "dag_count": 0
}
```

### Step 5: Seed the genesis block (first launch only)

```bash
docker compose exec tip-node node scripts/seed.js
```

This mints the genesis block, registers the founding VP, and writes the
genesis ring members to the DAG. You must complete this step before the
node is useful.

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

### Step 4: Seed (first launch only)

```bash
cd ..
node scripts/seed.js
```

---

## Option C: Manual Setup (Python)

```bash
git clone https://github.com/theailaborg/tip-protocol.git
cd tip-protocol/python
pip install cryptography click fastapi "uvicorn[standard]" pydantic websockets

cp ../.env.example ../.env
# Edit ../.env

python -m tip_node.main
```

Seed (first launch only):

```bash
python -m scripts.seed
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

**2. Clone via git (every node)** , `main` already carries the baked genesis.

```bash
git clone https://x-access-token:<TOKEN>@github.com/theailaborg/tip-protocol.git ~/tip-protocol
git -C ~/tip-protocol remote set-url origin https://github.com/theailaborg/tip-protocol.git
```

**3. Node identity + env (every node)** , owner must be uid 1001.

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

**4. Log directory permissions (GOTCHA)** , the compose bind-mounts
`./logs/node-1`, which docker creates root-owned, so the container cannot write
its per-level log files. Fix before first boot:

```bash
mkdir -p ~/tip-protocol/logs && sudo chown -R 1001:1001 ~/tip-protocol/logs
```

Skip this and the log dir stays empty (logs only reach docker stdout) and Loki
never gets the `level` label.

**5. Build (every node)** , bakes the genesis into the image.

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

**7. Validate** , across all nodes: `/health` shows `byzantineForkHalt=none`,
`joinState=ready`, `peers=<N-1>`, rounds advancing; same `genesis_hash`,
identities = genesis ring size, and the same committed tx count (converged).

**8. Observability** (obs host: Prometheus + Grafana + Loki + Caddy)

- **Metrics**: `infra/observability/prod/prometheus.yml` (gitignored) , job
  `tip-federation` (do NOT rename), targets = the nodes' **private** IPs `:4000`,
  `Bearer` = the shared `TIP_METRICS_TOKEN`, and `chmod 644` the file (a `sudo`
  edit that leaves it `root:600` crash-loops Prometheus). Verify
  `count(up{job="tip-federation"}==1)` returns N.
- **Logs**: promtail per node (`infra/observability/agent/`) , requires Step 4.
  `promtail.env`: `LOKI_URL=logs.<domain>`, `LOKI_PASSWORD=<plaintext>`,
  `NODE_LABEL=node<n>`; then `docker compose -f docker-compose.promtail.yml up -d`.
  It tags `node` + derives `level` from the per-level filenames. Set the Loki
  basic-auth (`LOKI_BASIC_AUTH_HASH` via `caddy hash-password`) in the obs `.env`.
- **DNS (GOTCHA)**: `logs.<domain>` must be **DNS-only (grey cloud), NOT
  Cloudflare-proxied** , Caddy owns TLS + basic-auth for the push; a proxy in
  front breaks the ACME challenge and the push times out. `grafana.<domain>`
  proxied is fine (browser UI).

---

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
- [ ] Port 4000 (REST API) is behind a reverse proxy (nginx, Caddo, or Cloudflare)

**Chain**

- [ ] The image was built from the correct `genesis-data/genesis.json` (the chain
  id and genesis are baked into the image, not set via env vars)
- [ ] Every node reports the **same `genesis_hash`** on `/health`
- [ ] The genesis founding identities are present (identities count = ring size)
  and consensus is advancing with `byzantineForkHalt=none`

**Monitoring**

- [ ] Uptime monitoring configured (alert if `/health` stops responding)
- [ ] Log aggregation configured (CloudWatch, Grafana Loki, or equivalent)
- [ ] Disk space monitoring on the data volume (DAG grows over time)

---

## VP Node Additional Configuration

If you are an accredited Verification Provider, add the following to your
`.env` after receiving your VP keypair and VP ID from The AI Lab.

```bash
TIP_NODE_TYPE=vp
TIP_VP_MODE=true
TIP_VP_ID=tip://id/VP-XX-yourorganisation
TIP_NODE_PRIVATE_KEY=<your_vp_private_key_hex>
TIP_NODE_PUBLIC_KEY=<your_vp_public_key_hex>
```

Your node will then be able to sign `REGISTER_IDENTITY` transactions.
Your biometric pipeline should call `POST /v1/identity/register` with
the following fields after completing all four biometric verification
layers for a user:

```json
{
  "tip_id":          "tip://id/XX-<16hex>",
  "region":          "XX",
  "public_key":      "<hex ML-DSA-65 public key>",
  "vp_id":           "tip://id/VP-XX-yourorganisation",
  "dedup_hash":      "<hex 64-char peppered hash>",
  "zk_dedup_proof":  "zkp:<64hex>",
  "vp_signature":    "<hex signature by VP private key over tip_id+dedup_hash>",
  "attested":        false
}
```

The `dedup_hash` is checked server-side for uniqueness and never written
to the DAG. Only the `zk_dedup_proof` (starting with `zkp:`) is published
to the DAG.

For the complete VP integration specification, contact:
accreditation@theailab.org

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
