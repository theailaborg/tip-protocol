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
git clone https://github.com/theailab-org/tip-protocol.git
cd tip-protocol
```

### Step 2: Configure your environment

```bash
cp .env.example .env
```

Open `.env` and set the following values. Everything else can stay as the
default for a development node.

```bash
# REQUIRED: Generate a random 256-bit secret
# Run: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
TIP_JWT_SECRET=<your_random_256_bit_hex>
TIP_ADMIN_API_KEY=<your_random_256_bit_hex>

# REQUIRED: Set your chain (use tip-devnet-v2 for testing)
TIP_CHAIN_ID=tip-devnet-v2

# REQUIRED for mainnet: Get the canonical genesis hash from theailab.org/genesis
# TIP_GENESIS_HASH=<mainnet_genesis_hash>

# OPTIONAL: Connect to the main network bootstrap peers
# TIP_BOOTSTRAP_PEERS=node.theailab.org:4001,node2.theailab.org:4001

# OPTIONAL: Set your public URL (needed for correct gossip peer advertising)
# TIP_PUBLIC_URL=https://your-node-hostname.com
```

Also set the PostgreSQL credentials in `.env`:

```bash
POSTGRES_DB=tip_protocol
POSTGRES_USER=tip
POSTGRES_PASSWORD=<choose_a_strong_password>
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
git clone https://github.com/theailab-org/tip-protocol.git
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
git clone https://github.com/theailab-org/tip-protocol.git
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

## Production Checklist

Before exposing your node to the public internet or connecting to the
mainnet bootstrap peers, complete this checklist.

**Security**

- [ ] `TIP_JWT_SECRET` is a random 256-bit hex value (not the placeholder)
- [ ] `TIP_ADMIN_API_KEY` is a random 256-bit hex value (not the placeholder)
- [ ] `.env` is in `.gitignore` and has never been committed to any repository
- [ ] PostgreSQL password is strong and not the default `changeme_in_production`
- [ ] Ports 4000 and 4001 are behind a firewall; only open to intended traffic
- [ ] TLS is configured (Let's Encrypt or AWS Certificate Manager) for port 4000
- [ ] The node process runs as a non-root user (handled automatically by Docker)

**Network**

- [ ] `TIP_PUBLIC_URL` is set to your node's public HTTPS URL
- [ ] `TIP_BOOTSTRAP_PEERS` points to the mainnet bootstrap peers
- [ ] Port 4001 (gossip) is open for TCP from any IP
- [ ] Port 4000 (REST API) is behind a reverse proxy (nginx, Caddo, or Cloudflare)

**Chain**

- [ ] `TIP_CHAIN_ID=tip-mainnet-v2` (not `tip-devnet-v2`)
- [ ] `TIP_GENESIS_HASH` is set to the canonical mainnet genesis hash from theailab.org/genesis
- [ ] The genesis block and founding VP transactions are present in your DAG
  (verify: `curl http://localhost:4000/v1/dag/stats` shows `vp_count >= 1`)

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

**Node exits with "CHANGE_THIS_IN_PRODUCTION" error**
Set `TIP_JWT_SECRET` and `TIP_ADMIN_API_KEY` in your `.env` file to
random 256-bit hex values. The node refuses to start with placeholder secrets.

---

## Getting Help

| Channel | Contact |
|---------|---------|
| General questions | chairman@theailab.org |
| VP accreditation | accreditation@theailab.org |
| Security issues | security@theailab.org |
| Bug reports | github.com/theailab-org/tip-protocol/issues |
| Documentation | docs: see docs/ directory in this repository |

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc.*
*Authored by Dinesh Mendhe. Licensed under TIPCL-1.0.*
