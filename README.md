# TIP Protocol: Trust Identity Protocol

> **The trust layer the internet was always missing.**

[![License: TIPCL-1.0](https://img.shields.io/badge/License-TIPCL--1.0-blue.svg)](./LICENSE.txt)
[![Protocol Spec: CC-BY 4.0](https://img.shields.io/badge/Spec-CC--BY%204.0-green.svg)](./spec/TIP_Protocol_Specification_v4.0.md)
[![Patent Pending](https://img.shields.io/badge/Patent-Pending-orange.svg)](./PATENTS.md)
[![Version](https://img.shields.io/badge/Version-2.0.0-navy.svg)](./CHANGELOG.md)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)]()
[![DAG](https://img.shields.io/badge/Ledger-Federated%20DAG-purple.svg)]()
[![Crypto](https://img.shields.io/badge/Crypto-Post--Quantum-red.svg)]()
[![Wikidata: Org](https://img.shields.io/badge/Wikidata-Q139715497-006699?logo=wikidata&logoColor=white)](https://www.wikidata.org/wiki/Q139715497)
[![Wikidata: Founder](https://img.shields.io/badge/Founder-Q139715509-006699?logo=wikidata&logoColor=white)](https://www.wikidata.org/wiki/Q139715509)

> Authored and maintained by **[The AI Lab Intelligence Unobscured, Inc.](https://www.wikidata.org/wiki/Q139715497)** ([theailab.org](https://theailab.org)). Inventor: **[Dinesh Mendhe](https://www.wikidata.org/wiki/Q139715509)**.

---

> **TIP Protocol Whitepaper, Version 1.0 is published.** The canonical public specification of the protocol (140 pages, eleven Parts, twelve Appendices, licensed CC BY 4.0) is available in PDF, HTML, EPUB, and DOCX at **[theailab.org/whitepaper](https://theailab.org/whitepaper)**. Citation: Mendhe, D. (2026). *TIP Protocol Whitepaper, Version 1.0: Trust Identity Protocol for the Verifiable Internet*. The AI Lab Intelligence Unobscured, Inc.

---

## What is TIP Protocol?

**TIP Protocol (Trust Identity Protocol)** is an open, federated, post-quantum cryptographic protocol that provides three things the internet has never had:

1. **Verified human identity**: provably one person, one account, backed by government ID and 3D biometric verification
2. **Signed content provenance**: every piece of content permanently bound to a declared origin (human-written, AI-assisted, AI-generated, or mixed)
3. **Deterministic public trust scores**: a 0-1000 reputation score computed from an immutable public ledger, reproducible by any node

TIP Protocol is to internet trust what HTTPS is to internet encryption. Before HTTPS, any data on the internet could be intercepted and tampered with. The solution was not a product: it was an open protocol that every browser, server, and platform adopted. TIP Protocol takes the same approach for trust in human identity and content origin.

```
tip://id/US-a3f8c91b2d4e7021     ← Verified human identity (TIP-ID)
tip://c/OH-7f2a91bc3d5e-a3f8     ← Content provenance record (TIP-CONTENT)
892 / 1000  [HIGHLY TRUSTED]     ← Public trust score (TIP-TRUST)
```

---

## Why This Exists

AI can now generate indistinguishable text, images, video, and audio at near-zero cost. Within a few years, no human will reliably distinguish AI-generated content from human-created content by inspection alone. Deepfakes have influenced elections. AI-cloned voices have enabled wire fraud. AI-written articles saturate search results.

Existing solutions all fail the same way:
- **Centralized verification services**: single points of failure
- **Content credentials (C2PA)**: no identity binding, no trust scores
- **Decentralized identifiers (DIDs)**: no content provenance, no scoring
- **AI detection**: arms race that no one wins

TIP Protocol reframes the problem: instead of asking the impossible question *"is this content fake?"*, it asks the tractable question *"does this content match what its creator declared?"*

---

## Three Protocol Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: TIP-ID (Identity)                                      │
│  Verified human bound to post-quantum keypair via 4-layer        │
│  biometric stack. One human, one TIP-ID. Federated, portable.   │
│  URI: tip://id/[REGION]-[ML_DSA_PUBKEY_HASH_16]                 │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: TIP-CONTENT (Provenance)                               │
│  Content hash + mandatory origin declaration (OH/AA/AG/MX)       │
│  signed by creator's TIP-ID and recorded on the federated DAG.  │
│  URI: tip://c/[ORIGIN]-[HASH14]-[ID_SHORT]                      │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: TIP-TRUST (Reputation)                                 │
│  Deterministic 0-1000 score computed from complete DAG history.  │
│  Any node, anywhere, computes the same score from the same data. │
│  No central database. No hidden manipulation.                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                    Federated DAG Network
              (anyone can run a node, anyone can verify)
```

---

## Quick Start

### 5-Minute Integration (HTTP Headers)

Add these to any web server: no SDK, no account, no code required:

```nginx
# Nginx
add_header X-TIP-Author       "tip://id/US-a3f8c91b2d4e7021";
add_header X-TIP-CTID         "tip://c/OH-7f2a91bc3d5e4a-a3f8";
add_header X-TIP-Origin       "OH";
add_header X-TIP-Signature    "[ML-DSA-65 signature base64]";
add_header X-TIP-Content-Bind "[domain-bind-hash]";
```

```apache
# Apache (.htaccess)
Header set X-TIP-Author       "tip://id/US-a3f8c91b2d4e7021"
Header set X-TIP-CTID         "tip://c/OH-7f2a91bc3d5e4a-a3f8"
Header set X-TIP-Origin       "OH"
Header set X-TIP-Signature    "[ML-DSA-65 signature base64]"
Header set X-TIP-Content-Bind "[domain-bind-hash]"
```

```html
<!-- HTML meta tags -->
<meta property="tip:author" content="tip://id/US-a3f8c91b2d4e7021" />
<meta property="tip:ctid"   content="tip://c/OH-7f2a91bc3d5e4a-a3f8" />
<meta property="tip:origin" content="OH" />
```

### System Requirements

A TIP node runs ML-DSA-65 signatures on every transaction and Groth16 ZK proofs on every identity registration. Both are CPU-bound, so single-core hosts are not sufficient even for a pilot.

| Tier | vCPU | RAM | Storage | Throughput target |
|------|------|-----|---------|-------------------|
| **Minimum** | 2 | 2 GB | 20 GB SSD | < 1K registrations / day |
| **Recommended** | 4 | 4 GB | 100 GB NVMe SSD | < 100K registrations / day |
| **High-traffic** | 8 | 8 GB | 500 GB+ NVMe SSD | > 100K registrations / day |

Notes:

- Storage grows ~14 KB per DAG transaction (signature + canonical JSON). Transient consensus data (certificates, equivocation votes, mempool, expired rotation participation) is pruned automatically by the cert-GC and rotation-boundary handlers; canonical state (transactions, identities, content, scores, commits, committee history) is retained as the authoritative ledger.
- Node.js 18+ and 64-bit OS are required (`better-sqlite3` and the post-quantum crypto bindings ship as native modules).

### Starting a Node

Two paths depending on whether you're running the canonical federation
or spinning up a local multi-node setup for development.

- **Production** — start the founding node that bootstraps the federation
  from `genesis.js`. This is the path The AI Lab runs in production. It
  is also the path needed by any operator running a registered node
  whose identity bundle was delivered out-of-band.
- **Development** — generate any number of additional nodes locally
  using `scripts/register-node.js`, each with isolated data, logs, and
  ports. Use this for local 2/3/4-node federations or for issuing
  registration bundles that get delivered to external operators.

---

#### Production: Run the Federation Founding Node

The genesis founding-node identity is baked into `genesis.js` at seed
time and never changes for the life of the federation. The AI Lab
delivers the operator a pre-filled `.env` file (founding-node ML-DSA-65
keys, port assignments, network defaults) along with the matching
`<id>.tip.json` key backup. Both files contain secrets and must be
`chmod 600`.

**Step 1.** Clone and install:

```bash
git clone https://github.com/theailab/tip-protocol.git
cd tip-protocol
npm install
```

**Step 2.** Drop the delivered `.env` at the repo root and back up the keys:

```bash
# .env file (delivered out-of-band — Bitwarden Send / Signal / hardware token)
cp /path/to/delivered/founding.env .env
chmod 600 .env

# Key backup — store off the live server (offline/cold storage)
cp /path/to/delivered/<id>.tip.json /secure/backups/<id>.tip.json
chmod 600 /secure/backups/<id>.tip.json
```

**Step 3.** Adjust the deployment-specific values in `.env`. Identity
fields (`TIP_NODE_ID`, `TIP_NODE_PRIVATE_KEY`, `TIP_NODE_PUBLIC_KEY`) and
ports come pre-filled — leave them as delivered. Update only:

```ini
# ── Network — adjust per host ─────────────────────────────────────────────
TIP_PUBLIC_IP=<this-server's-public-ip>      # required for libp2p reachability
TIP_PUBLIC_URL=https://tip.example.org       # optional, surfaced in API responses
TIP_CORS_ORIGINS=*                           # comma-separated origins, or "*"

# ── Database — pick one driver (see "Database Configuration" below) ──────
DB_DRIVER=postgres                           # sqlite | postgres | mariadb | mssql | oracle
DB_HOST=localhost                            # Docker service name when in compose
DB_PORT=5432
DB_NAME=tip_protocol
DB_USER=tip
DB_PASSWORD=<db-password>
```

The delivered `.env` already sets `TIP_DATA_DIR`, `TIP_DB_PATH`, and
`TIP_LOG_DIR` to per-node paths. Leave those as delivered.

**Step 4.** Open the firewall:
- `PORT` (REST API)
- `TIP_P2P_PORT` (libp2p TCP)

**Step 5.** Start.

Native:

```bash
npm start
```

Docker Compose:

```bash
docker compose up -d
docker compose logs -f tip-node
```

**Step 6.** Verify:

```bash
curl -s http://localhost:$PORT/health | jq '{joinState: .data.consensus.narwhal.joinState, halted: .data.consensus.halt.halted, peers: .data.peers.connected}'
# → { "joinState": "ready", "halted": false, "peers": 0 }    ← founding node alone

curl -s http://localhost:$PORT/health | jq -r '.data.p2p.bootstrap_addr'
# → "/ip4/<your-ip>/tcp/4001/p2p/12D3Koo..."
```

The `bootstrap_addr` is what every other node will use as
`TIP_BOOTSTRAP_PEERS` when it joins.

---

#### Development: Generate and Run Additional Nodes Locally

`scripts/register-node.js` issues a `NODE_REGISTERED` tx on the running
federation (signed by the founding VP) and writes a complete
self-contained bundle for the new node — including isolated `data/`
and `logs/` directories so multiple nodes on the same host don't
clobber each other. Use this both for local multi-node testing and for
producing the bundles that get delivered to external operators.

**Step 1.** Clone and install (skip if already done):

```bash
git clone https://github.com/theailab/tip-protocol.git
cd tip-protocol
npm install
```

**Step 2.** Generate a fresh genesis + founding-node + founding-VP keypair:

```bash
npm run seed:fresh
```

What this does (`scripts/seed.js`):
- Generates a new founding-VP ML-DSA-65 keypair → `genesis-data/founding-vp-keys.json`
- Generates a new founding-node ML-DSA-65 keypair → `genesis-data/founder-keys.json`
- Embeds the founding-node identity into `genesis.js`, `protocol-constants.js`, and `python/scripts/seed.py` (so all three implementations share the same chain anchor)
- Writes the canonical genesis block → `genesis-data/genesis.json`
- Writes a provenance record → `genesis-data/seed-output.json`

> **Why we can't reuse the committed `genesis.js`:** the founder private
> key (`genesis-data/founder-keys.json`) is `.gitignore`d for security
> and only exists on the machine that ran `seed`. Anyone cloning this
> repo therefore has the public-side genesis but cannot run the
> founding node without re-running `seed` to generate matching keys.
> Each `seed` run produces a new isolated dev federation — that's the
> intended behavior.

The plain `npm run seed` command is idempotent — re-running it on an
existing seed leaves keys in place and only regenerates derived files.
Use `seed:fresh` (which `rm -rf`s `genesis-data/` and `data/` first)
when you want a clean slate.

**Step 3.** Start the founding node — follow the **Production** section
above, but use the keys from your locally-generated
`genesis-data/founder-keys.json` to populate `.env`. Because the
founding-node `.env` doesn't get auto-generated, copy the template:

```bash
cp .env.example .env
chmod 600 .env
# Then paste TIP_NODE_ID / TIP_NODE_PRIVATE_KEY / TIP_NODE_PUBLIC_KEY
# from genesis-data/founder-keys.json into the corresponding fields,
# leave TIP_BOOTSTRAP_PEERS empty, and pick DB_DRIVER (sqlite is the
# fastest local option).
npm start
```

Once the founding node logs `joinState=ready` you can register
additional nodes against it.

**Step 4.** Generate one or more additional nodes:

```bash
node --experimental-vm-modules scripts/register-node.js \
  --name "Partner Node" \
  --node-url http://localhost:4000 \
  --port 4100 \
  --p2p-port 4101 \
  --public-ip 127.0.0.1
```

| Flag | Default | Description |
|---|---|---|
| `--name` | `TIP Node <id>` | Human-readable node name |
| `--node-url` | `http://localhost:4000` | Any healthy node's REST URL |
| `--port` | `4100` | REST API port for the new node |
| `--p2p-port` | `<port>+1` | libp2p TCP port for the new node |
| `--public-ip` | `127.0.0.1` | Publicly-reachable IP of the new node |

The script writes:

```
generated_nodes/<slug>-<short-id>/
├── <slug>.env          ← drop-in env file (ML-DSA-65 keys + ports + bootstrap multiaddr embedded)
├── <id>.tip.json       ← key backup, chmod 600
└── data/               ← per-node DB + keystore directory
```

The generated `.env` already sets `TIP_DATA_DIR`,
`TIP_DB_PATH=./generated_nodes/<slug>-<short-id>/data/tip.db`, and
`TIP_LOG_DIR=./logs/<slug>-<short-id>` so each node's storage stays
isolated.

**Start a generated node:**

```bash
node --env-file=./generated_nodes/<slug>-<short-id>/<slug>.env node/src/index.js
```

By default the generated node uses `DB_DRIVER=sqlite` (no extra setup).
For Postgres/MariaDB/MSSQL/Oracle, edit the generated `.env` and add
the `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD`
values for that node's database.

**Issuing bundles to external operators:** deliver the generated
`<slug>.env` and `<id>.tip.json` files out-of-band (Bitwarden Send,
Signal, hardware token). The recipient drops `<slug>.env` to `.env`
in their own clone of the repo, adjusts `TIP_PUBLIC_IP` and database
credentials, and runs `npm start`. Identity and `TIP_BOOTSTRAP_PEERS`
must NOT be regenerated — they're tied to the DAG registration.

#### Dev tooling — temp users and dispute-flow drivers

Two helper scripts make iterating on dispute flows tractable on a
local cluster:

- `scripts/seed-temp-users.js` — register N synthetic identities at
  varied scores so jury selection has a realistic pool to draw from
  (default: 50 users, 70% jury-eligible).
- `scripts/drive-jury.js` — auto-submit commit + reveal across all
  summoned jurors for a live dispute, optionally biased so the
  verdict lands UPHELD or DISMISSED.

CLI flags, the post-seed restart gotcha, and an end-to-end runbook
("file a dispute, drive it to a verdict in one developer session")
live in `scripts/README.md`.

---

#### Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Node tip://node/... not in registry` at handshake | Identity env vars were edited or regenerated. Restore the delivered values exactly, OR re-run `register-node.js` for that node. |
| `Genesis hash mismatch` at handshake | Wrong network / forked federation. The peer's `genesis.js` differs from yours. |
| `No bootstrap peers configured — discovery via mDNS only` | `TIP_BOOTSTRAP_PEERS` is empty. Founding nodes leave this empty intentionally; everyone else needs the founding node's `bootstrap_addr` here. |
| `joinState` stuck at `syncing` or `catching_up` | Bootstrap peer unreachable, or it is itself behind — check firewall, DNS, and the upstream peer's `/health`. |
| `DB connection error` (Postgres / MariaDB / Oracle) | For Docker, set `DB_HOST` to the **service name** (`postgres`, `mariadb`, `oracle`) not `localhost`. For native runs on the host, `localhost` is correct. |
| Multiple generated nodes sharing one `node/logs/` | `TIP_LOG_DIR` not set in the node's `.env`. Re-generate with the latest `register-node.js` (logs default to `./logs/<slug>-<short-id>`). |

---

#### Environment variable ownership

| In the founding `.env` (production) | In a generated `.env` (development / external operator) |
|---|---|
| `TIP_NODE_ID` (founder identity) | `TIP_NODE_ID` (registered identity, written by script) |
| `TIP_NODE_PRIVATE_KEY` | `TIP_NODE_PRIVATE_KEY` |
| `TIP_NODE_PUBLIC_KEY` | `TIP_NODE_PUBLIC_KEY` |
| `TIP_BOOTSTRAP_PEERS` empty | `TIP_BOOTSTRAP_PEERS=<founding bootstrap_addr>` |
| `PORT=4000`, `TIP_P2P_PORT=4001` | `PORT=<assigned>`, `TIP_P2P_PORT=<assigned>` |
| `TIP_DATA_DIR=./data`, `TIP_LOG_DIR=./logs/node-1` | per-node `./generated_nodes/<slug>/data` + `./logs/<slug>` |
| Operator-set: `TIP_PUBLIC_IP`, `TIP_PUBLIC_URL`, `TIP_CORS_ORIGINS`, `DB_DRIVER` + DB credentials | Same |

---

### Database Configuration

TIP Protocol supports five database engines. Switch by changing `DB_DRIVER` in `.env` — no code changes required.

| `DB_DRIVER` | Engine | npm package | Notes |
|-------------|--------|-------------|-------|
| `sqlite` | SQLite (file) | `better-sqlite3` | Installed — local dev only, no DB server needed |
| `postgres` | PostgreSQL | `pg` | Installed — production default |
| `mariadb` | MariaDB / MySQL | `mysql2` | Installed |
| `mysql` | MySQL | `mysql2` | Alias for `mariadb` |
| `oracle` | Oracle Database 23ai | `oracledb` | Installed (thin-mode, no Instant Client needed) |
| `mssql` | SQL Server | `mssql` | Installed |

**SQLite — local dev (no DB server):**

```ini
DB_DRIVER=sqlite
TIP_DB_PATH=./data/tip.db
```

**PostgreSQL — production default:**

```ini
DB_DRIVER=postgres
DB_HOST=localhost        # Docker service name: postgres
DB_PORT=5432
DB_NAME=tip_protocol
DB_USER=tip
DB_PASSWORD=secret
```

Docker: `docker compose -f docker-compose.local.yml --profile postgres up -d`

**MariaDB / MySQL:**

```ini
DB_DRIVER=mariadb
DB_HOST=localhost        # Docker service name: mariadb
DB_PORT=3306
DB_NAME=tip_protocol
DB_USER=tip
DB_PASSWORD=secret
```

Docker: `docker compose -f docker-compose.local.yml --profile mariadb up -d`

**Oracle Database 23ai:**

```ini
DB_DRIVER=oracle
DB_HOST=localhost        # Docker service name: oracle
DB_PORT=1521
DB_NAME=FREEPDB1         # service name, not SID
DB_USER=tip
DB_PASSWORD=secret
```

Docker: `docker compose -f docker-compose.local.yml --profile oracle up -d`

**SQL Server 2022:**

```ini
DB_DRIVER=mssql
DB_HOST=localhost        # Docker service name: mssql
DB_PORT=1433
DB_NAME=tip_protocol
DB_USER=sa
DB_PASSWORD=StrongPass123!   # must meet SQL Server complexity rules
DB_SSL=true
DB_SSL_REJECT_UNAUTHORIZED=false   # dev only — self-signed cert
```

Docker: `docker compose -f docker-compose.local.yml --profile mssql up -d`

> For remote or cloud databases, also set `DB_SSL=true` (and optionally `DB_SSL_REJECT_UNAUTHORIZED=true`).
> Connection pool defaults are `DB_POOL_MIN=2` / `DB_POOL_MAX=10` and apply to all server-side drivers.
> The Knex adapter uses an in-memory mirror for reads + fire-and-forget for writes (see `node/src/db/knex-adapter.js`).

---

### Media Storage (local / S3)

Registered content can carry media attachments (images, audio). Media
bytes are content-addressed (`media_id = SHAKE-256(bytes)`, deduplicated
by construction) and are NOT stored on chain; only the hash references
are. Access is restricted to the five roles with standing on the content
(author, assigned reviewer, disputer, juror, expert reviewer), and a
three-stage retention sweep deletes bytes after their dispute-relevance
window (21d base, 7d post-adjudication, 7d post-appeal); the on-chain
hashes remain verifiable forever.

Two interchangeable storage backends:

| Backend | Use | Env |
|---------|-----|-----|
| `fs` (default) | development, single machine | `TIP_MEDIA_BACKEND=fs`, `TIP_MEDIA_FS_PATH=./data/media` |
| `s3` | production | `TIP_MEDIA_BACKEND=s3` + bucket/region/KMS vars |

Storage is **per-node**: each operator provisions, pays for, and serves
their own bucket; peers fetch media through the origin node's API, never
from each other's buckets.

Setting up the S3 backend is one command (creates the bucket, encryption
key, and node credentials in ~10 minutes, for any host: EC2, EKS,
Hetzner, dev laptop):

```bash
cd infra/s3-media
cp terraform.tfvars.example terraform.tfvars   # fill 3 values
./setup.sh                                     # prints the env block for the node
```

Full start-to-end guide (including how to get AWS credentials):
[`infra/s3-media/README.md`](./infra/s3-media/README.md). Operator
runbook with console paths and smoke tests:
[`docs/PROD_S3_SETUP.md`](./docs/PROD_S3_SETUP.md).

---

### TLS and Reverse Proxy

The Node.js process serves plain HTTP on `PORT` and plain TCP libp2p on
`TIP_P2P_PORT` — TLS is terminated at the reverse proxy or load
balancer in front of it. Nginx, Caddy, Cloudflare, or any L7 LB is
sufficient; no TLS configuration inside the node is required.

For libp2p connections to remote peers, secure transport (Noise / TLS
1.3) is handled inside the libp2p stack itself — independent of any
reverse proxy in front of the REST API.

---

### Observability (Prometheus + Grafana)

Each node exposes Prometheus-format metrics on `GET /metrics` over its
REST port. A ready-to-run local stack (Prometheus + Grafana with the
`TIP Federation` dashboard pre-loaded) lives in `infra/observability/`:

```bash
cd infra/observability
cp .env.example .env       # edit if you want non-default creds or node list
docker compose up -d
```

- Grafana → http://localhost:3030  (defaults `admin` / `admin`)
- Prometheus → http://localhost:9090

Add or remove scrape targets by editing `TIP_NODE_TARGETS` in `.env`,
no edit of `prometheus.yml` needed. Full setup, configuration, and
production-hardening notes are in
[`infra/observability/README.md`](./infra/observability/README.md).

---

### Drop-in Badge Widget

```html
<!-- Load once -->
<script src="https://badge.theailab.org/tip-badge.min.js" defer></script>

<!-- Use anywhere -->
<tip-badge tip-id="tip://id/US-a3f8c91b" size="120" variant="gold-dark"></tip-badge>
<tip-badge type="mark" size="80" variant="light"></tip-badge>
<tip-badge auto size="80"></tip-badge>
```

---

## Origin Declaration System

Every piece of content registered through TIP Protocol carries a mandatory origin declaration. There are four categories:

| Code | Label | Meaning | Visual |
|------|-------|---------|--------|
| `OH` | Original Human | Created entirely by the uploader without AI generation tools | Blue shield |
| `AA` | AI-Assisted | Human primary author; AI tools used for enhancement | Purple shield |
| `AG` | AI-Generated | AI primary creator; human role was prompting or curation | Amber shield |
| `MX` | Mixed/Composite | Multiple sources, some human and some AI | Gray shield |

**Conservative labelling is never penalised.** If you declare content as AI-Generated when it was actually human-created, there is zero penalty. The system incentivises over-disclosure.

---

## Trust Score System

| Score | Tier | Shield | Meaning |
|-------|------|--------|---------|
| 850-1000 | HIGHLY TRUSTED | ✓ Green | Exceptional long-term record of consistent, honest origin declarations |
| 650-849 | TRUSTED | ✓ Blue | Established credibility, accurate origin labelling over time |
| 400-649 | VERIFIED | ✓ Gold | Identity confirmed by accredited VP, no violations. Default starting tier |
| 200-399 | CAUTION | ⚠ Amber | Mislabelling incidents or unresolved disputes on record |
| 0-199 | NOT TRUSTED | ✗ Red | Severe or repeated violations, identity may be suspended |

Scores are computed deterministically from the DAG. Any protocol-compliant node produces the same score for any TIP-ID from the same DAG history. There is no central score database and no hidden manipulation.

---

## Post-Quantum Cryptography

TIP Protocol mandates post-quantum cryptography at the protocol level. Every conforming implementation MUST use these algorithms:

| Function | Algorithm | Standard | Key/Sig Size |
|----------|-----------|----------|-------------|
| Primary signatures | ML-DSA-65 (Dilithium) | FIPS 204 | PK: 1.9KB, Sig: 3.3KB |
| Root signatures | SLH-DSA-128s (SPHINCS+) | FIPS 205 | PK: 32B, Sig: 7.8KB |
| Key encapsulation | ML-KEM-768 (Kyber) | FIPS 203 | PK: 1.1KB |
| Hashing | SHAKE-256 / SHA-3 | FIPS 202 | 256-bit output |

Hybrid signatures (Ed25519 + ML-DSA-65) are used during the transition period (Years 1-3) for backward compatibility.

---

## Federated DAG Network

TIP Protocol uses a Directed Acyclic Graph (DAG), not a blockchain:

- **No proof-of-work**: no energy-intensive mining
- **Parallel processing**: each transaction references two prior transactions
- **Throughput**: exceeds 5,000 transactions per second
- **Anyone can run a node**: no permission required
- **Full decentralization roadmap**: Phase 1 (coordinator), Phase 2 (21 validators), Phase 3 (self-validating at 100 TPS)

### Node Types

| Type | Role | Who Runs It |
|------|------|-------------|
| Full Node | Complete DAG history, independent verification | Enterprises, universities, NGOs |
| Light Node | Recent transactions + Merkle proofs | Browser extensions, mobile apps |
| VP Node | Full node + biometric hardware, mints TIP-IDs | Accredited Verification Providers |
| Archive Node | Complete DAG + historical snapshots | Academic institutions |

---

## Verification Provider (VP) Accreditation

Any organisation can become a Verification Provider and issue TIP-IDs by:

1. Implementing the four-layer biometric verification stack
2. Passing an independent security audit
3. Signing the TIP-VP Code of Conduct
4. Receiving accreditation from The AI Lab Intelligence Unobscured, Inc.

**Category A**: Identity-native organisations (banks, telecom, biometric companies like iProov, Jumio, Yoti)  
**Category B**: Content platforms and journalism organisations (news publishers, CPJ, RSF, SPJ)  
**Category C**: Government digital identity programmes (EU eIDAS, UK DSIT, Estonia e-Residency)  
**Category D**: Educational institutions (universities, colleges, research institutes)

To apply for VP accreditation: **accreditation@theailab.org**

---

## REST API Reference

```bash
# Resolve a TIP-ID
GET /v1/identity/:tipId

# Get trust score only
GET /v1/identity/:tipId/score

# Resolve content provenance
GET /v1/content/:ctid

# Look up content by hash (Creator Mode)
GET /v1/content/by-hash/:canonicalHash

# Register new content
POST /v1/content/register

# File a dispute
POST /v1/content/:ctid/dispute

# Revocation list
GET /v1/revocations

# Node health
GET /v1/health

# DAG statistics
GET /v1/stats
```

Full API documentation: [docs/API.md](./docs/API.md)

---

## GDPR and Privacy

TIP Protocol is designed from the ground up for GDPR compliance:

- **Zero raw biometrics stored**: facial scans produce a SHAKE-256 hash only; raw data is destroyed in the device secure enclave
- **Peppered deduplication hash**: device-held pepper prevents nation-state reidentification attacks
- **ZK proof on DAG**: deduplication is proven without revealing the hash
- **Score visibility modes**: FULL_PUBLIC / TIER_ONLY (default) / VERIFIED_ONLY
- **Article 17 erasure**: score history can be erased while preserving content provenance
- **DPIA published** before any European deployment
- **DPO appointed** as required by Article 37

---

## Repository Structure

```
tip-protocol/
├── README.md                    ← You are here
├── LICENSE.txt                  ← TIP Community License v1.0 (TIPCL-1.0)
├── NOTICE.txt                   ← Required attribution notice
├── PATENTS.md                   ← Patent disclosure
├── CONTRIBUTING.md              ← How to contribute
├── CODE_OF_CONDUCT.md           ← Community standards
├── SECURITY.md                  ← Security policy and disclosure
├── CHANGELOG.md                 ← Version history
├── .env.example                 ← Environment variable template
├── .gitignore                   ← Git ignore rules
│
├── spec/                        ← Protocol specification (CC-BY 4.0)
│   └── TIP_Protocol_Specification_v4.0.md
│
├── docs/                        ← Extended documentation
│   ├── API.md                   ← Full REST API reference
│   ├── GETTING_STARTED.md       ← Step-by-step integration guide
│   ├── VP_ACCREDITATION.md      ← How to become a Verification Provider
│   ├── GDPR_COMPLIANCE.md       ← GDPR and privacy architecture
│   ├── CRYPTOGRAPHY.md          ← Post-quantum cryptography details
│   └── BADGE_DESIGN.md          ← Visual badge specifications
│
├── node/                        ← Node.js reference implementation
│   ├── package.json
│   ├── src/
│   │   ├── index.js             ← Entry point
│   │   ├── dag.js               ← DAG engine + SQLite store + MemoryStore
│   │   ├── genesis.js           ← Genesis bootstrap
│   │   ├── api.js, routes/      ← REST API
│   │   ├── services/            ← Identity, content, dispute, governance, ...
│   │   ├── consensus/           ← Narwhal/Bullshark, commit-handler, rotation-coord
│   │   ├── network/             ← libp2p, handshake, peer-discovery
│   │   ├── sync/                ← Snapshot install, anti-entropy, peer-sync
│   │   ├── validators/          ← Tx validator, business rules
│   │   ├── db/                  ← Multi-DB adapter (Knex: pg/mariadb/mssql/oracle)
│   │   └── middleware/          ← Express error handler, request id, validation
│   └── tests/
│
├── python/                      ← Python reference implementation
│   ├── requirements.txt
│   ├── setup.py
│   ├── tip_node/
│   │   ├── __init__.py
│   │   ├── dag.py
│   │   ├── identity.py
│   │   ├── content.py
│   │   ├── trust.py
│   │   ├── crypto.py
│   │   └── api/
│   └── tests/
│
├── sdk/                         ← JavaScript SDK for platform integration
├── cli/                         ← Command-line tools
├── browser-extension/           ← [Moved to github.com/theailaborg/tip-extension]
├── badge/                       ← <tip-badge> web component
└── scripts/                     ← Utilities
    ├── seed.js                  ← Genesis block generation (founding-node bootstrap)
    ├── register-node.js         ← Issue NODE_REGISTERED tx + emit per-node bundle
    └── zk-setup.js              ← Groth16 trusted-setup helper
```

---

## Licensing

TIP Protocol uses a layered licensing model:

| Asset | License | Details |
|-------|---------|---------|
| Protocol Specification | **CC-BY 4.0** | Free for everyone, forever. Attribution required. |
| Reference Implementation | **TIPCL-1.0** | Free under $100K revenue. Paid above. Converts to Apache 2.0 on January 1, 2031. |
| TIP™ Trademarks | **Trademark Law** | Reserved by The AI Lab. Separate license required. |
| Patent Claims (16 inventions, A-P) | **Patent Law** | Included in TIPCL commercial license. Valid to ~2047. |

**Free for:** Individuals · Nonprofits · Journalism organisations · Governments · Education · Businesses under $100K annual revenue

**Requires a Commercial License:** Any entity with Annual Revenue exceeding USD $100,000 using TIP Protocol in a revenue-generating product or service.

Mandatory attribution for all users:
```
Built on TIP Protocol by The AI Lab Intelligence Unobscured, Inc.
theailab.org | Licensed under TIPCL-1.0
```

See [LICENSE.txt](./LICENSE.txt) for full terms.  
Commercial licensing: **licensing@theailab.org**

---

## Contributing

We welcome contributions from the community. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a pull request.

**Good first issues:** documentation improvements, additional language SDKs, test coverage  
**Core protocol changes:** require RFC process (see [docs/RFC_PROCESS.md](./docs/RFC_PROCESS.md))  
**Security vulnerabilities:** see [SECURITY.md](./SECURITY.md): do not open a public issue

---

## Trademarks

**TIP™**, **AI Trust ID™**, **AI Trust Registry™**, and **The Global Seal of Trust™** are trademarks of The AI Lab Intelligence Unobscured, Inc. This repository and its license do not grant any rights to use these marks. See [TRADEMARKS.md](./TRADEMARKS.md) for permitted uses.

---

## Patents

This software implements inventions that are the subject of pending U.S. patent applications filed by Dinesh Mendhe and assigned to The AI Lab Intelligence Unobscured, Inc. See [PATENTS.md](./PATENTS.md) for details.

---

## Links

| Resource | URL |
|----------|-----|
| Website | https://theailab.org |
| **Whitepaper v1.0** (canonical) | **https://theailab.org/whitepaper** |
| Whitepaper PDF | https://theailab.org/whitepaper/TIP_Protocol_Whitepaper_v1_0.pdf |
| Whitepaper errata | https://theailab.org/whitepaper/errata |
| Documentation | https://docs.theailab.org |
| Protocol Spec | https://github.com/theailaborg/tip-protocol/blob/main/spec/TIP_Protocol_Specification_v5_0.md |
| Badge Widget | https://badge.theailab.org |
| Verify a TIP-ID | https://vp.theailab.org/verify-record |
| Create a TIP-ID | https://vp.theailab.org/get-verified |
| VP Accreditation | https://theailab.org/accreditation |
| Commercial Licensing | https://theailab.org/licensing |
| TIP License (TIPCL-1.0) | https://github.com/theailaborg/tip-protocol/blob/main/LICENSE.txt |
| TIP Patents | https://github.com/theailaborg/tip-protocol/blob/main/PATENTS.md |
| TIP Trademarks | https://github.com/theailaborg/tip-protocol/blob/main/TRADEMARKS.md |
| TIP Privacy Policy | https://theailab.org/tip-privacy-policy |
| Security Disclosures | security@theailab.org |
| General Contact | tip@theailab.org |

---

## Genesis Block
The TIP Protocol network was founded on a genesis block signed by The AI Lab's SLH-DSA-128s root keypair. Every transaction on every node everywhere traces back to this genesis block. The genesis hash is compiled into every conforming node implementation.

**Chain ID:** `tip-mainnet-v2`  
**Founding Organisation:** The AI Lab Intelligence Unobscured, Inc.  
**Founded by:** Dinesh Mendhe  
**Genesis Ring:**  
· Dinesh Mendhe  
· Tushar Bhendarkar  
· The AI Lab Executive Leadership Members  
· [External validators to be confirmed at launch]

---
<div align="center">

**Copyright 2026 The AI Lab Intelligence Unobscured, Inc.**  
**Authored by Dinesh Mendhe · theailab.org**

*TIP™ · AI Trust ID™ · AI Trust Registry™ · The Global Seal of Trust™*  
*Trademarks of The AI Lab Intelligence Unobscured, Inc.*

</div>
