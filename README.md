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

- Storage grows ~14 KB per DAG transaction (signature + canonical JSON). The DAG is append-only — there is no built-in pruning.
- Node.js 18+ and 64-bit OS are required (`better-sqlite3` and the post-quantum crypto bindings ship as native modules).

### Run a Node (Node.js)

```bash
# Clone the repository
git clone https://github.com/theailab/tip-protocol.git
cd tip-protocol

# Install dependencies
npm install

# Configure
cp .env.example .env
# Edit .env — see the node setup sections below
```

Each node exposes two ports that must be open in your firewall:

| Port | Variable | Default | Protocol |
|------|----------|---------|----------|
| REST API | `PORT` | 4000 | HTTP |
| libp2p P2P | `TIP_P2P_PORT` | 4001 | TCP |

---

### Founding VP Node (first-time setup, run by The AI Lab)

The founding node bootstraps the network: it generates the genesis block, registers the founding VP, and writes node keys to `.env`. Run this once on the machine that will host the first node.

**Step 1 — Bootstrap genesis:**

```bash
node --experimental-vm-modules scripts/seed.js
```

This produces:
- `genesis-data/founding-vp-keys.json` — VP signing key (chmod 600, **never commit**)
- `genesis-data/genesis.json` — signed genesis block
- `genesis-data/seed.db` — bootstrap DAG state
- `TIP_NODE_PRIVATE_KEY` / `TIP_NODE_PUBLIC_KEY` written to `.env`

**Step 2 — Configure `.env`:**

```ini
# Identity — auto-written by seed.js, do not change
TIP_NODE_ID=<auto>
TIP_NODE_PRIVATE_KEY=<auto>
TIP_NODE_PUBLIC_KEY=<auto>

# Network
PORT=4000
TIP_P2P_PORT=4001
TIP_PUBLIC_IP=<your-server-public-ip>
TIP_ENABLE_MDNS=false
TIP_BOOTSTRAP_PEERS=          # empty for the founding node

# Database (see Database Configuration below)
DB_DRIVER=postgres
DB_HOST=localhost
DB_NAME=tip_protocol
DB_USER=tip
DB_PASSWORD=secret

# Logging
TIP_LOG_LEVEL=info
TIP_CONSOLE_LEVEL=warn
```

**Step 3 — Start the node:**

Native (Node.js 18+):

```bash
node --env-file=.env node/src/index.js
```

Docker Compose (PostgreSQL default):

```bash
docker compose -f docker-compose.local.yml up postgres node1 -d
docker compose -f docker-compose.local.yml logs -f node1
```

**Step 4 — Confirm it is up and note the bootstrap address:**

```bash
curl -s http://localhost:4000/health | jq '.data.p2p'
# Returns: { joinState: "ready", bootstrap_addr: "/ip4/<ip>/tcp/4001/p2p/12D3..." }
```

Save the `bootstrap_addr` value — every other node uses it as `TIP_BOOTSTRAP_PEERS`.

---

### Registering Additional Nodes

Node registration must be run by the founding operator — it requires `genesis-data/founding-vp-keys.json` and a healthy founding node.

```bash
node scripts/register-node.js \
  --name "Partner Node Name" \
  --node-url http://localhost:4000 \
  --port 4100 \
  --p2p-port 4101 \
  --public-ip <new-node-public-ip>
```

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | `TIP Node <id>` | Human-readable node name |
| `--node-url` | `http://localhost:4000` | Any healthy node's API URL |
| `--port` | `4100` | REST API port the new node will use |
| `--p2p-port` | `port+1` | libp2p port the new node will use |
| `--public-ip` | `127.0.0.1` | New node's publicly-reachable IP |

The script writes two files to `generated_nodes/<slug>-<id>/`:

```
generated_nodes/<slug>-<id>/
├── <slug>.env          ← drop-in node config with ML-DSA-65 keys
├── <id>.tip.json       ← key backup (chmod 600)
└── data/               ← per-node data dir
```

**Deliver to the node operator out-of-band** (Bitwarden Send, Signal, hardware token):
- `<id>.tip.json` — key backup
- `<slug>.env` — config with embedded keys

> Regenerating or editing the identity keys invalidates the DAG registration. The node will fail consensus handshakes. Always restore the delivered values if they are accidentally changed.

---

### Starting a Registered Node (node operator runbook)

After receiving `<id>.tip.json` and `<slug>.env` from the registering operator:

**Native (Node.js 18+):**

```bash
# 1. Clone and install
git clone https://github.com/theailab/tip-protocol.git
cd tip-protocol
npm install

# 2. Place the delivered env file
cp /path/to/delivered/<slug>.env .env
chmod 600 .env

# 3. Adjust deployment-specific values in .env:
#      TIP_PUBLIC_IP        → this server's public IP
#      TIP_BOOTSTRAP_PEERS  → founding node's bootstrap_addr (from GET /health)
#      DB_DRIVER            → your database engine (postgres / mariadb / oracle / sqlite)
#      DB_HOST / DB_NAME / DB_USER / DB_PASSWORD → your database credentials
#      TIP_PUBLIC_URL       → public HTTPS URL of this node (optional)

# 4. Open firewall: PORT (REST API) and TIP_P2P_PORT (libp2p P2P)

# 5. Start
node --env-file=.env node/src/index.js
```

**Docker:**

```bash
# 1. Clone
git clone https://github.com/theailab/tip-protocol.git
cd tip-protocol

# 2. Place the delivered env file
cp /path/to/delivered/<slug>.env .env
chmod 600 .env
# Set TIP_PUBLIC_IP, TIP_BOOTSTRAP_PEERS, DB_* vars as above

# 3. Build the image (first time only)
docker build -t tip-protocol/node:2.0.0 .

# 4. Start with PostgreSQL (default)
docker compose -f docker-compose.local.yml up postgres node1 -d
docker compose -f docker-compose.local.yml logs -f node1
```

**Verify the node joined the network:**

```bash
curl -s http://localhost:$PORT/health | jq '.data'
# Look for:  joinState: "ready",  peer_count >= 1

curl -s http://localhost:$PORT/v1/constants
```

**Expected startup log sequence:**

```
libp2p started on port 4001
Bootstrap peer connected: /ip4/<ip>/tcp/4001/p2p/12D3...
Consensus: syncing rounds from peers...
Consensus: joinState → ready
API listening on 0.0.0.0:4000
```

**Troubleshooting:**

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `joinState: syncing` persists | `TIP_BOOTSTRAP_PEERS` unreachable | Check IP, port, and founding node firewall |
| `peer_count: 0` after startup | `TIP_PUBLIC_IP` not set or wrong | Set to this server's public IP |
| DB connection error | Wrong `DB_HOST` or credentials | For Docker, use the service name (`postgres`, `mariadb`, `oracle`) not `localhost` |
| Keys rejected by peers | Identity keys were edited | Restore the original delivered values from `<id>.tip.json` |

---

#### Environment variable reference

| Variable | Who sets it | Description |
|----------|-------------|-------------|
| `TIP_NODE_ID` | `register-node.js` | Node identity URI |
| `TIP_NODE_PRIVATE_KEY` | `register-node.js` | ML-DSA-65 private key — never change |
| `TIP_NODE_PUBLIC_KEY` | `register-node.js` | ML-DSA-65 public key — never change |
| `TIP_BOOTSTRAP_PEERS` | Node operator | Founding node libp2p multiaddr (from `GET /health → data.p2p.bootstrap_addr`) |
| `TIP_PUBLIC_IP` | Node operator | This server's public IP (for peer discovery) |
| `PORT` | Node operator | REST API port |
| `TIP_P2P_PORT` | Node operator | libp2p P2P port |
| `DB_DRIVER` | Node operator | Database engine (`postgres` / `mariadb` / `oracle` / `sqlite`) |
| `TIP_PUBLIC_URL` | Node operator | Public HTTPS URL (optional, shown in API responses) |
| `TIP_CORS_ORIGINS` | Node operator | Allowed CORS origins |

---

### Database Configuration

TIP Protocol supports four database engines. Switch by changing `DB_DRIVER` in `.env` — no code changes required.

| `DB_DRIVER` | Engine | npm package | Notes |
|-------------|--------|-------------|-------|
| `sqlite` | SQLite (file) | `better-sqlite3` | Installed — local dev only, no DB server needed |
| `postgres` | PostgreSQL | `pg` | Installed — production default |
| `mariadb` | MariaDB / MySQL | `mysql2` | Installed |
| `mysql` | MySQL | `mysql2` | Alias for `mariadb` |
| `oracle` | Oracle Database 23ai | `oracledb` | Installed (thin-mode, no Instant Client needed) |
| `mssql` | SQL Server | `mssql` | Install separately: `npm install --workspace=node mssql` |

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

Docker: `docker compose -f docker-compose.local.yml up postgres node1 -d`

**MariaDB / MySQL:**

```ini
DB_DRIVER=mariadb
DB_HOST=localhost        # Docker service name: mariadb
DB_PORT=3306
DB_NAME=tip_node1
DB_USER=tip
DB_PASSWORD=secret
```

Docker: `docker compose -f docker-compose.local.yml --profile mariadb up mariadb node1 -d`

**Oracle Database 23ai:**

```ini
DB_DRIVER=oracle
DB_HOST=localhost        # Docker service name: oracle
DB_PORT=1521
DB_NAME=FREEPDB1
DB_USER=tip              # tip_node2 / tip_node3 / tip_node4 for additional nodes
DB_PASSWORD=secret
```

Docker: `docker compose -f docker-compose.local.yml --profile oracle up -d`

> For remote or cloud databases, also set `DB_SSL=true` (and optionally `DB_SSL_REJECT_UNAUTHORIZED=true`).
> Connection pool defaults are `DB_POOL_MIN=2` / `DB_POOL_MAX=10` and apply to all server-side drivers.

---

### TLS and Reverse Proxy

The Node.js process serves plain HTTP on `PORT` — TLS is terminated at the reverse proxy or load balancer in front of it. Nginx, Caddy, Cloudflare, or any L7 LB is sufficient; no TLS configuration inside the node is required.

### Run a Node (Python)

```bash
# Clone and enter
git clone https://github.com/theailab/tip-protocol.git
cd tip-protocol/python

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env

# Start the node
python -m tip_node.main

# Run tests (201 tests)
python -m pytest tests/ -v
```

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
│   │   ├── dag.js               ← DAG engine
│   │   ├── identity.js          ← TIP-ID management
│   │   ├── content.js           ← Content registration
│   │   ├── trust.js             ← Score computation
│   │   ├── crypto.js            ← Post-quantum crypto
│   │   ├── gossip.js            ← Peer gossip protocol
│   │   └── api/                 ← REST API routes
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
└── scripts/                     ← Utilities and seed scripts
    └── seed.py                  ← Genesis block generation
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
| Documentation | https://docs.theailab.org |
| Protocol Spec | https://github.com/theailaborg/tip-protocol/blob/main/spec/TIP_Protocol_Specification_v4_0.md |
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
