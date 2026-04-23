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

### Run a Node (Node.js)

```bash
# Clone the repository
git clone https://github.com/theailab/tip-protocol.git
cd tip-protocol

# Install dependencies
npm install

# Configure
cp .env.example .env
# Edit .env: set TIP_JWT_SECRET, TIP_ADMIN_API_KEY, TIP_GENESIS_HASH

# Start the node
npm start

# Run tests
npm test

# Node API will be available at:
# REST API:  http://localhost:4000
# Gossip:    tcp://localhost:4001
```

### Register a Node on the DAG

Every peer's public key must be on the DAG (signed by the founding VP) before gossip auth will accept it — new nodes cannot self-register. This step is run by an existing operator who holds the founding VP key.

**Prerequisites**

```bash
ls genesis-data/founding-vp-keys.json   # must exist
curl -s http://localhost:4000/health    # must return ok
```

**Step 1.** Generate a keypair and write a `NODE_REGISTERED` tx to the DAG:

```bash
node scripts/register-peer-node.js \
  --name=<node-name> \
  --port=<node-port> \
  --peer=ws://<existing-node-host>:4000
```

**Step 2.** The script writes two files to `generated-nodes/<node-name>/`:

```
generated-nodes/<node-name>/
├── keys.json   # node_id, public_key, private_key, algorithm, approving_vp
└── .env        # TIP_NODE_ID, TIP_NODE_PRIVATE_KEY, TIP_NODE_PUBLIC_KEY,
                # PORT, TIP_DATA_DIR, TIP_DB_PATH, TIP_PEERS
```

**Step 3.** Deliver both files to the node operator out-of-band (Bitwarden Send, Signal, hardware token). The genesis seed (`genesis-data/seed.db`) already ships in the repo and does not need to be delivered.

---

### Starting a Node

This runbook is run by the node operator after receiving `keys.json` and `.env` from the registering operator.

**Step 1.** Clone the repo and install dependencies:

```bash
git clone https://github.com/theailab/tip-protocol.git
cd tip-protocol
npm install
```

**Step 2.** Place the delivered files in the repo:

```bash
mkdir -p generated-nodes/<node-name>
mv /path/to/delivered/keys.json generated-nodes/<node-name>/keys.json
cp /path/to/delivered/.env .env
chmod 600 generated-nodes/<node-name>/keys.json .env
```

**Step 3.** Open `.env` and adjust the deployment-specific values. Identity fields (`TIP_NODE_ID`, `TIP_NODE_PRIVATE_KEY`, `TIP_NODE_PUBLIC_KEY`) must remain exactly as delivered:

```bash
# ── Identity — from the registration bundle, do not regenerate ────────────
TIP_NODE_ID=<as delivered>
TIP_NODE_PRIVATE_KEY=<as delivered>
TIP_NODE_PUBLIC_KEY=<as delivered>

# ── Network — adjust per deployment ───────────────────────────────────────
PORT=4000
HOST=0.0.0.0
TIP_PUBLIC_URL=https://tip.example.org
TIP_PEERS=wss://node.theailab.org            # The AI Lab public bootstrap node
TIP_DATA_DIR=/var/lib/tip/data
TIP_DB_PATH=/var/lib/tip/data/tip.db

# ── Optional ──────────────────────────────────────────────────────────────
TIP_REGION=US
TIP_NODE_TYPE=full                           # full | light | vp | archive
TIP_VP_ID=                                   # set only for a VP node
TIP_LOG_LEVEL=info                           # debug | info | warn | error
TIP_CORS_ORIGINS=https://example.org         # comma-separated, or "*"

# ── Optional tuning (scheduler intervals in ms) ───────────────────────────
# TIP_SCORE_RECOMPUTE_MS=43200000
# TIP_CLEAN_RECORD_MS=86400000
# TIP_VERDICT_CHECK_MS=300000
# TIP_PEER_HEALTH_MS=30000

# ── Optional media size caps (bytes) ──────────────────────────────────────
# TIP_MAX_VIDEO_BYTES=5368709120
# TIP_MAX_IMAGE_BYTES=52428800
# TIP_MAX_AUDIO_BYTES=524288000
# TIP_MAX_TEXT_BYTES=10485760
```

> `TIP_PEERS` accepts a comma-separated list of `ws://` or `wss://` URLs — the node appends `/gossip` to each. `wss://node.theailab.org` is the public bootstrap node operated by The AI Lab; additional peers may be added as the federation grows.
>
> Regenerating the identity keys invalidates the DAG registration — the gossip handshake will fail with `Node authentication failed`.

**Step 4.** Open the firewall on `PORT` for inbound gossip WebSocket and HTTP.

**Step 5.** Start the node using either method:

Native (Node.js):

```bash
npm start --prefix node
```

Docker Compose:

```bash
docker compose up -d          # starts tip-node in the background
docker compose logs -f tip-node
```

The compose file reads `.env` from the repo root and mounts `./data` into the container at `/app/data`, so `TIP_DATA_DIR` and `TIP_DB_PATH` are set automatically inside the container. Only the `.env` values need to be configured — no additional Docker arguments are required.

On first boot, `genesis-data/seed.db` is auto-copied to `TIP_DB_PATH` (node/src/index.js:57-61) so the founding VP and genesis block are available immediately.

**Step 6.** Within ~10s, these log lines should appear:

```
Node registered as: <node_id>
Gossip: connected to peer wss://node.theailab.org
Gossip: node <peer-node-id> authenticated (registered)
Gossip: sync imported <N> transactions
```

Troubleshooting:
- `Node authentication failed` — identity env vars were edited or regenerated; restore the delivered values.
- `could not connect to wss://…` — firewall, DNS, TLS cert, or the peer node is down.

**Step 7.** Verify the API:

```bash
curl http://localhost:$PORT/health
curl http://localhost:$PORT/v1/constants
```

---

#### Environment variable ownership

| Delivered by operator         | Set by node runner          |
|-------------------------------|-----------------------------|
| `TIP_NODE_ID`                 | `PORT`                      |
| `TIP_NODE_PRIVATE_KEY`        | `TIP_DATA_DIR`              |
| `TIP_NODE_PUBLIC_KEY`         | `TIP_DB_PATH`               |
| `TIP_PEERS` (peer gossip URL) | `TIP_PUBLIC_URL`            |
| `genesis-data/seed.db`        | `TIP_CORS_ORIGINS`, TLS, supervisor, backups |

---

### Assigning Peers

`TIP_PEERS` is a comma-separated list of `ws://` or `wss://` URLs that a node dials on startup. The node appends `/gossip` to each URL (node/src/gossip.js:419) and retries with 30s backoff on disconnect (gossip.js:428-431). Inbound connections from any source are also accepted, provided the peer passes the ML-DSA challenge against the DAG node registry.

#### Every node lists every other node

For the pilot, every participating node must list all other nodes in its `TIP_PEERS`. Each pair of nodes therefore dials each other, producing two sockets per pair — one in each direction. This is what the current gossip implementation requires for bidirectional transaction propagation.

Example for a 4-node network (The AI Lab bootstrap plus three partners):

```
Node on node.theailab.org
  TIP_PEERS=wss://node.partner1.io,wss://node.partner2.com,wss://node.partner3.xyz

Node on node.partner1.io
  TIP_PEERS=wss://node.theailab.org,wss://node.partner2.com,wss://node.partner3.xyz

Node on node.partner2.com
  TIP_PEERS=wss://node.theailab.org,wss://node.partner1.io,wss://node.partner3.xyz

Node on node.partner3.xyz
  TIP_PEERS=wss://node.theailab.org,wss://node.partner1.io,wss://node.partner2.com
```

A transaction created on any node is broadcast to its three directly connected peers. Each peer validates, stores, and relays with TTL=2 (gossip.js:354-356); duplicates are deduplicated by `seenTx` (gossip.js:336-338). All four DAGs converge on the same state.

If one node goes offline, its sockets close on the remaining nodes and outbound connections retry with 30s backoff. The remaining nodes continue to gossip among themselves, and the mesh heals automatically when the node returns.

#### Bootstrapping a fresh node

A new node's DAG contains only what shipped in `genesis-data/seed.db` — it does not yet know about other peers' `NODE_REGISTERED` txs. The first successful handshake must therefore be with a node that already has those txs. After that handshake, `SYNC_REQUEST` / `SYNC_RESPONSE` (gossip.js:326-366) backfills the DAG and subsequent peer handshakes succeed.

For this reason, every `TIP_PEERS` list should include `wss://node.theailab.org` — the public bootstrap node operated by The AI Lab — so a fresh node can sync the registry on first boot.

#### TLS

`wss://` is terminated at the reverse proxy or load balancer in front of the node — the Node.js process itself serves plain HTTP + WebSocket on `PORT`. Nginx, Caddy, Cloudflare, or an L7 LB in front is sufficient; no TLS configuration inside the node is required.

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
