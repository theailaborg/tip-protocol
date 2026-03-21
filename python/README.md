# TIP Protocol — Python Implementation

Full Python implementation of the Trust Identity Protocol v2.0.

## Setup

```bash
cd python
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

## Run Node

```bash
python -m tip_node.main
```

Server starts on `http://localhost:4000` by default.

## Run Tests

```bash
pytest tests/ -v
```

## Project Structure

```
python/
├── shared/          # Crypto primitives, constants, ZK verifier
│   ├── crypto.py    # ML-DSA-65 (Ed25519 stub), SHAKE-256, SHA-256
│   ├── constants.py # TX types, tiers, origin codes, score events
│   └── zk.py        # Groth16 ZK proof verifier (py_ecc)
├── tip_node/        # Node server implementation (primary)
│   ├── api.py       # REST API (stdlib http.server)
│   ├── dag.py       # DAG store (SQLite)
│   ├── scoring.py   # Trust scoring engine
│   ├── gossip.py    # TCP peer gossip layer
│   ├── config.py    # Configuration loader
│   ├── genesis.py   # Genesis block builder + validator
│   ├── logger.py    # Structured logging
│   ├── scheduler.py # Background tasks (merkle root, sync)
│   ├── main.py      # Entry point
│   └── validators/  # Transaction validation (4 layers)
├── node/            # Compatibility shims — re-exports from tip_node/ so
│                    #   `from node.dag import DAG` works alongside
│                    #   `from tip_node.dag import DAG`
├── sdk/             # Client SDK
│   └── client.py    # TIPClient, TIPIdentityClient, TIPContentClient, etc.
├── cli/             # Command-line interface
│   └── main.py      # `tip` CLI tool (Click)
├── scripts/         # Seed scripts
└── tests/           # Test suite (10 sections, ~150 checks)
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Node health check |
| GET | `/v1/node/info` | Node metadata + DAG stats |
| GET | `/v1/node/peers` | Connected peers |
| POST | `/v1/vp/register` | Register Verification Provider |
| GET | `/v1/vp/:vpId` | Resolve VP record |
| POST | `/v1/identity/register` | Register TIP-ID (requires VP signature + ZK proof) |
| GET | `/v1/identity/:tipId` | Resolve identity |
| GET | `/v1/identity/:tipId/score` | Get trust score + tier |
| POST | `/v1/content/register` | Register content with origin declaration |
| GET | `/v1/content/:ctid` | Resolve content record |
| POST | `/v1/content/:ctid/dispute` | File a dispute |
| POST | `/v1/content/:ctid/verify` | Verify content (jury eligible only) |
| GET | `/v1/revocations` | List revocations |
| POST | `/v1/revocations` | Create revocation |
| GET | `/v1/dedup/merkle-root` | Dedup registry merkle root |

## Environment Variables

See `.env.example` in the project root. Key variables:

- `TIP_NODE_PRIVATE_KEY` / `TIP_NODE_PUBLIC_KEY` — Node signing keypair
- `TIP_DB_PATH` — SQLite database path (default: `./data/tip.db`)
- `TIP_BOOTSTRAP_PEERS` — Comma-separated peer addresses
- `ZK_SKIP_VERIFY=true` — Skip ZK proof verification (tests only)

## License

SEE LICENSE IN LICENSE.txt

© 2026 The AI Lab Intelligence Unobscured, Inc.
