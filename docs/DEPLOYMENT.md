# TIP Protocol Deployment Guide

Pick your situation:

- You received a credentials bundle from The AI Lab and want your node on
  mainnet: [Joining an Existing Federation](#joining-an-existing-federation-partner-node).
- Your node is running and a new version is out: [Upgrading a node](#upgrading-a-node).
- You want to develop against the protocol on your laptop: [Development chain](#development-chain).
- You are founding a brand-new federation (Lab only): [`FOUNDING_FEDERATION.md`](./FOUNDING_FEDERATION.md).

---

## What a node is

Every TIP node is the same **full node**: it validates transactions, stores the
DAG, serves the REST API and takes part in consensus. There is no other node
type (`TIP_NODE_TYPE` stays `full`). Issuing TIP-IDs to people is done by the
separate Verification Provider application run by The AI Lab, which talks to a
node as a client; running a node never involves a VP key or biometrics.

The chain's genesis is committed in `genesis-data/genesis.json` and baked into
the Docker image. **Nobody seeds to run a node.** `scripts/seed.js` mints a
brand-new chain; run on a node meant to join mainnet it leaves that node with a
different `genesis_hash`, zero peers and `join_state: syncing` forever.

## Requirements

| | |
|---|---|
| Host | 4 cores, 8 GB RAM, 20 GB disk, Ubuntu or any Docker host; details in [`NODE_REQUIREMENTS.md`](./NODE_REQUIREMENTS.md) |
| Network | static public IP, inbound TCP **4000** (API) and **4001** (gossip), 25 Mbit/s sustained both ways |
| Software | Docker Engine with Compose (Docker Engine without Desktop also needs the `docker-buildx` plugin) |
| Domain | `https://<your-node-domain>` terminating TLS in front of `:4000` (reverse proxy or tunnel) |
| From The AI Lab | the credentials bundle (`node.env`, your node key), plus the log-shipping label and password |

---

## Joining an Existing Federation (partner node)

The chain already exists. Your node mints nothing; it proves it agrees with
everyone else. The AI Lab team has already registered your organization and
your node on chain and sent you the bundle; the zip password arrives on a
separate channel.

**1. Clone and place the credentials.**

```bash
git clone https://github.com/theailaborg/tip-protocol.git ~/tip-protocol
cd ~/tip-protocol
cp <bundle>/NODE-KEY__tip-node-<id>.tip.json genesis-data/backups/tip-node-<id>.tip.json
cp <bundle>/node.env .env                     # compose reads .env, not node.env
mkdir -p data logs/node-1
sudo chown -R 1001:1001 genesis-data/backups data logs   # 1001 is the container user
sudo chmod 600 genesis-data/backups/tip-node-<id>.tip.json
```

The `ORG-IDENTITY__*.tip.json` from the bundle does **not** go on this host. It
signs as your company, not as the node; keep it offline. Without `sudo`, create
`data/` and `logs/node-1/` yourself so the container user can write them.

**2. Confirm the chain.**

```bash
python3 -c "import json;print(json.load(open('genesis-data/genesis.json'))['genesis_hash'][:8])"   # d4666ce1 on mainnet
```

**3. Edit only what is yours in `.env`.** The delivered file is complete except
for the values only you know:

| line | what to do |
|---|---|
| `DB_PASSWORD=CHANGE_ME_STRONG_DB_PASSWORD` | always: choose a strong password; the compose stack creates the database with it |
| `TIP_PUBLIC_IP`, `TIP_PUBLIC_URL`, `TIP_API_ENDPOINT` | only if they still read `CHANGE_ME`: your static IP and `https://<your-node-domain>` |
| `TIP_CLASSIFIER_CALLBACK_SECRET` | only if The AI Lab gave you one (empty means the node polls for verdicts, which also works) |

Leave everything else as delivered (bootstrap peers, classifier URL and key,
metrics token, CORS, ports, `NODE_ENV=production`) and never add a
`TIP_*_ACTIVATION_MS` line: a different value forks your node.

**4. Start and wait for sync.**

```bash
sudo docker compose build tip-node && sudo docker compose up -d
curl -s http://localhost:4000/ready | python3 -m json.tool
```

`join_state` goes `syncing` → `catching_up` → `ready` while the node downloads
a snapshot (minutes). A dropped transfer restarts it; repeated restarts mean an
unstable link, not a broken node.

**5. Verify.** Open `https://<your-node-domain>/status` (or
`http://localhost:4000/status`): it is all green only when the node is reachable,
caught up, not halted, connected to a genesis node and agreeing on the state
root. The same three facts by hand:

```bash
curl -s http://localhost:4000/ready       # ready:true, halted:false
curl -s http://localhost:4000/health      # data.peers.connected >= 1  (peers only connect on the right genesis)
curl -s http://localhost:4000/v1/state-root ; curl -s https://node.theailab.org/v1/state-root
```

Equal `state_merkle_root` at equal `round` means your whole state is identical
to the federation's. Rounds advance every ~2 s, so compare the same round.

**6. Announce your domain** once `https://<your-node-domain>/health` answers
(the federation stores the URL on chain, The AI Lab scrapes `/metrics` through
it, people open `/status`):

```bash
curl -X POST http://localhost:4000/v1/node/endpoint/announce
```

The node probes its own domain first. `fetch failed` right after creating the
DNS record means the container cached the earlier "no such name" answer: wait
or recreate the container, then announce again. Your URL then shows as
`api_endpoint` in `https://node.theailab.org/v1/nodes`.

**7. Media storage before real traffic.** The delivered env writes media to the
node disk (`TIP_MEDIA_BACKEND=fs`). Production uses S3 with SSE-KMS:

- *Your own bucket* (recommended): follow [`PROD_S3_SETUP.md`](./PROD_S3_SETUP.md),
  then set `TIP_MEDIA_BACKEND=s3`, `TIP_MEDIA_S3_BUCKET`, `TIP_MEDIA_S3_REGION`,
  `TIP_MEDIA_S3_KMS_KEY_ID`. The instance role signs; no AWS keys in the env.
- *A bucket provided by The AI Lab*: you receive an access key scoped to the
  `media/` prefix; set the same four values plus `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY`, and rotate that key every 90 days.

Then `sudo docker compose up -d --force-recreate tip-node`, upload one image
against your node and confirm the object appears under `media/` in the bucket.
Tell The AI Lab team the bucket host so the classifier may download from it.

**8. Ship logs.** Create `infra/observability/agent/promtail.env` with
`LOKI_URL=logs.theailab.org` plus the `NODE_LABEL` and `LOKI_PASSWORD` The AI
Lab gave you, then:

```bash
cd infra/observability/agent && docker compose -f docker-compose.promtail.yml up -d
```

Your node appears under its label in the federation dashboard within a minute; a
`401` in `docker logs tip-promtail` means the password does not match. Details
and the macOS mount adjustment: [`PARTNER_LOG_SHIPPING.md`](./PARTNER_LOG_SHIPPING.md).

**Metrics** need nothing from you beyond step 6: The AI Lab adds
`<your-node-domain>:443` to its Prometheus targets.

**No static IP or inbound 4001?** The node still works outbound-only: it dials
the federation, nobody dials it, and the API reaches the internet through a
tunnel to `localhost:4000`. Then `TIP_PUBLIC_IP` stays empty and
`TIP_BOOTSTRAP_PEERS` **must list all three founding nodes**. It is a degraded
setup; agree it with The AI Lab team first.

---

## Upgrading a node

Releases are tags on `main` (`v2.7.9`). One node at a time, never two down at
once; on a 3-node federation quorum is 2. Order: the node that others bootstrap
from goes last. Run on the node host:

```bash
cd ~/tip-protocol && git fetch --tags origin
scripts/upgrade-node.sh v2.7.9 https://node.theailab.org     # peer = a node NOT being upgraded now
```

Good output, in order: `== genesis unchanged`, `== build ok`, the gate's
per-table roots ending in `MATCH: safe to restart`, `== READY after NNs`,
`RestartCount=0`. The script refuses to run if your genesis file differs from
the committed one or would change at the tag, checks out the tag, rebuilds the
image, stops the node, runs `scripts/check-boot-root.js --migrate` to prove the
database rebuilds to the live root of the untouched peer, and starts the node
only on `MATCH`. On a macOS Docker host prefix it with
`NODE_OPTIONS=--dns-result-order=ipv4first`.

`GATE FAILED` leaves the node stopped on the new tag. Do not start it: it would
halt at boot. The gate prints which table's root differs; stop the rollout and
investigate.

Before touching the next node: `/ready` shows `ready:true, halted:false`,
`RestartCount` stays 0 for a few minutes, `/v1/state-root` matches the untouched
nodes at the same round. Nodes on different versions reporting identical roots is
normal. A `HALT (byzantine_fork)` after boot is not, even if it clears itself:
stop and run the gate against that node's database.

---

## Development chain

For local development use the three-node local cluster in
[`TESTING_RUNBOOK.md`](./TESTING_RUNBOOK.md): `npm run seed:local` mints a
private genesis and node keys, `docker-compose.local.yml` runs the nodes. That is
the only place seeding belongs; it never touches mainnet or the test cluster.

---

## Troubleshooting

**Zero peers, `join_state: syncing` forever.** Wrong genesis (step 2 must print
the mainnet prefix; someone ran `seed`), `TIP_BOOTSTRAP_PEERS` empty, or inbound
4001 closed. Peers only connect on the right genesis, so one connected peer ends
the doubt.

**Node cannot read its key (`EACCES`) or `logs/` stays empty.** The container is
uid 1001: `sudo chown -R 1001:1001 genesis-data/backups logs` and restart.

**`/ready` shows `halted:true` after an upgrade.** The database rebuilt to a
different root than the fleet holds. Stop; run
`scripts/check-boot-root.js --migrate --peer https://node.theailab.org` and read
which table differs.

**Announce returns `fetch failed`.** DNS for your domain was created moments
ago and the container cached the negative answer; wait or recreate the container.

**`docker logs tip-promtail` shows `401`.** `LOKI_PASSWORD` does not match the
one issued; ask The AI Lab team.

**Prometheus shows your node `DOWN` with 401.** Your `TIP_METRICS_TOKEN` is not
the delivered one (a value starting `certtest` is a test-network token).

**Media uploads fail after switching to S3.** The bucket policy or KMS key does
not allow your role or user; the smoke tests in `PROD_S3_SETUP.md` isolate which.

---

## Getting help

| Channel | Contact |
|---------|---------|
| Node operations | chairman@theailab.org |
| Security issues | security@theailab.org |
| Bug reports | github.com/theailaborg/tip-protocol/issues |

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc.*
*Authored by Dinesh Mendhe. Licensed under TIPCL-1.0.*
