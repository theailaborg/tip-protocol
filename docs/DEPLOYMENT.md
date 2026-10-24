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

`git clone` prints `Cloning into '/home/<you>/tip-protocol'...`; the copy and
permission commands print nothing when they succeed. Check the key landed:

```bash
ls -l genesis-data/backups/
```

```text
-rw------- 1 1001 1001 12205 Oct 24 10:12 tip-node-<id>.tip.json
```

Owner `1001 1001` and `-rw-------` are what matter.

The `ORG-IDENTITY__*.tip.json` from the bundle does **not** go on this host. It
signs as your company, not as the node; keep it offline. Without `sudo`, create
`data/` and `logs/node-1/` yourself so the container user can write them.

**2. Confirm the chain.**

```bash
python3 -c "import json;print(json.load(open('genesis-data/genesis.json'))['genesis_hash'][:8])"
```

```text
d4666ce1
```

Anything else means a wrong branch or a stale clone: stop here.

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
```

The build takes a few minutes and ends with `tip-node  Built`; `up -d` then
prints:

```text
 ✔ Container tip-postgres  Healthy
 ✔ Container tip-node      Started
```

Then watch the join:

```bash
curl -s http://localhost:4000/ready
```

```text
{"ok":true,"status":200,"data":{"ready":false,"db_ok":true,"halted":false,"join_state":"syncing"}}
```

Repeat until it reads:

```text
{"ok":true,"status":200,"data":{"ready":true,"db_ok":true,"halted":false,"join_state":"ready"}}
```

`curl: (7) Failed to connect` in the first seconds only means the container is
still starting.

`join_state` goes `syncing` → `catching_up` → `ready` while the node downloads
a snapshot (minutes). A dropped transfer restarts it; repeated restarts mean an
unstable link, not a broken node.

**5. Verify on the status page.** Open `http://localhost:4000/status` (later
`https://<your-node-domain>/status`). It refreshes every 3 s, needs no login,
and the banner reads **All good** only when all ten checks pass:

| check | must say | if not |
|---|---|---|
| Node reachable | `version 2.7.x` | the container is not up: `docker compose ps`, `docker compose logs tip-node` |
| Database readable | `N transactions` | PostgreSQL not healthy or `DB_PASSWORD` changed after first start |
| Consensus running | `running` | `halted`: see Troubleshooting |
| Caught up with the federation | `join state: ready` | `syncing` / `catching_up` is normal for the first minutes after start |
| No fork halt | `roots consistent` | the node rebuilt a different state than the fleet: stop, see Troubleshooting |
| Connected to peers | `N connected`, N ≥ 1 | zero peers means wrong genesis, empty `TIP_BOOTSTRAP_PEERS` or 4001 blocked |
| Connected to a genesis node | `K of 3 genesis nodes in the peer list`, K ≥ 1 | your bootstrap peers are not the founding nodes |
| Peers agree on state root | all peers `✓ same root` in the table below | one peer differing is their problem; all differing is yours |
| Rounds advancing | `last advance` a few seconds ago | the federation is stalled or your node lost its peers |
| Public endpoint announced | your `https://` URL | expected `none on chain` until step 6 |

The peers table under the checks lists every connected node with its round and
state root; the three founding nodes carry a `genesis` pill. The same facts by
hand, if you prefer curl:

```bash
curl -s http://localhost:4000/ready
```

```text
{"ok":true,"status":200,"data":{"ready":true,"db_ok":true,"halted":false,"join_state":"ready"}}
```

```bash
curl -s http://localhost:4000/health | python3 -m json.tool
```

```text
{
    "ok": true,
    "status": 200,
    "data": {
        "status": "ok",
        "node_id": "tip://node/<your-node-id>",
        "node_type": "full",
        "dag_count": 2070,
        "version": "2.7.9",
        "protocol": "2.0.0",
        "peers": { "connected": 3, "peer_ids": ["12D3KooW...", "..."] },
        ...
    }
}
```

`node_id` must be the id in your bundle's key file name, `version` the release
you built, and `peers.connected` at least 1 (peers only connect on the right
genesis).

```bash
curl -s http://localhost:4000/v1/state-root ; echo ; curl -s https://node.theailab.org/v1/state-root
```

```text
{"ok":true,"status":200,"data":{"round":20705712,"state_merkle_root":"beabb4258139acdb6615de5c71f1a65952d77a3616f9772b854bcd12bf0820c6", ...}}
{"ok":true,"status":200,"data":{"round":20705712,"state_merkle_root":"beabb4258139acdb6615de5c71f1a65952d77a3616f9772b854bcd12bf0820c6", ...}}
```

Equal `state_merkle_root` at equal `round` means your whole state is identical
to the federation's. Rounds advance every ~2 s; if the two rounds differ, run
it again until they line up.

**6. Announce your domain** once `https://<your-node-domain>/health` answers
(the federation stores the URL on chain, The AI Lab scrapes `/metrics` through
it, people open `/status`):

```bash
curl -s -X POST http://localhost:4000/v1/node/endpoint/announce
```

```text
{"ok":true,"status":202,"data":{"node_id":"tip://node/<your-node-id>","api_endpoint":"https://<your-node-domain>","confirmation":"proposed"}}
```

`proposed` means the transaction is on its way; it commits in seconds.
`"confirmation":"unchanged"` means it was already on chain. The errors you can
meet, each with its fix:

| response contains | fix |
|---|---|
| `api_endpoint probe failed: https://<domain>/health unreachable (fetch failed)` | DNS or TLS not ready, or the container cached the earlier "no such name" answer: wait or recreate the container, then announce again |
| `answers as "<other id>" not "<your id>"` | your domain points at a different node |
| `TIP_API_ENDPOINT not configured` | set it in `.env`, recreate the container, announce again |
| `not on chain yet` | the registration has not committed; tell The AI Lab team |

Confirm from the federation's side:

```bash
curl -s https://node.theailab.org/v1/nodes | python3 -m json.tool | grep -A3 '"<your-node-id>"'
```

`"api_endpoint"` must now show your URL instead of `null`.

**7. Media storage before real traffic.** The delivered env writes media to the
node disk (`TIP_MEDIA_BACKEND=fs`). Production uses S3 with SSE-KMS:

- *Your own bucket* (recommended): follow [`PROD_S3_SETUP.md`](./PROD_S3_SETUP.md),
  then set `TIP_MEDIA_BACKEND=s3`, `TIP_MEDIA_S3_BUCKET`, `TIP_MEDIA_S3_REGION`,
  `TIP_MEDIA_S3_KMS_KEY_ID`. The instance role signs; no AWS keys in the env.
- *A bucket provided by The AI Lab* (hosts without an instance role, such as a
  Mac or bare metal; the Lab side is `PROD_S3_SETUP.md` section C): you receive
  an access key scoped to the `media/` prefix; set the same four values plus `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY`, and rotate that key every 90 days.

Then `sudo docker compose up -d --force-recreate tip-node` (prints
`✔ Container tip-node  Started`), upload one image against your node and confirm
the object appears under `media/` in the bucket:

```bash
aws s3 ls s3://<your-bucket>/media/ --recursive | tail -1
```

```text
2026-10-24 10:41:07     482113 media/<media-id>
```

and that the node logged no S3 error:

```bash
sudo docker compose logs --since 10m tip-node | grep -ci "s3.*error"
```

```text
0
```

Tell The AI Lab team the bucket host so the classifier may download from it.

**8. Ship logs.** Create `infra/observability/agent/promtail.env` with
`LOKI_URL=logs.theailab.org` plus the `NODE_LABEL` and `LOKI_PASSWORD` The AI
Lab gave you, then:

```bash
cd infra/observability/agent && docker compose -f docker-compose.promtail.yml up -d
```

```text
 ✔ Container tip-promtail  Started
```

```bash
docker logs --tail 20 tip-promtail
```

A healthy agent shows `msg="Starting Promtail"` and lines like
`msg="Adding target" key="/app/node/logs/..."`, with no `401` and no
`error sending batch`. A `401` means the password does not match. Your node
appears under its label in the federation dashboard within a minute. Details
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
cd ~/tip-protocol && scripts/upgrade-node.sh v2.7.9 https://node.theailab.org   # peer = a node NOT being upgraded now
```

How that deploys the new version:

1. fetches the tags and checks out `v2.7.9`, so that release's source is on disk
   (refusing first if your `genesis.json` is modified or would change);
2. `docker compose build tip-node` builds a new image from that source;
3. stops the running container;
4. runs the new code once, read-only, against your database
   (`scripts/check-boot-root.js --migrate`): applies the release's migrations and
   proves the database rebuilds to the state root the untouched peer serves live;
5. only on `MATCH`, `docker compose up -d --force-recreate tip-node` starts a
   fresh container from the new image; `/health` now reports the new version.

A successful upgrade prints this (mainnet node 3 going to 2.7.9; hashes and
row counts differ per node and day):

```text
== [ip-172-31-41-19] upgrading to v2.7.9, gate peer https://node.theailab.org
== genesis unchanged (d4666ce1); at v2.7.9
== build ok
== stopped; running root gate
database : tip_node3
rebuilt  : 97c11eb1da89b9c5455c03593f7165530d10dc5cb99abd7375c87b09a164d6c1
expected : 97c11eb1da89b9c5455c03593f7165530d10dc5cb99abd7375c87b09a164d6c1  (https://node.theailab.org at round 20445720)
  identities               790ee7ba8a11568d  rows=75
  content                  fac1a1d00ff7a939  rows=629
  ...                      (one line per state table)
  protocol_params          095efd252bae917b  rows=163
MATCH: safe to restart
== started; waiting for /ready
== READY after 30s: {"ok":true,"status":200,"data":{"ready":true,"db_ok":true,"halted":false,"join_state":"ready"}}
{"ok":true,"status":200,"data":{"status":"ok","node_id":"tip://node/97f096a95b681852","node_type":"full","dag_count":2070,"version":"2.7.9", ...
RestartCount=0
```

It worked when all four hold: `rebuilt` equals `expected`, the gate ends in
`MATCH: safe to restart`, `== READY` appears, and `/health` shows the new
`version` with `RestartCount=0`. It did not work if it ends in any of these:

| last line | meaning | node state |
|---|---|---|
| `MISMATCH: do not restart, this node would halt at boot` then `== GATE FAILED (rc=1)` | your database rebuilds to a different root than the peer | stopped; do not start it, investigate the table whose root differs from the peer's |
| `check-boot-root failed: ...` then `== GATE FAILED` | the gate could not run (peer unreachable, DB down, migration error) | stopped; fix the cause and rerun the command |
| `== genesis changed ...` or `== ... is locally modified; refusing` | not a routine release, or a hand-edited genesis | untouched, still running the old version |
| no `== READY` after 10 minutes, or `RestartCount` above 0 | the new version started but is not healthy | running; read `docker compose logs tip-node` before touching another node |

On a macOS Docker host prefix the command with
`NODE_OPTIONS=--dns-result-order=ipv4first`. If your checkout predates the
script (no `scripts/upgrade-node.sh` yet), run
`git fetch --tags origin && git checkout <tag>` once to obtain it, then the
command above.

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
different root than the fleet holds. Stop the node and run the gate by hand:

```bash
sudo docker compose stop tip-node
sudo docker compose run --rm --no-deps -T --entrypoint node tip-node \
  scripts/check-boot-root.js --migrate --peer https://node.theailab.org
```

It prints the same block as in [Upgrading a node](#upgrading-a-node): compare
each table's root with the same command run on a healthy node; the table that
differs is where your database drifted. Send that output to The AI Lab team.

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
