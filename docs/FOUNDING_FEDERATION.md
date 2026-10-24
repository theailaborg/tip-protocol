# Founding a New Federation (cold start)

Lab-internal. These are the reproducible steps used for the mainnet launch:
fresh cloud hosts to a live, converged federation, plus observability. A partner
joining the existing chain never does any of this; they follow
[`DEPLOYMENT.md`](./DEPLOYMENT.md), *Joining an Existing Federation*.

The container runs as **uid 1001** (`tipnode`); every file it reads or writes
must be owned by `1001`. The genesis is **baked into the image**, so rebuild
after any genesis change. Deploy code with **git**, never a code copy.

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
scp <node>.env ubuntu@<node-ip>:~/tip-protocol/.env
```

Keep `.env` at parity with `.env.example`; missing keys silently fall back to
protocol defaults. Prod values: `NODE_ENV=production`, `TIP_CORS_ORIGINS`
listing every browser client (the VP app; NOT `*`), a shared `TIP_METRICS_TOKEN`
identical on all nodes, `TIP_CRYPTO_POOL_SIZE=2` on 4-core hosts. Every
`TIP_*_ACTIVATION_MS` stays unset: the code defaults are the mainnet epochs.

**Media storage (S3)**: the node writes media bytes to S3 (SSE-KMS) and hands
the classifier presigned URLs. Provision the bucket + KMS key + IAM role once
and set `TIP_MEDIA_BACKEND=s3`, `TIP_MEDIA_S3_BUCKET`, `TIP_MEDIA_S3_REGION`,
`TIP_MEDIA_S3_KMS_KEY_ID` in each node's `.env`. Full step-by-step:
[`PROD_S3_SETUP.md`](./PROD_S3_SETUP.md). Credentials come from the instance
role (EC2) / IRSA (EKS), never a long-lived `AWS_ACCESS_KEY_ID` in the env.

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
reboots). Once all three are up, give every node the other two as bootstrap
peers so a restart never depends on one box.

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
has not seen, before consensus starts. On the first node of a rollout watch the
boot logs and confirm the expected set applied:

```bash
docker exec tip-postgres psql -U tip -d "$DB_NAME" -tAc \
  "SELECT name FROM knex_migrations ORDER BY id;"
```

**7. Validate** across all nodes: `/ready` is `ready:true, halted:false`,
`/health` shows `peers.connected = N-1`, rounds advancing; the same
`state_merkle_root` at the same round from `/v1/state-root`; identities =
genesis ring size; the same committed tx count (converged).

**8. Observability** (obs host: Prometheus + Grafana + Loki + Caddy). The
runbook is [`infra/observability/prod/README.md`](../infra/observability/prod/README.md).
The load-bearing gotchas:

- **Metrics**: `infra/observability/prod/prometheus.yml` (gitignored), job
  `tip-federation` (do NOT rename), targets = the nodes' **private** IPs `:4000`
  and partner domains `:443`, `Bearer` = the shared `TIP_METRICS_TOKEN`, and
  `chmod 644` the file (a `sudo` edit that leaves it `root:600` crash-loops
  Prometheus). Verify `count(up{job="tip-federation"}==1)` returns N.
- **Logs**: promtail per node (`infra/observability/agent/`), requires Step 4.
  `promtail.env`: `LOKI_URL=logs.<domain>`, `LOKI_PASSWORD=<plaintext>`,
  `NODE_LABEL=node<n>`; then `docker compose -f docker-compose.promtail.yml up -d`.
  Set the Loki basic-auth (`LOKI_BASIC_AUTH_HASH` via `caddy hash-password`) in
  the obs `.env`.
- **DNS (GOTCHA)**: `logs.<domain>` must be **DNS-only (grey cloud), NOT
  Cloudflare-proxied**: Caddy owns TLS + basic-auth for the push; a proxy in
  front breaks the ACME challenge and the push times out. `grafana.<domain>`
  proxied is fine (browser UI).
