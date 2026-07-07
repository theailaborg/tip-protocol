# Production Observability , Deploy Runbook

One monitoring host runs the full stack; every node EC2 runs one small log
agent. Metrics are scraped FROM the nodes (pull), logs are shipped TO the
monitoring host (push). Grafana is the single pane for both, behind one login.

```
                       METRICS (pull)                      LOGS (push)
node1 EC2  ── :4000/metrics (Bearer token) ──┐   ┌── promtail ── files+stdout
node2 EC2  ── :4000/metrics ─────────────────┤   ├── promtail
node3 EC2  ── :4000/metrics ─────────────────┤   ├── promtail
                                             ▼   ▼
                monitoring EC2:   Prometheus   Loki     (both private)
                                        \       /
                                         Grafana  ◄── Caddy :443 (TLS + login)
                                                       Caddy logs.<domain> :443 (basic auth, ingestion only)
```

## Exposure model

| Surface | Exposure |
|---|---|
| `https://<OBS_DOMAIN>` (Grafana login) | public, TLS , the only human entry point |
| `https://<LOGS_DOMAIN>` (Loki push) | public, TLS, basic-auth , agents only |
| Prometheus, Loki | no published ports; compose network only |
| Node `/metrics` | rides the public API port; 401 without the bearer token |
| Node logs | never exposed; agents push outbound only |

Per-node internals (peers, mempool, sync state, log content) stay behind the
Grafana login. If a public network-status view is wanted later, use Grafana's
per-dashboard "public dashboard" toggle for one overview board; everything
else stays gated.

## Prerequisites

- A small EC2 for monitoring (t3.small is plenty). Security group: inbound
  80 + 443 from anywhere, 22 from your IP. Nothing else.
- Two DNS A records to that instance: `grafana.yourdomain.org` (OBS_DOMAIN)
  and `logs.yourdomain.org` (LOGS_DOMAIN).
- One shared metrics token: `openssl rand -hex 32`
- One log-shipping password, hashed for Caddy:
  `docker run --rm caddy:2 caddy hash-password --plaintext '<password>'`
  When pasting the hash into `.env`, escape every `$` as `$$` (compose treats
  bare `$` as variable interpolation and silently blanks the hash).

## Step 1 , monitoring host (once)

```bash
git clone <repo> && cd tip-protocol/infra/observability/prod

cp prometheus.yml.example prometheus.yml   # fill node addresses + the metrics token
cp .env.example .env                        # OBS_DOMAIN, LOGS_DOMAIN,
                                            # GRAFANA_ADMIN_PASSWORD, LOKI_BASIC_AUTH_HASH
# .env is read by compose (root); prometheus.yml is read INSIDE the container
# by user nobody (uid 65534) , chmod 600 under ubuntu makes Prometheus
# crash-loop with "permission denied".
chmod 600 .env
sudo chown 65534:65534 prometheus.yml && sudo chmod 400 prometheus.yml

docker compose -f docker-compose.obs.yml up -d
```

Caddy provisions both TLS certificates automatically. Open
`https://<OBS_DOMAIN>`, log in as `admin`, create Viewer accounts for other
operators. All TIP dashboards are provisioned; the Loki datasource appears
under Explore.

## Step 2 , each node EC2 (once per node)

Metrics , add the shared token to the node's `.env` and restart it:

```bash
TIP_METRICS_TOKEN=<token>
# verify:
curl -s -o /dev/null -w '%{http_code}\n' localhost:4000/metrics                                    # 401
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer <token>" localhost:4000/metrics # 200
```

Logs , run the agent next to the node container:

```bash
cd tip-protocol/infra/observability/agent
cp promtail.env.example promtail.env   # LOKI_URL=logs.yourdomain.org
                                       # LOKI_PASSWORD=<plaintext of the caddy hash>
                                       # NODE_LABEL=node1   (unique per host)
docker compose -f docker-compose.promtail.yml up -d
```

The agent tails the node's `TIP_LOG_DIR` files and the container's stdout,
labeling every line with `{job="tip-node", node="<NODE_LABEL>"}`. The basic
auth username is always `promtail`; `LOKI_PASSWORD` is the PLAINTEXT of the
hash in the monitoring host's `.env`. Rotating the hash means updating every
node's `promtail.env` too, or agents 401 and silently drop batches.

If the agent logs `no such host` for the logs domain while `dig @1.1.1.1`
resolves it: the AWS VPC resolver is refusing the record (stale negative
cache from before the DNS record existed, or a Route 53 PRIVATE hosted zone
shadowing your domain in the VPC). Pin the monitoring host's IP:

```yaml
# docker-compose.override.yml next to docker-compose.promtail.yml
services:
  promtail:
    extra_hosts:
      - "logs.yourdomain.org:<monitoring EIP>"
```

No extra security-group rules on nodes: `/metrics` shares the already-open
API port, and promtail pushes outbound over 443.

## Step 3 , verify end to end

```bash
# metrics: every node target "up" AND filed under the job the dashboards
# query , zero results here means the job got renamed and every panel
# will show "No data" despite healthy scrapes:
docker exec tip-obs-prometheus wget -qO- \
  'http://localhost:9090/api/v1/query?query=up{job="tip-federation"}' \
  | grep -c instance

docker exec tip-obs-prometheus wget -qO- 'http://localhost:9090/api/v1/targets' \
  | grep -o '"health":"[a-z]*"'

# logs: every node label present
docker exec tip-obs-loki wget -qO- 'http://localhost:3100/loki/api/v1/label/node/values'
```

In Grafana: the federation dashboard shows all nodes; Explore → Loki →
`{job="tip-node"} |= "ERROR"` shows error lines from the whole federation,
`{node="node2"}` isolates one host. Metric spike → same-minute logs is the
core workflow.

## Operations

- **Retention**: metrics 30d (`--storage.tsdb.retention.time`), logs 14d
  (`loki-config.yml` `retention_period`). Size ~1-2 GB/node/month metrics,
  ~0.5-2 GB/node/month logs at default levels.
- **Rotate the metrics token**: update every node `.env` + restart, then
  `prometheus.yml` + `docker compose restart prometheus`.
- **Rotate the log password**: new Caddy hash in `.env`,
  `docker compose up -d caddy`, then update each node's `promtail.env`.
- **Upgrade the stack**: `docker compose -f docker-compose.obs.yml pull && docker compose -f docker-compose.obs.yml up -d`
  (volumes persist data across upgrades).
- **Log volume too chatty?** Raise the node's `TIP_LOG_LEVEL` /
  `TIP_CONSOLE_LEVEL` (warn is the intended prod default); promtail ships
  whatever the node writes.
- **Log/disk hygiene** (bounded by construction):
  - Container stdout logs are rotated by the compose `logging:` blocks (json-file, 50 MB x 3 = 150 MB max per container).
  - Node app-log files (`info/error/access.log` 3 d, `debug.log` 1 d) self-prune on date rollover; Loki holds the authoritative 14-day archive. Tune via `TIP_LOG_RETENTION_DAYS` / `TIP_DEBUG_LOG_RETENTION_DAYS`.
  - Docker build cache is reclaimed weekly by a cron on every host (`0 4 * * 0 docker builder prune -af && docker image prune -f`). Reinstall with `sudo crontab -e` if a host is rebuilt.
- All secrets (`prometheus.yml`, `.env`, `promtail.env`) are gitignored;
  keep them chmod 600.

## Try it locally first

The local dev stack (`infra/observability/docker-compose.yml`) runs the same
Loki + promtail against your local cluster's `node/logs/`:

```bash
cd infra/observability && docker compose up -d
# Grafana http://localhost:3030 → Explore → Loki → {job="tip-node"}
```

Same datasource, same labels, same queries as prod , what you see locally is
what you get on AWS.
