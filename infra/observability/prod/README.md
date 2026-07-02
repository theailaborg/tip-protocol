# Production Observability

One monitoring host runs Prometheus + Grafana + Caddy and scrapes every
federation node over the node's public API port, authenticated with a shared
bearer token. Nodes can live on separate EC2 instances (or any provider);
nothing node-side is exposed beyond the API port they already serve.

```
node1 EC2 ── :4000/metrics ─┐  Bearer TIP_METRICS_TOKEN
node2 EC2 ── :4000/metrics ─┼──> Prometheus (private) ──> Grafana (login) <── Caddy :443 (TLS)
node3 EC2 ── :4000/metrics ─┘
```

## Public vs private

| Surface | Exposure |
|---|---|
| Caddy :443 (Grafana login page) | public, TLS, the only entry point |
| Grafana | 127.0.0.1 on the host; sign-up off, anonymous off |
| Prometheus | compose-network only; no published port |
| Node `/metrics` | rides the public API port but returns 401 without the bearer token |

Per-node internals (peers, mempool, resource pressure, sync state) stay behind
the Grafana login. If a public network-status view is wanted later, use
Grafana's per-dashboard "public dashboard" toggle for a single overview board;
everything else stays gated.

## Node-side setup (each EC2 node, once)

1. Generate one shared token on any machine and add it to every node's `.env`:

   ```bash
   openssl rand -hex 32       # -> TIP_METRICS_TOKEN=<value>
   ```

2. Restart the node. Verify the gate:

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' http://localhost:4000/metrics                                   # 401
   curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" http://localhost:4000/metrics # 200
   ```

No extra security-group rules: `/metrics` shares the API port that is already
open. Optional host metrics: run `prom/node-exporter` on each instance and
open :9100 ONLY to the monitoring host's security group.

## Monitoring host setup (once)

1. Instance: any small EC2 box (t3.small is plenty). Security group: inbound
   80 + 443 from anywhere, 22 from your IP. Point a DNS A record
   (e.g. `grafana.yourdomain.org`) at it.
2. Clone the repo (the stack reuses `infra/observability/grafana/` dashboards
   and provisioning) and configure:

   ```bash
   cd infra/observability/prod
   cp prometheus.yml.example prometheus.yml   # node addresses + the token; chmod 600
   cp .env.example .env                        # OBS_DOMAIN + GRAFANA_ADMIN_PASSWORD
   docker compose -f docker-compose.obs.yml up -d
   ```

3. Open `https://<OBS_DOMAIN>`, log in as `admin`, create Viewer accounts for
   other operators. All TIP dashboards (home, federation, consensus health,
   networking, rotation, snapshot) are provisioned automatically.

## Verify end to end

```bash
# on the monitoring host: every node target should be "up"
docker exec tip-obs-prometheus wget -qO- 'http://localhost:9090/api/v1/targets' \
  | grep -o '"health":"[a-z]*"'
```

Scrape failures show as `up == 0` per target on the federation dashboard;
a node whose token does not match logs 401s in its own access log.

## Operational notes

- `prometheus.yml` and `.env` hold secrets and are gitignored; keep them
  chmod 600 on the host.
- Retention is 30d (`--storage.tsdb.retention.time`); size the volume ~1-2 GB
  per node per month at the default 15s interval.
- Rotating the metrics token: update every node's `.env` + restart, then
  update `prometheus.yml` and `docker compose restart prometheus` (brief
  scrape gap only, no data loss).
- Scraping over private links (VPC peering / same VPC) works the same; just
  use private IPs in `prometheus.yml`.
