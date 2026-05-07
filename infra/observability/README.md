# TIP Federation observability stack (local dev)

Local Prometheus + Grafana for the TIP dev federation. Scrapes each
node's `/metrics` endpoint and renders the `TIP Federation` dashboard
out of the box.

## Run

```bash
cd infra/observability
cp .env.example .env       # then edit .env if you want non-default credentials or node list
docker compose up -d
```

- Grafana → http://localhost:3030  (creds from `.env`, defaults `admin` / `admin`)
- Prometheus → http://localhost:9090  (`Status > Targets` shows scrape health)

Stop with `docker compose down`. Add `-v` to wipe stored time series.

## Configuration (`.env`)

Defaults are fine for loopback. Override these in `.env` before exposing
the stack on any non-loopback interface:

| Variable | Default | Purpose |
|---|---|---|
| `GF_ADMIN_USER` | `admin` | Grafana admin username |
| `GF_ADMIN_PASSWORD` | `admin` | Grafana admin password — change this |
| `GF_ANON_ENABLED` | `true` | Anonymous viewer — set `false` for prod |
| `GF_HTTP_PORT` | `3030` | Host port Grafana binds to |
| `PROM_HTTP_PORT` | `9090` | Host port Prometheus binds to |
| `PROM_RETENTION` | `7d` | Prometheus TSDB retention |
| `TIP_NODE_TARGETS` | 5 nodes on `host.docker.internal:4000-4400` | Comma-separated `host:port` list of TIP nodes to scrape |

`.env` is git-ignored. `.env.example` is the committed template.

## Prometheus targets

Targets are driven by `TIP_NODE_TARGETS` in `.env` — no need to edit
`prometheus.yml`. On container startup the entrypoint converts the
comma-separated list into a `file_sd_configs` JSON file that Prometheus
re-reads every 30s.

To add or remove a node:

```bash
# 1. Edit .env, change TIP_NODE_TARGETS (e.g. add a 6th node)
TIP_NODE_TARGETS=host.docker.internal:4000,host.docker.internal:4100,host.docker.internal:4200,host.docker.internal:4300,host.docker.internal:4400,host.docker.internal:4500

# 2. Restart only the prometheus container
docker compose up -d --force-recreate prometheus
```

`host.docker.internal` resolves to the host machine from inside the
prom container on Linux/Mac/Windows (via the `extra_hosts` mapping in
`docker-compose.yml`). For TIP nodes on a different host or network,
substitute the actual reachable address.

The `node` label on metrics comes from each TIP node's `/metrics`
output (its real registered TIP node id, not the port), so dashboards
group by node identity regardless of `host:port` rewiring.

## Adding a dashboard

Drop a Grafana JSON export into `grafana/dashboards/`. The provisioning
config (`grafana/provisioning/`) auto-loads everything in that
directory on Grafana startup — no UI import step needed.

## Metrics reference

Each TIP node exposes Prometheus-format metrics on `GET /metrics` over
its REST port (the same one in `TIP_NODE_TARGETS`). Use Prometheus's
`/graph` UI to explore available series, or query directly via the HTTP
API.

## NOT production-ready

This stack is local-dev tooling. Before exposing any of it on a
non-loopback interface:

- Replace `GF_SECURITY_ADMIN_PASSWORD=admin` with a strong secret.
- Disable `GF_AUTH_ANONYMOUS_ENABLED`.
- Put Prometheus on a private network — it has no auth.
- Decide whether each node's `/metrics` should be reachable publicly
  (BFT default is yes; firewall/reverse-proxy if not).
