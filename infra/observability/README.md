# TIP Federation observability stack (local dev)

Local Prometheus + Grafana for the 3-node TIP dev federation. Scrapes
each node's `/metrics` endpoint and renders the `TIP Federation`
dashboard out of the box.

## Run

```bash
cd infra/observability
cp .env.example .env       # then edit .env if you want non-default credentials
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

`.env` is git-ignored. `.env.example` is the committed template.

## Adding a node

Edit `prometheus.yml`, append the new `host:port` to `static_configs`,
then reload without a restart:

```bash
docker compose kill -s HUP prometheus
```

Auto-discovery (HTTP service discovery via the federation handshake) is
tracked as Consensus issue #43 in `my-notes/issues.md` — once shipped,
this manual step goes away.

## Metrics reference

`my-notes/metrics-guide.md` lists every exposed metric, sample PromQL
queries, and the alert rules that should run in production.

## NOT production-ready

This stack is local-dev tooling. Before exposing any of it on a
non-loopback interface:

- Replace `GF_SECURITY_ADMIN_PASSWORD=admin` with a strong secret.
- Disable `GF_AUTH_ANONYMOUS_ENABLED`.
- Put Prometheus on a private network — it has no auth.
- Decide whether each node's `/metrics` should be reachable publicly
  (BFT default is yes; firewall/reverse-proxy if not).
