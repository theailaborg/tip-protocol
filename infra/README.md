# infra

Deployment assets that live outside the node application.

| Path | What it is |
|---|---|
| `observability/prod/` | **The** monitoring stack: Prometheus, Loki, Grafana, Caddy. Use this for every real cluster, production and test, single host or multi host. Start at its README. |
| `observability/agent/` | Per-node promtail log agent. One per node, in every cluster. |
| `observability/` | Local development stack only (Docker Desktop, no TLS). Not for shared hosts. |
| `s3-media/` | Terraform for the per-node S3 media buckets. |

Do not hand-write a variant of the observability stack. A fork silently misses
the auth hardening, log-rotation limits and pinned plugin version that live in
`prod/`, and it cannot inherit later fixes.
