# Node Requirements

Hardware and software requirements for running a TIP federation node. Every
number here is empirical: measured on the production federation during the
2026-07 load-test campaign (sustained 40 registrations/s at 100% acceptance,
50,000+ transactions on chain, burst tests to 100 tx/s), not estimated.

## Minimum

Runs the full stack (node + postgres + log agent) correctly at launch-scale
traffic.

| Resource | Spec | Basis |
|---|---|---|
| CPU | 2 vCPU | Sustained 40 reg/s at 100% acceptance on 2 vCPU. The Node.js event loop is the ceiling, not signature verification. |
| RAM | 4 GB | Node process ~850 MB RSS at 50k txs, postgres ~200 MB, agent ~50 MB. Comfortable to roughly 200-300k txs; the in-memory mirror grows ~15-17 KB per tx. |
| Disk | 20 GB gp3 | 8 GB volumes caused four disk-full incidents in two days of testing. Baseline (OS + images + WAL) is ~4.5 GB; chain data grows ~25 KB per registration. |
| Runtime | Node.js 24+ | Native ML-DSA verify via OpenSSL 3.5 (0.25 ms/verify). Node 22 works but verifies through the JS fallback at ~5 ms, dropping the sustained ceiling from ~40 to ~30 reg/s. |
| Software | Docker + Compose, postgres 16 | The shipped compose stack. |
| Media storage | S3 bucket + KMS key (prod) | `TIP_MEDIA_BACKEND=s3` with `TIP_MEDIA_S3_BUCKET`, `TIP_MEDIA_S3_REGION`, `TIP_MEDIA_S3_KMS_KEY_ID` and scoped IAM credentials. Media bytes live off-node (presigned upload/download), so media volume does not count against node disk. Dev/test can use `TIP_MEDIA_BACKEND=fs`, which DOES consume node disk. On S3-backed nodes the single-request `POST /v1/media/upload` answers `410`, so uploads never spool to node disk; per-mime caps default to 15 GiB video / 1 GiB audio / 1 GiB image (`TIP_MAX_*_BYTES`). |

Capacity at minimum spec: ~15 reg/s with flat latencies (submit p95 under
400 ms, cross-node commit p50 ~2.7 s), ~40 reg/s sustained maximum, 60+/s
burst absorption with graceful shedding (503s on the excess, zero halts).

## Recommended

Headroom for growth and no operational babysitting.

| Resource | Spec | Basis |
|---|---|---|
| CPU | 4 vCPU, non-burstable (m7i/c7i class) | Burstable (t3) CPU credits decay under sustained load. Four dedicated cores roughly double the ceiling and leave room for `TIP_CRYPTO_POOL_SIZE=2`. |
| RAM | 8 GB | Pushes the in-memory-mirror ceiling past ~1M txs. |
| Disk | 50 GB gp3 | ~2M registrations of chain growth plus images, WAL, logs, and snapshot serving without thought. |
| Monitoring | separate small instance | Prometheus + Loki + Grafana per `infra/observability/prod/README.md`; keep the disk-free panel wired, it fires before postgres starts failing writes. |

## Two properties operators must understand

**More nodes do not add throughput.** Every node verifies and commits every
transaction; federation capacity is roughly one node's capacity, and each
added committee member slightly increases per-node overhead (more acks per
certificate, more gossip). Nodes buy fault tolerance and trust distribution.
Bigger nodes buy throughput. Spec each node as if it carries the whole chain,
because it does.

**Reads are effectively free.** The specs above are for the write path
(consensus). Verification lookups, badge checks, and content reads are local
DB reads, cacheable and CDN-friendly, and do not consume consensus capacity
on either tier.

## Scaling levers, in order of cost

1. Instance resize (config-only): ~5-7x from 2 to 16-32 vCPU.
2. Crypto pool sizing on the bigger instance (`TIP_CRYPTO_POOL_SIZE` ~ cores minus 2).
3. Native-core rewrite (Rust): pays another 3-5x, but only worth it on large
   hardware; see the protocol scaling notes before considering.
