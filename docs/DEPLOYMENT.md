# Running a TIP Protocol Node

This page is for organisations that want to run a node on the TIP network.
Joining is a guided process with The AI Lab team: every node is registered on
chain before it can connect, and its keys and configuration are delivered to
the operator directly. Email **tip@theailab.org** to start.

For running a local development cluster, see the README.

---

## Node Types

| Type | Who Runs It | What It Does | Requires Accreditation? |
|------|-------------|-------------|------------------------|
| **Full Node** | Registered partner organisations | Validates transactions, stores the DAG, serves the REST API, participates in consensus | No |
| **VP Node** | Accredited Verification Providers | Everything a full node does, plus issues TIP-IDs to verified humans | Yes |

If you are running a node for the first time, you are running a full node.
VP accreditation: see [`VP_ACCREDITATION.md`](./VP_ACCREDITATION.md).

---

## How Joining Works

1. **Talk to us.** We register your organisation and your node on the network.
2. **Receive your bundle.** We send an encrypted bundle with your node
   identity and configuration, and the password through a separate channel.
3. **Guided setup.** We walk you through starting the node, media storage,
   metrics and logs, and confirm it is in sync with the network.
4. **Upgrades.** We tell you when a release must be installed and how.

---

## What You Need

| Item | Full Node |
|------|-----------|
| Linux host (Ubuntu recommended) with Docker and Docker Compose | Required |
| Stable public hostname for the REST API (HTTPS) | Required |
| Open port 4001 (consensus and gossip), or an outbound-only setup agreed with us | Required |
| Persistent disk for the PostgreSQL database | Required |
| Object storage for media (S3), or local disk for evaluation | Recommended |

---

## Check a Running Node

```bash
curl http://localhost:4000/health
```

Expected response:

```json
{
  "status": "ok",
  "version": "2.8.0",
  "node_id": "tip://node/<id>",
  "dag_count": 0
}
```

Every node also serves a status page at `/status` (for example
https://node.theailab.org/status). A healthy node shows the banner
**All good**.

---

## Getting Help

| Channel | Contact |
|---------|---------|
| Running a node | tip@theailab.org |
| VP accreditation | accreditation@theailab.org |
| Security issues | security@theailab.org |
| Bug reports | github.com/theailaborg/tip-protocol/issues |

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc.*
*Authored by Dinesh Mendhe. Licensed under TIPCL-1.0.*
