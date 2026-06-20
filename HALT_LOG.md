# TIP Consensus Halt Log

---

## Halt Event — 2026-06-20T10:40:31Z

**Detected at:** rounds 926, 928, 932 (cascading), node affected: 4000 (node1/725edc5831b1c6d1)
**Trigger:** Running `uat-signature-unification.js` (GH #51 UAT) — Phase 5 revocations (REVOKE_VOLUNTARY → REVOKE_VP → REVOKE_DECEASED → REVOKE_DEVICE) submitted in rapid succession against 5-node local cluster.
**Symptom:** `anti-entropy: byzantine-fork halt threshold reached — 2/2 peers disagree at committed_round=926; self.state_root=74ad8410e57987ed`. Node1 repeatedly diverged from 2-peer majority at rounds 926 → 928 → 932, each time auto-recovering via snapshot resync. Cluster stabilized at round ~947 with halted=False on all nodes.
**Node logs (relevant excerpt):**
```
[WARN] [dc5831b1c6d1] [tip.bullshark] Round 504: deferred anchor timed out with 1 cert(s) permanently missing — triggering snapshot resync
[WARN] [dc5831b1c6d1] [tip.bullshark] Round 594: deferred anchor timed out with 1 cert(s) permanently missing — triggering snapshot resync
[WARN] [dc5831b1c6d1] [tip.bullshark] Round 678: deferred anchor timed out with 2 cert(s) permanently missing — triggering snapshot resync
[WARN] [dc5831b1c6d1] [tip.bullshark] Round 768: deferred anchor timed out with 5 cert(s) permanently missing — triggering snapshot resync
[ERROR] [dc5831b1c6d1] [tip.anti-entropy] byzantine-fork halt threshold reached — 2/2 peers disagree at committed_round=926; self.state_root=74ad8410e57987ed
[ERROR] [dc5831b1c6d1] [tip.narwhal] HALT (byzantine_fork): 2/2 peers disagree at committed_round=926; self.state_root=74ad8410e57987ed
[NOTICE] [dc5831b1c6d1] [tip.anti-entropy] anti-entropy: majority minority detected while halted at round=932 — scheduling auto-recovery in 5000ms
[NOTICE] [dc5831b1c6d1] [tip.narwhal] Cleared byzantine_fork halt (was: 2/2 peers disagree at committed_round=932)
[NOTICE] [dc5831b1c6d1] [tip.anti-entropy] anti-entropy: auto-recovery: syncing snapshot from 12D3KooWCLeJ
```
**Cluster state at halt:**
- Node 4000 (725edc5831b1c6d1): round 926, HALTED (byzantine_fork), state_root=74ad8410e57987ed, committed=147
- Node 4100 (47652beb1df3eb6f): round 926, NOT halted, state_root=1fd8e4803cd5be66, committed=143
- Node 4200 (01c469e755ffcdac): round 926, NOT halted, state_root=1fd8e4803cd5be66, committed=141
- Node 4300 (49223316dddbcf1e): round 926, NOT halted, state_root=1fd8e4803cd5be66, committed=141
- Node 4400 (6009b76dc0da4df0): round 926, NOT halted, state_root=1fd8e4803cd5be66, committed=141
**Notable:** Preceding rounds (504, 594, 678, 768) all had `deferred anchor timed out with N cert(s) permanently missing`. Pattern suggests node1 is consistently missing some anchor certificates. Auto-recovery (majority-minority snapshot sync) eventually converged cluster at round 947 (halted=False all nodes). Post-recovery txs_committed still diverges: node1=147 vs nodes 3-5=141.
**Session context:** Branch `test/combined-120-121`. Testing sign changes from PRs #122/#52/#123. UAT rapid revocation sequence (REVOKE_VP + REVOKE_DECEASED in same UAT phase) may have created a signing cascade that diverged state.

---

## Halt Event — 2026-06-20T10:11:16Z

**Detected at:** round 400–407, all 5 nodes affected; two isolated sub-clusters formed
**Trigger:** Rebuilt Docker image from `test/combined-120-121` branch (issues #120 + #121 changes), then restarted mixed-db cluster to test signing changes. Full `docker compose down` then `docker compose up -d`.
**Symptom:** Two isolated genesis clusters formed after restart:
- Node1 (PostgreSQL, port 4000): genesis founding_node=`tip://node/725edc5831b1c6d1` (STALE — from a previous cluster initialization). Operating alone at rounds 404–410.
- Nodes 2–5 (MariaDB/Oracle/MSSQL/SQLite, ports 4100–4400): genesis founding_node=`tip://node/efbe3707224fb785` (correct per current `genesis.json`). Operating as an isolated 4-node sub-cluster.
- All nodes: `nodeCount=1, activeParticipants=1, batchesThisRound=0, certs_created=0`. Rounds advancing via fast-forward (empty rounds only) but no actual transactions ever committed.
- `sub_quorum` halt triggers every ~63 seconds on all nodes.
- Snapshot sync fails between the two clusters: `genesis rotation does not match LOCAL genesis founding_node`.
- `batches_created=0` across all nodes — confirms the cluster has NEVER had functional batch creation in this mixed-db setup (predates this session).
**Node logs (relevant excerpt):**
```
[WARN] [0646ee1f8ce0] [tip.anti-entropy] snapshot fallback from 12D3KooWN2eL failed: genesis rotation does not match LOCAL genesis founding_node — peer claimed tip://node/725edc5831b1c, local has tip://node/efbe3707224fb
[WARN] [cdcc2d363c39] [tip.rotation-coord] Rotation 1 submitTx threw: [object Object]
[WARN] [cdcc2d363c39] [tip.anti-entropy] sub_quorum escape — no round advance for 63s
```
**Cluster state at halt:**
- Node 4000: round 404-410, genesis=725edc5b, halted=true (sub_quorum), peers=4, nodeCount=1, batches_created=0
- Node 4100: round 406-412, genesis=efbe3707, halted=true (sub_quorum), peers=4, nodeCount=1, batches_created=0
- Node 4200: round 406-412, genesis=efbe3707, halted=true (sub_quorum), peers=4, nodeCount=1, batches_created=0
- Node 4300: round 406-412, genesis=efbe3707, halted=true (sub_quorum), peers=4, nodeCount=1, batches_created=0
- Node 4400: round 406-412, genesis=efbe3707, halted=true (sub_quorum), peers=4, nodeCount=1, batches_created=0
**Session context:** Branch `test/combined-120-121` (local merge of fix/issue-121-ctid-binding + fix/issue-120-signing-hardening). Testing signing hardening changes. PRs #122, #52, #123 open.

---

## Halt Event — 2026-06-20T06:23:03Z

**Detected at:** round 400, all 5 nodes affected: 4000, 4100, 4200, 4300, 4400
**Trigger:** Mixed-DB integration cluster (docker-compose.mixed-db.yml) running after issue #117 Knex migration test session completed (PR #118). Cluster left running continuously for ~43 minutes post-test.
**Symptom:** All 5 nodes return HTTP 503 with `"status":"halted"`, `"reason":"sub_quorum"`. Rounds stopped advancing at 400.

```
Node 4000 halt: "No consensus progress for 44s — quorum unreachable. 3/1 certs at round 400."
Node 4100 halt: "No consensus progress for 28s — quorum unreachable. 3/1 certs at round 400."
Node 4200 halt: "No consensus progress for 44s — quorum unreachable. 3/1 certs at round 400."
Node 4300 halt: "No consensus progress for 44s — quorum unreachable. 1/1 certs at round 400."
Node 4400 halt: "No consensus progress for 32s — quorum unreachable. 3/1 certs at round 400."
```

**Node logs (relevant excerpt):**
```
[2026-06-20T06:24:03.782Z] [WARN] [60d94a0519cf] [tip.anti-entropy] sync-status: rejected unauthorized peer 12D3KooWHadj
[2026-06-20T06:24:07.810Z] [WARN] [60d94a0519cf] [tip.anti-entropy] sync-status: rejected unauthorized peer 12D3KooWHadj
[2026-06-20T06:24:11.864Z] [WARN] [60d94a0519cf] [tip.anti-entropy] sync-status: rejected unauthorized peer 12D3KooWHadj
[2026-06-20T06:24:15.872Z] [WARN] [60d94a0519cf] [tip.anti-entropy] sync-status: rejected unauthorized peer 12D3KooWHadj
[2026-06-20T06:24:16.064Z] [WARN] [60d94a0519cf] [tip.sync] Sync: rejected request from unauthorized peer 12D3KooWHadjF6TXWPqX6Rg2ZfAKPi6CJw52xz3N2FNDJcQiupxP

[2026-06-20T06:24:03.798Z] [WARN] [cdcc2d363c39] [tip.anti-entropy] anti-entropy: sub_quorum escape — no round advance for 60s; triggering snapshot resync (issue #13)
```

**Cluster state at halt:**
- Node 4000 (postgres): round 400, halted=true, merkleRoot=e59dfcff627e1aa5daa55cc55d870451b7e2558d1393b016d72d7cc50ccde2fe, peers=4
- Node 4100 (mariadb): round 400, halted=true, merkleRoot=e59dfcff627e1aa5daa55cc55d870451b7e2558d1393b016d72d7cc50ccde2fe, peers=4
- Node 4200 (oracle):  round 400, halted=true, merkleRoot=e59dfcff627e1aa5daa55cc55d870451b7e2558d1393b016d72d7cc50ccde2fe, peers=4
- Node 4300 (mssql):   round 400, halted=true, merkleRoot=e59dfcff627e1aa5daa55cc55d870451b7e2558d1393b016d72d7cc50ccde2fe, peers=3 ⚠️
- Node 4400 (sqlite):  round 400, halted=true, merkleRoot=e59dfcff627e1aa5daa55cc55d870451b7e2558d1393b016d72d7cc50ccde2fe, peers=4

**Notable diagnostics:**
- merkleRoot is IDENTICAL across all 5 nodes — this is NOT a state divergence, purely a consensus halt
- node4 (4300/MSSQL) has only 3 connected peers — missing `12D3KooWHadjF6TXWPqX6Rg2ZfAKPi6CJw52xz3N2FNDJcQiupxP` (node5/sqlite)
- node4 is continuously rejecting node5 as "unauthorized peer" on both anti-entropy sync-status and sync RPC channels
- node4 has 135 parked certs and peer_unauthorized_inbound=639 — rejections accumulating since ~round 200
- node4 reports only `1/1 certs` at halt vs `3/1 certs` for others — far fewer certificates collected
- node1 triggered sub_quorum escape / snapshot resync (issue #13 workaround)
- All nodes: activeParticipants=1, registeredNodes=5 — sub_quorum because quorum requires >1 active

**Session context:** Branch fix/issue-117-knex-migrations, PR #118 open. Mixed-DB integration test cluster running post-21/21 verification pass.
