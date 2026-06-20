# TIP Consensus Halt Solutions

Solutions accumulate here across sessions. Apply ONLY after the cross-check gate (user says "let's apply halt solutions").

---

## Solution 1 — Restart node4 container only

**Found:** 2026-06-20
**Addresses halt event:** 2026-06-20T06:23:03Z
**Root cause:** node4's in-memory `authorizedPeers` map never has node5's peerId. Restarting clears the map and forces a fresh handshake attempt. If node5 is running and reachable, the handshake should succeed and node4 will authorize node5.
**Confidence:** LOW-MEDIUM
**Risk:** If the cause of the failed handshake is node5's registration not being in node4's MSSQL DB (timing at boot), the restart might fail to authorize node5 again. Also doesn't address underlying relay-path asymmetry.

**Changes required:**
- No code changes — runtime action only:
```bash
docker compose -f docker-compose.mixed-db.yml restart node4
# Watch for: "OK: tip://node/... — authorized" for 12D3KooWHadj (node5)
docker logs -f tip-mixed-node4 2>&1 | grep -E 'authorized|handshake|halt'
```

**Why not applied yet:** awaiting cross-check against other solutions in this file.

---

## Solution 2 — Full cluster restart

**Found:** 2026-06-20
**Addresses halt event:** 2026-06-20T06:23:03Z
**Root cause:** All handshake state is lost on container restart. Fresh start forces all 5 nodes to redo all 10 peer handshakes from scratch, likely succeeding this time when all DBs are fully warmed.
**Confidence:** HIGH (for this specific halt instance)
**Risk:** Does NOT fix the relay-path lag root cause. Same halt will recur after the cluster runs long enough for relay-path lag to cause node4 cert starvation again.

**Changes required:**
- No code changes — runtime action only:
```bash
docker compose -f docker-compose.mixed-db.yml down
docker compose -f docker-compose.mixed-db.yml up -d
# Wait for all 5 to be healthy, then verify:
./scripts/verify-mixed-db.sh
```

**Why not applied yet:** awaiting cross-check against other solutions in this file.

---

## Solution 3 — Add explicit bootstrap peers for node4↔node5 in docker-compose.mixed-db.yml

**Found:** 2026-06-20
**Addresses halt event:** 2026-06-20T06:23:03Z
**Root cause:** node4 and node5 have no `TIP_BOOTSTRAP_PEERS` pointing at each other. They rely solely on the known-peers hint from other nodes during handshake, which may arrive too late or be missed. Adding explicit bootstrap ensures they attempt a direct connection and handshake at startup.
**Confidence:** MEDIUM
**Risk:** Local-only fix (docker-compose.mixed-db.yml is gitignored). Doesn't address the underlying relay-path lag for the production 5-node cluster.

**Changes required:**
- `docker-compose.mixed-db.yml` — add `TIP_BOOTSTRAP_PEERS` to node4's environment:
```diff
  node4:
    environment:
      ...
+     TIP_BOOTSTRAP_PEERS: "/ip4/172.30.1.14/tcp/4401/p2p/12D3KooWHadjF6TXWPqX6Rg2ZfAKPi6CJw52xz3N2FNDJcQiupxP"
```
- `docker-compose.mixed-db.yml` — add `TIP_BOOTSTRAP_PEERS` to node5's environment:
```diff
  node5:
    environment:
      ...
+     TIP_BOOTSTRAP_PEERS: "/ip4/172.30.1.13/tcp/4301/p2p/12D3KooWCoqJCtFdUc9q1M6o9187H4zDxzPUqXRAtsrkry6XVzR6"
```

Note: node5's peerId (`12D3KooWHadjF6TXWPqX6Rg2ZfAKPi6CJw52xz3N2FNDJcQiupxP`) was observed in the health output. Must be confirmed after a restart since libp2p peerIds can be regenerated if the key changes.

**Why not applied yet:** awaiting cross-check against other solutions in this file.

---

## Solution 4 — Fix relay-path lag: ensure all-pairs P2P mesh in network/node.js

**Found:** 2026-06-20
**Addresses halt event:** 2026-06-20T06:23:03Z (and the known open issue from CLAUDE.md: nodes 4100↔4300 not directly meshed)
**Root cause:** The peer discovery mechanism doesn't guarantee all-pairs direct connections. node4 connects to 3 peers, missing node5. When this missing link affects cert propagation (node4 sees `certs_parked: 135`, `batches_received: 186` vs ~478 for others), node4 starves of certs, activeParticipants drops to 1 for all nodes, and sub_quorum halts.
**Confidence:** HIGH (addresses documented root cause)
**Risk:** Changing peer discovery may affect the standard 5-node cluster (not just the mixed-DB cluster). Requires understanding why all-pairs isn't already enforced.

**Investigation required before implementing:**
- Read `node/src/network/peer-discovery.js` lines around dialKnownPeers and bootstrap logic
- Check if the known-peers hint in HandshakeAck is propagating all 5 peer addresses to node4 at boot
- Check whether node4's bootstrap peers environment var is empty (it is in docker-compose.mixed-db.yml — node4 only has `depends_on: node1`)

**Likely fix location:** `docker-compose.mixed-db.yml` node4 section, OR `node/src/network/peer-discovery.js` dialKnownPeers retry logic if a peer is not yet up when the hint arrives.

**Why not applied yet:** awaiting cross-check against other solutions in this file. Also requires reading peer-discovery.js to confirm the exact change needed.

---

## Solution 5 — Increase handshake retry / backoff in network/node.js

**Found:** 2026-06-20
**Addresses halt event:** 2026-06-20T06:23:03Z
**Root cause:** The handshake may have been attempted while node5 was still booting (it only depends on node1 starting, not on being healthy). If the handshake failed due to a transient connection error or timeout, there is no automatic re-attempt — once a peer fails handshake, it's not retried until a new connection event fires.
**Confidence:** MEDIUM
**Risk:** Adding aggressive retries could cause thundering-herd at boot. Must be backoff-limited.

**Changes required:**
- `node/src/network/node.js` — in the `peer:connect` handler, if handshake initiation fails, schedule a retry with exponential backoff (e.g., 5s, 15s, 45s) rather than silently dropping.
- Alternatively, add a periodic sweep in `peer-discovery.js` that dials connected-but-not-authorized peers.

**Why not applied yet:** awaiting cross-check against other solutions in this file.

## Solution 6 — Rate-limit UAT test submissions to prevent anchor cert drop under burst

**Found:** 2026-06-20
**Addresses halt event:** 2026-06-20T10:40:31Z
**Root cause:** UAT rapid API submission (multiple revocations in sequence with <100ms gaps) saturates local p2p cert propagation. Node1 misses anchor certs at progressively increasing frequency (1 → 1 → 2 → 5 missing) until state root diverges.
**Confidence:** MEDIUM
**Risk:** Low — purely a test harness change, does not affect production node behavior.

**Changes required:**
- `scripts/uat-signature-unification.js` line ~350 (Phase 5 revocations): add 500ms sleep between each revocation API call to give the network time to propagate certs before the next anchor cycle.

**Why not applied yet:** awaiting cross-check against other solutions in this file.

## Solution 7 — Increase Bullshark anchor deferred-commit timeout in narwhal.js

**Found:** 2026-06-20
**Addresses halt event:** 2026-06-20T10:40:31Z
**Root cause:** `deferred anchor timed out with N cert(s) permanently missing` — the anchor timeout fires before all node's certificates arrive, causing different commit decisions on different nodes under burst.
**Confidence:** MEDIUM
**Risk:** Medium — increasing timeout increases latency for anchor commits. Need to verify the timeout constant and its impact on normal operation.

**Changes required:**
- Search for `deferred.*anchor.*timeout` or `permanently missing` in `node/src/consensus/` to find the timeout constant.
- Increase from current value (likely 60s based on ~round interval gap) to 120-180s to give slow cert propagation more time.

**Why not applied yet:** awaiting cross-check against other solutions in this file.
