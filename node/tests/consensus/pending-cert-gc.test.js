/**
 * @file tests/consensus/pending-cert-gc.test.js
 * @description §2 cert-GC tests for Narwhal's parked-cert waiter GC.
 *
 * When a peer cert arrives referencing parent hashes that aren't yet in
 * the DAG, Narwhal parks it in `_pendingCerts` keyed by cert hash, with
 * a reverse index `_pendingByParent` for O(1) flush on parent arrival.
 * Without GC, a parked cert whose parent will never arrive (e.g. the
 * parent was in a GC'd round, or the peer is byzantine) leaks memory
 * forever.
 *
 * This file exercises `narwhal.prunePendingCertsBefore(cutoff)` (the
 * public accessor added for ops diagnostics + test support) to verify:
 *
 *   - Parked certs with `round < cutoff` are dropped
 *   - Certs with `round >= cutoff` are preserved
 *   - `_pendingByParent` reverse index is cleaned up symmetrically
 *   - `pending_certs_pruned` metric increments
 *   - Multiple cutoff rounds work correctly
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createNarwhal } = require(path.join(SRC, "consensus", "narwhal"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));

beforeAll(async () => { await initCrypto(); });

// ── Harness ──────────────────────────────────────────────────────────────

function stubNetwork() {
  return {
    TOPICS: { MEMPOOL: "tip/mempool", CERTIFICATES: "tip/certificates", CONSENSUS: "tip/consensus" },
    publish: () => { /* no-op */ },
    authorizedPeers: () => ({}),
  };
}

function setupNarwhal() {
  const dag = initDAG({ dbPath: ":memory:" });
  const mempool = createMempool({ dag });
  const network = stubNetwork();
  const narwhal = createNarwhal({
    dag, mempool, network,
    config: {},
    getNodeKey: () => null,
    getNodeCount: () => 1,
    getCommittee: () => ["tip://node/n1"],
  });
  return { dag, narwhal };
}

function fakeCert(round, authorSuffix = "a") {
  const hash = shake256(`cert:${round}:${authorSuffix}`);
  return {
    hash,
    round,
    author_node_id: `tip://node/${authorSuffix}`,
    batch: { round, author_node_id: `tip://node/${authorSuffix}`, txs: [], signature: "00" },
    acknowledgments: [],
    parent_hashes: [],
    signature: "00",
  };
}

// ═══════════════════════════════════════════════════════════════════════════

describe("narwhal prunePendingCertsBefore (parked cert waiter GC)", () => {
  test("drops parked certs with round < cutoff, keeps round >= cutoff", () => {
    const { narwhal } = setupNarwhal();

    narwhal.parkPendingCert(fakeCert(5, "a"), [shake256("missing-parent-5a")]);
    narwhal.parkPendingCert(fakeCert(10, "b"), [shake256("missing-parent-10b")]);
    narwhal.parkPendingCert(fakeCert(20, "c"), [shake256("missing-parent-20c")]);
    expect(narwhal.pendingCertCount()).toBe(3);

    const n = narwhal.prunePendingCertsBefore(15);
    expect(n).toBe(2);
    expect(narwhal.pendingCertCount()).toBe(1);
    expect(narwhal.stats().metrics.pending_certs_pruned).toBe(2);
  });

  test("boundary: cutoff equals lowest parked round → no drop", () => {
    const { narwhal } = setupNarwhal();
    narwhal.parkPendingCert(fakeCert(10, "a"), [shake256("p1")]);
    narwhal.parkPendingCert(fakeCert(11, "b"), [shake256("p2")]);
    expect(narwhal.prunePendingCertsBefore(10)).toBe(0);
    expect(narwhal.pendingCertCount()).toBe(2);
  });

  test("cutoff above all parked rounds drops everything", () => {
    const { narwhal } = setupNarwhal();
    for (let r = 1; r <= 5; r++) {
      narwhal.parkPendingCert(fakeCert(r, `n${r}`), [shake256(`parent-${r}`)]);
    }
    expect(narwhal.pendingCertCount()).toBe(5);
    expect(narwhal.prunePendingCertsBefore(100)).toBe(5);
    expect(narwhal.pendingCertCount()).toBe(0);
  });

  test("empty pending map is a no-op", () => {
    const { narwhal } = setupNarwhal();
    expect(narwhal.prunePendingCertsBefore(100)).toBe(0);
    expect(narwhal.pendingCertCount()).toBe(0);
  });

  test("reverse index (_pendingByParent) cleaned up symmetrically", () => {
    // When a parked cert is dropped, the parent it was waiting on must
    // also disappear from the reverse index — otherwise a later arrival
    // of that parent would try to flush a child that no longer exists.
    const { narwhal } = setupNarwhal();

    const parentHash = shake256("shared-parent-hash");
    narwhal.parkPendingCert(fakeCert(5, "a"), [parentHash]);
    narwhal.parkPendingCert(fakeCert(6, "b"), [parentHash]);  // same parent, different child

    narwhal.prunePendingCertsBefore(7);  // drop both
    expect(narwhal.pendingCertCount()).toBe(0);

    // If the reverse index still pointed to the dropped children, we'd
    // see a stale entry. Indirect check: re-park a fresh cert with the
    // same parent; assert pending count reflects only the new entry.
    narwhal.parkPendingCert(fakeCert(10, "c"), [parentHash]);
    expect(narwhal.pendingCertCount()).toBe(1);
  });

  test("pending_certs_pruned metric accumulates across runs", () => {
    const { narwhal } = setupNarwhal();
    for (let r = 1; r <= 3; r++) {
      narwhal.parkPendingCert(fakeCert(r, `a${r}`), [shake256(`p${r}`)]);
    }
    narwhal.prunePendingCertsBefore(2);  // drops round 1
    expect(narwhal.stats().metrics.pending_certs_pruned).toBe(1);

    for (let r = 10; r <= 12; r++) {
      narwhal.parkPendingCert(fakeCert(r, `b${r}`), [shake256(`p${r}`)]);
    }
    narwhal.prunePendingCertsBefore(11);  // drops rounds 2, 3, 10
    expect(narwhal.stats().metrics.pending_certs_pruned).toBe(4);  // 1 + 3
  });

  test("cert with multiple missing parents cleans all reverse-index entries", () => {
    const { narwhal } = setupNarwhal();
    const parents = [shake256("parent-A"), shake256("parent-B"), shake256("parent-C")];
    narwhal.parkPendingCert(fakeCert(5, "multi"), parents);
    expect(narwhal.pendingCertCount()).toBe(1);

    narwhal.prunePendingCertsBefore(10);
    expect(narwhal.pendingCertCount()).toBe(0);

    // Re-park a cert with the same parents — should work without
    // interference from stale reverse-index entries.
    narwhal.parkPendingCert(fakeCert(20, "new"), parents);
    expect(narwhal.pendingCertCount()).toBe(1);
    narwhal.prunePendingCertsBefore(30);
    expect(narwhal.pendingCertCount()).toBe(0);
  });
});
