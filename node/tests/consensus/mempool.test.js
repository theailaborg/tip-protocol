/**
 * @file tests/consensus/mempool.test.js
 * @description Mempool unit tests, with focus on `addFront` — the
 * front-prepending insert added in #64 to support orphan-batch
 * requeueing without starving the original (older) submission.
 *
 * Coverage map:
 *   1. baseline `add` + `drain` ordering (FIFO via Map insertion order)
 *      — pinned because `addFront` only preserves "older = drained
 *      first" semantics if the underlying `drain` honors insertion
 *      order. Lock the contract `addFront` relies on.
 *   2. `addFront` happy path — single front-loaded tx drains before
 *      any back-added tx, with custom `receivedAt` honored.
 *   3. `addFront` rejection paths — duplicate, mempool_full,
 *      missing tx_id.
 *   4. multi-tx requeue under reverse-iteration — caller-side pattern
 *      from `narwhal._resetRoundState` preserves original batch FIFO
 *      after the txs come back through `addFront`.
 *   5. `addFront` side effects — onTxAdded callback fires (so Narwhal
 *      wakes from idle), counters increment, dag.saveMempoolTx is
 *      called for crash recovery.
 *   6. age-based eviction respects the caller-supplied `receivedAt`
 *      so an orphan-requeued tx doesn't get a fresh TTL it didn't
 *      earn (would mask starvation).
 *
 * Why this matters: the "narwhal-stale-batch" regression (#64) only
 * holds end-to-end if `addFront` preserves submit order on requeue.
 * If a future refactor drops the Map-pivot or appends instead of
 * prepends, the orphan tx ages out behind newer arrivals and the
 * silent-loss bug returns under load — these tests are the seal.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../../../shared/time");

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initDAG } = require(path.join(SRC, "dag"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { TX_REJECTION_REASON } = require(path.join(SHARED, "constants"));

// ── Helpers ────────────────────────────────────────────────────────────────

function makeTx(id, extra = {}) {
  return { tx_id: id, type: "TEST", payload: { n: id }, ...extra };
}

function ids(txs) { return txs.map(t => t.tx_id); }

// ═══════════════════════════════════════════════════════════════════════════
// 1. Baseline add + drain — pin FIFO insertion-order semantics.
//    addFront's correctness rests on this invariant; if a refactor breaks
//    Map insertion-order drain, addFront silently degrades and the
//    orphan-tx starvation bug returns. This is the seal.
// ═══════════════════════════════════════════════════════════════════════════

describe("mempool — baseline FIFO drain order (addFront's substrate)", () => {
  test("drain returns txs in add() order", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);

    mempool.add(makeTx("A"));
    mempool.add(makeTx("B"));
    mempool.add(makeTx("C"));

    expect(ids(mempool.drain(10))).toEqual(["A", "B", "C"]);
    expect(mempool.size()).toBe(0);
  });

  test("drain respects limit, leaves the rest in original order", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);
    for (const id of ["A", "B", "C", "D"]) mempool.add(makeTx(id));

    expect(ids(mempool.drain(2))).toEqual(["A", "B"]);
    expect(mempool.size()).toBe(2);
    expect(ids(mempool.drain(10))).toEqual(["C", "D"]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. addFront happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("mempool.addFront — happy path", () => {
  test("prepends a single tx so it drains FIRST, ahead of pre-existing entries", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);

    mempool.add(makeTx("B"));
    mempool.add(makeTx("C"));

    // A was orphaned from a stale-batch round and is being requeued.
    // It must drain before B and C even though it's added last.
    const r = mempool.addFront(makeTx("A"), nowMs() - 10_000);
    expect(r).toEqual({ added: true });

    expect(ids(mempool.drain(10))).toEqual(["A", "B", "C"]);
  });

  test("returns {added:true} and updates received_total counter", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);
    const before = mempool.stats().counters.received_total;

    expect(mempool.addFront(makeTx("X"), nowMs())).toEqual({ added: true });
    expect(mempool.stats().counters.received_total).toBe(before + 1);
    expect(mempool.size()).toBe(1);
  });

  test("preserves the caller-supplied receivedAt (no fresh TTL on requeue)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    // 1s TTL — very tight so we can verify eviction behavior precisely.
    const mempool = createMempool(dag, { maxTxAgeSec: 1 });

    // Tx was originally received 5s ago; if addFront resets the clock,
    // it would survive the next drain() eviction sweep and starve newer
    // arrivals. Old timestamp must persist so eviction triggers.
    mempool.addFront(makeTx("OLD"), nowMs() - 5000);
    mempool.add(makeTx("NEW"));

    // drain() runs _evictStale first; the 5s-old front entry must be
    // evicted, leaving NEW as the only drainable tx.
    expect(ids(mempool.drain(10))).toEqual(["NEW"]);
    expect(mempool.stats().counters.evicted_total).toBe(1);
  });

  test("missing receivedAt falls back to now() — no crash, just a fresh stamp", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);

    // Caller may legitimately not have an original timestamp (e.g.
    // peer-relay path); the function must not throw.
    expect(mempool.addFront(makeTx("Y"))).toEqual({ added: true });
    expect(mempool.stats().oldestAgeSec).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. addFront rejection paths
// ═══════════════════════════════════════════════════════════════════════════

describe("mempool.addFront — rejection paths", () => {
  test("rejects tx without tx_id and increments rejected_total", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);
    const before = mempool.stats().counters.rejected_total;

    const r = mempool.addFront({ type: "NO_ID" });
    expect(r).toEqual({ added: false, reason: "tx missing tx_id" });
    expect(mempool.stats().counters.rejected_total).toBe(before + 1);
  });

  test("rejects null tx", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);
    expect(mempool.addFront(null)).toEqual({ added: false, reason: "tx missing tx_id" });
  });

  test("dedup: returns {added:false, reason:'duplicate'} without rejecting (not a counter event)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);
    mempool.add(makeTx("DUP"));

    const rejectedBefore = mempool.stats().counters.rejected_total;
    const r = mempool.addFront(makeTx("DUP"), nowMs() - 1000);

    expect(r).toEqual({ added: false, reason: "duplicate" });
    // Not a "rejected_total" event — duplicates are common after partial
    // requeue / double-submit and are noise, not flow-control failures.
    expect(mempool.stats().counters.rejected_total).toBe(rejectedBefore);
    // And original drain order must NOT change (existing entry stays put).
    expect(ids(mempool.drain(10))).toEqual(["DUP"]);
  });

  test("mempool_full: rejects when at capacity and counts as rejection", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag, { maxSize: 2 });
    mempool.add(makeTx("A"));
    mempool.add(makeTx("B"));

    const r = mempool.addFront(makeTx("C"), nowMs());
    expect(r).toEqual({ added: false, reason: "mempool_full" });
    expect(mempool.stats().counters.rejected_total).toBe(1);
    expect(mempool.size()).toBe(2);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Multi-tx orphan-requeue under reverse-iteration
//    Mirrors the actual call-site pattern in narwhal._resetRoundState:
//      for (let i = orphanedTxs.length - 1; i >= 0; i--) {
//        mempool.addFront(orphanedTxs[i], nowMs());
//      }
//    After reverse-iteration the orphaned batch must drain in its
//    ORIGINAL order (T0, T1, T2, ...), ahead of any newer arrivals.
// ═══════════════════════════════════════════════════════════════════════════

describe("mempool.addFront — orphan-batch requeue (reverse-iteration pattern from narwhal._resetRoundState)", () => {
  test("3-tx orphaned batch drains in original FIFO order ahead of newer txs", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);

    // After self's orphaned batch was cleared, the mempool already has
    // newer arrivals from the post-orphan window.
    mempool.add(makeTx("NEW1"));
    mempool.add(makeTx("NEW2"));

    // Orphaned batch (in submit order) — requeue caller-side reverse loop.
    const orphaned = [makeTx("OLD1"), makeTx("OLD2"), makeTx("OLD3")];
    for (let i = orphaned.length - 1; i >= 0; i--) {
      const r = mempool.addFront(orphaned[i], nowMs());
      expect(r).toEqual({ added: true });
    }

    // Drain order: orphaned txs in their original FIFO, then newer arrivals.
    expect(ids(mempool.drain(10))).toEqual(["OLD1", "OLD2", "OLD3", "NEW1", "NEW2"]);
  });

  test("requeue into empty mempool yields original FIFO", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);

    const orphaned = [makeTx("T0"), makeTx("T1"), makeTx("T2"), makeTx("T3")];
    for (let i = orphaned.length - 1; i >= 0; i--) mempool.addFront(orphaned[i], nowMs());

    expect(ids(mempool.drain(10))).toEqual(["T0", "T1", "T2", "T3"]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. Side effects — Narwhal wakeup callback + disk persistence
// ═══════════════════════════════════════════════════════════════════════════

describe("mempool.addFront — side effects (callback, persistence)", () => {
  test("invokes onTxAdded so Narwhal wakes from idle", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);
    const seen = [];
    mempool.onTxAdded((tx) => seen.push(tx.tx_id));

    mempool.addFront(makeTx("WAKE"), nowMs());
    expect(seen).toEqual(["WAKE"]);
  });

  test("does NOT invoke onTxAdded on duplicate or full rejection", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag, { maxSize: 1 });
    mempool.add(makeTx("X"));
    const seen = [];
    mempool.onTxAdded((tx) => seen.push(tx.tx_id));

    mempool.addFront(makeTx("X"), nowMs());      // duplicate
    mempool.addFront(makeTx("FULL"), nowMs());   // mempool_full
    expect(seen).toEqual([]);
  });

  test("persists to dag.saveMempoolTx so a restart still sees the requeued tx", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool1 = createMempool(dag);
    mempool1.add(makeTx("B"));
    mempool1.addFront(makeTx("A"), nowMs() - 5000);

    // Simulate restart — second mempool instance restores from the same
    // dag. Order of restore is whatever the dag returns; for SQLite-backed
    // dag it's `ORDER BY received_at ASC`. The functional invariant we
    // care about: the front-loaded tx survives the restart at all.
    const mempool2 = createMempool(dag);
    expect(mempool2.size()).toBe(2);
    expect(mempool2.has("A")).toBe(true);
    expect(mempool2.has("B")).toBe(true);
  });

  test("survives dag.saveMempoolTx throwing — in-memory state is still updated", () => {
    // Disk failure during requeue must not abort the in-memory enqueue —
    // the tx still drains in the next round; we just lose crash recovery
    // for it. The function logs and continues.
    const flakeyDag = {
      saveMempoolTx: () => { throw new Error("disk full"); },
      getMempoolTxs: () => [],
      deleteMempoolTxs: () => { },
    };
    const mempool = createMempool(flakeyDag);

    expect(mempool.addFront(makeTx("RESCUE"), nowMs())).toEqual({ added: true });
    expect(mempool.size()).toBe(1);
    expect(ids(mempool.drain(10))).toEqual(["RESCUE"]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. tx_rejections wiring — mempool_full drops are recorded for replay
//    Seals the no-loss invariant at the mempool admit boundary: a tx
//    that the API admitted but the mempool refused must leave a row in
//    `tx_rejections` so the outcome endpoint can answer "what happened".
// ═══════════════════════════════════════════════════════════════════════════

describe("mempool — tx_rejections wiring on mempool_full", () => {
  test("add() at capacity records a mempool_full rejection with full tx body", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag, { maxSize: 1, nodeId: "tip://node/test" });

    mempool.add(makeTx("FIRST"));
    const rejected = makeTx("REJECTED", { tx_type: "REGISTER_IDENTITY" });
    const r = mempool.add(rejected);
    expect(r).toEqual({ added: false, reason: "mempool_full" });

    const row = dag.getTxRejection("REJECTED");
    expect(row).not.toBeNull();
    expect(row.reason).toBe(TX_REJECTION_REASON.MEMPOOL_FULL);
    expect(row.dropper_node_id).toBe("tip://node/test");
    expect(row.tx_type).toBe("REGISTER_IDENTITY");
    // Full tx body preserved for operator-initiated replay.
    expect(row.tx_data).toEqual(rejected);
    // Detail captures the cap that was breached (operators can correlate
    // mempool_full bursts with the configured limit at the time).
    expect(row.reason_detail).toContain("cap=1");
  });

  test("addFront() at capacity records a mempool_full rejection (front-load tag in detail)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag, { maxSize: 1, nodeId: "tip://node/test" });
    mempool.add(makeTx("FIRST"));

    const r = mempool.addFront(makeTx("ORPHAN"), nowMs() - 5000);
    expect(r).toEqual({ added: false, reason: "mempool_full" });

    const row = dag.getTxRejection("ORPHAN");
    expect(row.reason).toBe(TX_REJECTION_REASON.MEMPOOL_FULL);
    expect(row.reason_detail).toContain("front-load");
  });

  test("duplicate add does NOT create a tx_rejection row (tx is still alive)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag, { nodeId: "tip://node/test" });

    mempool.add(makeTx("DUP"));
    const r = mempool.add(makeTx("DUP"));
    expect(r).toEqual({ added: false, reason: "duplicate" });

    // The original tx is still pending; no loss to record. Recording one
    // here would leave a misleading "this tx was rejected" row alongside
    // a still-live mempool entry, breaking the outcome endpoint contract.
    expect(dag.getTxRejection("DUP")).toBeNull();
    expect(dag.countTxRejections()).toBe(0);
  });

  test("missing tx_id is logged but not persisted (no PK to index)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag, { nodeId: "tip://node/test" });

    const r = mempool.add({ tx_type: "INVALID" });
    expect(r).toEqual({ added: false, reason: "tx missing tx_id" });
    expect(dag.countTxRejections()).toBe(0);
  });

  test("nodeId defaults to 'unknown' when not configured (test fixtures stay simple)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag, { maxSize: 1 });  // no nodeId
    mempool.add(makeTx("FIRST"));
    mempool.add(makeTx("REJ"));
    expect(dag.getTxRejection("REJ").dropper_node_id).toBe("unknown");
  });
});

describe("mempool — tx_rejections wiring on TTL eviction", () => {
  test("_evictStale (via drain) records mempool_ttl_expired with full body for each evicted tx", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    // 1s TTL — short window so the test can plant pre-aged entries via
    // addFront's caller-supplied receivedAt without sleeping.
    const mempool = createMempool(dag, { maxTxAgeSec: 1, nodeId: "tip://node/test" });

    const stale1 = makeTx("STALE-1", { tx_type: "REGISTER_IDENTITY" });
    const stale2 = makeTx("STALE-2", { tx_type: "REGISTER_CONTENT" });
    const fresh  = makeTx("FRESH",   { tx_type: "REGISTER_IDENTITY" });

    // Both planted with receivedAt 5s in the past — well past 1s TTL.
    mempool.addFront(stale1, nowMs() - 5000);
    mempool.addFront(stale2, nowMs() - 5000);
    mempool.add(fresh);

    // drain() runs _evictStale on entry. Stale entries are removed and
    // a tx_rejection row is written for each. Fresh tx survives.
    expect(ids(mempool.drain(10))).toEqual(["FRESH"]);
    expect(mempool.stats().counters.evicted_total).toBe(2);

    // Each evicted tx has a rejection row stamped with our nodeId, the
    // canonical TTL reason, the configured TTL in detail, and the full
    // tx body (so a future replay path can re-validate + re-submit).
    for (const stale of [stale1, stale2]) {
      const row = dag.getTxRejection(stale.tx_id);
      expect(row).not.toBeNull();
      expect(row.reason).toBe(TX_REJECTION_REASON.MEMPOOL_TTL_EXPIRED);
      expect(row.dropper_node_id).toBe("tip://node/test");
      expect(row.tx_type).toBe(stale.tx_type);
      expect(row.reason_detail).toContain("ttl=1s");
      expect(row.tx_data).toEqual(stale);
    }
    // Fresh (drained) tx must NOT appear in rejections.
    expect(dag.getTxRejection("FRESH")).toBeNull();
    expect(dag.countTxRejections()).toBe(2);
  });

  test("getAll() also triggers eviction wiring (mempool gossip path)", () => {
    // _evictStale is called from both drain() and getAll(); the gossip
    // path uses getAll, so a tx that ages out without ever being drained
    // must still leave a rejection row. Catches a future refactor that
    // moves the wiring into drain() only.
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag, { maxTxAgeSec: 1, nodeId: "tip://node/test" });

    const stale = makeTx("AGED");
    mempool.addFront(stale, nowMs() - 5000);

    expect(mempool.getAll()).toEqual([]);  // evicted out from under getAll
    expect(dag.getTxRejection("AGED").reason).toBe(TX_REJECTION_REASON.MEMPOOL_TTL_EXPIRED);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. Module surface — export shape
// ═══════════════════════════════════════════════════════════════════════════

describe("mempool — exported surface", () => {
  test("addFront is part of the returned API alongside add/drain/etc.", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const mempool = createMempool(dag);
    // Sanity guard: a refactor that drops `addFront` from the return
    // literal would silently make narwhal._resetRoundState fall back to
    // a hard error at call time — explicit assertion here catches it
    // at suite startup instead.
    for (const name of ["add", "addFront", "drain", "remove", "has", "getAll", "size", "clear", "stats", "onTxAdded"]) {
      expect(typeof mempool[name]).toBe("function");
    }
  });
});
