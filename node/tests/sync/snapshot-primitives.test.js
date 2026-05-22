/**
 * @file tests/sync/snapshot-primitives.test.js
 * @description §14/#49 unit tests for the snapshot install primitives.
 *
 * Covers the building blocks the e2e snapshot tests exercise via the
 * round-trip path:
 *
 *   dag.addTx (snapshot-install path)  — auto-fill is gated on tx_id
 *                                        being absent, so genesis-style
 *                                        txs (prev:[] with tx_id set)
 *                                        round-trip without corruption
 *   dag.iterateAllTransactions         — deterministic ordering for sender
 *   dag.iterateAllCommitsExcept        — exclusion semantics for the latest
 *   sync/snapshot-roots builders       — domain-separated SHAKE-256, empty-
 *                                        input root constants, ordering-
 *                                        sensitivity (different order →
 *                                        different root)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, computeTxId, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { GENESIS_TX_ID } = require(path.join(SRC, "genesis"));
const {
  createTxsFullRootBuilder,
  createCommitsFullRootBuilder,
  computeTxsFullRoot,
  computeCommitsFullRoot,
  canonTx,
  canonCommit,
  EMPTY_TXS_FULL_ROOT,
  EMPTY_COMMITS_FULL_ROOT,
} = require(path.join(SRC, "sync", "snapshot-roots"));

beforeAll(async () => {
  await initCrypto();
});

// Helper: build a content-addressed tx with given prev. Used for both
// submission-path testing (no tx_id, addTx auto-fills) and snapshot-
// install-path testing (tx_id pre-set, addTx preserves canonical bytes).
function makeTx({ prev = [], tx_type = "REGISTER_CONTENT", data = { ctid: "tip://content/u" }, timestamp = 1767225600000 } = {}) {
  const body = { tx_type, timestamp, prev, data };
  body.tx_id = computeTxId(body);
  body.signature = "00";
  return body;
}

// ─── dag.addTx — snapshot-install path (genesis-style preservation) ─────────

describe("dag.addTx — snapshot-install path", () => {
  test("preserves prev:[] verbatim when tx_id is set (genesis-style round-trip)", () => {
    // Critical for #49: genesis ships with prev:[] and tx_id set. Any
    // auto-fill of prev on the install path would change canonical
    // bytes → verifyTxId fails. addTx must skip auto-fill entirely
    // when tx_id is already pinned.
    const dag = initDAG({ dbPath: ":memory:" });
    const tx = makeTx({ prev: [] });
    expect(() => dag.addTx(tx)).not.toThrow();
    const got = dag.getTx(tx.tx_id);
    expect(got).not.toBeNull();
    expect(got.prev).toEqual([]);
  });

  test("rejects tx whose canonical content has been tampered (tx_id no longer matches)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const tx = makeTx({ prev: [GENESIS_TX_ID, GENESIS_TX_ID] });
    tx.data.ctid = "tip://content/tampered";        // mutate after tx_id is fixed
    expect(() => dag.addTx(tx)).toThrow(/tx_id mismatch/i);
  });

  test("idempotent — duplicate save is a silent no-op (INSERT OR IGNORE)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const tx = makeTx({ prev: [GENESIS_TX_ID, GENESIS_TX_ID] });
    dag.addTx(tx);
    expect(() => dag.addTx(tx)).not.toThrow();
    const all = dag.getAllTxs().filter(t => t.tx_id === tx.tx_id);
    expect(all).toHaveLength(1);
  });

  test("auto-fill still fires for submission-style callers (no tx_id, prev:[])", () => {
    // Regression check on the gating: tests + scheduler/scoring/jury
    // pass {tx_type, data, timestamp, prev:[]} without tx_id and rely
    // on auto-fill to populate prev from _prev before computing tx_id.
    const dag = initDAG({ dbPath: ":memory:" });
    const before = dag.getRecentPrev();
    expect(before).toHaveLength(2);
    const submitted = dag.addTx({
      tx_type: "REGISTER_CONTENT",
      timestamp: 1777248000000,
      data: { ctid: "tip://content/submission" },
      prev: [],
      signature: "00",
    });
    // tx_id was computed from auto-filled prev (= before).
    expect(submitted.tx_id).toBeTruthy();
    expect(submitted.prev).toEqual(before);   // auto-filled
    expect(dag.getTx(submitted.tx_id)).not.toBeNull();
  });

  test("after batch install in tx_id order, _prev points at [highest, second-highest]", () => {
    // Snapshot-install loop installs txs in tx_id ASC order. addTx's
    // _updatePrev fires per row, leaving the ring at the last two
    // installed tx_ids — exactly what reprime-from-bootstrap would
    // compute, so no separate reprime call is needed.
    const dag = initDAG({ dbPath: ":memory:" });
    const baseline = dag.getRecentPrev();
    const tx1 = makeTx({ prev: [...baseline], timestamp: 1777248001000 });
    dag.addTx(tx1);
    const tx2 = makeTx({ prev: dag.getRecentPrev(), timestamp: 1777248002000 });
    dag.addTx(tx2);
    const ring = dag.getRecentPrev();
    expect(ring[0]).toBe(tx2.tx_id);
    expect(ring[1]).toBe(tx1.tx_id);
  });
});

// ─── dag.iterateAllTransactions ─────────────────────────────────────────────

describe("dag.iterateAllTransactions", () => {
  test("yields every row from the transactions table", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const before = [...dag.iterateAllTransactions()];
    const tx = makeTx({ prev: [GENESIS_TX_ID, GENESIS_TX_ID] });
    dag.addTx(tx);
    const after = [...dag.iterateAllTransactions()];
    expect(after.length).toBe(before.length + 1);
    expect(after.find(t => t.tx_id === tx.tx_id)).toBeTruthy();
  });

  test("ordering is deterministic across two iterators on the same store", () => {
    // Same DAG → two iterations → identical order. This is what makes
    // sender + receiver hashes converge.
    const dag = initDAG({ dbPath: ":memory:" });
    const tx = makeTx({ prev: [GENESIS_TX_ID, GENESIS_TX_ID] });
    dag.addTx(tx);
    const a = [...dag.iterateAllTransactions()].map(t => t.tx_id);
    const b = [...dag.iterateAllTransactions()].map(t => t.tx_id);
    expect(a).toEqual(b);
  });
});

// ─── dag.iterateAllCommitsExcept ────────────────────────────────────────────

describe("dag.iterateAllCommitsExcept", () => {
  function mkCommit(round, idx) {
    return {
      round,
      anchor_cert_hash: "a".repeat(64),
      leader_node_id: "node-x",
      committee: ["node-x"],
      support_count: 1,
      consensus_index: idx,
      committed_at: `2026-01-01T00:00:0${round}.000Z`,
      state_merkle_root: "0".repeat(64),
      txs_merkle_root: "0".repeat(64),
      ack_signer_ids: [],
      ack_signatures: [],
    };
  }

  test("yields every commit when latestRound is omitted", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    dag.saveCommit(mkCommit(1, 0));
    dag.saveCommit(mkCommit(2, 1));
    dag.saveCommit(mkCommit(3, 2));
    const all = [...dag.iterateAllCommitsExcept()];
    expect(all.map(c => c.round).sort((a, b) => a - b)).toEqual([1, 2, 3]);
  });

  test("excludes the row matching latestRound", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    dag.saveCommit(mkCommit(1, 0));
    dag.saveCommit(mkCommit(2, 1));
    dag.saveCommit(mkCommit(3, 2));
    const filtered = [...dag.iterateAllCommitsExcept(2)];
    expect(filtered.map(c => c.round)).toEqual([1, 3]);
  });

  test("yields rows in ascending round order (deterministic across iterations)", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    // Insert in non-monotonic order to verify sort, not insertion order.
    dag.saveCommit(mkCommit(3, 2));
    dag.saveCommit(mkCommit(1, 0));
    dag.saveCommit(mkCommit(2, 1));
    const a = [...dag.iterateAllCommitsExcept(2)].map(c => c.round);
    const b = [...dag.iterateAllCommitsExcept(2)].map(c => c.round);
    expect(a).toEqual([1, 3]);
    expect(b).toEqual(a);
  });
});

// ─── sync/snapshot-roots — root builders ────────────────────────────────────

describe("snapshot-roots.createTxsFullRootBuilder", () => {
  test("empty input → EMPTY_TXS_FULL_ROOT constant", () => {
    const b = createTxsFullRootBuilder();
    expect(b.finalize()).toBe(EMPTY_TXS_FULL_ROOT);
  });

  test("EMPTY_TXS_FULL_ROOT has the expected domain-separated shape", () => {
    expect(EMPTY_TXS_FULL_ROOT).toBe(shake256("tip:txs-full-root:empty"));
  });

  test("identical row sequence → identical root", () => {
    const a = createTxsFullRootBuilder();
    const b = createTxsFullRootBuilder();
    a.addRow('{"a":1}'); a.addRow('{"b":2}');
    b.addRow('{"a":1}'); b.addRow('{"b":2}');
    expect(a.finalize()).toBe(b.finalize());
  });

  test("different ordering of identical rows → different root (order-sensitive)", () => {
    const a = createTxsFullRootBuilder();
    const b = createTxsFullRootBuilder();
    a.addRow('{"a":1}'); a.addRow('{"b":2}');
    b.addRow('{"b":2}'); b.addRow('{"a":1}');
    expect(a.finalize()).not.toBe(b.finalize());
  });

  test("addRowObject canonicalizes and matches addRow with manually-canonicalized JSON", () => {
    const a = createTxsFullRootBuilder();
    const b = createTxsFullRootBuilder();
    a.addRowObject({ b: 2, a: 1 });    // unsorted keys
    b.addRow('{"a":1,"b":2}');         // canonical (sorted)
    expect(a.finalize()).toBe(b.finalize());
  });

  test("finalize() twice throws (consumed builder)", () => {
    const b = createTxsFullRootBuilder();
    b.addRow('{"a":1}');
    b.finalize();
    expect(() => b.finalize()).toThrow(/finalize\(\) already called/);
    expect(() => b.addRow('{"a":2}')).toThrow(/finalize\(\) already called/);
  });

  test("rowCount() reflects appended rows", () => {
    const b = createTxsFullRootBuilder();
    expect(b.rowCount()).toBe(0);
    b.addRow('{"a":1}');
    expect(b.rowCount()).toBe(1);
    b.addRow('{"b":2}');
    expect(b.rowCount()).toBe(2);
  });
});

describe("snapshot-roots.createCommitsFullRootBuilder", () => {
  test("empty input → EMPTY_COMMITS_FULL_ROOT", () => {
    const b = createCommitsFullRootBuilder();
    expect(b.finalize()).toBe(EMPTY_COMMITS_FULL_ROOT);
  });

  test("uses a different domain than the txs builder (domain separation)", () => {
    const a = createTxsFullRootBuilder();
    const b = createCommitsFullRootBuilder();
    a.addRow('{"x":1}');
    b.addRow('{"x":1}');
    // Same single row, different domain prefix → different root.
    expect(a.finalize()).not.toBe(b.finalize());
  });
});

describe("snapshot-roots.computeTxsFullRoot / computeCommitsFullRoot", () => {
  test("empty DAG → empty roots", () => {
    // initDAG always seeds genesis, so to test "no txs" path we go via
    // a stub that returns no rows. For the integration shape, see the
    // e2e tests in snapshot-handler.test.js.
    const stubDag = { iterateAllTransactions: function* () { } };
    expect(computeTxsFullRoot(stubDag)).toBe(EMPTY_TXS_FULL_ROOT);
  });

  test("computeTxsFullRoot reflects the txs the DAG yields, in iteration order", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const rootBefore = computeTxsFullRoot(dag);
    const tx = makeTx({ prev: [GENESIS_TX_ID, GENESIS_TX_ID] });
    dag.addTx(tx);
    const rootAfter = computeTxsFullRoot(dag);
    expect(rootAfter).not.toBe(rootBefore);     // new row → new root
  });

  test("computeCommitsFullRoot excludes the latestRound", () => {
    const dag = initDAG({ dbPath: ":memory:" });
    const c1 = {
      round: 1, anchor_cert_hash: "1".repeat(64), leader_node_id: "n", committee: ["n"],
      support_count: 1, consensus_index: 0, committed_at: 1767225601000,
      state_merkle_root: "0".repeat(64), txs_merkle_root: "0".repeat(64),
      ack_signer_ids: [], ack_signatures: [],
    };
    const c2 = { ...c1, round: 2, consensus_index: 1, committed_at: 1767225602000 };
    dag.saveCommit(c1);
    dag.saveCommit(c2);
    // Rooting with latest=2 should hash only c1; with latest=1 only c2.
    const rootExcl2 = computeCommitsFullRoot(dag, 2);
    const rootExcl1 = computeCommitsFullRoot(dag, 1);
    expect(rootExcl2).not.toBe(rootExcl1);
    // Excluding all = empty root.
    dag.saveCommit({ ...c1, round: 0 });          // no-op for our two
    expect(computeCommitsFullRoot(dag, 0)).not.toBe(EMPTY_COMMITS_FULL_ROOT);  // c1 + c2 still there
  });
});

// ─── Canonical projections ──────────────────────────────────────────────────

describe("snapshot-roots canonical projections", () => {
  test("canonTx produces a stable shape regardless of input field order", () => {
    const a = canonTx({ tx_id: "x", tx_type: "T", data: { a: 1 }, timestamp: "ts", prev: [], signature: "s" });
    const b = canonTx({ signature: "s", prev: [], timestamp: "ts", data: { a: 1 }, tx_type: "T", tx_id: "x" });
    expect(a).toEqual(b);
  });

  test("snapshot sender ships canonical-JSON bytes (sorted keys) — not raw JSON.stringify output", async () => {
    // The actual concern: testing canonicalJson() directly tests
    // shared infrastructure that already underlies the signing path.
    // What needs testing here is whether the snapshot pipeline
    // ITSELF goes through canonicalJson — i.e., nobody introduced a
    // JSON.stringify shortcut in the sender or a non-sorted projection.
    //
    // We capture the actual wire bytes of a SnapshotTxRow as it leaves
    // the sender, then assert they equal canonicalJson(canonTx(parsed)).
    // If anyone introduces a non-canonical serialiser in the sender,
    // the recomputed canonical bytes will differ from what was sent.
    const { createSnapshotHandler } = require(path.join(SRC, "sync", "snapshot-handler"));
    const { loadTypes, decode } = require(path.join(SRC, "network", "proto"));
    const { canonicalJson } = require(path.join(SHARED, "crypto"));
    const { createStreamPair } = require(path.resolve(__dirname, "../helpers/stream-pair"));
    const { buildCommittedDag } = require(path.resolve(__dirname, "../helpers/commit-builder"));

    await loadTypes();
    const fx = buildCommittedDag({ committeeSize: 1, seedTxs: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });
    const { client, server } = createStreamPair();

    const sourceHandler = createSnapshotHandler({
      dag: fx.sourceDag,
      network: { node: {}, handle: async () => { } },
      isAuthorizedPeer: () => true,
    });
    const destHandler = createSnapshotHandler({
      dag: destDag,
      network: { node: {}, openStream: async () => client },
      isAuthorizedPeer: () => true,
    });

    // Capture every length-prefixed frame the sender emits.
    const sentFrames = [];
    const origSink = server.sink;
    server.sink = async (src) => {
      await origSink((async function* () {
        for await (const f of src) {
          sentFrames.push(Buffer.from(f));
          yield f;
        }
      })());
    };

    await Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ]);

    // Find a SnapshotTxRow frame: try-decode each middle frame and pick
    // one whose canonical_json parses as a tx (has tx_id + tx_type).
    let wire = null;
    let parsed = null;
    for (let i = 1; i < sentFrames.length - 1; i++) {
      const body = sentFrames[i].subarray(4);    // strip 4-byte length prefix
      try {
        const row = decode("SnapshotTxRow", body);
        if (!row.canonicalJson || !row.canonicalJson.length) continue;
        const candidateWire = Buffer.from(row.canonicalJson).toString("utf8");
        const candidate = JSON.parse(candidateWire);
        if (candidate.tx_id && candidate.tx_type) {
          wire = candidateWire;
          parsed = candidate;
          break;
        }
      } catch { /* not a SnapshotTxRow */ }
    }
    expect(wire).not.toBeNull();

    // Wire bytes must equal canonicalJson(canonTx(parsed)) exactly.
    // If the sender ever switches to JSON.stringify or a non-sorted
    // projection, this fails — even though the receiver-side root
    // check would still pass (both sides hash the same broken bytes).
    expect(wire).toBe(canonicalJson(canonTx(parsed)));

    // Sanity: top-level key order is alphabetical (sorted-key contract).
    expect(wire.startsWith('{"data":')).toBe(true);
  });

  test("canonTx defaults missing prev to [] and missing signature to null", () => {
    const c = canonTx({ tx_id: "x", tx_type: "T", data: {}, timestamp: "ts" });
    expect(c.prev).toEqual([]);
    expect(c.signature).toBeNull();
  });

  test("canonCommit produces the same shape regardless of input order or omitted optionals", () => {
    const base = {
      round: 5, anchor_cert_hash: "a", leader_node_id: "n",
      committee: ["x"], support_count: 1, consensus_index: 7,
      committed_at: "ts", state_merkle_root: "s", txs_merkle_root: "t",
      ack_signer_ids: ["x"], ack_signatures: ["sig"],
    };
    // anchor_batch_hash is intentionally omitted from `base` to verify
    // the projection defaults it to null for pre-#50 rows. Same for
    // BFT-Time fields (`ack_signed_ats`, `cert_timestamp`) which default
    // to [] / 0 for pre-BFT-Time rows.
    expect(canonCommit(base)).toEqual({
      round: 5,
      anchor_cert_hash: "a",
      anchor_batch_hash: null,
      leader_node_id: "n",
      committee: ["x"],
      support_count: 1,
      consensus_index: 7,
      committed_at: "ts",
      state_merkle_root: "s",
      txs_merkle_root: "t",
      ack_signer_ids: ["x"],
      ack_signatures: ["sig"],
      ack_signed_ats: [],
      cert_timestamp: 0,
    });
  });

  test("canonCommit preserves anchor_batch_hash when present (#50 self-contained rows)", () => {
    const c = {
      round: 5, anchor_cert_hash: "a", anchor_batch_hash: "deadbeef",
      leader_node_id: "n", committee: ["x"], support_count: 1,
      consensus_index: 7, committed_at: "ts",
      state_merkle_root: "s", txs_merkle_root: "t",
      ack_signer_ids: ["x"], ack_signatures: ["sig"],
    };
    expect(canonCommit(c).anchor_batch_hash).toBe("deadbeef");
  });
});
