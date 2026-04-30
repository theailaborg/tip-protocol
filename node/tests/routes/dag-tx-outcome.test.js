/**
 * @file tests/routes/dag-tx-outcome.test.js
 * @description #64 follow-up — REST surface for the no-loss outcome
 * endpoint: `GET /v1/dag/tx/:txId/outcome`.
 *
 * Closes the loop with mempool + commit-handler wiring. Together they
 * guarantee an API consumer who got `tip_id` at submit time can always
 * resolve the tx into one of: committed, pending, rejected{reason},
 * unknown. Pre-fix, the same client would GET 404 forever and never
 * know whether the tx was lost, queued, or just slow.
 *
 * Drives the actual express router (not a mock) so a regression in the
 * HTTP wire (missing route mount, wrong field shape) fails here even
 * if the underlying dag layer is untouched.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const express = require("express");
const request = require("supertest");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto } = require(path.join(SHARED, "crypto"));
const { TX_REJECTION_REASON } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const dagRoutes = require(path.join(SRC, "routes", "dag"));

beforeAll(async () => {
  await initCrypto();
});

function makeApp() {
  const dag = initDAG({ dbPath: ":memory:" });
  const app = express();
  app.use("/v1", dagRoutes.createRouter({ dag }));
  return { app, dag };
}

describe("GET /v1/dag/tx/:txId/outcome", () => {
  // ── Branch 1: committed ──────────────────────────────────────────────────
  test("200 {status:'committed'} for a tx in dag.transactions", async () => {
    const { app, dag } = makeApp();
    // Use the genesis tx that's auto-written on store init. Any committed
    // tx works; genesis is convenient because it's always present.
    const tx = dag.getAllTxs()[0];
    expect(tx).toBeDefined();

    const res = await request(app).get(`/v1/dag/tx/${tx.tx_id}/outcome`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      tx_id:   tx.tx_id,
      status:  "committed",
      at:      tx.timestamp,
      tx_type: tx.tx_type,
    });
  });

  // ── Branch 2: pending ────────────────────────────────────────────────────
  test("200 {status:'pending'} for a tx still in the mempool", async () => {
    const { app, dag } = makeApp();
    // Real tx_ids are 64-char hex (SHAKE-256 of canonical form), not URIs.
    // Use hex here so the route param matches without %-encoding gymnastics
    // and matches what a production client would actually GET.
    const txId = "a".repeat(64);
    dag.saveMempoolTx({
      tx_id: txId,
      tx_type: "REGISTER_IDENTITY",
      timestamp: "2026-04-30T08:00:00.000Z",
      data: { tip_id: "tip://id/X" },
    });

    const res = await request(app).get(`/v1/dag/tx/${txId}/outcome`);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("pending");
    expect(res.body.tx_id).toBe(txId);
    expect(res.body.tx_type).toBe("REGISTER_IDENTITY");
    expect(res.body.at).toBe("2026-04-30T08:00:00.000Z");
  });

  // ── Branch 3: rejected — generic ─────────────────────────────────────────
  test("200 {status:'rejected', reason, reason_detail, ...} for a recorded drop", async () => {
    const { app, dag } = makeApp();
    const txId = "b".repeat(64);
    dag.saveTxRejection({
      tx_id:             txId,
      reason:            TX_REJECTION_REASON.MEMPOOL_FULL,
      reason_detail:     "cap=10000",
      rejected_at_ms:    1_700_000_000_000,
      dropper_node_id:   "tip://node/test",
      tx_type:           "REGISTER_CONTENT",
    });

    const res = await request(app).get(`/v1/dag/tx/${txId}/outcome`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      tx_id:           txId,
      status:          "rejected",
      reason:          "mempool_full",
      reason_detail:   "cap=10000",
      at:              1_700_000_000_000,
      dropper_node_id: "tip://node/test",
      tx_type:         "REGISTER_CONTENT",
    });
  });

  // ── Branch 3 variants: specific reason codes flow through unchanged ──────
  // These exist so a future refactor that wraps/transforms the reason
  // (e.g. lowercasing, or stripping the row before responding) would
  // break here, not silently degrade outcome-endpoint output for users.
  test("specific reason codes round-trip verbatim through the endpoint", async () => {
    const { app, dag } = makeApp();

    const cases = [
      { txId: "1".repeat(64), code: TX_REJECTION_REASON.IDENTITY_ALREADY_REGISTERED },
      { txId: "2".repeat(64), code: TX_REJECTION_REASON.CONTENT_ALREADY_REGISTERED },
      { txId: "3".repeat(64), code: TX_REJECTION_REASON.MEMPOOL_TTL_EXPIRED },
      { txId: "4".repeat(64), code: TX_REJECTION_REASON.REVALIDATION_FAILED },
    ];
    for (const { txId, code } of cases) {
      dag.saveTxRejection({
        tx_id: txId, reason: code, dropper_node_id: "tip://node/test",
      });
    }
    for (const { txId, code } of cases) {
      const res = await request(app).get(`/v1/dag/tx/${txId}/outcome`);
      expect(res.body.reason).toBe(code);
    }
  });

  test("rejected response includes rejected_at_round when the drop was at consensus time", async () => {
    const { app, dag } = makeApp();
    const txId = "c".repeat(64);
    dag.saveTxRejection({
      tx_id:             txId,
      reason:            TX_REJECTION_REASON.REVALIDATION_FAILED,
      reason_detail:     "Identity already registered",
      rejected_at_round: 4242,
      dropper_node_id:   "tip://node/test",
    });

    const res = await request(app).get(`/v1/dag/tx/${txId}/outcome`);
    expect(res.body.rejected_at_round).toBe(4242);
  });

  // ── Branch 4: unknown ────────────────────────────────────────────────────
  test("200 {status:'unknown'} for a tx_id this node has no record of", async () => {
    const { app } = makeApp();
    const txId = "d".repeat(64);
    const res = await request(app).get(`/v1/dag/tx/${txId}/outcome`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      tx_id:  txId,
      status: "unknown",
    });
  });

  // ── Lookup precedence ───────────────────────────────────────────────────
  // Defensive: if a stale rejection row somehow survives alongside a
  // committed tx (shouldn't happen — INSERT OR IGNORE on tx_id PK
  // means the second observer is a no-op — but a tooling-level mistake
  // could plant both), the endpoint must report `committed`. Anything
  // else would let a stale row override ground truth and confuse
  // clients into resubmitting an already-committed tx.
  test("committed wins over a same-tx_id rejection row (ground-truth precedence)", async () => {
    const { app, dag } = makeApp();
    const tx = dag.getAllTxs()[0];
    // Plant a rejection row for the same tx_id.
    dag.saveTxRejection({
      tx_id: tx.tx_id, reason: TX_REJECTION_REASON.REVALIDATION_FAILED,
      reason_detail: "stale row that should not override committed status",
      dropper_node_id: "tip://node/test",
    });

    const res = await request(app).get(`/v1/dag/tx/${tx.tx_id}/outcome`);
    expect(res.body.status).toBe("committed");
  });
});
