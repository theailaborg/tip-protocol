"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ dag }) {
  const router = express.Router();

  router.get("/dag/tx/:txId", asyncHandler((req, res) => {
    const tx = dag.getTx(req.params.txId);
    if (!tx) throw { status: 404, error: "Transaction not found" };
    res.json(tx);
  }));

  // Outcome endpoint (#64 follow-up — no-loss invariant). Answers
  // "what happened to my tx" with a single, definitive response so an
  // API consumer who got `tip_id` at submit time never has to grep
  // logs or poll forever-404. Reads the three sources populated by
  // every drop site between API admission and committed DAG state:
  //   - dag.transactions  → committed (tx made it all the way through)
  //   - mempool           → pending   (still queued for batching)
  //   - dag.tx_rejections → rejected  (dropped, with specific reason)
  // and falls back to "unknown" when none match.
  //
  // Order matters: check committed first because once a tx commits, an
  // older rejection row from a previous attempt (different tx_id, same
  // logical operation) won't pollute the answer. The current tx_id is
  // content-addressed, so a single tx_id is in at most one bucket.
  router.get("/dag/tx/:txId/outcome", asyncHandler((req, res) => {
    const txId = req.params.txId;

    // 1. Committed — happiest path, cheapest read (PK lookup).
    const tx = dag.getTx(txId);
    if (tx) {
      return res.json({
        tx_id:    txId,
        status:   "committed",
        at:       tx.timestamp,
        tx_type:  tx.tx_type,
      });
    }

    // 2. Pending — still in the persistent mempool, awaiting a batch
    // + cert. PK lookup against the mempool table (added alongside
    // this endpoint so we don't have to scan all pending txs).
    const pending = dag.getMempoolTx(txId);
    if (pending) {
      return res.json({
        tx_id:    txId,
        status:   "pending",
        at:       pending.timestamp,
        tx_type:  pending.tx_type,
      });
    }

    // 3. Rejected — recorded by a drop site. Per-node observation; the
    // node serving this request answers from its own POV. Detail
    // carries the specific error (validator message, business-rule
    // failure, "transaction rollback: ...") for client display.
    const rej = dag.getTxRejection(txId);
    if (rej) {
      return res.json({
        tx_id:             txId,
        status:            "rejected",
        reason:            rej.reason,
        reason_detail:     rej.reason_detail,
        at:                rej.rejected_at_ms,
        rejected_at_round: rej.rejected_at_round,
        dropper_node_id:   rej.dropper_node_id,
        tx_type:           rej.tx_type,
      });
    }

    // 4. Unknown — never seen on this node. Could mean: client
    // submitted to a different node, the tx is older than this node's
    // retention horizon, or the tx_id is malformed/forged. Caller
    // should retry against the originating node before assuming loss.
    return res.json({
      tx_id:  txId,
      status: "unknown",
    });
  }));

  // Latest 2f+1-signed state attestation. `state_merkle_root` covers the
  // canonical derived state at this round; `txs_merkle_root` is the
  // ordered tx_id root for light-client inclusion proofs. Replaces the
  // old `/v1/dedup/merkle-root` placeholder which was a single-node
  // shake256(counts || hour) hash with no cryptographic guarantee.
  router.get("/state-root", asyncHandler((_req, res) => {
    const c = dag.getLatestCommit && dag.getLatestCommit();
    if (!c) throw { status: 404, error: "No committed round yet" };
    res.json({
      round: c.round,
      state_merkle_root: c.state_merkle_root,
      txs_merkle_root: c.txs_merkle_root,
      cert_timestamp: c.cert_timestamp,
      committed_at: c.committed_at,
      anchor_batch_hash: c.anchor_batch_hash,
      support_count: c.support_count,
    });
  }));

  return router;
}

module.exports = { createRouter };
