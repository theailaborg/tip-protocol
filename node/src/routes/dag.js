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
