"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");
const { computeMerkleRoot } = require("../services/helpers");

function createRouter({ dag }) {
  const router = express.Router();

  router.get("/dag/tx/:txId", asyncHandler((req, res) => {
    const tx = dag.getTx(req.params.txId);
    if (!tx) throw { status: 404, error: "Transaction not found" };
    res.json(tx);
  }));

  router.get("/dedup/merkle-root", asyncHandler((req, res) => {
    res.json({
      merkle_root: computeMerkleRoot(dag),
      dedup_count: dag.dedupCount(),
      timestamp: new Date().toISOString(),
    });
  }));

  return router;
}

module.exports = { createRouter };
