"use strict";

const express = require("express");
const { TX_TYPES, PROTOCOL } = require("../../../shared/constants");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ dag, scoring, config, broadcast }) {
  const router = express.Router();

  router.get("/health", (req, res) => {
    res.json({
      status: "ok",
      node_id: config.nodeId,
      node_type: config.nodeType,
      dag_count: dag.count(),
      version: config.nodeVersion,
      protocol: PROTOCOL.version,
      timestamp: new Date().toISOString(),
    });
  });

  router.get("/v1/node/info", (req, res) => {
    res.json({
      node_id: config.nodeId,
      node_type: config.nodeType,
      region: config.region,
      dag_tx_count: dag.count(),
      protocol_version: PROTOCOL.version,
      node_version: config.nodeVersion,
      identity_count: dag.getTxsByType(TX_TYPES.REGISTER_IDENTITY).length,
      content_count: dag.getTxsByType(TX_TYPES.REGISTER_CONTENT).length,
    });
  });

  router.get("/v1/node/peers", (req, res) => {
    res.json({ peers: config.peers || [] });
  });

  router.get("/v1/node/registry", (req, res) => {
    res.json({ nodes: dag.getAllNodes() });
  });

  router.get("/v1/node/:nodeId", (req, res) => {
    const node = dag.getNode(req.params.nodeId);
    if (!node) return res.status(404).json({ error: "Node not found" });
    res.json(node);
  });

  return router;
}

module.exports = { createRouter };
