"use strict";

const express = require("express");
const { TX_TYPES, PROTOCOL } = require("../../../shared/constants");
const PC = require("../../../shared/protocol-constants");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ dag, scoring, config, broadcast }) {
  const router = express.Router();

  router.get("/health", (req, res) => {
    // Deep check: verify DB is actually readable
    let dbOk = true;
    let dagCount = 0;
    try {
      dagCount = dag.count();
    } catch {
      dbOk = false;
    }

    const status = dbOk ? "ok" : "degraded";
    const statusCode = dbOk ? 200 : 503;
    const mem = process.memoryUsage();

    res.status(statusCode).json({
      status,
      node_id: config.nodeId,
      node_type: config.nodeType,
      dag_count: dagCount,
      version: config.nodeVersion,
      protocol: PROTOCOL.version,
      uptime_seconds: Math.floor(process.uptime()),
      memory_mb: {
        rss: Math.round(mem.rss / 1048576),
        heap_used: Math.round(mem.heapUsed / 1048576),
        heap_total: Math.round(mem.heapTotal / 1048576),
      },
      timestamp: new Date().toISOString(),
    });
  });

  router.get("/node/info", (req, res) => {
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

  router.get("/node/peers", (req, res) => {
    res.json({ peers: config.peers || [] });
  });

  router.get("/node/registry", (req, res) => {
    res.json({ nodes: dag.getAllNodes() });
  });

  router.get("/constants", (req, res) => {
    res.json({
      ...PC.get(),
      media_limits: config.mediaLimits,
    });
  });

  router.get("/node/:nodeId", asyncHandler((req, res) => {
    const node = dag.getNode(req.params.nodeId);
    if (!node) throw { status: 404, error: "Node not found" };
    res.json(node);
  }));

  return router;
}

module.exports = { createRouter };
