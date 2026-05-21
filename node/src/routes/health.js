"use strict";

const express = require("express");
const { TX_TYPES, PROTOCOL } = require("../../../shared/constants");
const PC = require("../../../shared/protocol-constants");
const { asyncHandler } = require("../middleware/error-handler");
const { nowIso } = require("../../../shared/time");

function createRouter({ dag, scoring, config, consensus, network }) {
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

    // Live network stats
    const net = network?.current;
    const cons = consensus?.current;
    const peerCount = net ? net.peerCount() : 0;
    const connectedPeers = net ? net.peers().map(p => p.toString()) : [];

    // Consensus halt check — report explicitly when sub-quorum so load
    // balancers / orchestrators can take this instance out of rotation
    // until it recovers. Monitors should alert on status=halted.
    let consensusHalt = null;
    try { consensusHalt = cons?.isConsensusHalted ? cons.isConsensusHalted() : null; }
    catch { /* best-effort — if the check itself throws, treat as unknown */ }

    let status, statusCode;
    if (!dbOk) { status = "degraded"; statusCode = 503; }
    else if (consensusHalt?.halted) { status = "halted"; statusCode = 503; }
    else { status = "ok"; statusCode = 200; }

    const mem = process.memoryUsage();

    const body = {
      status,
      node_id: config.nodeRegisteredId || config.nodeId,
      node_type: config.nodeType,
      dag_count: dagCount,
      version: config.nodeVersion,
      protocol: PROTOCOL.version,
      uptime_seconds: Math.floor(process.uptime()),
      p2p: net ? {
        peer_id: net.peerId,
        multiaddrs: net.multiaddrs(),
        bootstrap_addr: config.publicIp
          ? `/ip4/${config.publicIp}/tcp/${config.p2pPort || 4001}/p2p/${net.peerId}`
          : null,
      } : null,
      peers: {
        connected: peerCount,
        peer_ids: connectedPeers,
      },
      memory_mb: {
        rss: Math.round(mem.rss / 1048576),
        heap_used: Math.round(mem.heapUsed / 1048576),
        heap_total: Math.round(mem.heapTotal / 1048576),
      },
      timestamp: nowIso(),
    };

    // Consensus stats (if running)
    if (cons) {
      body.consensus = cons.stats();
      if (consensusHalt) body.consensus.halt = consensusHalt;
    }

    res.status(statusCode).json(body);
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
    const net = network?.current;
    res.json({
      connected: net ? net.peerCount() : 0,
      peers: net ? net.peers().map(p => p.toString()) : [],
    });
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
