"use strict";

const express = require("express");
const { GENESIS_PAYLOAD, getGenesisHash } = require("../genesis");

// Public node registry: what is on chain about every node, minus keys. Feeds
// the /status page (names next to peer ids, founding badge) and replaces the
// hand-kept node sheet.
function createRouter({ dag, config }) {
  const router = express.Router();

  const foundingIds = new Set(
    (Array.isArray(GENESIS_PAYLOAD.founding_nodes) ? GENESIS_PAYLOAD.founding_nodes : [])
      .map(n => n && n.node_id).filter(Boolean),
  );

  function publicNode(row) {
    return {
      node_id: row.node_id,
      name: row.name || null,
      status: row.status || null,
      api_endpoint: row.api_endpoint || null,
      operated_by: row.operated_by || null,
      founding: foundingIds.has(row.node_id),
      registered_at: row.registered_at ?? null,
    };
  }

  router.get("/nodes", (req, res) => {
    let rows = [];
    try { rows = dag.getAllNodes() || []; } catch { rows = []; }
    const nodes = rows.map(publicNode).sort((a, b) => {
      if (a.founding !== b.founding) return a.founding ? -1 : 1;
      return String(a.name || a.node_id).localeCompare(String(b.name || b.node_id));
    });
    res.json({
      ok: true,
      status: 200,
      data: {
        genesis_hash: getGenesisHash(),
        self: config.nodeRegisteredId || config.nodeId || null,
        founding_node_ids: [...foundingIds],
        nodes,
      },
    });
  });

  return router;
}

module.exports = { createRouter };
