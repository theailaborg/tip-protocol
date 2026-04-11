/**
 * @file @tip-protocol/node/src/index.js
 * @description TIP Protocol Full Node — Entry Point
 *
 * Starts:
 *   1. SQLite-backed DAG store
 *   2. Trust scoring engine
 *   3. Express REST API (v1)
 *   4. WebSocket gossip server (peer-to-peer DAG propagation)
 *   5. Merkle root publisher (scheduled)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

require("dotenv").config();

const http    = require("http");
const { createApp }        = require("./api");
const { initDAG }          = require("./dag");
const { initScoring }      = require("./scoring");
const { initGossip }       = require("./gossip");
const { scheduledTasks }   = require("./scheduler");
const { loadConfig }       = require("./config");
const { log }              = require("./logger");
const { generateMLDSAKeypair, initCrypto } = require("../../shared/crypto");
const PC = require("../../shared/protocol-constants");

async function main() {
  await initCrypto();
  const config = loadConfig();

  // Load or generate node signing keypair
  if (config.nodePrivateKey && config.nodePublicKey) {
    log.info("Node signing keys loaded from environment");
  } else {
    const kp = generateMLDSAKeypair();
    config.nodePrivateKey = kp.privateKey;
    config.nodePublicKey  = kp.publicKey;
    log.warn("No TIP_NODE_PRIVATE_KEY set — generated ephemeral keypair. Tx signatures will not survive restart.");
  }

  log.info("=== TIP Protocol Node v2.0.0 ===");
  log.info(`Node ID     : ${config.nodeId}`);
  log.info(`Region      : ${config.region}`);
  log.info(`Port        : ${config.port}`);
  log.info(`Data dir    : ${config.dataDir}`);
  log.info(`Node type   : ${config.nodeType}`);
  log.info("================================");

  // 1. Initialise DAG store
  // On first boot: if seed.db exists, copy it so founding data is available immediately
  const fs   = require("fs");
  const path = require("path");
  const seedDb = path.resolve(__dirname, "../../genesis-data/seed.db");
  if (!fs.existsSync(config.dbPath) && fs.existsSync(seedDb)) {
    fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
    fs.copyFileSync(seedDb, config.dbPath);
    log.info(`Copied seed DB to ${config.dbPath} (first boot with seeded data)`);
  }

  const dag = initDAG(config);
  log.info(`DAG initialised. Transactions: ${dag.count()}`);

  // Load protocol constants from genesis block
  const { getGenesisPayload } = require("./genesis");
  const genesisPayload = getGenesisPayload();
  if (genesisPayload?.protocol_constants) {
    PC.init(genesisPayload.protocol_constants);
    log.info("Protocol constants loaded from genesis block");
  } else {
    log.warn("No protocol_constants in genesis — using hardcoded defaults");
  }

  // Look up this node's registered ID from the node registry (by public key)
  if (config.nodePublicKey) {
    const allNodes = dag.getAllNodes();
    const myNode = allNodes.find(n => n.public_key === config.nodePublicKey);
    if (myNode) {
      config.nodeRegisteredId = myNode.node_id;
      log.info(`Node registered as: ${myNode.node_id}`);
    } else {
      log.warn("This node is not in the node registry — gossip auth will be unverified");
    }
  }

  // 2. Initialise trust scoring engine
  const scoring = initScoring(dag, config);
  log.info("Trust scoring engine ready");

  // 3. Build Express app (gossip ref injected after init — circular dep: gossip needs server needs app)
  const gossipRef = { current: null };
  const app = createApp({ dag, scoring, config, gossip: gossipRef });

  // 4. HTTP server
  const server = http.createServer(app);

  // 5. WebSocket gossip layer
  const gossip = initGossip(server, dag, config);
  gossipRef.current = gossip;
  log.info(`Gossip server ready (WebSocket)`);

  // 6. Scheduled tasks (Merkle root publish, score recomputation, etc.)
  scheduledTasks(dag, scoring, gossip, config);

  // 7. Start listening
  server.listen(config.port, () => {
    log.info(`Node listening on http://0.0.0.0:${config.port}`);
    log.info(`REST API   : http://0.0.0.0:${config.port}/v1/`);
    log.info(`Health     : http://0.0.0.0:${config.port}/health`);
  });

  // Graceful shutdown
  process.on("SIGTERM", () => {
    log.info("SIGTERM received — shutting down gracefully");
    server.close(() => {
      dag.close();
      process.exit(0);
    });
  });
}

main().catch(err => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
