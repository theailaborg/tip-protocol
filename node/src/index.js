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

require("dotenv").config({ path: process.env.DOTENV_PATH || ".env" });

// Init protocol constants BEFORE requiring any application module.
// shared/protocol-constants.js no longer auto-loads on first getter
// access — touching CONSENSUS/NETWORK/JURY/etc. before init() now throws.
// Any subsequent require chain (api → routes → services → consensus → ...)
// is free to reference constants lazily inside function bodies.
const PC = require("../../shared/protocol-constants");
const { getGenesisPayload } = require("./genesis");
PC.init(getGenesisPayload().protocol_constants);

const http = require("http");
const { createApp } = require("./api");
const { initDAG } = require("./dag");
const { initScoring } = require("./scoring");
const { createScheduler } = require("./scheduler");
const { initNetworkAndConsensus } = require("./init-network");
const { loadConfig } = require("./config");
const { log } = require("./logger");
const { generateMLDSAKeypair, initCrypto } = require("../../shared/crypto");

async function main() {
  await initCrypto();
  const config = loadConfig();

  // Load or generate node signing keypair
  if (config.nodePrivateKey && config.nodePublicKey) {
    log.info("Node signing keys loaded from environment");
  } else {
    const kp = generateMLDSAKeypair();
    config.nodePrivateKey = kp.privateKey;
    config.nodePublicKey = kp.publicKey;
    log.warn("No TIP_NODE_PRIVATE_KEY set — generated ephemeral keypair. Tx signatures will not survive restart.");
  }

  // Startup banner: notice-level so it always shows regardless of TIP_CONSOLE_LEVEL
  log.notice(`=== TIP Protocol Node v${config.nodeVersion} ===`);
  log.notice(`Node ID     : ${config.nodeId}`);
  log.notice(`Region      : ${config.region}`);
  log.notice(`Port        : ${config.port}`);
  log.notice(`Data dir    : ${config.dataDir}`);
  log.notice(`Node type   : ${config.nodeType}`);
  log.notice("================================");

  // 1. Initialise DAG store
  // initDAG creates genesis block + VP + founding identities from genesis.js
  // if the DB doesn't exist yet — no seed.db copy needed.
  const fs = require("fs");
  const path = require("path");
  if (!fs.existsSync(config.dbPath)) {
    fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
  }

  const dag = initDAG(config);
  log.info(`DAG initialised. Transactions: ${dag.count()}`);

  // Look up this node's registered ID from the node registry (by public key)
  if (config.nodePublicKey) {
    const allNodes = dag.getAllNodes();
    const myNode = allNodes.find(n => n.public_key === config.nodePublicKey);
    if (myNode) {
      config.nodeRegisteredId = myNode.node_id;
      log.info(`Node registered as: ${myNode.node_id}`);
    } else if (config.nodeId.startsWith("tip://node/")) {
      // Node registered on another node but not yet synced locally — use TIP_NODE_ID from .env
      config.nodeRegisteredId = config.nodeId;
      log.info(`Node ID from env (pending sync): ${config.nodeId}`);
    } else {
      log.error("This node's public key is not in the node registry. Certificates will use an unregistered ID. Re-run seed or register this node.");
    }
  }

  // 2. Initialise trust scoring engine
  const scoring = initScoring(dag, config);
  log.info("Trust scoring engine ready");

  // 3. Build Express app
  const consensusRef = { current: null };
  const networkRef = { current: null };
  const app = createApp({ dag, scoring, config, consensus: consensusRef, network: networkRef });

  // 4. HTTP server
  const server = http.createServer(app);

  // 5. P2P network + Narwhal/Bullshark consensus (returns nulls on failure)
  const { network, consensus } = await initNetworkAndConsensus({ dag, scoring, config });
  networkRef.current = network;
  consensusRef.current = consensus;

  // 8. Scheduled tasks (Merkle root publish, score recomputation, etc.)
  const scheduler = createScheduler(dag, scoring, network, config);

  // 9. Start listening
  server.listen(config.port, () => {
    log.notice(`Node listening on http://0.0.0.0:${config.port}`);
    log.info(`REST API   : http://0.0.0.0:${config.port}/v1/`);
    log.info(`Health     : http://0.0.0.0:${config.port}/health`);
    if (network) log.info(`P2P        : ${network.multiaddrs().join(", ")}`);
  });

  // Graceful shutdown
  function shutdown(signal) {
    log.info(`${signal} received — shutting down gracefully`);
    server.close(async () => {
      try { scheduler.stop(); } catch { }
      try { if (consensus) consensus.stop(); } catch { }
      try { if (network) await network.stop(); } catch { }
      try { dag.close(); } catch { }
      log.info("Shutdown complete");
      process.exit(0);
    });
    setTimeout(() => {
      log.error("Graceful shutdown timed out — forcing exit");
      process.exit(1);
    }, 10000);
  }
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch(err => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
