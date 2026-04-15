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

const http = require("http");
const { createApp } = require("./api");
const { initDAG } = require("./dag");
const { initScoring } = require("./scoring");
const { createScheduler } = require("./scheduler");
const { initConsensus } = require("./consensus");
const { createNetworkNode } = require("./network/node");
const { loadTypes } = require("./network/proto");
const { loadConfig } = require("./config");
const { log } = require("./logger");
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
    config.nodePublicKey = kp.publicKey;
    log.warn("No TIP_NODE_PRIVATE_KEY set — generated ephemeral keypair. Tx signatures will not survive restart.");
  }

  log.info(`=== TIP Protocol Node v${config.nodeVersion} ===`);
  log.info(`Node ID     : ${config.nodeId}`);
  log.info(`Region      : ${config.region}`);
  log.info(`Port        : ${config.port}`);
  log.info(`Data dir    : ${config.dataDir}`);
  log.info(`Node type   : ${config.nodeType}`);
  log.info("================================");

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

  // 3. Load Protobuf schemas
  await loadTypes();

  // 4. Build Express app
  const consensusRef = { current: null };
  const networkRef = { current: null };
  const app = createApp({ dag, scoring, config, consensus: consensusRef, network: networkRef });

  // 5. HTTP server
  const server = http.createServer(app);

  // 6. libp2p network node + Narwhal/Bullshark consensus
  const p2pPort = parseInt(process.env.TIP_P2P_PORT || "4001", 10);
  const bootstrapPeers = (process.env.TIP_BOOTSTRAP_PEERS || "").split(",").map(s => s.trim()).filter(Boolean);
  const enableMdns = process.env.TIP_ENABLE_MDNS !== "false";

  let network = null;
  let consensus = null;

  try {
    // Node registry lookup for handshake verification
    const getNodeKey = (nId) => {
      const n = dag.getNode(nId);
      return n?.public_key || null;
    };

    network = await createNetworkNode({
      port: p2pPort,
      bootstrapPeers,
      enableMdns,
      handlers: {},
      nodeId: config.nodeRegisteredId || config.nodeId,
      nodePrivateKey: config.nodePrivateKey,
      getNodeKey,
      getLatestRound: () => dag.getLatestRound(),
      getMerkleRoot: () => "",
    });

    networkRef.current = network;
    // Peer authorization via TIP handshake — network.authorizedPeers() has verified peers
    const isAuthorizedPeer = (peerId) => !!network.authorizedPeers()[peerId];
    consensus = initConsensus({ dag, scoring, config, network, isAuthorizedPeer });
    consensusRef.current = consensus;

    // Wire GossipSub topic handlers to consensus
    const { TOPICS } = require("./network/node");
    const pubsub = network.node.services.pubsub;
    pubsub.addEventListener("message", (event) => {
      const { topic, data } = event.detail;
      try {
        if (topic === TOPICS.MEMPOOL) consensus.handlers.onBatch(data);
        else if (topic === TOPICS.CONSENSUS) consensus.handlers.onAck(data);
        else if (topic === TOPICS.CERTIFICATES) consensus.handlers.onCertificate(data);
      } catch (err) {
        log.error(`Consensus message error on ${topic}: ${err.message}`);
      }
    });

    // Start consensus rounds + sync protocol
    await consensus.start();
    log.info(`Consensus ready: Narwhal + Bullshark on port ${p2pPort}`);
  } catch (err) {
    log.warn(`Consensus layer failed to start: ${err.message}`);
    log.warn("Node running without consensus — single-node mode only");
  }

  // 8. Scheduled tasks (Merkle root publish, score recomputation, etc.)
  const scheduler = createScheduler(dag, scoring, network, config);

  // 9. Start listening
  server.listen(config.port, () => {
    log.info(`Node listening on http://0.0.0.0:${config.port}`);
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
