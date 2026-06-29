/**
 * @file @tip-protocol/node/src/index.js
 * @description TIP Protocol Full Node — Entry Point
 *
 * Starts:
 *   1. DAG store (SQLite, PostgreSQL, MariaDB, MSSQL, or Oracle via Knex)
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
const { getGenesisPayload, verifyGenesisSignature, verifyGenesisVPSignature } = require("./genesis");
PC.init(getGenesisPayload().protocol_constants);

const http = require("http");
const { createApp } = require("./api");
const { initDAGAsync } = require("./dag");
const { initScoring } = require("./scoring");
const { createScheduler } = require("./scheduler");
const { initNetworkAndConsensus } = require("./init-network");
const { loadConfig } = require("./config");
const { log } = require("./logger");
const { generateMLDSAKeypair, initCrypto } = require("../../shared/crypto");
const { resolveDriver } = require("./db/index");
const { createPrescanJobs } = require("./services/prescan-jobs");
const { initPrescanWorker } = require("./init-prescan-worker");
const { initMediaRetention } = require("./init-media-retention");
const { initEndpointAnnounce } = require("./init-endpoint-announce");
const { createMediaStorage } = require("./services/media-storage");
const processErrors = require("./process-error-handler");

// Process-level error boundary for the long-running loops Express can't reach
// (consensus ticks, p2p streams, anti-entropy). captureError classifies + counts;
// transient continues, the narrow fatal set shuts down. See process-error-handler.js.
process.on("uncaughtException", (err, origin) => {
  processErrors.captureError(err, { origin: origin || "uncaughtException" });
});
process.on("unhandledRejection", (reason) => {
  const err = reason instanceof Error ? reason : new Error(String((reason && (reason.message || reason)) || reason));
  processErrors.captureError(err, { origin: "unhandledRejection" });
});

async function main() {
  await initCrypto();
  verifyGenesisSignature();
  verifyGenesisVPSignature();
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
  const effectiveDriver = resolveDriver(config);
  const isSQLite = effectiveDriver === "sqlite" || effectiveDriver === "memory";

  const defaultPorts = { postgres: 5432, mariadb: 3306, mysql: 3306, mssql: 1433, sqlserver: 1433, oracle: 1521 };
  const dbEndpoint = config.dbUrl
    ? config.dbUrl.replace(/:\/\/[^:]+:[^@]+@/, "://<credentials>@")
    : `${config.dbHost}:${config.dbPort || defaultPorts[effectiveDriver] || ""}/${config.dbName}`;

  log.notice(`=== TIP Protocol Node v${config.nodeVersion} ===`);
  log.notice(`Node ID     : ${config.nodeId}`);
  log.notice(`Region      : ${config.region}`);
  log.notice(`Port        : ${config.port}`);
  log.notice(`Node type   : ${config.nodeType}`);
  if (isSQLite) {
    log.notice(`DB driver   : sqlite`);
    log.notice(`Data dir    : ${config.dbPath}`);
  } else {
    log.notice(`DB driver   : ${effectiveDriver}`);
    log.notice(`DB endpoint : ${dbEndpoint}`);
  }
  log.notice("================================");

  // 1. Initialise DAG store
  // initDAG creates genesis block + VP + founding identities from genesis.js
  // if the DB doesn't exist yet — no seed.db copy needed.
  const fs = require("fs");
  const path = require("path");
  if (isSQLite && !fs.existsSync(config.dbPath)) {
    fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
  }

  const dag = await initDAGAsync(config);
  log.notice(`DB          : connected (${effectiveDriver})`);
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

  // 3. Build Express app — prescanJobs queue is node-local and bound to dag.
  const consensusRef = { current: null };
  const networkRef = { current: null };
  const prescanJobs = createPrescanJobs({ dag });
  const app = createApp({ dag, scoring, config, consensus: consensusRef, network: networkRef, prescanJobs });

  // 4. HTTP server
  const server = http.createServer(app);

  // 5. P2P network + Narwhal/Bullshark consensus (returns nulls on failure)
  const { network, consensus } = await initNetworkAndConsensus({ dag, scoring, config });
  networkRef.current = network;
  consensusRef.current = consensus;

  // 8. Scheduled tasks (score recomputation, peer health). Verdict-check
  // and clean-record migrated to commit-handler post-round triggers —
  // see consensus/verdict-trigger.js and consensus/clean-record-trigger.js.
  // State-root attestation is `commits.state_merkle_root` (2f+1 signed
  // every anchor commit), exposed at GET /v1/state-root.
  const scheduler = createScheduler(network, config);

  // 8a. Prescan worker — claims jobs off the node-local queue, calls the
  // classifier, aggregates, and emits PRESCAN_COMPLETED via consensus.
  // Runs in-process for v1; split to a sibling process via docker-compose
  // / pm2 when classifier traffic justifies it.
  const prescanWorkers = initPrescanWorker({
    dag, prescanJobs, consensusRef, config,
    mediaService: app.locals.mediaService,
  });

  // 8b. Media retention sweep — periodic deletion of expired content
  // media and orphan uploads. Disabled in tests and via env. Shares the
  // mediaStorage instance with the API (createApp built it).
  const mediaRetention = initMediaRetention({
    dag,
    mediaStorage: app.locals.mediaStorage,
  });

  // 8c. One-shot api_endpoint reconcile — announces TIP_API_ENDPOINT on
  // chain when the nodes row disagrees. No-op when unconfigured.
  initEndpointAnnounce({ dag, config, governanceService: app.locals.governanceService });

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
      try { mediaRetention.stop(); } catch { }
      // Await prescan worker drain so in-flight classifier calls finish
      // before the process exits. Without this, the safety net is the
      // queue's claim-timeout (60s) — recovers correctness, costs latency.
      try { await prescanWorkers.stopAll(); } catch { }
      // Drain pending fire-and-forget DB writes. The workers' markDone /
      // markFailed calls are queued on the knex adapter's _ff chain; without
      // this flush, the queue row's "done" mark can race with process exit
      // and lose, leaving an orphaned 'claimed' row that the claim-timeout
      // safety net has to recover. No-op for in-memory and SQLite stores.
      try { await dag.flush(); } catch { }
      try { if (consensus) consensus.stop(); } catch { }
      try { if (network) await network.stop(); } catch { }
      try { dag.close(); } catch { }
      log.info("Shutdown complete");
      process.exit(0);
    });
    // 65s timeout matches the classifier's TEXT_TIMEOUT_MS (60s) plus a
    // few-second buffer for the rest of the shutdown sequence (consensus,
    // network, dag.close). Anything still in-flight past this is a stuck
    // process — exit hard. Docker-compose's stop_grace_period should be
    // ≥ this so the SIGTERM grace window matches.
    setTimeout(() => {
      log.error("Graceful shutdown timed out — forcing exit");
      process.exit(1);
    }, 65000);
  }
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  // Identity for the structured error records. The process error boundary is
  // observe-only: it never halts the node (no shutdown hook is registered).
  processErrors.init({ nodeId: config.nodeId });
}

main().catch(err => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
