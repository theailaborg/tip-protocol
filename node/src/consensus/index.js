/**
 * @file @tip-protocol/node/src/consensus/index.js
 * @description Consensus layer orchestrator for TIP Protocol.
 *
 * Initializes and wires together:
 *   - Mempool (persistent, crash-safe)
 *   - Narwhal (data availability — certificate creation + broadcast)
 *   - Bullshark (ordering — anchor commit + deterministic tx ordering)
 *   - Commit handler (processes ordered txs → DAG + derived state)
 *   - Network integration (GossipSub topic handlers)
 *
 * Usage:
 *   const consensus = await initConsensus({ dag, scoring, config, network });
 *   consensus.addTx(tx);           // add validated tx to mempool
 *   consensus.start();             // start consensus rounds
 *   consensus.stop();              // graceful shutdown
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { createMempool } = require("./mempool");
const { createNarwhal } = require("./narwhal");
const { createBullshark } = require("./bullshark");
const { createCommitHandler } = require("./commit-handler");
const { createSyncHandler } = require("../sync/sync-handler");
const { getLogger } = require("../logger");

const log = getLogger("tip.consensus");

/**
 * Initialize the consensus layer.
 *
 * @param {Object} options
 * @param {Object} options.dag       DAG store
 * @param {Object} options.scoring   Scoring engine
 * @param {Object} options.config    Node config
 * @param {Object} options.network   libp2p network node (from network/node.js)
 * @returns {Object} Consensus interface
 */
function initConsensus({ dag, scoring, config, network }) {
  // ── Helper: get registered node public key ────────────────────────────────
  function getNodeKey(nodeId) {
    const node = dag.getNode(nodeId);
    return node?.public_key || null;
  }

  // ── Helper: get sorted registered node IDs ────────────────────────────────
  function getNodeIds() {
    return dag.getAllNodes()
      .filter(n => n.status === "active")
      .map(n => n.node_id)
      .sort();
  }

  // ── Helper: get total registered node count ───────────────────────────────
  function getNodeCount() {
    return dag.getAllNodes().filter(n => n.status === "active").length;
  }

  // ── Create mempool (persistent) ───────────────────────────────────────────
  const mempool = createMempool(dag);
  log.info(`Mempool initialized (${mempool.size()} pending txs restored)`);

  // ── Create commit handler ─────────────────────────────────────────────────
  const commitHandler = createCommitHandler({ dag, scoring, config });

  // ── Create sync handler (Merkle tree + catch-up protocol) ──────────────────
  const syncHandler = createSyncHandler({ dag, network });

  // ── Create Bullshark (ordering) ───────────────────────────────────────────
  const bullshark = createBullshark({
    dag,
    getNodeIds,
    onOrderedTxs: (orderedTxs, round) => {
      const result = commitHandler.commitOrderedTxs(orderedTxs, round);
      // Update Merkle tree with newly committed certificate hashes
      const certs = dag.getCertificatesByRound(round);
      for (const cert of certs) syncHandler.onCertificateCommitted(cert.hash);
      log.info(`Bullshark round ${round}: ${result.committed} committed, ${result.dropped} dropped`);
    },
  });

  // ── Create Narwhal (data availability) ────────────────────────────────────
  const narwhal = createNarwhal({
    dag,
    mempool,
    network,
    config,
    getNodeKey,
    getNodeCount,
    onCommit: (certificates, round) => {
      bullshark.onRoundComplete(certificates, round);
    },
  });

  // ── Wire network message handlers ────────────────────────────────────────
  // These are called by the libp2p GossipSub topic subscriptions.
  // Each topic routes to the correct Narwhal handler.
  function _wireNetworkHandlers() {
    if (!network) {
      log.warn("No network node — consensus running in local-only mode");
      return;
    }

    // Narwhal listens for:
    // MEMPOOL topic → incoming batches from peers
    // CONSENSUS topic → incoming batch acks from peers
    // CERTIFICATES topic → incoming certificates from peers
    log.info("Consensus network handlers wired");
  }

  _wireNetworkHandlers();

  // ── Public interface ──────────────────────────────────────────────────────

  return {
    /**
     * Add a validated transaction to the mempool.
     * Called by API services after validation.
     * @param {Object} tx  Validated tx (must have tx_id)
     * @returns {{ added: boolean, reason?: string }}
     */
    addTx(tx) {
      return mempool.add(tx);
    },

    /**
     * Start consensus rounds (Narwhal + Bullshark) and sync protocol.
     */
    async start() {
      await syncHandler.registerProtocol();
      narwhal.start();
      log.info("Consensus started");
    },

    /**
     * Stop consensus gracefully.
     */
    stop() {
      narwhal.stop();
      log.info("Consensus stopped");
    },

    /**
     * Get the network handlers for libp2p topic subscriptions.
     * Returned as an object so the network node can wire them up.
     */
    handlers: {
      onBatch: (data) => narwhal.handleIncomingBatch(data),
      onAck: (data) => narwhal.handleIncomingAck(data),
      onCertificate: (data) => narwhal.handleIncomingCertificate(data),
    },

    /** Access to mempool (for API services to check pending status) */
    mempool,

    /** Sync: request certificates from a peer */
    syncFromPeer: (peerId) => syncHandler.syncFromPeer(peerId),

    /** Current Merkle root of certificate DAG */
    merkleRoot: () => syncHandler.merkleRoot(),

    /** Stats for monitoring / health endpoint */
    stats() {
      return {
        narwhal: narwhal.stats(),
        bullshark: bullshark.stats(),
        mempool: mempool.stats(),
        merkleRoot: syncHandler.merkleRoot(),
      };
    },
  };
}

module.exports = { initConsensus };
