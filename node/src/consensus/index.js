/**
 * @file @tip-protocol/node/src/consensus/index.js
 * @description Consensus layer orchestrator for TIP Protocol.
 *
 * Wires together:
 *   - Mempool (persistent, crash-safe tx queue)
 *   - Narwhal (data availability — certificate creation + broadcast)
 *   - Bullshark (ordering — anchor commit + deterministic tx ordering)
 *   - Commit handler (validates + writes ordered txs to DAG atomically)
 *   - Sync handler (Merkle tree + certificate catch-up protocol)
 *   - Peer sync (auto-sync on peer connect)
 *   - Participant tracking (active quorum management)
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
const { getNodeCount, pruneInactive } = require("./participants");
const { onPeerAuthorized } = require("./peer-sync");
const { getLogger } = require("../logger");

const log = getLogger("tip.consensus");

/**
 * Get sorted list of active participant node IDs.
 * @param {Set} activeParticipants  Active participant set
 * @returns {string[]}
 */
function getActiveNodeIds(activeParticipants) {
  return [...activeParticipants].sort();
}

/**
 * Look up a node's public key from the DAG registry.
 * Used by Narwhal for batch/cert signature verification.
 *
 * @param {Object} dag     DAG store
 * @param {string} nodeId  Node ID to look up
 * @returns {string|null}  Public key or null if not found
 */
function getNodeKey(dag, nodeId) {
  const n = dag.getNode(nodeId);
  return n?.public_key || null;
}

/**
 * Initialize the consensus layer.
 *
 * @param {Object} options
 * @param {Object}   options.dag              DAG store
 * @param {Object}   options.scoring          Scoring engine
 * @param {Object}   options.config           Node config
 * @param {Object}   options.network          libp2p network node
 * @param {Function} options.isAuthorizedPeer (peerId) => boolean
 * @returns {Object} Consensus interface
 */
function initConsensus({ dag, scoring, config, network, isAuthorizedPeer = () => false }) {
  const nodeId = config.nodeRegisteredId || config.nodeId;

  // Active participants — quorum based on who's actually producing certificates
  const activeParticipants = new Set([nodeId]);

  // ── Create mempool (persistent) ───────────────────────────────────────────
  const mempool = createMempool(dag);
  log.info(`Mempool initialized (${mempool.size()} pending txs restored)`);

  // ── Create commit handler ─────────────────────────────────────────────────
  const commitHandler = createCommitHandler({ dag, scoring, config });

  // ── Create sync handler (Merkle tree + catch-up protocol) ──────────────────
  const syncHandler = createSyncHandler({ dag, network, isAuthorizedPeer });

  const bullshark = createBullshark({
    dag,
    getNodeIds: () => getActiveNodeIds(activeParticipants),
    onOrderedTxs: (orderedTxs, round) => {
      const result = commitHandler.commitOrderedTxs(orderedTxs, round);
      // Update Merkle tree with newly committed certificate hashes
      try {
        const certs = dag.getCertificatesByRound(round);
        for (const cert of certs) syncHandler.onCertificateCommitted(cert.hash);
      } catch { /* ignore */ }
      log.info(`Bullshark round ${round}: ${result.committed} committed, ${result.dropped} dropped`);
    },
  });

  const narwhal = createNarwhal({
    dag, mempool, network, config,
    getNodeKey: (nId) => getNodeKey(dag, nId),
    getNodeCount: () => getNodeCount(dag),
    activeParticipants,
    onCommit: (certificates, round) => bullshark.onRoundComplete(certificates, round),
    notePendingTxCert: (cert) => bullshark.notePendingTxCert(cert),
    hasPendingWork: () => bullshark.hasPendingWork(),
  });

  // ── Wire network events ────────────────────────────────────────────────

  if (network) {
    // Auto-sync after handshake completes
    network.onPeerAuthorized(async (peerId, tipNodeId) => {
      await onPeerAuthorized(peerId, tipNodeId, { syncHandler, commitHandler, dag, narwhal, bullshark, activeParticipants });
    });

    // Prune inactive participants on peer disconnect
    network.node.addEventListener("peer:disconnect", () => {
      pruneInactive(activeParticipants, nodeId, dag);
    });

    log.info("Consensus network handlers wired");
  } else {
    log.warn("No network node — consensus running in local-only mode");
  }

  // ── Public interface ───────────────────────────────────────────────────

  return {
    /**
     * Add a validated transaction to the mempool.
     * Called by API services after validation.
     * @param {Object} tx  Validated tx (must have tx_id)
     * @returns {{ added: boolean, reason?: string }}
     */
    addTx: (tx) => mempool.add(tx),

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