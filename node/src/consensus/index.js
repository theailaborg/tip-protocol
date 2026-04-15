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
const { computeQuorum } = require("./certificate");
const { createCommitHandler } = require("./commit-handler");
const { createSyncHandler } = require("../sync/sync-handler");
const { CONSENSUS } = require("../../../shared/protocol-constants");
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
function initConsensus({ dag, scoring, config, network, isAuthorizedPeer = () => false }) {
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

  // ── Active participants tracking ──────────────────────────────────────────
  // Quorum is based on nodes actually participating (producing certs), not
  // the full registry. Prevents registered-but-offline nodes from inflating
  // quorum and blocking consensus. Shared between Narwhal and Bullshark.
  const activeParticipants = new Set();
  const nodeId = config.nodeRegisteredId || config.nodeId;
  activeParticipants.add(nodeId); // self is always active

  function getActiveNodeIds() {
    return [...activeParticipants].sort();
  }

  // ── Create mempool (persistent) ───────────────────────────────────────────
  const mempool = createMempool(dag);
  log.info(`Mempool initialized (${mempool.size()} pending txs restored)`);

  // ── Create commit handler ─────────────────────────────────────────────────
  const commitHandler = createCommitHandler({ dag, scoring, config });

  // ── Create sync handler (Merkle tree + catch-up protocol) ──────────────────
  const syncHandler = createSyncHandler({ dag, network, isAuthorizedPeer });

  // ── Create Bullshark (ordering) ───────────────────────────────────────────
  const bullshark = createBullshark({
    dag,
    getNodeIds: getActiveNodeIds,
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
    activeParticipants,
    onCommit: (certificates, round) => {
      bullshark.onRoundComplete(certificates, round);
    },
  });

  // ── Wire network event handlers ──────────────────────────────────────────
  function _wireNetworkHandlers() {
    if (!network) {
      log.warn("No network node — consensus running in local-only mode");
      return;
    }

    // Auto-sync AFTER handshake completes (peer is authorized)
    network.onPeerAuthorized(async (peerId, tipNodeId) => {
      log.info(`Peer authorized: ${tipNodeId} — syncing certificates from ${peerId.slice(0, 12)}...`);
      try {
        const result = await syncHandler.syncFromPeer(peerId);
        if (result.imported > 0) {
          log.info(`Synced ${result.imported} certificates from peer (rounds ${result.fromRound}-${result.toRound})`);

          // Replay transactions from synced certificates through the commit handler
          // so that identities, nodes, content, etc. are applied to the DAG.
          let committed = 0;
          for (let r = result.fromRound; r <= result.toRound; r++) {
            try {
              const certs = dag.getCertificatesByRound(r);
              for (const cert of certs) {
                const txs = cert.batch?.txs || [];
                if (txs.length > 0) {
                  const res = commitHandler.commitOrderedTxs(txs, r);
                  committed += res.committed;
                }
              }
            } catch (err) {
              log.warn(`Failed to replay round ${r}: ${err.message}`);
            }
          }
          if (committed > 0) log.info(`Replayed ${committed} transactions from synced certificates`);

          narwhal.resyncRound();
        }
      } catch (err) {
        log.warn(`Sync from peer ${peerId.slice(0, 12)} failed: ${err.message}`);
      }
    });

    // Remove stale participants on peer disconnect
    network.node.addEventListener("peer:disconnect", () => {
      _pruneInactiveParticipants();
    });

    log.info("Consensus network handlers wired");
  }

  /**
   * Remove participants that haven't produced a certificate in the last N rounds.
   * Called on peer disconnect to clean up stale entries.
   */
  function _pruneInactiveParticipants() {
    const inactiveThreshold = CONSENSUS.PARTICIPANT_INACTIVE_ROUNDS;
    const latestRound = dag.getLatestRound();
    if (latestRound < inactiveThreshold) return;

    const recentAuthors = new Set();
    for (let r = Math.max(1, latestRound - inactiveThreshold + 1); r <= latestRound; r++) {
      try {
        const certs = dag.getCertificatesByRound(r);
        for (const cert of certs) recentAuthors.add(cert.author_node_id);
      } catch { /* ignore */ }
    }

    // Always keep self
    recentAuthors.add(nodeId);

    for (const participant of activeParticipants) {
      if (!recentAuthors.has(participant)) {
        activeParticipants.delete(participant);
        log.info(`Removed inactive participant: ${participant} (active: ${activeParticipants.size}, quorum: ${computeQuorum(activeParticipants.size)})`);
      }
    }
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
