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
const { createSnapshotHandler } = require("../sync/snapshot-handler");
const { getActiveCommittee, getNodeCount } = require("./participants");
const { onPeerAuthorized } = require("./peer-sync");
const { createConsensusSummary } = require("./summary");
const { CONSENSUS } = require("../../../shared/protocol-constants");
const { getLogger } = require("../logger");

const log = getLogger("tip.consensus");

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

  // ── Create mempool (persistent) ───────────────────────────────────────────
  const mempool = createMempool(dag);
  log.info(`Mempool initialized (${mempool.size()} pending txs restored)`);

  // ── Create commit handler ─────────────────────────────────────────────────
  const commitHandler = createCommitHandler({ dag, scoring, config });

  // ── Create sync handler (Merkle tree + catch-up protocol) ──────────────────
  const syncHandler = createSyncHandler({ dag, network, isAuthorizedPeer });

  // ── Create snapshot handler (§14 state-snapshot fast-sync) ─────────────────
  // Serves the latest committed state + 2f+1 acks to new joiners so they
  // can catch up in O(state size) instead of O(chain length). Orthogonal to
  // sync-handler (which does cert replay) — a joiner typically tries
  // snapshot first and falls back to cert sync if no peer has a recent enough
  // commit. Fallback wiring lives in the join flow (not in this orchestrator).
  const snapshotHandler = createSnapshotHandler({ dag, network, isAuthorizedPeer });

  // Active committee is derived deterministically from DAG state: registered +
  // produced a cert in the last K rounds. Every node reading the same DAG
  // computes the same committee, so leader rotation and quorum match.
  // `narwhalRef.current` is populated below; this closure is called from
  // Bullshark / Narwhal after both are wired.
  const narwhalRef = { current: null };
  const getCommittee = (round) => {
    const r = round != null ? round : (narwhalRef.current ? narwhalRef.current.currentRound() : 1);
    return getActiveCommittee(dag, r);
  };

  const bullshark = createBullshark({
    dag,
    getNodeIds: getCommittee,
    onOrderedTxs: (orderedTxs, round) => {
      const result = commitHandler.commitOrderedTxs(orderedTxs, round);
      log.info(`Bullshark round ${round}: ${result.committed} committed, ${result.dropped} dropped`);
    },
  });

  const narwhal = createNarwhal({
    dag, mempool, network, config,
    getNodeKey: (nId) => getNodeKey(dag, nId),
    getNodeCount: () => getNodeCount(dag),
    getCommittee,
    onCommit: (certificates, round) => bullshark.onRoundComplete(certificates, round),
    // Rebuild Merkle tree whenever ANY cert is saved (own, peer, or synced),
    // so the root always reflects canonical DAG state.
    onCertSaved: (cert) => syncHandler.onCertificateCommitted(cert.hash),
  });
  narwhalRef.current = narwhal;

  // Periodic heartbeat summary — emits one INFO line per interval with
  // deltas, stays silent during true idle. Per-round events are debug-level.
  const summary = createConsensusSummary({
    narwhal, bullshark,
    intervalMs: CONSENSUS.CONSENSUS_SUMMARY_INTERVAL_MS,
  });

  // ── Wire network events ────────────────────────────────────────────────

  if (network) {
    // Auto-sync after handshake completes
    network.onPeerAuthorized(async (peerId, tipNodeId) => {
      await onPeerAuthorized(peerId, tipNodeId, {
        syncHandler, snapshotHandler, commitHandler, dag, narwhal, bullshark, nodeId,
      });
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
     * Pass { awaitPeers: true } for joiner nodes so production is gated on
     * the first peer handshake + sync, preventing premature batch/ack
     * broadcasts that would be rejected by peers whose node registries
     * haven't yet incorporated us via consensus.
     */
    async start({ awaitPeers = false } = {}) {
      await syncHandler.registerProtocol();
      await snapshotHandler.registerProtocol();
      if (awaitPeers) narwhal.enterSyncMode();
      narwhal.start();
      summary.start();
      log.notice(`Consensus started${awaitPeers ? " — awaiting peer sync" : ""}`);
    },

    /**
     * Stop consensus gracefully.
     */
    stop() {
      summary.stop();
      narwhal.stop();
      log.notice("Consensus stopped");
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

    /** §14: fast-sync derived state from a peer via the snapshot protocol */
    requestSnapshotFromPeer: (peerId, opts) => snapshotHandler.requestSnapshotFromPeer(peerId, opts),

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