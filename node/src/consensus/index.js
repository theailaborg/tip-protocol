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
const { computeHaltStatus } = require("./halt-status");
const { getActiveCommittee, getNodeCount } = require("./participants");
const { onPeerAuthorized } = require("./peer-sync");
const { createConsensusSummary } = require("./summary");
const { createAntiEntropy } = require("./anti-entropy");
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
  // Construction is deferred to after bullshark is created so the snapshot
  // server can ship peer's bullshark.lastCommittedRound to joiners (lets the
  // joiner advance its own committed_round counter past the snapshot anchor
  // when the network's been idle for many rounds).

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
    // BFT-Time — bullshark passes the anchor cert's timestamp (median of
    // acks.signed_at, deterministic across nodes) so commit-handler can
    // use it as the canonical wall-clock for derived state, audit logs,
    // and post-round verdict triggers (Commit 3). Threaded through `opts`
    // so the existing { fromSync } API stays stable.
    onOrderedTxs: (orderedTxs, round, certTimestamp) => {
      const result = commitHandler.commitOrderedTxs(orderedTxs, round, { certTimestamp });
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

  // §14 snapshot handler — created here (after bullshark) so it can ship
  // peer's bullshark.lastCommittedRound in SnapshotHeader. The joiner
  // uses this to advance its own committed_round counter past the
  // snapshot anchor when the network's been idle, so anti-entropy
  // doesn't false-positive a "behind" gap and loop.
  const snapshotHandler = createSnapshotHandler({ dag, network, isAuthorizedPeer, bullshark });

  // Periodic heartbeat summary — emits one INFO line per interval with
  // deltas, stays silent during true idle. Per-round events are debug-level.
  const summary = createConsensusSummary({
    narwhal, bullshark,
    intervalMs: CONSENSUS.CONSENSUS_SUMMARY_INTERVAL_MS,
  });

  // §28 anti-entropy reconciliation loop. Pull-side safety net: every
  // ANTI_ENTROPY_INTERVAL_MS each authorized peer is probed for its
  // committed_round + state_merkle_root. Self-behind → pull gap via
  // /tip/sync/1.0.0; equal round but divergent root → byzantine fork
  // signal (log + metric, no auto-resolve). Pairs with cert GC (§2)
  // which otherwise leaves briefly-offline nodes unable to recover
  // via GossipSub retention alone.
  const antiEntropy = createAntiEntropy({
    network, syncHandler,
    // #46: snapshot fallback when peer's GC horizon prunes the round we
    // need. Without these the AE loop spins forever on lagging nodes
    // that fell past gc_depth rounds behind.
    snapshotHandler,
    narwhal,
    isAuthorizedPeer,
    getSelfNodeId: () => nodeId,
    getConsensusState: () => ({
      round: narwhal.currentRound(),
      committed_round: bullshark.lastCommittedRound(),
      consensus_index: bullshark.stats().consensusIndex || 0,
      state_merkle_root: (() => {
        const latest = dag.getLatestCommit && dag.getLatestCommit();
        return latest?.state_merkle_root || "";
      })(),
      txs_merkle_root: (() => {
        const latest = dag.getLatestCommit && dag.getLatestCommit();
        return latest?.txs_merkle_root || "";
      })(),
      cert_merkle_root: syncHandler.merkleRoot(),
    }),
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
      await antiEntropy.start();
      if (awaitPeers) narwhal.enterSyncMode();
      narwhal.start();
      summary.start();
      log.notice(`Consensus started${awaitPeers ? " — awaiting peer sync" : ""}`);
    },

    /**
     * Stop consensus gracefully.
     */
    stop() {
      antiEntropy.stop();
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

    /**
     * "Can we make forward progress right now?" Returns
     * `{ halted, reason, lastAdvanceAt, staleMs, [message] }`. Halted when
     * consensus is running but hasn't advanced a round in > 3× ROUND_TIMEOUT_MS
     * (quorum unreachable — peers offline, partition). Loud, honest signal
     * used by the /v1 write gate to 503 new requests and by /health to
     * surface degraded status.
     *
     * Implementation delegates to `computeHaltStatus` — see that file for
     * the full decision tree. Accepts an injectable `now` for tests.
     */
    isConsensusHalted({ now } = {}) {
      return computeHaltStatus(narwhal.stats(), {
        roundTimeoutMs: CONSENSUS.ROUND_TIMEOUT_MS,
        now,
      });
    },

    /** Sync: request certificates from a peer */
    syncFromPeer: (peerId) => syncHandler.syncFromPeer(peerId),

    /** §14: fast-sync derived state from a peer via the snapshot protocol */
    requestSnapshotFromPeer: (peerId, opts) => snapshotHandler.requestSnapshotFromPeer(peerId, opts),

    /** Current Merkle root of certificate DAG */
    merkleRoot: () => syncHandler.merkleRoot(),

    /** §28 anti-entropy cluster sync view — for GET /v1/sync-status */
    getSyncStatus: () => antiEntropy.getStatus(),

    /** Stats for monitoring / health endpoint */
    stats() {
      return {
        narwhal: narwhal.stats(),
        bullshark: bullshark.stats(),
        mempool: mempool.stats(),
        merkleRoot: syncHandler.merkleRoot(),
        antiEntropy: antiEntropy.stats(),
      };
    },
  };
}

module.exports = { initConsensus };