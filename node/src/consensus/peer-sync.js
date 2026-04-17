/**
 * @file @tip-protocol/node/src/consensus/peer-sync.js
 * @description Handles certificate sync + tx replay when a new peer connects.
 *
 * After a peer completes the TIP handshake, this module:
 *   1. Syncs missing certificates from the peer (with retry + backoff)
 *   2. Replays transactions from synced certificates through the commit handler
 *   3. Resyncs Narwhal to the latest round
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS } = require("../../../shared/protocol-constants");
const { getLogger } = require("../logger");

const log = getLogger("tip.consensus");

/**
 * Sync certificates from a peer with retry and exponential backoff.
 * @param {string} peerId       libp2p peer ID
 * @param {Object} syncHandler  Sync handler instance
 * @returns {Promise<{ imported: number, fromRound: number, toRound: number }>}
 */
async function syncWithRetry(peerId, syncHandler) {
  const maxRetries = CONSENSUS.SYNC_MAX_RETRIES;
  const retryBaseMs = CONSENSUS.SYNC_RETRY_BASE_MS;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await syncHandler.syncFromPeer(peerId);
    } catch (err) {
      log.warn(`Sync attempt ${attempt}/${maxRetries} from ${peerId.slice(0, 12)} failed: ${err.message}`);
      if (attempt < maxRetries) {
        await new Promise(r => setTimeout(r, attempt * retryBaseMs));
      }
    }
  }
  return { imported: 0, fromRound: 0, toRound: 0 };
}

/**
 * Replay transactions from synced certificates through the commit handler.
 * This applies derived state (identities, content, scores, etc.) to the DAG.
 *
 * @param {Object} dag            DAG store
 * @param {Object} commitHandler  Commit handler instance
 * @param {number} fromRound      First round to replay
 * @param {number} toRound        Last round to replay
 * @returns {number} Total committed transactions
 */
function replaySyncedTxs(dag, commitHandler, fromRound, toRound) {
  let committed = 0;
  for (let r = fromRound; r <= toRound; r++) {
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
  return committed;
}

/**
 * Handle a newly authorized peer — sync + replay + resync Narwhal.
 * Called by consensus/index.js when network.onPeerAuthorized fires.
 *
 * @param {string} peerId        libp2p peer ID
 * @param {string} tipNodeId     TIP node ID of the peer
 * @param {Object} deps          { syncHandler, commitHandler, dag, narwhal, bullshark, activeParticipants }
 */
async function onPeerAuthorized(peerId, tipNodeId, { syncHandler, commitHandler, dag, narwhal, bullshark, activeParticipants }) {
  log.info(`Peer authorized: ${tipNodeId} — syncing certificates from ${peerId.slice(0, 12)}...`);

  // Enter sync mode — suppress all round production until sync + first peer batch
  narwhal.enterSyncMode();

  try {
    const result = await syncWithRetry(peerId, syncHandler);

    if (result.imported > 0) {
      log.info(`Synced ${result.imported} certificates from peer (rounds ${result.fromRound}-${result.toRound})`);

      const committed = replaySyncedTxs(dag, commitHandler, result.fromRound, result.toRound);
      if (committed > 0) log.info(`Replayed ${committed} transactions from synced certificates`);

      // Mark synced certificates as ordered so Bullshark doesn't re-commit their txs
      bullshark.markOrderedUpTo(result.toRound);

      // Resync round and wait for peer's batch to learn the exact round
      narwhal.resyncRound();
    } else {
      // Nothing to sync — this node is already up to date, go back to ready
      narwhal.exitSyncMode();
    }

    // Add peer to active participants after successful sync.
    // Quorum now reflects real network size — node can't create solo certificates.
    // Stays idle after this — waits for peer's live batch to learn current round.
    if (activeParticipants && !activeParticipants.has(tipNodeId)) {
      activeParticipants.add(tipNodeId);
      log.info(`Added peer ${tipNodeId} to active participants (active: ${activeParticipants.size})`);
    }
  } catch (err) {
    log.warn(`Sync from peer ${peerId.slice(0, 12)} failed: ${err.message}`);
  }
}

module.exports = { syncWithRetry, replaySyncedTxs, onPeerAuthorized };
