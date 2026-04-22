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
 * @param {Object} [opts]
 * @param {number} [opts.fromRound]  Override start round (see sync-handler.syncFromPeer)
 * @returns {Promise<{ imported: number, fromRound: number, toRound: number, peerLatestRound: number }>}
 */
async function syncWithRetry(peerId, syncHandler, { fromRound } = {}) {
  const maxRetries = CONSENSUS.SYNC_MAX_RETRIES;
  const retryBaseMs = CONSENSUS.SYNC_RETRY_BASE_MS;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await syncHandler.syncFromPeer(peerId, { fromRound });
    } catch (err) {
      log.warn(`Sync attempt ${attempt}/${maxRetries} from ${peerId.slice(0, 12)} failed: ${err.message}`);
      if (attempt < maxRetries) {
        await new Promise(r => setTimeout(r, attempt * retryBaseMs));
      }
    }
  }
  return { imported: 0, fromRound: 0, toRound: 0, peerLatestRound: 0 };
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
          // fromSync=true relaxes the prev-reference existence check —
          // internal-only txs (scheduler merkle publish, scoring, jury; #13)
          // aren't broadcast via consensus, so their tx_ids can be referenced
          // as prev by synced txs but won't exist on this node. The cert's
          // BFT signatures already prove integrity.
          const res = commitHandler.commitOrderedTxs(txs, r, { fromSync: true });
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
 * Attempt §14 state-snapshot fast-sync from a peer. Returns the snapshot's
 * committed round on success so the caller can start cert-sync from the
 * gap onwards (snapRound + 1), or 0 if no snapshot was installed.
 *
 * A null/undefined snapshotHandler, a peer with no qualifying commit, or
 * any verification failure all resolve to 0 — the caller then falls
 * through to the full cert-replay path. We intentionally do NOT throw:
 * snapshot is an optimisation, cert replay is the correctness-guaranteeing
 * fallback, and a single flaky peer shouldn't block the joiner.
 */
async function tryFastSyncSnapshot(peerId, tipNodeId, { snapshotHandler, bullshark }) {
  if (!snapshotHandler) return 0;
  try {
    const snap = await snapshotHandler.requestSnapshotFromPeer(peerId, {
      minRound: 0,
      requesterNodeId: tipNodeId || "",
    });
    if (!snap || !snap.round) return 0;
    // Tell Bullshark the anchor at snap.round is already committed so it
    // doesn't try to re-order whatever catch-up certs arrive next. State
    // has been written by the snapshot installer already.
    if (bullshark?.markOrderedUpTo) bullshark.markOrderedUpTo(snap.round);
    log.notice(
      `Snapshot fast-sync: installed round=${snap.round} ` +
      `consensus_index=${snap.consensus_index} rows=${snap.rows_installed} ` +
      `peer=${peerId.slice(0, 12)}`
    );
    return snap.round;
  } catch (err) {
    // Expected on peers that don't have a commit yet (fresh networks),
    // on peers that reject our minRound, or when verification fails.
    // All cases: fall back to cert replay.
    log.info(`Snapshot fast-sync skipped for ${peerId.slice(0, 12)}: ${err.message}`);
    return 0;
  }
}

/**
 * Handle a newly authorized peer — snapshot fast-sync (if possible), cert
 * catch-up for the remaining gap, tx replay, resync Narwhal.
 *
 * Two-phase sync:
 *   Phase 1 (§14 fast-path): pull derived state + 2f+1 acks at a recent
 *     committed round. Cryptographically verified; atomic install. Skips
 *     replaying the entire chain from round 1.
 *   Phase 2 (cert catch-up): pull certificates for rounds the snapshot
 *     doesn't cover (snap_round + 1 → peer's latest). Small gap on a
 *     long-running network; whole chain on a fresh one (when no snapshot
 *     exists yet).
 *
 * Either phase failing is non-fatal — we try both and the joiner ends up
 * as caught up as the available data allows. Correctness is guaranteed
 * by Phase 2 (cert signatures + DAG replay); Phase 1 is a bandwidth/time
 * optimisation layered on top.
 *
 * @param {string} peerId        libp2p peer ID
 * @param {string} tipNodeId     TIP node ID of the peer
 * @param {Object} deps          { syncHandler, snapshotHandler, commitHandler,
 *                                 dag, narwhal, bullshark, nodeId }
 */
async function onPeerAuthorized(peerId, tipNodeId, deps) {
  const { syncHandler, snapshotHandler, commitHandler, dag, narwhal, bullshark, nodeId } = deps;
  log.notice(`Peer authorized: ${tipNodeId} — bootstrapping from ${peerId.slice(0, 12)}...`);

  // Enter sync mode — suppress all round production until sync + first peer batch
  narwhal.enterSyncMode();

  try {
    // ── Phase 1: snapshot fast-sync (non-fatal on failure) ────────────────
    const snapRound = await tryFastSyncSnapshot(peerId, nodeId, { snapshotHandler, bullshark });

    // ── Phase 2: cert catch-up for the gap after the snapshot ─────────────
    // fromRound = snapRound + 1 if we have a snapshot, else default (round 1
    // for a fresh DAG, or latest+1 for a resuming node). syncFromPeer reads
    // dag.getLatestRound() when fromRound is undefined.
    const fromRound = snapRound > 0 ? snapRound + 1 : undefined;
    const result = await syncWithRetry(peerId, syncHandler, { fromRound });

    if (result.imported > 0) {
      log.info(`Synced ${result.imported} certificates from peer (rounds ${result.fromRound}-${result.toRound})`);

      const committed = replaySyncedTxs(dag, commitHandler, result.fromRound, result.toRound);
      if (committed > 0) log.info(`Replayed ${committed} transactions from synced certificates`);

      // Mark synced certificates as ordered so Bullshark doesn't re-commit their txs
      bullshark.markOrderedUpTo(result.toRound);
    }

    // Transition back to ready using the peer's authoritative latest round.
    // SyncResponse.latestRound is always present — use it to set _currentRound
    // so we start producing at the same round the cluster is on (or one after).
    // Falls back to DAG-derived round if peer didn't report one; falls back
    // further to the snapshot's round if even that's 0.
    const targetRound = result.peerLatestRound || snapRound || 0;
    narwhal.exitSyncMode(targetRound);

    // Committee is derived from DAG state — peer's certs (and any nodes
    // installed via snapshot) are already reflected. No local mutation needed.
  } catch (err) {
    log.warn(`Sync from peer ${peerId.slice(0, 12)} failed: ${err.message}`);
  }
}

module.exports = { syncWithRetry, replaySyncedTxs, tryFastSyncSnapshot, onPeerAuthorized };
