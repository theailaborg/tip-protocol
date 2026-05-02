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
          // Replay synced txs through commit-handler. As of Commit 2 (#13),
          // every tx that touches the `_prev` ring flows through consensus,
          // so prev references are always resolvable in canonical-order
          // replay (Bullshark's total order guarantees the prev tx is
          // already committed by the time we process its referrer).
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
    // Advance Bullshark's committed_round counter to peer's CURRENT
    // committed_round (carried in SnapshotHeader.peer_committed_round),
    // not just to the snapshot's anchor round. State at peer's current
    // round is identical to state at snap.round when no commit rows
    // exist between them — verified at install time by the bundle-vs-
    // claim consistency check in snapshot-handler. Without this advance,
    // on idle networks the joiner's counter sticks at snap.round (e.g.
    // 1504) while peer's is much higher (e.g. 5650), and anti-entropy
    // detects a fake "behind by N rounds" gap and loops trying to pull
    // certs that have been GC'd.
    const targetRound = Math.max(snap.peer_committed_round || 0, snap.round);
    if (bullshark?.markOrderedUpTo) bullshark.markOrderedUpTo(targetRound);
    // Adopt peer's network-wide consensus_index so dashboards converge
    // across all nodes (Cosmos/Sui/Aptos pattern). Monotonic — won't go
    // backwards if our local value happens to be higher (mid-run
    // restart with more history). See SnapshotHeader.peer_consensus_index.
    const targetConsensusIndex = Math.max(snap.peer_consensus_index || 0, snap.consensus_index || 0);
    if (bullshark?.setConsensusIndex) bullshark.setConsensusIndex(targetConsensusIndex);
    log.notice(
      `Snapshot fast-sync: installed round=${snap.round} ` +
      `peer_committed_round=${snap.peer_committed_round || snap.round} ` +
      `peer_consensus_index=${targetConsensusIndex} ` +
      `consensus_index=${snap.consensus_index} rows=${snap.rows_installed} ` +
      `peer=${peerId.slice(0, 12)}`
    );
    // Return snap.round (NOT targetRound). The caller uses this as the
    // cert-sync start point: `fromRound = snapRound + 1`. Cert-sync must
    // pull every cert from snap.round+1 onwards — INCLUDING the
    // [snap.round+1, peer_committed_round] window — because the snapshot
    // ships derived state + commits but NOT certificates. Without these
    // certs, the joiner's local DAG has no way to populate the K-round
    // window used by participants.getActiveCommittee for runtime committee
    // derivation.
    //
    // Live fingerprint (2026-05-02): node 2 installed snap at round=98
    // with peer_committed_round=146; this code previously returned 146,
    // sync started at 147, all peer certs after 147 referenced parents in
    // the [99, 146] gap that node 2 didn't have, every cert was parked,
    // node 2's K-window saw only its own certs, derived quorum=1, shipped
    // 1-ack certs, node 1 (full DAG) rejected them with quorum=2 → halt.
    //
    // Bullshark counter (markOrderedUpTo above) still advances to
    // peer_committed_round — that's correct for the "peer is at this
    // height" operational signal — but cert-sync needs the underlying
    // cert data, hence snap.round here. Pre-§4 didn't hit this because
    // K was 4 rounds (the K-window happened to be entirely after
    // peer_committed_round); §4 raised K to 300 rounds, exposing the gap.
    //
    // See follow-up issue: ship recent certs in the snapshot itself so
    // joiners arriving after peer cert-GC (>500 rounds idle) can still
    // reconstruct their K-window.
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
    let result = await syncWithRetry(peerId, syncHandler, { fromRound });
    let effectiveSnapRound = snapRound;

    // #45: peer GC'd past our requested round → cert sync returned an
    // empty payload with snapshotRequired=true. Without this branch the
    // bootstrap path would silently fall through to exitSyncMode at
    // peerLatestRound with no certs in the local DAG, leaving the joiner
    // unable to walk parent refs at the new round — a recipe for halt
    // or fork. Fires when Phase 1 (snapshot) was skipped (no
    // snapshotHandler / no qualifying commit) or when the peer GC'd
    // between Phase 1 and Phase 2.
    //
    // Mirrors the consumer at anti-entropy.js — a single shared signal
    // for "give up on cert sync from this peer, fall back to snapshot."
    if (result.snapshotRequired) {
      log.warn(
        `Sync: peer ${peerId.slice(0, 12)} signals snapshot_required ` +
        `(earliest=${result.earliestAvailableRound || "?"}); retrying snapshot fast-sync`
      );
      const retrySnapRound = await tryFastSyncSnapshot(peerId, nodeId, { snapshotHandler, bullshark });
      if (retrySnapRound > 0) {
        effectiveSnapRound = retrySnapRound;
        result = await syncWithRetry(peerId, syncHandler, { fromRound: retrySnapRound + 1 });
        // If the retry ALSO comes back snapshot_required, the peer is
        // GC-ing faster than we can sync. Don't recurse; let
        // anti-entropy or another peer's onPeerAuthorized try later.
        if (result.snapshotRequired) {
          log.warn(`Sync: snapshot retry still GC'd by peer ${peerId.slice(0, 12)} — staying in sync mode`);
          return;
        }
      } else {
        // Snapshot fallback also failed — give up on this peer rather
        // than exit sync mode with empty state. Anti-entropy or another
        // peer's onPeerAuthorized retries.
        log.warn(`Sync: snapshot fallback failed for peer ${peerId.slice(0, 12)} — staying in sync mode`);
        return;
      }
    }

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
    const targetRound = result.peerLatestRound || effectiveSnapRound || 0;
    narwhal.exitSyncMode(targetRound);

    // Committee is derived from DAG state — peer's certs (and any nodes
    // installed via snapshot) are already reflected. No local mutation needed.
  } catch (err) {
    log.warn(`Sync from peer ${peerId.slice(0, 12)} failed: ${err.message}`);
  }
}

module.exports = { syncWithRetry, replaySyncedTxs, tryFastSyncSnapshot, onPeerAuthorized };
