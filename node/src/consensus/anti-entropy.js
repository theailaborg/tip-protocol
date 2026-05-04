/**
 * @file @tip-protocol/node/src/consensus/anti-entropy.js
 * @description §28 — periodic sync-status reconciliation across the federation.
 *
 * Cert GC (§2) created a new failure mode: a briefly-offline node can return
 * to find peers have already pruned the certs it missed. GossipSub retention
 * is ~3.5s (5 heartbeats), cert GC retains ~17min — the gap between these is
 * where silent divergence lives. Anti-entropy is the pull-side safety net
 * that catches whatever the push path (DirectPeers + GossipSub + retry) misses.
 *
 * Loop (every ANTI_ENTROPY_INTERVAL_MS, default 4s):
 *   for each authorized peer:
 *     rpc = /tip/sync-status/1.0.0  (lightweight — small request/response,
 *                                    NOT gossipsub)
 *     compare peer.round, peer.state_merkle_root to self:
 *
 *       peer.committed_round > self.committed_round
 *         → self is behind — pull gap via /tip/sync/1.0.0
 *
 *       peer.committed_round === self.committed_round
 *         && peer.state_merkle_root !== self.state_merkle_root
 *         → DIVERGENCE at committed state; log + metric; DO NOT auto-resolve
 *           (byzantine event; halt + page)
 *
 *       otherwise
 *         → no-op (self equal or ahead, nothing to do)
 *
 * Trust model: we only query authorized peers (TIP handshake completed,
 * in `_authorizedPeers`). An RPC reply from an unauthorized peer is
 * impossible — gossipsub / stream handlers gate on authorization.
 *
 * Invariants:
 *   - Never auto-resolves divergent state at the same round. A fork is
 *     a byzantine safety event; picking a winner silently makes it worse.
 *     Halt-gate (#30) will trip if consensus stalls; divergence metric
 *     lets ops see it even if consensus stays liveness-healthy.
 *   - Never pulls from unauthorized peers.
 *   - Per-peer timeout (ANTI_ENTROPY_PEER_TIMEOUT_MS) so one slow peer
 *     can't stall the reconciliation cycle.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { CONSENSUS, NETWORK } = require("../../../shared/protocol-constants");
const { encode, decode, bytesToHex, hexToBytes } = require("../network/proto");
const { dialKnownPeers } = require("../network/peer-discovery");
const { getLogger } = require("../logger");

const log = getLogger("tip.anti-entropy");

/**
 * Create the anti-entropy reconciliation service.
 *
 * @param {Object} options
 * @param {Object} options.dag              DAG store (for our current state)
 * @param {Object} options.network          Network node (openStream, handle, authorizedPeers)
 * @param {Object} options.syncHandler      Sync handler (syncFromPeer for gap pulls)
 * @param {Function} options.getSelfNodeId  () => our TIP node_id
 * @param {Function} options.getConsensusState  () => { round, committed_round, consensus_index, state_merkle_root, txs_merkle_root, cert_merkle_root }
 * @param {Object} [options.log]            Override logger (for tests)
 * @returns {Object} { start, stop, getStatus, queryPeer, checkAndReconcile, registerProtocol, _handleIncomingSyncStatus, _metrics }
 */
function createAntiEntropy({ network, syncHandler, snapshotHandler, narwhal, getSelfNodeId, getConsensusState, isAuthorizedPeer, log: customLog } = {}) {
  const _log = customLog || log;
  const _isAuthorizedPeer = typeof isAuthorizedPeer === "function" ? isAuthorizedPeer : null;
  const _metrics = {
    checks_total: 0,
    peers_queried: 0,
    peer_rpc_failures: 0,
    peer_rpc_timeouts: 0,
    peer_identity_mismatch: 0,
    peer_unauthorized_query: 0,    // client side: peer missing from authorized map at query time
    peer_unauthorized_inbound: 0,   // server side: unauthorized peer asked for our status
    gaps_pulled: 0,
    consensus_divergence_total: 0,
    loops_run: 0,
  };

  // Rolling cache of the last successful status per peer — feeds both the
  // REST endpoint and the loop's decision logic. Key: TIP node_id.
  const _lastStatus = new Map();

  let _timer = null;
  let _running = false;
  let _protocolRegistered = false;

  const SYNC_STATUS_PROTOCOL = NETWORK.SYNC_STATUS_PROTOCOL;

  // ──────────────────────────────────────────────────────────────────────
  // Server side: respond to sync-status probes.
  // ──────────────────────────────────────────────────────────────────────

  async function _handleIncomingSyncStatus({ stream, connection }) {
    try {
      // Authorization gate: sync-status leaks our committed round +
      // state_merkle_root, which is committee-level telemetry. Serve only
      // to peers that completed the TIP handshake. Matches the gate on
      // sync-handler and snapshot-handler.
      const remotePeerId = connection?.remotePeer?.toString?.();
      if (_isAuthorizedPeer && remotePeerId && !_isAuthorizedPeer(remotePeerId)) {
        _metrics.peer_unauthorized_inbound++;
        _log.warn(`sync-status: rejected unauthorized peer ${remotePeerId.slice(0, 12)}`);
        try { await stream.close(); } catch { /* ignore */ }
        return;
      }

      // Read the request (empty payload; we only care that the peer asked).
      for await (const _chunk of stream.source) {
        break;  // one message is enough
      }

      const state = getConsensusState ? getConsensusState() : {};

      // #48 backstop: every status reply carries our current known-peers
      // view. The caller dials any new entries — fixes missed pushes and
      // rejoins after transient disconnects within ANTI_ENTROPY_INTERVAL_MS.
      // Recipient is excluded so they don't get their own address back.
      let knownPeers = [];
      try {
        if (network && typeof network.knownPeers === "function") {
          knownPeers = (await network.knownPeers(remotePeerId)) || [];
        }
      } catch (err) {
        _log.debug(`anti-entropy: knownPeers build failed: ${err.message}`);
      }

      const response = encode("SyncStatusResponse", {
        nodeId: getSelfNodeId ? (getSelfNodeId() || "") : "",
        round: state.round || 0,
        committedRound: state.committed_round || 0,
        consensusIndex: state.consensus_index || 0,
        stateMerkleRoot: hexToBytes(state.state_merkle_root || ""),
        txsMerkleRoot: hexToBytes(state.txs_merkle_root || ""),
        certMerkleRoot: hexToBytes(state.cert_merkle_root || ""),
        knownPeers: knownPeers.map(kp => ({
          nodeId: kp.node_id || "",
          multiaddrs: Array.isArray(kp.multiaddrs) ? kp.multiaddrs : [],
        })),
      });

      try { await stream.sink([response]); }
      catch (err) { _log.warn(`sync-status reply failed: ${err.message}`); }
    } catch (err) {
      _log.warn(`sync-status handler error: ${err.message}`);
      try { await stream.close(); } catch { /* ignore */ }
    }
  }

  /**
   * Register the sync-status protocol handler on the libp2p node. Idempotent.
   */
  async function registerProtocol() {
    if (_protocolRegistered) return;
    if (!network || typeof network.handle !== "function") return;
    await network.handle(SYNC_STATUS_PROTOCOL, (args) => _handleIncomingSyncStatus(args));
    _protocolRegistered = true;
    _log.info(`sync-status protocol registered: ${SYNC_STATUS_PROTOCOL}`);
  }

  // ──────────────────────────────────────────────────────────────────────
  // Client side: probe a peer for its state.
  // ──────────────────────────────────────────────────────────────────────

  /**
   * Ask a peer for its current sync status. Bounded by ANTI_ENTROPY_PEER_TIMEOUT_MS.
   *
   * @param {string} peerId  libp2p peer ID string
   * @returns {Promise<Object|null>} parsed status or null on error/timeout
   */
  async function queryPeer(peerId) {
    if (!network || typeof network.openStream !== "function") return null;
    _metrics.peers_queried++;

    const timeoutMs = CONSENSUS.ANTI_ENTROPY_PEER_TIMEOUT_MS;
    let stream = null;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { if (stream) stream.close(); } catch { /* ignore */ }
    }, timeoutMs);

    try {
      stream = await network.openStream(peerId, SYNC_STATUS_PROTOCOL);

      // Send empty request.
      const request = encode("SyncStatusRequest", {});
      try { await stream.sink([request]); }
      catch (err) {
        throw new Error(`send failed: ${err.message}`);
      }

      // Read response.
      const chunks = [];
      for await (const chunk of stream.source) {
        chunks.push(chunk.subarray());
      }
      // Timeout fired and closed the stream from under us — classify as
      // a timeout regardless of what (if anything) the peer managed to
      // write first. Without this check the early-close on timeout
      // would be indistinguishable from a peer returning an empty body.
      if (timedOut) {
        _metrics.peer_rpc_timeouts++;
        _log.debug(`sync-status timeout for ${peerId.slice(0, 12)} (${timeoutMs}ms, early close)`);
        return null;
      }
      if (chunks.length === 0) return null;

      let msg;
      try {
        msg = decode("SyncStatusResponse", Buffer.concat(chunks));
      } catch (err) {
        _metrics.peer_rpc_failures++;
        _log.debug(`sync-status decode failed for ${peerId.slice(0, 12)}: ${err.message}`);
        return null;
      }

      // Cross-check the claimed TIP node_id against the one we already
      // authorized for this libp2p peerId during the handshake. A peer
      // could lie about their node_id in the response (nothing in the
      // proto signs it), so if we accepted any value we'd let peer A
      // poison peer B's entry in `_lastStatus` by returning B's node_id.
      // Reject the response on mismatch — treat as RPC failure.
      const claimedNodeId = msg.nodeId || "";
      const expectedNodeId = (() => {
        try {
          const map = network.authorizedPeers ? network.authorizedPeers() : null;
          return map ? (map[peerId] || "") : "";
        } catch { return ""; }
      })();

      // If the peer isn't in our authorized map AT QUERY TIME, treat as
      // unauthorized. This covers two cases: (a) caller passed an
      // unauthorized peerId (caller bug), (b) race — peer got
      // deauthorized between _runOnce's snapshot and this query. Either
      // way, we've lost the link to a verified handshake identity for
      // this peer, so their response shouldn't enter our cache.
      if (!expectedNodeId) {
        _metrics.peer_unauthorized_query++;
        _log.debug(`sync-status: peer ${peerId.slice(0, 12)} not in authorized map — rejecting response`);
        return null;
      }

      if (claimedNodeId !== expectedNodeId) {
        _metrics.peer_identity_mismatch++;
        _log.warn(`sync-status identity mismatch from ${peerId.slice(0, 12)}: claimed=${claimedNodeId} expected=${expectedNodeId}`);
        return null;
      }

      // #48 backstop: dial any new peers the responder told us about.
      // dialKnownPeers dedups against our current authorized set and
      // skips self, so receiving a peer we already have is a no-op.
      // Each newly-dialed peer still proves identity via TIP handshake.
      const knownPeers = (msg.knownPeers || []).map(kp => ({
        node_id: kp.nodeId || "",
        multiaddrs: Array.isArray(kp.multiaddrs) ? kp.multiaddrs : [],
      }));
      if (knownPeers.length > 0 && network && network.node) {
        const authorizedMap = (() => {
          try {
            const obj = network.authorizedPeers ? network.authorizedPeers() : {};
            // dialKnownPeers wants a Map<peerId, tipNodeId>; convert.
            return new Map(Object.entries(obj));
          } catch { return new Map(); }
        })();
        const ownNodeId = getSelfNodeId ? (getSelfNodeId() || "") : "";
        dialKnownPeers(network.node, knownPeers, authorizedMap, ownNodeId, _log);
      }

      return {
        node_id: claimedNodeId,
        round: Number(msg.round || 0),
        committed_round: Number(msg.committedRound || 0),
        consensus_index: Number(msg.consensusIndex || 0),
        state_merkle_root: bytesToHex(msg.stateMerkleRoot || Buffer.alloc(0)),
        txs_merkle_root: bytesToHex(msg.txsMerkleRoot || Buffer.alloc(0)),
        cert_merkle_root: bytesToHex(msg.certMerkleRoot || Buffer.alloc(0)),
        checked_at: Date.now(),
      };
    } catch (err) {
      if (timedOut) {
        _metrics.peer_rpc_timeouts++;
        _log.debug(`sync-status timeout for ${peerId.slice(0, 12)} (${timeoutMs}ms)`);
      } else {
        _metrics.peer_rpc_failures++;
        _log.debug(`sync-status failed for ${peerId.slice(0, 12)}: ${err.message}`);
      }
      return null;
    } finally {
      clearTimeout(timer);
      try { if (stream) stream.close(); } catch { /* ignore */ }
    }
  }

  /**
   * #46: peer's cert GC horizon is past our requested fromRound, so cert
   * sync can't help. Request a §14 state snapshot instead.
   *
   * Suspends round production for the duration of the install (snapshot
   * rewrites the local DAG atomically — committing at stale rounds mid-
   * install would corrupt state). Resumes via narwhal.exitSyncMode at
   * the snapshot's anchor round on success, or at our pre-install round
   * on failure. narwhal is round-monotonic + DAG-floored, so neither
   * path can move us backwards from where we already are.
   *
   * Without this fallback an authorized peer that drifts past gc_depth
   * rounds behind (slow link, paused VM, transient outage) loops here
   * forever — every AE cycle hits the same wall.
   *
   * @returns {"snapshot_installed"|"snapshot_failed"|"snapshot_required_no_handler"}
   */
  async function _runSnapshotFallback(peerId, syncResult, selfState) {
    if (!snapshotHandler || typeof snapshotHandler.requestSnapshotFromPeer !== "function") {
      // Backward-compat: AE wired without a snapshot handler. Fall back
      // to old behavior — log and let the next AE cycle retry; halt-gate
      // catches truly stuck nodes after 3× round timeout.
      _log.warn(`anti-entropy: peer ${peerId.slice(0, 12)} signaled snapshot_required but no snapshot handler available — node will stay behind until peer's GC horizon allows cert sync (unlikely on idle federations)`);
      return "snapshot_required_no_handler";
    }

    const minRound = Number(syncResult.earliestAvailableRound || 0);
    _log.info(`anti-entropy: cert sync says snapshot_required (peer earliest=${minRound}); falling back to snapshot fast-sync`);

    if (narwhal && typeof narwhal.enterSyncMode === "function") {
      narwhal.enterSyncMode();
    }

    try {
      const installed = await snapshotHandler.requestSnapshotFromPeer(peerId, { minRound });
      const targetRound = Number(installed?.round || 0);
      // snapshot-handler.requestSnapshotFromPeer fires narwhal.markSnapshotInstalled
      // on success, transitioning syncing → catching_up. We do NOT call
      // exitSyncMode here — production stays gated until a subsequent AE
      // cycle asserts our state_merkle_root matches an authorized peer's
      // and the cert tail has reached catchUpTarget (markCaughtUp path).
      _metrics.gaps_pulled++;
      _log.info(`anti-entropy: snapshot fast-sync recovered ${peerId.slice(0, 12)} at round=${targetRound} (rows=${installed?.rows_installed || 0})`);
      return "snapshot_installed";
    } catch (err) {
      _log.warn(`anti-entropy: snapshot fallback from ${peerId.slice(0, 12)} failed: ${err.message}`);
      // Failure floor: snapshot didn't land. Fall back to ready at our
      // pre-install round so the node isn't pinned in syncing waiting on
      // a transition that won't come. The next AE tick / next peer-auth
      // retries from a different peer.
      if (narwhal && typeof narwhal.exitSyncMode === "function") {
        const safeRound = Number(selfState.round || 0);
        narwhal.exitSyncMode(safeRound);
      }
      return "snapshot_failed";
    }
  }

  /**
   * Compare one peer's status against our own and take the appropriate action.
   * Pure function of inputs + side effects — no scheduling here.
   *
   * @param {string} peerId
   * @param {Object} peerStatus  from queryPeer
   * @param {Object} selfState   from getConsensusState
   * @returns {"behind"|"ahead"|"equal"|"divergent"|"pull_failed"|"snapshot_installed"|"snapshot_failed"|"snapshot_required_no_handler"}
   */
  async function checkAndReconcile(peerId, peerStatus, selfState) {
    if (!peerStatus) return "ahead";  // conservative — no info, do nothing
    _lastStatus.set(peerStatus.node_id || peerId, peerStatus);

    const selfCommitted = Number(selfState.committed_round || 0);
    const peerCommitted = Number(peerStatus.committed_round || 0);
    const selfRoot = String(selfState.state_merkle_root || "");
    const peerRoot = String(peerStatus.state_merkle_root || "");

    if (peerCommitted > selfCommitted) {
      // We're behind. Pull the gap via existing sync protocol. fromRound
      // starts at our next-uncommitted round so we only fetch the delta.
      _log.info(`anti-entropy: behind peer ${peerStatus.node_id || peerId.slice(0, 12)} by ${peerCommitted - selfCommitted} rounds — pulling gap`);

      let syncResult = null;
      try {
        if (syncHandler && typeof syncHandler.syncFromPeer === "function") {
          syncResult = await syncHandler.syncFromPeer(peerId, { fromRound: selfCommitted + 1 });
        }
      } catch (err) {
        _log.warn(`anti-entropy: gap pull from ${peerId.slice(0, 12)} failed: ${err.message}`);
        return "pull_failed";
      }

      // #46: peer's GC horizon already pruned the cert range we need.
      // Fall back to §14 state snapshot via the focused helper. Returning
      // the Promise directly (rather than `return await`) is fine —
      // checkAndReconcile is async and the caller awaits its result.
      if (syncResult?.snapshotRequired) {
        return _runSnapshotFallback(peerId, syncResult, selfState);
      }

      // Normal cert-sync gap pull succeeded (or no syncHandler wired).
      _metrics.gaps_pulled++;
      return "behind";
    }

    if (peerCommitted === selfCommitted && selfRoot && peerRoot && selfRoot !== peerRoot) {
      // Real divergence — equal round, different roots. This is a byzantine
      // safety event. Log at WARN so it's noisy, emit the metric, do NOT
      // auto-resolve. Ops should correlate with halt-gate / audit logs and
      // either rejoin the minority node or halt the fork.
      _metrics.consensus_divergence_total++;
      _log.warn(`anti-entropy: DIVERGENCE at committed_round=${selfCommitted} with peer ${peerStatus.node_id || peerId.slice(0, 12)} — self.state_root=${selfRoot.slice(0, 16)} peer.state_root=${peerRoot.slice(0, 16)}`);
      return "divergent";
    }

    // Caught-up recovery. Two paths into ready depending on which non-ready
    // state we're in:
    //
    //   catching_up → ready: snapshot was installed, cert tail closed,
    //     state-root matches an authorized peer at the snapshot's recorded
    //     peer head. markCaughtUp gates this.
    //
    //   syncing → ready: peer-auth fired enterSyncMode but install was
    //     unnecessary (we were already at peer's committed round) and
    //     either succeeded into catching_up then bounced back, or never
    //     made it past install at all. If a peer now agrees on round +
    //     root, sync is a no-op and the override exitSyncMode unblocks
    //     production. Without this branch the node sits in syncing until
    //     onPeerAuthorized's syncWithRetry budget exhausts (60-90s) AND no
    //     reconnect re-fires enterSyncMode in between.
    if (
      peerCommitted === selfCommitted
      && selfRoot && peerRoot && selfRoot === peerRoot
      && narwhal
      && typeof narwhal.joinState === "function"
    ) {
      const state = narwhal.joinState();
      if (state === "catching_up" && typeof narwhal.markCaughtUp === "function") {
        const target = typeof narwhal.catchUpTarget === "function" ? narwhal.catchUpTarget() : 0;
        if (selfCommitted >= target) {
          _log.info(`anti-entropy: catch-up confirmed by peer ${peerStatus.node_id || peerId.slice(0, 12)} at round=${selfCommitted} — promoting to ready`);
          narwhal.markCaughtUp(selfCommitted);
        }
      } else if (state === "syncing" && typeof narwhal.exitSyncMode === "function") {
        _log.info(`anti-entropy: caught up while in syncing (no install needed) — peer ${peerStatus.node_id || peerId.slice(0, 12)} at round=${selfCommitted}, exiting via override`);
        narwhal.exitSyncMode(selfCommitted);
      }
    }

    return peerCommitted < selfCommitted ? "ahead" : "equal";
  }

  // ──────────────────────────────────────────────────────────────────────
  // Background loop.
  // ──────────────────────────────────────────────────────────────────────

  async function _runOnce() {
    if (!_running) return;
    _metrics.loops_run++;

    let selfState;
    try { selfState = getConsensusState ? getConsensusState() : {}; }
    catch (err) {
      _log.warn(`anti-entropy: getConsensusState threw: ${err.message}`);
      return;
    }

    // Snapshot authorized peers at loop start so a mid-cycle join/leave
    // doesn't cause partial iteration.
    let peerEntries = [];
    try {
      if (network && typeof network.authorizedPeers === "function") {
        peerEntries = Object.entries(network.authorizedPeers());
      }
    } catch { /* network not ready yet */ }

    // Parallel fan-out. Cycle duration = max(slowest peer, peer-timeout)
    // instead of sum — a single slow/dead peer no longer blocks probing
    // every other peer. Per-peer timeout inside queryPeer bounds each
    // leg independently. If _running flips to false mid-cycle we stop
    // scheduling subsequent cycles; in-flight probes complete naturally.
    await Promise.all(peerEntries.map(async ([peerId]) => {
      if (!_running) return;
      _metrics.checks_total++;
      try {
        const status = await queryPeer(peerId);
        if (!_running) return;   // don't mutate _lastStatus after shutdown
        if (status) await checkAndReconcile(peerId, status, selfState);
      } catch (err) {
        _log.debug(`anti-entropy: peer ${peerId.slice(0, 12)} cycle error: ${err.message}`);
      }
    }));
  }

  function _scheduleNext() {
    if (!_running) return;
    const interval = CONSENSUS.ANTI_ENTROPY_INTERVAL_MS;
    _timer = setTimeout(async () => {
      try { await _runOnce(); }
      catch (err) { _log.warn(`anti-entropy: runOnce error: ${err.message}`); }
      _scheduleNext();
    }, interval);
  }

  async function start() {
    if (_running) return;
    _running = true;
    await registerProtocol();
    _log.info(`anti-entropy started (interval=${CONSENSUS.ANTI_ENTROPY_INTERVAL_MS}ms, peer_timeout=${CONSENSUS.ANTI_ENTROPY_PEER_TIMEOUT_MS}ms)`);
    _scheduleNext();
  }

  function stop() {
    _running = false;
    if (_timer) { clearTimeout(_timer); _timer = null; }
    _log.info("anti-entropy stopped");
  }

  // ──────────────────────────────────────────────────────────────────────
  // REST-endpoint feed: snapshot of current cluster sync state.
  // ──────────────────────────────────────────────────────────────────────

  function getStatus() {
    const selfState = getConsensusState ? getConsensusState() : {};
    const selfRound = Number(selfState.committed_round || 0);
    const selfRoot = String(selfState.state_merkle_root || "");

    const peers = [];
    for (const [nodeId, s] of _lastStatus.entries()) {
      const inSync = s.committed_round === selfRound && s.state_merkle_root === selfRoot;
      peers.push({
        node_id: nodeId,
        round: s.round,
        committed_round: s.committed_round,
        consensus_index: s.consensus_index,
        state_merkle_root: s.state_merkle_root,
        in_sync: inSync,
        checked_at: new Date(s.checked_at).toISOString(),
      });
    }

    const allInSync = peers.length > 0 && peers.every(p => p.in_sync);

    return {
      self: {
        node_id: getSelfNodeId ? (getSelfNodeId() || "") : "",
        round: Number(selfState.round || 0),
        committed_round: selfRound,
        consensus_index: Number(selfState.consensus_index || 0),
        state_merkle_root: selfRoot,
      },
      peers,
      in_sync: allInSync,
      timestamp: new Date().toISOString(),
    };
  }

  return {
    start,
    stop,
    getStatus,
    queryPeer,
    checkAndReconcile,
    registerProtocol,
    _handleIncomingSyncStatus,
    // Exposed for metrics scraping + tests.
    stats: () => ({ metrics: { ..._metrics }, last_status_size: _lastStatus.size }),
    SYNC_STATUS_PROTOCOL,
  };
}

module.exports = { createAntiEntropy };
