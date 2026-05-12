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
const { bftHaltThreshold } = require("./certificate");
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
function createAntiEntropy({ network, syncHandler, snapshotHandler, narwhal, getSelfNodeId, getConsensusState, isAuthorizedPeer, cancelPendingCommit: cancelPendingCommitCb = null, log: customLog } = {}) {
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
    consensus_divergence_distinct_peers: 0,  // max distinct peers seen disagreeing in any single window
    byzantine_fork_halts_triggered: 0,        // times we asked narwhal to halt
    loops_run: 0,
  };

  // Rolling cache of the last successful status per peer — feeds both the
  // REST endpoint and the loop's decision logic. Key: TIP node_id.
  const _lastStatus = new Map();

  // Per-peer first-observed timestamp for an active divergence at the
  // current (committed_round, root) tuple. Cleared as soon as the peer
  // converges (matching root) or moves to a new committed_round. Used to
  // time-bound the catch-up race guard: a brief sync-time mismatch is
  // normal and must not trigger halt, but divergence persisting at the
  // same committed_round longer than CONSENSUS.SYNC_DIVERGENCE_GRACE_MS
  // is malicious-or-corrupted (an honest replay arriving at the same
  // committed_round must produce the same state_root) and must be flagged
  // regardless of either side's joinState.
  // Key: TIP node_id. Value: { round, rootKey, firstSeenMs }.
  const _peerDivergenceFirstSeen = new Map();

  // Distinct peers reporting divergence at our (committed_round, state_root).
  // Key: `${round}:${rootPrefix}`. Value: Set<peerNodeId>. Old-round entries
  // are pruned as committed_round advances — divergence observations at a
  // round we've moved past are historical noise.
  //
  // Halt threshold is f+1 where f = floor((n-1)/3) over committee size n.
  // Rationale: with at most f byzantine peers, f+1 distinct peers disagreeing
  // implies ≥1 honest peer disagrees → we are the byzantine minority. This
  // is the formal "we are wrong" signal in BFT and the safe halt point.
  // Anything lower (e.g. halt-on-first) is exploitable by a single byzantine
  // peer to halt the network.
  const _divergenceObservations = new Map();

  // Per-key (round:ourRoot) map of peerNodeId → peerRoot for all peers
  // currently disagreeing with us. Used by the unanimous-minority detector
  // to verify all disagreeing peers converge on the SAME alternative root
  // before triggering auto-recovery (prevents a single liar from forcing us
  // to resync toward their forged root).
  const _peerRootsForKey = new Map(); // key → Map<peerNodeId, peerRoot>

  // Cooldown to prevent auto-recovery from firing in a tight loop when a
  // snapshot install doesn't immediately heal the divergence (e.g. because
  // the installed snapshot is still processed while the AE tick sees stale data).
  let _lastAutoRecoveryAt = 0;
  let _lastSnapshotResyncCompletedAt = 0;
  let _minorityRecoveryPending = false;
  let _snapshotResyncInFlight = false;  // Bug 1: prevents concurrent calls on this node
  const _cancelPendingCommit = typeof cancelPendingCommitCb === "function" ? cancelPendingCommitCb : null;
  const SNAPSHOT_RESYNC_COOLDOWN_MS = CONSENSUS.SNAPSHOT_RESYNC_COOLDOWN_MS || 60000;

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

      // Surface our narwhal join_state so peers know NOT to flag divergence
      // against us while we're syncing or catching_up — our mirror is being
      // populated in flight during those phases and any state-root we
      // compute is partial.
      const _selfJoinState = (narwhal && typeof narwhal.joinState === "function")
        ? String(narwhal.joinState() || "ready")
        : "ready";

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
        joinState: _selfJoinState,
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
        // Empty string from a legacy peer (pre-join_state proto field) is
        // treated as "ready" — historically peers wouldn't have replied at
        // all if they weren't running, and the only consumer is the
        // catch-up guard below which fails-open in the absence of signal.
        join_state: String(msg.joinState || "ready"),
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
    // Reset install guard so the new sync cycle can accept a fresh snapshot.
    if (typeof snapshotHandler.resetInstallState === "function") {
      snapshotHandler.resetInstallState();
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
      _clearDivergenceAccumulators();  // Bug 2: stale pre-install observations would re-trigger BYZ_FORK
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
      // Bug 3: cancel any deferred anchor timer that was running before this
      // install attempt. On success, onSnapshotInstalled calls cancelPendingCommit.
      // On failure, nothing cancels it — the stale timer can fire later and trigger
      // another resync loop.
      if (_cancelPendingCommit) {
        try { _cancelPendingCommit(0); } catch { /* best-effort */ }
      }
      return "snapshot_failed";
    }
  }

  // ──────────────────────────────────────────────────────────────────────
  // Byzantine-fork halt: divergence accumulator + threshold trigger.
  // ──────────────────────────────────────────────────────────────────────

  /**
   * Resolve the BFT halt threshold for the current committee. Delegates
   * to the shared `bftHaltThreshold` helper (single source of truth) so
   * AE and any future caller can never disagree on the formula.
   *
   * @returns {number} threshold; Infinity if committee size unknown
   */
  function _bftHaltThreshold() {
    const n = (narwhal && typeof narwhal.committeeSize === "function")
      ? Number(narwhal.committeeSize() || 0)
      : 0;
    return bftHaltThreshold(n);
  }

  /**
   * Record a divergence observation from `peerNodeId` at our (round, root).
   * Drops accumulator entries for rounds we've moved past — those are
   * historical noise once committed_round has advanced.
   *
   * @returns {{observed: number, threshold: number}}
   */
  function _recordDivergence(peerNodeId, atRound, ourRoot, peerRoot) {
    const key = `${atRound}:${ourRoot.slice(0, 16)}`;

    let set = _divergenceObservations.get(key);
    if (!set) {
      set = new Set();
      _divergenceObservations.set(key, set);
    }
    set.add(peerNodeId);

    // Track what root this peer claims at this round — needed to detect
    // unanimous minority (all disagree AND all agree on the same alternative).
    let peerRootMap = _peerRootsForKey.get(key);
    if (!peerRootMap) {
      peerRootMap = new Map();
      _peerRootsForKey.set(key, peerRootMap);
    }
    if (peerRoot) peerRootMap.set(peerNodeId, peerRoot);

    for (const k of _divergenceObservations.keys()) {
      const r = Number(k.split(":")[0]);
      if (r < atRound) {
        _divergenceObservations.delete(k);
        _peerRootsForKey.delete(k);
      }
    }
    return { observed: set.size, threshold: _bftHaltThreshold() };
  }

  /**
   * Clear all (or rounds ≤ upToRound) divergence accumulator entries so that
   * a post-recovery AE tick doesn't immediately re-trigger BYZ_FORK on stale
   * pre-recovery observations. Called after successful snapshot install, after
   * halt auto-recovery, and when all peers self-heal.
   */
  function _clearDivergenceAccumulators(upToRound) {
    if (upToRound !== undefined) {
      for (const k of [..._divergenceObservations.keys()]) {
        if (Number(k.split(":")[0]) <= upToRound) {
          _divergenceObservations.delete(k);
          _peerRootsForKey.delete(k);
        }
      }
    } else {
      _divergenceObservations.clear();
      _peerRootsForKey.clear();
    }
  }

  /**
   * Returns true when a MAJORITY of disagreeing peers all hold the same
   * alternative root — meaning we are provably in the minority.
   * Requires at least `threshold` peers to avoid a single-peer false positive.
   *
   * Handles 3-way splits (e.g., nodes 1+2 each have a unique root, nodes 3+4+5
   * share the majority root): even though disagreers aren't unanimous with each
   * other, the majority root (held by ≥ recoveryThreshold peers) is unambiguous.
   */
  function _isUnanimousMinority(atRound, ourRoot, observed, threshold) {
    if (observed < threshold) return { unanimous: false };

    // Auto-recovery requires a SIMPLE MAJORITY (>n/2) of the total committee
    // to hold the same alternative root — not just the BFT halt threshold (f+1).
    // With n=5 the halt threshold is 2 (f+1), but a 2+2 split has both sides
    // seeing exactly 2 disagreers: both would trigger recovery simultaneously,
    // each tries to snapshot-sync the other, circular deadlock. Requiring 3 of 5
    // means a 2+2 split never auto-recovers (manual) while genuine 3+2 and 3-way
    // (1+1+3) splits do: the 2 minority nodes each see 3 peers holding root C and
    // recover from the majority, while the 3 majority nodes see only 2 disagreers
    // and stay put.
    const n = (narwhal && typeof narwhal.committeeSize === "function")
      ? Number(narwhal.committeeSize() || 0) : 0;
    const recoveryThreshold = n > 0 ? Math.floor(n / 2) + 1 : threshold;
    if (observed < recoveryThreshold) return { unanimous: false };

    const key = `${atRound}:${ourRoot.slice(0, 16)}`;
    const peerRootMap = _peerRootsForKey.get(key);
    if (!peerRootMap || peerRootMap.size === 0) return { unanimous: false };

    // Count how many disagreeing peers hold each distinct root.
    // If any single root is held by >= recoveryThreshold peers, that is the
    // majority root — we are the minority regardless of what the remaining
    // peers hold.
    const rootCounts = new Map();
    for (const [, root] of peerRootMap) {
      rootCounts.set(root, (rootCounts.get(root) || 0) + 1);
    }
    for (const [consensusRoot, count] of rootCounts) {
      if (count >= recoveryThreshold && consensusRoot !== ourRoot) {
        const sourcePeerNodeId = [...peerRootMap.entries()].find(([, r]) => r === consensusRoot)?.[0];
        return { unanimous: true, consensusRoot, sourcePeerNodeId };
      }
    }
    return { unanimous: false };
  }

  /**
   * Time-bounded catch-up race tracker. Returns true if this peer has
   * been continuously divergent (different state_root than ours at the
   * same committed_round) for longer than CONSENSUS.SYNC_DIVERGENCE_
   * GRACE_MS — at which point an honest sync-time mismatch is no longer
   * plausible and the divergence is real (corrupted / malicious /
   * deterministic-bug).
   *
   * Tracking is keyed by peerNodeId only — NOT by (round, root) tuple.
   * Both sides' committed_round advances every few seconds, so a tuple-
   * keyed tracker would reset its timestamp on every round change and
   * never reach grace. The signal we care about is "this peer has been
   * persistently divergent across rounds," not "this peer has been
   * stuck at this exact (round, root) tuple." The entry is cleared by
   * `_clearDivergenceTracker` only when the peer converges (matching
   * root or non-equal committed_round, both signaled from
   * `_reconcileWithPeer`'s outer match branch).
   *
   * The grace timer resets when the peer's joinState changes (e.g.,
   * syncing → catching_up). Each FSM transition represents a new phase
   * of honest state-rebuilding; the 30s window measures continuous
   * divergence *within a single phase*, not cumulative divergence across
   * multiple sync phases. Without this reset, a normal restart that
   * progresses through syncing → catching_up → ready would exhaust the
   * grace in the syncing phase and then flag every catching_up AE poll as
   * a byzantine event — producing hundreds of false canary increments.
   *
   * @param {string} peerNodeId
   * @param {string} currentPeerJoinState  peer's current join_state value
   */
  function _persistentDivergence(peerNodeId, currentPeerJoinState) {
    if (!peerNodeId) return false;
    const existing = _peerDivergenceFirstSeen.get(peerNodeId);
    if (!existing || existing.lastJoinState !== currentPeerJoinState) {
      _peerDivergenceFirstSeen.set(peerNodeId, { firstSeenMs: Date.now(), lastJoinState: currentPeerJoinState });
      if (existing) {
        _log.debug(`anti-entropy: divergence grace reset for ${peerNodeId.slice(-8)} — joinState changed ${existing.lastJoinState} → ${currentPeerJoinState}`);
      }
      return false;
    }
    const elapsedMs = Date.now() - existing.firstSeenMs;
    if (elapsedMs > CONSENSUS.SYNC_DIVERGENCE_GRACE_MS) {
      _log.debug(`anti-entropy: divergence grace expired for ${peerNodeId.slice(-8)} (join=${currentPeerJoinState}, elapsed=${Math.round(elapsedMs/1000)}s > grace=${CONSENSUS.SYNC_DIVERGENCE_GRACE_MS/1000}s) — promoting to persistent`);
      return true;
    }
    return false;
  }

  function _clearDivergenceTracker(peerNodeId) {
    if (peerNodeId && _peerDivergenceFirstSeen.has(peerNodeId)) {
      _peerDivergenceFirstSeen.delete(peerNodeId);
    }
  }

  /**
   * Per-peer divergence check used by narwhal's batch handler to decide
   * whether to ack. Returns true iff our last cached AE status for this
   * peer shows same committed_round AND different non-empty state roots.
   *
   * Symmetric: every node applies this rule, so a divergent peer is
   * naturally excluded from cert formation (no peer signs their batches),
   * without anyone declaring a halt. Pairs with the threshold halt in
   * narwhal — halt is "stop us if we're wrong"; this is "deny attestation
   * to peers we currently disagree with."
   *
   * @param {string} peerNodeId  TIP node_id (NOT libp2p peerId)
   * @returns {boolean}
   */
  function isPeerDivergent(peerNodeId) {
    if (!peerNodeId) return false;
    const cached = _lastStatus.get(peerNodeId);
    if (!cached) return false;  // never polled — default trust

    const state = getConsensusState ? getConsensusState() : {};
    const selfCommitted = Number(state.committed_round || 0);
    const selfRoot = String(state.state_merkle_root || "");
    const peerCommitted = Number(cached.committed_round || 0);
    const peerRoot = String(cached.state_merkle_root || "");

    if (peerCommitted !== selfCommitted) return false;     // round skew, not divergence
    if (!selfRoot || !peerRoot) return false;              // no commits yet on either side
    return selfRoot !== peerRoot;
  }

  /**
   * Last AE-observed join_state for a peer. Pure read of the status
   * cache; defaults to "ready" when unknown so callers fail-open
   * against legacy peers / first-tick races. Used by narwhal's ack-
   * filter as a cache-lag race guard during the brief window where a
   * peer just transitioned catching_up → ready and is producing batches
   * before our next AE poll updates the cache. Persistent malicious-
   * non-ready peers are caught by the divergence detector's time-bounded
   * escalation, not here.
   */
  function peerJoinState(peerNodeId) {
    if (!peerNodeId) return "ready";
    const cached = _lastStatus.get(peerNodeId);
    return String(cached?.join_state || "ready");
  }

  /**
   * Snapshot of peers we'd currently refuse to ack. For ops surfacing in
   * /v1/sync-status. O(n) over `_lastStatus` — n is committee-size.
   */
  function divergentPeers() {
    const out = [];
    for (const [nodeId] of _lastStatus.entries()) {
      if (isPeerDivergent(nodeId)) out.push(nodeId);
    }
    return out;
  }

  /**
   * Trigger narwhal halt when distinct-peer disagreement reaches the BFT
   * threshold. Idempotent — narwhal.haltDueToByzantineFork early-returns
   * once already halted. Logging fires only on the threshold-crossing
   * call so we don't spam ERROR every AE cycle.
   */
  function _maybeHalt(atRound, ourRoot, observed, threshold, peerNodeId) {
    if (observed < threshold) {
      _log.debug(`anti-entropy: _maybeHalt: ${observed}/${threshold} divergent peers at round=${atRound} — below threshold, no halt`);
      return;
    }
    if (!narwhal || typeof narwhal.haltDueToByzantineFork !== "function") return;
    const alreadyHalted = typeof narwhal.byzantineForkHalt === "function"
      && narwhal.byzantineForkHalt();
    if (alreadyHalted) {
      // Halt fired at threshold (2 peers). Minority-recovery requires a majority
      // (3 of 5 peers). The 3rd+ peer reports on subsequent AE ticks when
      // alreadyHalted=true. Re-check recovery now that `observed` has grown.
      const { unanimous: u2, sourcePeerNodeId: src2 } = _isUnanimousMinority(atRound, ourRoot, observed, threshold);
      if (u2 && src2 && !_minorityRecoveryPending) {
        const RECOVERY_DELAY_MS = CONSENSUS.BYZANTINE_FORK_AUTO_RECOVERY_DELAY_MS || 5000;
        const RECOVERY_COOLDOWN_MS = CONSENSUS.BYZANTINE_FORK_AUTO_RECOVERY_COOLDOWN_MS || 30000;
        const sinceLastMs = Date.now() - _lastAutoRecoveryAt;
        if (_lastAutoRecoveryAt > 0 && sinceLastMs < RECOVERY_COOLDOWN_MS) {
          _log.warn(`anti-entropy: majority minority while halted at round=${atRound} — cooldown active (${Math.floor(sinceLastMs / 1000)}s < ${RECOVERY_COOLDOWN_MS / 1000}s)`);
          return;
        }
        _minorityRecoveryPending = true;
        _log.warn(
          `anti-entropy: majority minority detected while halted at round=${atRound} — ` +
          `majority of peers hold same alternative root. Scheduling auto-recovery from ${src2.slice(-8)} in ${RECOVERY_DELAY_MS}ms.`
        );
        setTimeout(() => {
          _minorityRecoveryPending = false;
          _autoRecoverFromMinority(src2, atRound);
        }, RECOVERY_DELAY_MS);
      }
      return;
    }

    _metrics.byzantine_fork_halts_triggered++;
    const reason = `${observed}/${threshold} peers disagree at committed_round=${atRound}; self.state_root=${ourRoot.slice(0, 16)}`;
    _log.error(`anti-entropy: byzantine-fork halt threshold reached — ${reason}`);
    narwhal.haltDueToByzantineFork({ reason, atRound, peerNodeId });

    // Option B — unanimous minority auto-recovery. When ALL disagreeing peers
    // agree on the SAME alternative root, we are provably the minority: our
    // committed state is wrong (incomplete DAG walk, GC-driven truncation, etc.)
    // and the honest majority is correct. Trigger a snapshot resync from the
    // majority peer instead of waiting for manual clearByzantineForkHalt().
    //
    // Safety bound: only fire when peers unanimously converge on one root.
    // If peers disagree among themselves, halt stays manual — ambiguous fork.
    const { unanimous, sourcePeerNodeId } = _isUnanimousMinority(atRound, ourRoot, observed, threshold);
    if (unanimous && sourcePeerNodeId) {
      const RECOVERY_DELAY_MS = CONSENSUS.BYZANTINE_FORK_AUTO_RECOVERY_DELAY_MS || 5000;
      const RECOVERY_COOLDOWN_MS = CONSENSUS.BYZANTINE_FORK_AUTO_RECOVERY_COOLDOWN_MS || 30000;
      const sinceLastMs = Date.now() - _lastAutoRecoveryAt;
      if (_lastAutoRecoveryAt > 0 && sinceLastMs < RECOVERY_COOLDOWN_MS) {
        _log.warn(
          `anti-entropy: unanimous minority at round=${atRound} — auto-recovery cooldown active ` +
          `(${Math.floor(sinceLastMs / 1000)}s since last recovery, cooldown=${RECOVERY_COOLDOWN_MS / 1000}s). ` +
          `Halt remains; retry in ${Math.ceil((RECOVERY_COOLDOWN_MS - sinceLastMs) / 1000)}s.`
        );
        return;
      }
      _log.warn(
        `anti-entropy: majority minority at round=${atRound} — majority of peers hold same ` +
        `alternative root. Scheduling auto-recovery from ${sourcePeerNodeId.slice(-8)} in ${RECOVERY_DELAY_MS}ms.`
      );
      setTimeout(() => _autoRecoverFromMinority(sourcePeerNodeId, atRound), RECOVERY_DELAY_MS);
    }
  }

  /**
   * Auto-recovery path for the unanimous-minority case. Clears the halt,
   * enters sync mode, and installs the majority peer's snapshot — restoring
   * our committed state to what the honest cluster has agreed on.
   *
   * Only fires after unanimous minority detection. Verifies the halt is
   * still present before acting to handle race with manual clearByzantineForkHalt.
   */
  async function _autoRecoverFromMinority(sourceTipNodeId, atRound) {
    if (!narwhal) return;

    const halt = typeof narwhal.byzantineForkHalt === "function" && narwhal.byzantineForkHalt();
    if (!halt) {
      _log.info("anti-entropy: auto-recovery: halt already cleared — skipping");
      return;
    }

    // Resolve libp2p peerId from TIP node_id for snapshot transport.
    let libp2pPeerId = null;
    if (network && typeof network.authorizedPeers === "function") {
      for (const [pid, tipId] of Object.entries(network.authorizedPeers())) {
        if (tipId === sourceTipNodeId) { libp2pPeerId = pid; break; }
      }
    }
    if (!libp2pPeerId) {
      _log.warn(`anti-entropy: auto-recovery: cannot resolve libp2p peerId for ${sourceTipNodeId} — halting manually`);
      return;
    }

    _log.notice(`anti-entropy: auto-recovery: clearing byzantine_fork halt, syncing snapshot from ${libp2pPeerId.slice(0, 12)}`);

    // Clear halt BEFORE enterSyncMode so narwhal can respond to sync transitions.
    if (typeof narwhal.clearByzantineForkHalt === "function") {
      narwhal.clearByzantineForkHalt();
    }
    // Bug 2: clear stale divergence observations so the first AE tick after recovery
    // doesn't immediately re-trigger BYZ_FORK on pre-recovery entries at the same round.
    _clearDivergenceAccumulators();
    // Reset install guard so the recovery snapshot is accepted as a fresh cycle.
    if (snapshotHandler && typeof snapshotHandler.resetInstallState === "function") {
      snapshotHandler.resetInstallState();
    }

    let selfState = {};
    try { selfState = getConsensusState ? getConsensusState() : {}; } catch { /* best-effort */ }

    const result = await _runSnapshotFallback(libp2pPeerId, { snapshotRequired: true, earliestAvailableRound: 0 }, selfState);
    if (result === "snapshot_installed") {
      // Set cooldown only on confirmed success — failed installs must not
      // consume the cooldown window (SI-3 / CI-2).
      _lastAutoRecoveryAt = Date.now();
      _log.notice(`anti-entropy: auto-recovery complete — snapshot installed from ${libp2pPeerId.slice(0, 12)}, resuming consensus`);
    } else {
      _log.warn(`anti-entropy: auto-recovery: snapshot install returned '${result}' — manual intervention may be needed`);
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
      // If we have an active byzantine_fork halt, a cert-gap pull cannot heal
      // the divergence — we committed wrong state at a past round and need a
      // full snapshot resync. The unanimous-minority path (Option B) only fires
      // when peer.committed_round === self.committed_round, but if peers moved
      // on while we were halted, AE never re-detects the divergence and we loop
      // on cert-gap pulls forever. Detect this here and go straight to snapshot.
      const selfByzHalt = narwhal && typeof narwhal.byzantineForkHalt === "function"
        && narwhal.byzantineForkHalt();
      if (selfByzHalt) {
        const RECOVERY_COOLDOWN_MS = CONSENSUS.BYZANTINE_FORK_AUTO_RECOVERY_COOLDOWN_MS || 30000;
        const sinceLastMs = Date.now() - _lastAutoRecoveryAt;
        if (_lastAutoRecoveryAt > 0 && sinceLastMs < RECOVERY_COOLDOWN_MS) {
          _log.warn(
            `anti-entropy: byzantine_fork halt active (committed_round=${selfCommitted}, peer=${peerCommitted}) — ` +
            `cooldown active, retry in ${Math.ceil((RECOVERY_COOLDOWN_MS - sinceLastMs) / 1000)}s`
          );
          return "behind";
        }
        _log.warn(
          `anti-entropy: byzantine_fork halt active at committed_round=${selfCommitted} — ` +
          `peer is ${peerCommitted - selfCommitted} rounds ahead; cert-gap pull cannot heal ` +
          `state divergence, escalating directly to snapshot resync`
        );
        if (typeof narwhal.clearByzantineForkHalt === "function") {
          narwhal.clearByzantineForkHalt();
        }
        const result = await _runSnapshotFallback(
          peerId, { snapshotRequired: true, earliestAvailableRound: 0 }, selfState
        );
        if (result === "snapshot_installed") {
          _lastAutoRecoveryAt = Date.now();
        }
        return result;
      }

      // We're behind. Pull the gap via existing sync protocol. fromRound
      // starts at our next-uncommitted round so we only fetch the delta.
      _log.info(`anti-entropy: behind peer ${peerStatus.node_id || peerId.slice(0, 12)} by ${peerCommitted - selfCommitted} rounds — pulling gap`);

      const fromRound = selfCommitted + 1;
      let syncResult = null;
      try {
        if (syncHandler && typeof syncHandler.syncFromPeer === "function") {
          syncResult = await syncHandler.syncFromPeer(peerId, { fromRound });
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
      // Catch-up race guard, time-bounded. During snapshot install or
      // cert-tail replay, the mirror is being populated in flight and a
      // freshly-computed state_merkle_root briefly reflects partial state
      // — flagging divergence then would false-halt every fresh joiner
      // (verified live 2026-05-06: fresh-DB Node 2 halted itself in
      // joinState=syncing within seconds of restart). So we tolerate
      // mismatch while either side is non-ready... but only briefly.
      //
      // An honest replay that reaches the same committed_round as ours
      // MUST produce the same state_root — that's the consensus invariant.
      // If a non-ready peer's mismatch persists past
      // SYNC_DIVERGENCE_GRACE_MS at the same (committed_round, root)
      // tuple, this is no longer a fresh-joiner race; it's a stuck-
      // byzantine peer that lost its halt flag on restart, or has
      // corrupted state, or hit a deterministic bug. Drop the joinState
      // exemption and treat as real divergence.
      const peerNode = peerStatus.node_id || peerId;
      const peerLabel = peerStatus.node_id || peerId.slice(0, 12);
      const selfJoinState = (narwhal && typeof narwhal.joinState === "function")
        ? String(narwhal.joinState() || "ready")
        : "ready";
      const peerJoinState = String(peerStatus.join_state || "ready");
      if (selfJoinState !== "ready" || peerJoinState !== "ready") {
        const persistent = _persistentDivergence(peerNode, peerJoinState);
        if (!persistent) {
          // Within grace — diagnostic only, don't flag. Logged at debug
          // because this fires every AE tick (~4s) per diverging peer
          // until the grace window closes (~7-8 lines per event), which
          // would flood info.log. The actionable signal is the warn
          // emitted once when grace is exceeded (escalation path below).
          const selfCI = Number(selfState.consensus_index || 0);
          const peerCI = Number(peerStatus.consensus_index || 0);
          _log.debug(
            `anti-entropy: round=${selfCommitted} state-mismatch with peer ${peerLabel} ` +
            `(self.join=${selfJoinState} peer.join=${peerJoinState}, within sync grace) ` +
            `self.root=${selfRoot.slice(0, 16)} peer.root=${peerRoot.slice(0, 16)} ` +
            `self.ci=${selfCI} peer.ci=${peerCI} (delta=${peerCI - selfCI})`
          );
          return "equal";
        }
        // Past grace — fall through to flag as malicious. Log at WARN so
        // ops sees the escalation explicitly (vs the within-grace info).
        _log.warn(
          `anti-entropy: persistent divergence past sync grace with peer ${peerLabel} ` +
          `(peer.join=${peerJoinState}); promoting to byzantine-fork divergence flag`
        );
      }

      // Real divergence — equal round, different roots, both sides ready
      // (or non-ready past sync grace). Byzantine safety event: never
      // auto-resolve (picking a winner silently makes a fork worse).
      // Accumulate distinct-peer disagreements at (round, ourRoot) and
      // halt narwhal once ≥ f+1 peers disagree — that's the formal proof
      // we're the byzantine minority. Until threshold, log + metric so
      // ops can see the disagreement building up.
      _metrics.consensus_divergence_total++;
      _log.warn(`anti-entropy: DIVERGENCE at committed_round=${selfCommitted} with peer ${peerLabel} — self.state_root=${selfRoot.slice(0, 16)} peer.state_root=${peerRoot.slice(0, 16)}`);

      const { observed, threshold } = _recordDivergence(peerNode, selfCommitted, selfRoot, peerRoot);
      if (observed > _metrics.consensus_divergence_distinct_peers) {
        _metrics.consensus_divergence_distinct_peers = observed;
      }
      _maybeHalt(selfCommitted, selfRoot, observed, threshold, peerNode);
      return "divergent";
    }

    // Roots match (or rounds differ): peer is converged or still
    // catching up. Clear any divergence tracker entry so a peer that
    // recovered from a transient race isn't held against the grace
    // window if it ever hits another mismatch later.
    _clearDivergenceTracker(peerStatus.node_id || peerId);

    // Self-healing halt clear. When we're halted with byzantine_fork and
    // this peer's root now matches ours at the same committed_round, check
    // whether ALL known peers agree with our root. If they do, the fork
    // self-healed (minority nodes took our snapshot and converged) and we
    // can safely clear the halt and resume cert production.
    //
    // This is the "majority un-halt" path: minority nodes recover via
    // _isUnanimousMinority → snapshot resync; majority nodes recover here
    // once they observe the minority has converged to their root.
    const selfByzHalt = narwhal && typeof narwhal.byzantineForkHalt === "function" && narwhal.byzantineForkHalt();
    if (selfByzHalt && peerCommitted === selfCommitted && selfRoot && peerRoot && selfRoot === peerRoot) {
      let allConverged = true;
      for (const [, cached] of _lastStatus.entries()) {
        const cachedRoot = String(cached?.state_merkle_root || "");
        const cachedCommitted = Number(cached?.committed_round || 0);
        // Only count peers that are explicitly divergent at this round.
        // Peers with different committed_round or empty root are still syncing
        // — don't let them block halt-clear, they'll re-converge on their own.
        if (cachedCommitted === selfCommitted && cachedRoot && cachedRoot !== selfRoot) {
          allConverged = false;
          break;
        }
      }
      if (allConverged && _lastStatus.size > 0) {
        _log.warn(
          `anti-entropy: byzantine_fork halt at round=${selfCommitted} self-healed — ` +
          `all peers now agree on root=${selfRoot.slice(0, 16)}; clearing halt`
        );
        if (typeof narwhal.clearByzantineForkHalt === "function") {
          narwhal.clearByzantineForkHalt();
        }
        // Bug 2: clear stale observations so the next AE tick doesn't immediately
        // re-trigger BYZ_FORK from the now-resolved pre-convergence entries.
        _clearDivergenceAccumulators(selfCommitted);
        // Restart round production. clearByzantineForkHalt only clears the
        // flag; it does NOT reset _lastRoundAdvanceAt, clear stale _peerBatches,
        // or reschedule _beginRound. Without this, the halt-cleared node's round
        // timer is dead: peers already have the pre-halt batch so dedup-drops
        // the retry rebroadcast, no new acks flow, and the round never advances.
        // exitSyncMode advances _currentRound past the stale halt round, clears
        // stale batch/cert maps, resets the sub_quorum timestamp, and kicks off
        // a fresh _beginRound — mirroring what minority nodes receive via
        // _autoRecoverFromMinority.
        if (typeof narwhal.exitSyncMode === "function") {
          narwhal.exitSyncMode(selfCommitted);
        }
      }
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

    // Halt status surfaces both narwhal's flag and the AE-side accumulator
    // so ops can see "we're at 1/2 disagreements" before the halt fires.
    const haltStatus = (narwhal && typeof narwhal.byzantineForkHalt === "function")
      ? narwhal.byzantineForkHalt()
      : null;
    let observedAtSelf = 0;
    for (const [k, set] of _divergenceObservations.entries()) {
      const [r] = k.split(":");
      if (Number(r) === selfRound) observedAtSelf = Math.max(observedAtSelf, set.size);
    }

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
      byzantine_fork_halt: haltStatus,
      divergence: {
        threshold: _bftHaltThreshold(),
        distinct_peers_observed: observedAtSelf,
        filtered_peers: divergentPeers(),
      },
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Trigger an immediate snapshot resync from the best available authorized
   * peer. Called by bullshark when a deferred anchor timer fires with certs
   * that are permanently missing (paused node produced no certs for those
   * rounds — AE can never pull what was never created).
   *
   * Picks the peer with the highest committed_round from recent AE status
   * cache, falling back to any authorized peer if the cache is empty.
   */
  async function triggerSnapshotResync(fromRound, missingCount) {
    // Guard: if already syncing/catching_up, a snapshot install is in progress.
    // Firing another resync compounds the cert gap instead of healing it —
    // each install jumps forward ~15 rounds, leaving a fresh gap that triggers
    // yet another timeout→resync loop. The current sync will fill the gap.
    const currentState = narwhal && typeof narwhal.joinState === "function" ? narwhal.joinState() : "ready";
    if (currentState === "syncing" || currentState === "catching_up") {
      _log.warn(`anti-entropy: triggerSnapshotResync skipped — already in ${currentState} (round=${fromRound}, missing=${missingCount})`);
      return "already_syncing";
    }

    // Bug 1 — intra-node in-flight guard. Prevents a second concurrent call on
    // this node from racing past the joinState check before the first call has
    // transitioned narwhal into syncing (enterSyncMode fires inside
    // _runSnapshotFallback, not here, so there is a short window after the
    // joinState check where _snapshotResyncInFlight is the only barrier).
    if (_snapshotResyncInFlight) {
      _log.warn(`anti-entropy: triggerSnapshotResync skipped — resync already in flight (round=${fromRound}, missing=${missingCount})`);
      return "already_syncing";
    }

    // Serialization guard: if any peer is currently syncing/catching_up, defer
    // this resync with jitter. With BULLSHARK_DEFER_MS=60s, snapshot resyncs are
    // rare (only genuinely GC'd certs trigger them). If two nodes hit the timer
    // simultaneously anyway, this prevents both from entering syncing at once
    // (which would drop active participants to 3 < quorum=4 and cause sub_quorum).
    // NOTE: _lastStatus is a ~4s-stale cache. A peer that entered syncing <4s ago
    // won't appear here — the fresh-peer queryPeer below catches that case.
    for (const [, s] of _lastStatus.entries()) {
      if (s && (s.joinState === "syncing" || s.joinState === "catching_up")) {
        const jitterMs = 5000 + Math.floor(Math.random() * 10000); // 5-15s
        _log.warn(
          `anti-entropy: triggerSnapshotResync deferred — peer ${(s.node_id || "?").slice(0, 12)} ` +
          `already in ${s.joinState}; retrying in ${Math.round(jitterMs / 1000)}s ` +
          `(round=${fromRound}, missing=${missingCount})`
        );
        setTimeout(() => {
          const st = narwhal && typeof narwhal.joinState === "function" ? narwhal.joinState() : "ready";
          if (st === "ready" && !_snapshotResyncInFlight) triggerSnapshotResync(fromRound, missingCount).catch(() => {});
        }, jitterMs);
        return "deferred";
      }
    }

    _log.warn(
      `anti-entropy: triggerSnapshotResync requested (round=${fromRound}, missing=${missingCount}) ` +
      `— selecting best peer for snapshot pull`
    );

    // Pick the authorized peer with the highest committed_round from the
    // status cache. If cache is stale or empty, fall back to any peer.
    let bestPeerId = null;
    let bestRound = -1;

    let authorizedPeerIds = [];
    try {
      if (network && typeof network.authorizedPeers === "function") {
        authorizedPeerIds = Object.keys(network.authorizedPeers());
      }
    } catch { /* network not ready */ }

    // Map libp2p peerId → last known committed_round via _lastStatus
    for (const peerId of authorizedPeerIds) {
      // _lastStatus keyed by node_id; find matching entry by iterating
      // (cache is small — committee size, typically 5)
      let peerCommitted = 0;
      for (const [, s] of _lastStatus.entries()) {
        // peerStatus objects don't carry libp2p peerId directly; use any
        // peer that is ahead of us as a reasonable choice.
        const cr = Number(s.committed_round || 0);
        if (cr > peerCommitted) peerCommitted = cr;
      }
      if (peerCommitted > bestRound) {
        bestRound = peerCommitted;
        bestPeerId = peerId;
      }
    }

    // If we couldn't identify a best peer, fall back to first authorized peer.
    if (!bestPeerId && authorizedPeerIds.length > 0) {
      bestPeerId = authorizedPeerIds[0];
    }

    if (!bestPeerId) {
      _log.warn(`anti-entropy: triggerSnapshotResync: no authorized peers available — cannot resync`);
      return "no_peers";
    }

    _log.info(`anti-entropy: triggerSnapshotResync: pulling snapshot from ${bestPeerId.slice(0, 12)} (cached_round=${bestRound})`);

    // Bug 1 — fresh peer query. The _lastStatus cache is up to 4s stale. Two nodes
    // can simultaneously fire triggerSnapshotResync (12ms apart from the same deferred
    // anchor timer), both see each other as "ready" in the stale cache, both proceed,
    // pull from different peers, install different roots → BYZ_FORK. A live RPC to the
    // selected peer verifies it is genuinely ready before we commit to entering sync
    // mode. If the peer just entered syncing (caught by the fresh status), defer with
    // jitter so only one node syncs at a time.
    const freshPeerStatus = await queryPeer(bestPeerId);
    if (freshPeerStatus) {
      const freshJoinState = freshPeerStatus.join_state || "ready";
      if (freshJoinState === "syncing" || freshJoinState === "catching_up") {
        const jitterMs = 8000 + Math.floor(Math.random() * 12000); // 8-20s
        _log.warn(
          `anti-entropy: triggerSnapshotResync: fresh-check found peer ${bestPeerId.slice(0, 12)} ` +
          `in ${freshJoinState} — deferring ${Math.round(jitterMs / 1000)}s to avoid simultaneous sync`
        );
        setTimeout(() => {
          const st = narwhal && typeof narwhal.joinState === "function" ? narwhal.joinState() : "ready";
          if (st === "ready" && !_snapshotResyncInFlight) triggerSnapshotResync(fromRound, missingCount).catch(() => {});
        }, jitterMs);
        return "deferred";
      }
    }

    let selfState = {};
    try { selfState = getConsensusState ? getConsensusState() : {}; } catch { /* best-effort */ }

    if (typeof snapshotHandler.resetInstallState === "function") {
      snapshotHandler.resetInstallState();
    }

    _snapshotResyncInFlight = true;
    try {
      const result = await _runSnapshotFallback(bestPeerId, { snapshotRequired: true, earliestAvailableRound: 0 }, selfState);
      if (result === "snapshot_installed") {
        _lastAutoRecoveryAt = Date.now();
        _lastSnapshotResyncCompletedAt = Date.now();
        _log.notice(`anti-entropy: triggerSnapshotResync complete — snapshot installed, resuming consensus`);
      } else {
        _log.warn(`anti-entropy: triggerSnapshotResync: snapshot install returned '${result}'`);
      }
      return result;
    } finally {
      _snapshotResyncInFlight = false;
    }
  }

  function isSnapshotResyncThrottled() {
    return _lastSnapshotResyncCompletedAt > 0 &&
      (Date.now() - _lastSnapshotResyncCompletedAt) < SNAPSHOT_RESYNC_COOLDOWN_MS;
  }

  return {
    start,
    stop,
    getStatus,
    queryPeer,
    checkAndReconcile,
    registerProtocol,
    isPeerDivergent,
    peerJoinState,
    divergentPeers,
    triggerSnapshotResync,
    isSnapshotResyncThrottled,
    _handleIncomingSyncStatus,
    // Exposed for metrics scraping + tests.
    stats: () => ({ metrics: { ..._metrics }, last_status_size: _lastStatus.size }),
    SYNC_STATUS_PROTOCOL,
  };
}

module.exports = { createAntiEntropy };
