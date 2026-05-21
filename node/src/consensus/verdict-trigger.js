/**
 * @file @tip-protocol/node/src/consensus/verdict-trigger.js
 * @description Post-round verdict trigger — owns the pending-deadlines
 * heap and decides when to submit verdict batches based on BFT-Time.
 *
 * Replaces the scheduler's `verdict-check` poll (Commit 2 of #13/#15).
 * Triggered by Bullshark round commits via `commit-handler`'s post-round
 * hook, using `cert.timestamp` as the deterministic clock. Idle networks
 * pay zero DB cost; busy networks pay one query per verdict, not per round.
 *
 * Boundary contract:
 *
 *   commit-handler invokes this module at exactly two points:
 *
 *     1. `onTxCommitted(tx)` — called per applied tx in
 *         `_applyDerivedState`. Updates heap state for verdict-relevant
 *         tx types: pushes a deadline entry on `JURY_SUMMONS`, drops the
 *         resolved entry on `ADJUDICATION_RESULT` / `APPEAL_RESULT` /
 *         `APPEAL_FILED`. No-op for anything else.
 *
 *     2. `checkPending(certTimestamp)` — called once at end of
 *         `commitOrderedTxs` (post Phase 2). Walks heap.peek() while
 *         the smallest deadline has been crossed by cert.timestamp;
 *         pops each entry, builds the verdict batch via the jury
 *         builders, and submits it through consensus mempool. Verdict
 *         txs go through Bullshark like any other; commit-handler's
 *         first-wins guards drop duplicates from racing nodes.
 *
 * Determinism:
 *
 *   - All N nodes' commit-handlers run this in lockstep on the same
 *     committed state and the same `cert.timestamp` (median of the
 *     anchor cert's acks.signed_at). Each node's heap is identical;
 *     each builds the same verdict batch (modulo per-node signatures
 *     and prev — which is fine, since first-wins guards dedup at commit).
 *
 *   - `submitBatch` may throw if the mempool already holds an identical
 *     tx (peer beat us). That's expected and not an error — we log debug
 *     and continue. The next round's check will see the verdict already
 *     committed and skip via the idempotency guard.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES } = require("../../../shared/constants");
const { JURY, APPEAL } = require("../../../shared/protocol-constants");
const { createPendingDeadlines } = require("./pending-deadlines");
const { getLogger } = require("../logger");

const log = getLogger("tip.verdict-trigger");

// Dev-only escape hatch — pairs with the validator-side bypass in
// business-rules.js. When set, `checkPending` ignores the heap's
// reveal_deadline so verdicts fire as soon as reveals land, instead of
// waiting out the on-chain (immutable) deadline. Identical predicate runs
// on every node, so leader gating + idempotency guard still hold.
function _devBypassVoteWindows() {
  return process.env.NODE_ENV !== "production"
      && process.env.TIP_DEV_BYPASS_VOTE_WINDOWS === "1";
}

/**
 * Convert a JURY_SUMMONS reveal_deadline (ISO string) to integer epoch ms.
 * Returns 0 on invalid input — caller skips the entry.
 */
function _parseDeadline(iso) {
  if (typeof iso !== "string" || !iso) return 0;
  const ms = iso;
  return Number.isFinite(ms) && ms > 0 ? ms : 0;
}

/**
 * @param {Object} deps
 * @param {Object}   deps.dag
 * @param {Object}   deps.jury          { buildAdjudicationBatch, buildAppealBatch }
 * @param {Object}   deps.scoring       Scoring engine — passed through to jury builders
 * @param {Object}   deps.config        Node config — passed through to jury builders
 * @param {Function} deps.submitBatch   (txs) => void  Consensus batch submitter
 * @param {Function} [deps.getCommittee] (round) => string[]  Sorted active node_ids.
 *   Used for round-modulo leader gating: only the round's leader emits the
 *   verdict batch, cutting per-verdict mempool flood from N-fold (every node
 *   submits) to K-fold (one batch per round until the verdict commits, where
 *   K = rounds until commit, typically 2-3). Without this dep, every node
 *   fires (legacy behaviour, fine at small federation scale).
 */
function createVerdictTrigger({ dag, jury, scoring, config, submitBatch, getCommittee }) {
  if (!dag) throw new Error("verdict-trigger: dag required");

  const _myNodeId = config?.nodeRegisteredId || config?.nodeId;

  const _heap = createPendingDeadlines();

  // Rehydration runs once on explicit `rehydrate()` call (caller-driven).
  // consensus/index.js invokes it at consensus init so the heap reflects
  // any disputes that committed before this process started.
  let _rehydrated = false;

  // Track which (ctid, stage) keys have a heap entry to avoid pushing
  // duplicate deadlines when multiple JURY_SUMMONS for the same dispute
  // arrive (one per juror in the same batch). Values stay set even after
  // pop, but `removeByCtid` cleans up on resolution. The size of this
  // set is bounded by concurrent disputes — same scale as the heap.
  const _tracked = new Set();
  const _key = (ctid, stage) => `${stage}:${ctid}`;

  /**
   * Boot rehydration — scan the DAG for committed JURY_SUMMONS that have
   * no matching resolution (ADJUDICATION_RESULT / APPEAL_RESULT) and no
   * superseding APPEAL_FILED, then seed the heap. Idempotent.
   */
  function _rehydrateOnce() {
    if (_rehydrated) return;
    _rehydrated = true;

    if (typeof dag.getTxsByType !== "function") return;

    try {
      const resolved = new Set();

      for (const t of dag.getTxsByType(TX_TYPES.ADJUDICATION_RESULT)) {
        if (t.data?.ctid) resolved.add(_key(t.data.ctid, "jury"));
      }
      for (const t of dag.getTxsByType(TX_TYPES.APPEAL_RESULT)) {
        if (t.data?.ctid) resolved.add(_key(t.data.ctid, "appeal"));
      }
      // APPEAL_FILED supersedes the jury stage — drop the jury deadline
      // so the post-round check doesn't re-fire it.
      for (const t of dag.getTxsByType(TX_TYPES.APPEAL_FILED)) {
        if (t.data?.ctid) resolved.add(_key(t.data.ctid, "jury"));
      }

      let pushed = 0;
      for (const s of dag.getTxsByType(TX_TYPES.JURY_SUMMONS)) {
        const ctid = s.data?.ctid;
        if (!ctid) continue;
        const stage = s.data?.is_appeal ? "appeal" : "jury";
        const key = _key(ctid, stage);
        if (resolved.has(key) || _tracked.has(key)) continue;
        const deadline = _parseDeadline(s.data?.reveal_deadline);
        if (!deadline) continue;
        _heap.push({ deadline, ctid, stage });
        _tracked.add(key);
        pushed++;
      }

      if (pushed > 0) {
        log.info(`Rehydrated ${pushed} pending verdict deadline${pushed === 1 ? "" : "s"} from DAG`);
      }
    } catch (err) {
      log.warn(`Heap rehydration failed: ${err.message}`);
    }
  }

  /**
   * Update heap state for a freshly-committed tx. Called from
   * commit-handler's `_applyDerivedState` for the tx types listed below;
   * a no-op for anything else.
   */
  function onTxCommitted(tx) {
    if (!tx || !tx.tx_type) return;
    const d = tx.data || {};
    if (!d.ctid) return;

    switch (tx.tx_type) {
      case TX_TYPES.JURY_SUMMONS: {
        const stage = d.is_appeal ? "appeal" : "jury";
        const key = _key(d.ctid, stage);
        if (_tracked.has(key)) return;  // already have a deadline entry for this (ctid, stage)
        const deadline = _parseDeadline(d.reveal_deadline);
        if (!deadline) return;
        _heap.push({ deadline, ctid: d.ctid, stage });
        _tracked.add(key);
        return;
      }

      case TX_TYPES.ADJUDICATION_RESULT: {
        const key = _key(d.ctid, "jury");
        _heap.removeByCtid(d.ctid, "jury");
        _tracked.delete(key);
        return;
      }

      case TX_TYPES.APPEAL_RESULT: {
        const key = _key(d.ctid, "appeal");
        _heap.removeByCtid(d.ctid, "appeal");
        _tracked.delete(key);
        return;
      }

      case TX_TYPES.APPEAL_FILED: {
        // Jury stage is over — drop its deadline so we don't re-check it.
        const key = _key(d.ctid, "jury");
        _heap.removeByCtid(d.ctid, "jury");
        _tracked.delete(key);
        return;
      }

      default:
        return;
    }
  }

  /**
   * Post-round trigger. Walks the heap top while its deadline is at or
   * below `certTimestamp`, pops each entry, and submits a verdict batch
   * for it via consensus mempool. Idempotency guard skips ctids that
   * already have a matching result in the DAG (e.g. another node beat
   * us to it on a previous round).
   *
   * Bullshark commits between rounds are sub-second, so the loop here is
   * tight — most rounds don't enter it (peek().deadline > cert.ts), and
   * when they do, only ripe entries get popped.
   */
  /**
   * Round-modulo leader gate. Returns true if this node is the
   * deterministic leader for the given round (so we should fire the
   * verdict batch). When `getCommittee` isn't wired (legacy callers),
   * defaults to true so every node fires — that's the original
   * pre-leader-gate behaviour and still correct via first-wins dedup.
   */
  // Bypass-mode "ready" signal: enough unique-juror reveals committed to
  // reach quorum. Replaces the deadline gate — without it, a freshly-summoned
  // dispute fires NO_QUORUM auto-escalation before any reveals can land,
  // emitting orphan expert summons (since APPEAL_FILED with a non-tip-id
  // appellant fails canFileAppeal at deliver-time). Same dedup discipline
  // as the verdict tally so ill-formed duplicate reveals can't satisfy quorum.
  function _quorumReachedFor(entry) {
    const isAppeal = entry.stage === "appeal";
    const reveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, entry.ctid)
      .filter(r => !!r.data?.is_appeal === isAppeal);
    const uniqueJurors = new Set();
    for (const r of reveals) {
      const id = r?.data?.juror_tip_id;
      if (id) uniqueJurors.add(id);
    }
    const required = isAppeal ? APPEAL.MIN_VOTES : JURY.QUORUM;
    return uniqueJurors.size >= required;
  }

  function _isMyRoundLeader(round) {
    if (typeof getCommittee !== "function") return true;
    const committee = getCommittee(round);
    if (!Array.isArray(committee) || committee.length === 0) return true;
    const sorted = [...committee].sort();
    const idx = Math.abs(Math.trunc(round)) % sorted.length;
    return sorted[idx] === _myNodeId;
  }

  function checkPending(certTimestamp, round) {
    if (!Number.isFinite(certTimestamp) || certTimestamp <= 0) return;
    if (!jury || !scoring || !config || typeof submitBatch !== "function") return;

    // Leader gate — skip if I'm not this round's deterministic leader.
    // Bullshark commits anchors every wave (~2 rounds), so even with the
    // gate, K leaders may fire the same verdict before commit-handler's
    // first-wins dedup catches it; K is bounded by rounds-until-commit.
    if (Number.isFinite(round) && !_isMyRoundLeader(round)) return;

    // Dev bypass changes the "ready to fire" signal from "deadline passed"
    // to "quorum reached" — that way we don't fire NO_QUORUM auto-escalation
    // on a fresh dispute just because the deadline gate is disabled. Heap is
    // ordered by deadline, irrelevant under bypass, so we walk a snapshot
    // and pull entries by ctid instead of pop-from-top.
    const bypass = _devBypassVoteWindows();
    const eligible = bypass
      ? _heap.snapshot().filter(e => _quorumReachedFor(e))
      : null;
    let bypassIdx = 0;

    let fired = 0;
    while (true) {
      let top;
      if (bypass) {
        if (bypassIdx >= eligible.length) break;
        top = eligible[bypassIdx++];
        if (!_heap.removeByCtid(top.ctid, top.stage)) continue;
      } else {
        top = _heap.peek();
        if (!top || top.deadline > certTimestamp) break;
        _heap.pop();
      }
      _tracked.delete(_key(top.ctid, top.stage));

      try {
        // Idempotency — another node may have already landed the verdict.
        const resultType = top.stage === "appeal"
          ? TX_TYPES.APPEAL_RESULT
          : TX_TYPES.ADJUDICATION_RESULT;
        if (dag.getTxsByTypeAndCtid(resultType, top.ctid).length > 0) continue;

        // For the jury stage, an APPEAL_FILED also supersedes — skip.
        if (top.stage === "jury"
          && dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, top.ctid).length > 0) continue;

        // Pull reveals + summons for this dispute, filtered by stage.
        const isAppeal = top.stage === "appeal";
        const summons = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, top.ctid)
          .filter(s => !!s.data?.is_appeal === isAppeal);
        if (summons.length === 0) continue;

        const reveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, top.ctid)
          .filter(r => !!r.data?.is_appeal === isAppeal);

        const batch = isAppeal
          ? jury.buildAppealBatch(top.ctid, reveals, summons, dag, scoring, config)
          : jury.buildAdjudicationBatch(top.ctid, reveals, summons, dag, scoring, config);

        if (!batch || !Array.isArray(batch.txs) || batch.txs.length === 0) continue;

        try {
          submitBatch(batch.txs);
          fired++;
          log.info(`Verdict proposed for ${top.ctid} (${top.stage} → ${batch.verdict}) — ${batch.txs.length} txs in batch`);
        } catch (err) {
          // Mempool may reject as duplicate (peer beat us), or consensus
          // is halted — either way, NOT fatal: next round's check will
          // see the result land or retry.
          const reason = err?.error || err?.message || String(err);
          log.warn(`Verdict batch submission deferred for ${top.ctid} (${top.stage}): ${reason}`);
        }
      } catch (err) {
        log.warn(`Verdict trigger failed for ${top.ctid} (${top.stage}): ${err.message}`);
      }
    }

    return fired;
  }

  // ─── Test / diagnostic surface ─────────────────────────────────────────

  /** Force the heap rehydration scan (used by tests + ops endpoints). */
  function rehydrate() {
    return _rehydrateOnce();
  }

  /** Snapshot of current heap entries — for tests + dashboards. */
  function pending() {
    return _heap.snapshot();
  }

  /** Heap size — O(1). */
  function size() {
    return _heap.size();
  }

  return { onTxCommitted, checkPending, rehydrate, pending, size };
}

module.exports = { createVerdictTrigger };
