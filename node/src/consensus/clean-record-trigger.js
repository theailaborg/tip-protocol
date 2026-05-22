/**
 * @file @tip-protocol/node/src/consensus/clean-record-trigger.js
 * @description Clean-record bonus trigger — fires once per UTC day (as
 * measured by `cert.timestamp`), proposing a SCORE_UPDATE batch for every
 * identity that has been clean for `REPUTATION.CLEAN_PERIOD_DAYS`.
 *
 * Replaces the scheduler's wall-clock-driven `clean-record` task. Same
 * eligibility query (`dag.getCleanRecordEligible`), same SCORE_UPDATE
 * shape — only the trigger source changes. Driven by post-round
 * commit-handler using BFT-Time so the day-boundary check is
 * deterministic across all nodes.
 *
 * Cost reduction:
 *   Without leader gating, every node would emit the same daily batch
 *   (N-fold mempool flood per day). With day-modulo leader gating, only
 *   one node per day emits. If today's leader is offline, the next day's
 *   leader runs the same eligibility query — the cumulative "90 days
 *   clean since last offense" predicate naturally catches missed
 *   identities, so worst-case bonus delivery is one day late.
 *
 * Boundary contract:
 *   commit-handler invokes `checkPending(certTimestamp)` once per round
 *   after Phase 2 (alongside `verdict-trigger.checkPending`). 99.99% of
 *   calls hit a one-line same-day fast path with no DB. Once cert.ts
 *   crosses a UTC day boundary AND we are today's leader, we run the
 *   eligibility query, build a batch, submit through consensus mempool.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { REPUTATION } = require("../../../shared/protocol-constants");
const { toIso } = require("../../../shared/time");
const { getLogger } = require("../logger");

const log = getLogger("tip.clean-record-trigger");

const MS_PER_DAY = 86400000;

function _dayOfEpoch(ms) {
  return Math.floor(ms / MS_PER_DAY);
}

/**
 * @param {Object} deps
 * @param {Object}   deps.dag           DAG store (for `getCleanRecordEligible` + `isRevoked`)
 * @param {Object}   deps.scoring       Scoring engine (for `buildScoreUpdateTx`)
 * @param {Object}   deps.config        Node config (signs the SCORE_UPDATE txs)
 * @param {Function} deps.submitBatch   Consensus batch submitter
 * @param {Function} [deps.getCommittee] () => string[]  Sorted active node_ids.
 *   Used for day-modulo leader gating. Without it, every node fires
 *   (legacy behaviour — fine at small federation scale).
 */
function createCleanRecordTrigger({ dag, scoring, config, submitBatch, getCommittee }) {
  if (!dag) throw new Error("clean-record-trigger: dag required");

  const _myNodeId = config?.nodeRegisteredId || config?.nodeId;

  // Day-of-epoch of the most recent cert.timestamp we've already scanned.
  // 0 on boot, so the first round after start triggers a scan if we're
  // today's leader. Process-local (not persisted): a fresh node will
  // re-scan on first round even if another node already scanned today.
  // Same first-wins dedup at commit-time catches duplicates by
  // `(tip_id, ctid=null, reason="clean_record_bonus")`.
  let _lastScannedDay = 0;

  /**
   * Day-modulo leader gate. Returns true if this node is the
   * deterministic leader for the given UTC day. Without `getCommittee`
   * wired, defaults to true (every node fires).
   */
  function _isMyDay(dayOfEpoch) {
    if (typeof getCommittee !== "function") return true;
    const committee = getCommittee();
    if (!Array.isArray(committee) || committee.length === 0) return true;
    const sorted = [...committee].sort();
    const idx = Math.abs(Math.trunc(dayOfEpoch)) % sorted.length;
    return sorted[idx] === _myNodeId;
  }

  /**
   * Run the eligibility query if cert.ts has crossed a day boundary
   * since our last scan AND we are today's leader.
   */
  function checkPending(certTimestamp) {
    if (!Number.isFinite(certTimestamp) || certTimestamp <= 0) return;
    if (!scoring || !config || typeof submitBatch !== "function") return;

    const today = _dayOfEpoch(certTimestamp);
    if (today <= _lastScannedDay) return;
    _lastScannedDay = today;

    if (!_isMyDay(today)) return;

    const cutoffMs = certTimestamp - REPUTATION.CLEAN_PERIOD_DAYS * MS_PER_DAY;

    let eligible;
    try {
      eligible = dag.getCleanRecordEligible(cutoffMs)
        .filter(tipId => !dag.isRevoked(tipId));
    } catch (err) {
      log.warn(`Clean-record eligibility query failed: ${err.message}`);
      return;
    }

    if (eligible.length === 0) return;

    const proposedTimestamp = certTimestamp;
    // Window-scoped reason. The bonus is recurring (every CLEAN_PERIOD_DAYS),
    // so a constant `"clean_record_bonus"` reason would collide forever
    // under the (tip_id, ctid, reason) dedup at commit-handler — only the
    // first window's bonus would ever land. Embedding the trigger-day's
    // ISO date scopes the dedup naturally per day:
    //   - Same node firing twice on the same day  → same reason → dedup ✓
    //   - Two nodes firing on the same day        → same BFT-time-derived
    //     day → same reason → second one rejected ✓ (multi-leader race)
    //   - Same user on a later day (next window)  → different reason →
    //     accepted, predicate's window check is the actual eligibility gate.
    const todayISO = toIso(today * MS_PER_DAY).slice(0, 10);
    const reason = `clean_record_bonus:${todayISO}`;
    const txs = eligible.map(tipId => scoring.buildScoreUpdateTx({
      tipId,
      delta: REPUTATION.CLEAN_PERIOD_BONUS,
      reason,
      ctid: null,
      relatedTxId: null,
      timestamp: proposedTimestamp,
      getRecentPrev: () => dag.getRecentPrev(),
      config,
    }));

    try {
      submitBatch(txs);
      log.info(`Clean-record bonus proposed: ${eligible.length} identities (+${REPUTATION.CLEAN_PERIOD_BONUS} each)`);
    } catch (err) {
      // Mempool already has the same batch (peer beat us) or consensus
      // is halted. Next day's scan retries; first-wins dedup at commit
      // handles overlap.
      log.debug(`Clean-record batch submission deferred: ${err?.error || err?.message || err}`);
    }
  }

  /** Test/diagnostic accessor. */
  function lastScannedDay() {
    return _lastScannedDay;
  }

  return { checkPending, lastScannedDay };
}

module.exports = { createCleanRecordTrigger };
