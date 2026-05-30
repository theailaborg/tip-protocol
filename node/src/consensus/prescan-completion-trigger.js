/**
 * @file @tip-protocol/node/src/consensus/prescan-completion-trigger.js
 * @description Failover trigger for stuck async prescans. Runs at the
 * end of each round (same pattern as prescan-review-trigger.js): when
 * content has been sitting in prescan_status='pending' past the genesis
 * fail-open deadline, a deterministic round-modulo leader emits a
 * synthesised PRESCAN_COMPLETED with failed=true so the content can't
 * sit in PENDING_PRESCAN forever.
 *
 * Why a separate trigger and not just the worker:
 *
 *   - The prescan_jobs queue is node-local. If the API node that
 *     received the registration dies (or its worker dies + can't be
 *     restarted), the job blob is lost — other nodes can't re-classify
 *     because they don't have the text body (REGISTER_CONTENT carries
 *     only content_hash).
 *   - This trigger doesn't try to re-classify. It just emits a clean
 *     fail-open so downstream consumers (h=48 reviewer trigger, dispute
 *     gates, dashboard) can finally see the content.
 *
 * Determinism: round-modulo leader picks one emitter per round. Other
 * nodes' duplicate emissions are caught by commit-handler's first-wins
 * dedup on (PRESCAN_COMPLETED, ctid). The original assignee's worker —
 * if it ever revives and finishes — also gets dedup'd by the same rule.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { computeTxId, signTransaction } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { TX_TYPES } = require("../../../shared/constants");
const { PRESCAN_WORKER } = require("../../../shared/protocol-constants");
const { getLogger } = require("../logger");

const log = getLogger("tip.prescan-completion-trigger");

/**
 * @param {Object} deps
 * @param {Object}   deps.dag           DAG store (provides getContentsStuckInPrescan + getRecentPrev).
 * @param {Object}   deps.config        Node config (signs node-emitted txs).
 * @param {Function} deps.submitTx      Consensus tx submitter.
 * @param {Function} [deps.getCommittee] (round) => string[]  Active node_ids.
 *   Round-modulo leader gating; defaults to "every node fires" when omitted
 *   (same fall-through as the other consensus triggers).
 */
function createPrescanCompletionTrigger({ dag, config, submitTx, getCommittee }) {
  if (!dag) throw new Error("prescan-completion-trigger: dag required");

  const _myNodeId = config?.nodeRegisteredId || config?.nodeId;
  const _nodePrivateKey = config?.nodePrivateKey;

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
    if (!config || typeof submitTx !== "function") return;
    if (!_nodePrivateKey || !_myNodeId) return;
    if (Number.isFinite(round) && !_isMyRoundLeader(round)) return;

    _emitFailOpenCompletions(certTimestamp, round);
  }

  function _emitFailOpenCompletions(certTimestamp, round) {
    const cutoff = certTimestamp - PRESCAN_WORKER.FAIL_OPEN_AFTER_MS;
    let stuck;
    try {
      stuck = dag.getContentsStuckInPrescan(cutoff);
    } catch (err) {
      log.warn(`getContentsStuckInPrescan failed: ${err.message}`);
      return;
    }
    if (!stuck || stuck.length === 0) return;

    for (const content of stuck) {
      try {
        const tx = _buildFailOpenTx({ ctid: content.ctid, contentType: content.prescan_content_type });
        try {
          submitTx(tx);
          log.warn(
            `Fail-open PRESCAN_COMPLETED emitted for ${content.ctid} ` +
            `(stuck ${certTimestamp - content.registered_at}ms past registered_at, round=${round})`,
          );
        } catch (err) {
          const reason = err?.error || err?.message || String(err);
          log.debug(`Fail-open submit deferred for ${content.ctid}: ${reason}`);
        }
      } catch (err) {
        log.warn(`Fail-open build failed for ${content.ctid}: ${err.message}`);
      }
    }
  }

  function _buildFailOpenTx({ ctid, contentType }) {
    const completedAt = nowMs();
    const txBody = {
      tx_type: TX_TYPES.PRESCAN_COMPLETED,
      timestamp: completedAt,
      prev: dag.getRecentPrev(),
      data: {
        ctid,
        probability: 0,
        tier: "low",
        flagged: false,
        overall_degraded: false,           // silent fail-open: don't surface as degraded
        content_type: contentType || "multi",
        content_type_meta: {
          hint_provided: null,
          resolution: "fail_open",
          reason: "prescan_pending_past_fail_open_deadline",
        },
        modality_results: [],
        classifier_version: "unknown",
        classifier_providers_used: "fail_open_failover",
        completed_at: completedAt,
        node_id: _myNodeId,
        failed: true,
        failure_reason: "prescan_pending_past_fail_open_deadline",
      },
    };
    txBody.tx_id = computeTxId(txBody);
    return signTransaction(txBody, _nodePrivateKey);
  }

  return { checkPending };
}

module.exports = { createPrescanCompletionTrigger };
