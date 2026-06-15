/**
 * @file @tip-protocol/node/src/services/media-access-policy.js
 * @description Pure predicate: "is this TIP-ID currently allowed to read
 * media for this ctid?" Used by media-service.fetchForReviewer before any
 * bytes are streamed or any presigned URL is minted.
 *
 * Allowed roles (in priority order):
 *
 *   author             — requester == content.signer_tip_id (creator
 *                        viewing their own media; always allowed)
 *   assigned_reviewer  — requester == prescan_reviews.assigned_reviewer
 *                        AND review state is currently open
 *                        (TRIGGERED / CONFIRMED)
 *   disputer           — requester filed a CONTENT_DISPUTED tx on this
 *                        ctid (dispute is open or resolved — either way,
 *                        they had standing)
 *
 * Everyone else → { ok: false, code: "forbidden" }. The role string is
 * surfaced upstream so it can land on access logs / S3 bucket logs (when
 * operators enable them at the storage layer).
 *
 * No DAG mutations, no IO, no clocks beyond `dag.*` lookups — the
 * predicate is fully testable as a pure function of (dag-snapshot,
 * ctid, requester_tip_id).
 *
 * NOTE: juror + expert-reviewer paths are scaffolded but commented out
 * until the dispute-committee / appeal-assignment schemas land. Adding a
 * role is a one-line append here once the corresponding dag lookup exists.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { PRESCAN_REVIEW_STATES, TX_TYPES } = require("../../../shared/constants");

const OPEN_REVIEW_STATES = new Set([
  PRESCAN_REVIEW_STATES.TRIGGERED,
  PRESCAN_REVIEW_STATES.CONFIRMED,
]);

// Stage-2 juror has a non-appeal JURY_SUMMONS; Stage-3 expert has an
// appeal JURY_SUMMONS. The is_appeal flag on the tx distinguishes them.
function _hasSummons(dag, ctid, requesterTipId, isAppeal) {
  if (typeof dag.getTxsByTypeAndCtid !== "function") return false;
  return dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid)
    .some(tx => tx.data?.juror_tip_id === requesterTipId
             && !!tx.data?.is_appeal === !!isAppeal);
}

// Panel is "open" while no terminal tx has landed. Stage-2 closes on
// ADJUDICATION_RESULT; Stage-3 closes on APPEAL_RESULT. The juror's job
// (vote commit + reveal + rationale) ships before the terminal tx, so
// cutting access at terminal-tx is the right gate.
function _panelOpen(dag, ctid, terminalTxType) {
  if (typeof dag.getTxsByTypeAndCtid !== "function") return true;
  return dag.getTxsByTypeAndCtid(terminalTxType, ctid).length === 0;
}

function canAccessMedia(dag, ctid, requesterTipId) {
  const content = dag.getContent(ctid);
  if (!content) return { ok: false, code: "content_not_found", status: 404 };

  if (content.signer_tip_id === requesterTipId) {
    return { ok: true, role: "author" };
  }

  const openReview = typeof dag.getOpenPrescanReviewByCtid === "function"
    ? dag.getOpenPrescanReviewByCtid(ctid)
    : null;
  if (openReview
    && openReview.assigned_reviewer === requesterTipId
    && OPEN_REVIEW_STATES.has(openReview.state)) {
    return { ok: true, role: "assigned_reviewer" };
  }

  if (typeof dag.hasDispute === "function" && dag.hasDispute(ctid, requesterTipId)) {
    return { ok: true, role: "disputer" };
  }

  if (_hasSummons(dag, ctid, requesterTipId, /* isAppeal */ false)
      && _panelOpen(dag, ctid, TX_TYPES.ADJUDICATION_RESULT)) {
    return { ok: true, role: "juror" };
  }

  if (_hasSummons(dag, ctid, requesterTipId, /* isAppeal */ true)
      && _panelOpen(dag, ctid, TX_TYPES.APPEAL_RESULT)) {
    return { ok: true, role: "expert_reviewer" };
  }

  return { ok: false, code: "forbidden", status: 403 };
}

module.exports = { canAccessMedia };
