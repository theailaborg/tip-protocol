/**
 * @file @tip-protocol/node/src/tx-attribution.js
 * @description Single source of truth for "which tip_id(s) does this tx
 * belong to" for activity-feed / outcome-endpoint purposes.
 *
 * Returns EVERY tip_id the user-facing question "show me txs that involve me"
 * should surface — broader than score-effects' `scoreTargetTipId` (which only
 * returns score-affecting subjects). For most txs that is a single party; for
 * multi-party disputes/appeals it is BOTH (or all three) parties, so the
 * counterparty also sees the lifecycle event in their feed (#40).
 *
 * Used by:
 *   - dag.saveTx        → indexes the tx under every subject (tx_subjects)
 *   - dag.saveMempoolTx → indexes the pending tx under every subject
 *   - dag.saveTxRejection (via tx-rejection-sink) → indexes the rejection
 *   - getActivity (identity-service) → unions all three sources
 *
 * When a tx genuinely has no individual subject (org/system-level:
 * VP_REGISTERED, NODE_REGISTERED, AI_CLASSIFIER_RESULT, auto-cascade
 * CONTENT_DISPUTED) the array is empty and the tx never appears in any
 * user's activity feed (correct — it's not "theirs").
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES } = require("../../shared/constants");

// Drop falsy entries and de-duplicate while preserving order (the first
// element is the primary actor — kept stable for the legacy single-value
// `subject_tip_id` column via subjectTipId()).
function _clean(ids) {
  const out = [];
  for (const id of ids) {
    if (id && !out.includes(id)) out.push(id);
  }
  return out;
}

/**
 * Every tip_id this tx should surface to, primary actor first.
 *
 * Multi-party txs (#40) return both/all parties so a dispute or appeal shows
 * up in the feed of everyone it concerns, not just the actor who filed it.
 *
 * @param {Object} tx  Validated transaction
 * @returns {string[]}  Deduped tip_ids (possibly empty)
 */
function subjectTipIds(tx) {
  if (!tx || !tx.data) return [];
  const d = tx.data;
  switch (tx.tx_type) {

    // ── Subject IS the tip_id (self-affecting txs) ──────────────────────
    case TX_TYPES.REGISTER_IDENTITY:
    case TX_TYPES.SCORE_UPDATE:
    case TX_TYPES.LINK_PLATFORM:
    case TX_TYPES.UNLINK_PLATFORM:
    case TX_TYPES.UPDATE_DEVICE_BINDING:
    case TX_TYPES.REVOKE_VOLUNTARY:
    case TX_TYPES.REVOKE_VP:
    case TX_TYPES.REVOKE_DECEASED:
    case TX_TYPES.REVOKE_DEVICE:
    case TX_TYPES.KEY_ROTATED:
    case TX_TYPES.KEY_RECOVERY:
    case TX_TYPES.UPDATE_PROFILE:
    case TX_TYPES.BIND_DOMAIN:   // d.tip_id is the claimant identity
      return _clean([d.tip_id]);

    // ── Author actions on owned content ─────────────────────────────────
    case TX_TYPES.REGISTER_CONTENT:
      // CNA-2.2: signer_tip_id is the canonical field; in self-attribution
      // mode the signer is the author.
      return _clean([d.signer_tip_id]);
    case TX_TYPES.UPDATE_ORIGIN:
    case TX_TYPES.CONTENT_RETRACTED:
      return _clean([d.author_tip_id]);

    // ── Active-role single-party txs — actor is the subject ─────────────
    case TX_TYPES.CONTENT_VERIFIED:
      return _clean([d.verifier_tip_id]);
    case TX_TYPES.JURY_VOTE_COMMIT:
    case TX_TYPES.JURY_VOTE_REVEAL:
    case TX_TYPES.JURY_SUMMONS:
      return _clean([d.juror_tip_id]);

    // ── Multi-party: prescan reviews ────────────────────────────────────
    // A reviewer reviews a creator's content; both see the review lifecycle.
    case TX_TYPES.PRESCAN_REVIEW_TRIGGERED:
      return _clean([d.assigned_reviewer_tip_id, d.creator_tip_id]);
    case TX_TYPES.PRESCAN_REVIEW_DISMISSED:
    case TX_TYPES.PRESCAN_REVIEW_CONFIRMED:
    case TX_TYPES.PRESCAN_REVIEW_RECUSED:
      // creator_tip_id embedded by review-service.js so the creator also sees
      // the verdict on their content, not just the reviewer's own action.
      return _clean([d.reviewer_tip_id, d.creator_tip_id]);

    // ── Multi-party: disputes & appeals (#40) ───────────────────────────
    // Both parties see the whole lifecycle, not just their own action.
    case TX_TYPES.CONTENT_DISPUTED:
      // The author ALWAYS sees a dispute on their content. The disputer sees it
      // too: a human disputer for user-filed disputes, or for auto-cascade the
      // reviewer escalation (disputer_tip_id) / escalating creator
      // (escalated_by_tip_id). Window-expiry auto-disputes embed author_tip_id.
      return _clean([d.disputer_tip_id, d.author_tip_id, d.escalated_by_tip_id]);

    case TX_TYPES.ADJUDICATION_RESULT:
      // The author being adjudicated AND the disputer who filed it both see
      // the verdict. (disputer_tip_id embedded by jury.js for #40.)
      return _clean([d.author_tip_id, d.disputer_tip_id]);

    case TX_TYPES.APPEAL_FILED:
      // Auto-escalation has no human appellant (SYSTEM_AUTO_ESCALATION) — fall
      // back to [author, disputer]. User appeals surface to all three; the
      // appellant is usually one of the other two, deduped by _clean().
      if (d.appellant_tip_id === "SYSTEM_AUTO_ESCALATION") {
        return _clean([d.author_tip_id, d.disputer_tip_id]);
      }
      return _clean([d.appellant_tip_id, d.author_tip_id, d.disputer_tip_id]);

    case TX_TYPES.APPEAL_RESULT:
      // Was unattributed (null) — now both parties see the resolution.
      // author/disputer embedded on every APPEAL_RESULT path by jury.js (#40).
      return _clean([d.author_tip_id, d.disputer_tip_id]);

    // ── No individual owner — org / system / consensus level ────────────
    // VP_*/NODE_* are about organizations; AI_CLASSIFIER_RESULT and
    // PRESCAN_COMPLETED are system results tied to a ctid; INTEREST_REGISTERED
    // is governance; COMMITTEE_ROTATION is consensus; UNBIND_DOMAIN is
    // node-emitted on revocation with no human party in its payload.
    case TX_TYPES.VP_REGISTERED:
    case TX_TYPES.VP_SUSPENDED:
    case TX_TYPES.NODE_REGISTERED:
    case TX_TYPES.NODE_ENDPOINT_UPDATED:
    case TX_TYPES.AI_CLASSIFIER_RESULT:
    case TX_TYPES.PRESCAN_COMPLETED:
    case TX_TYPES.INTEREST_REGISTERED:
    case TX_TYPES.COMMITTEE_ROTATION:
    case TX_TYPES.UNBIND_DOMAIN:
      return [];

    default:
      return [];
  }
}

/**
 * Legacy single-value attribution — the primary actor (first subject), or
 * null. Preserved so the denormalised `subject_tip_id` column and any external
 * caller keep working unchanged. The activity feed uses subjectTipIds().
 *
 * @param {Object} tx  Validated transaction
 * @returns {string|null}
 */
function subjectTipId(tx) {
  const ids = subjectTipIds(tx);
  return ids.length ? ids[0] : null;
}

module.exports = { subjectTipId, subjectTipIds };
