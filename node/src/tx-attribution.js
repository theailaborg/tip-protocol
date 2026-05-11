/**
 * @file @tip-protocol/node/src/tx-attribution.js
 * @description Single source of truth for "which tip_id does this tx
 * belong to" for activity-feed / outcome-endpoint purposes.
 *
 * Returns the most relevant tip_id for the user-facing question:
 * "show me txs that involve me." Broader than score-effects'
 * `scoreTargetTipId` (which only returns score-affecting subjects) —
 * this includes verifiers, disputers, jurors, and appellants so
 * activity feeds surface every role a user actually played.
 *
 * Used by:
 *   - dag.saveTx        → populates `transactions.subject_tip_id` index
 *   - dag.saveMempoolTx → populates `mempool.subject_tip_id`
 *   - dag.saveTxRejection (via tx-rejection-sink) → populates
 *     `tx_rejections.subject_tip_id`
 *   - getActivity (identity-service) → joins all three sources
 *
 * Per-row, single tip_id — keeps the index column simple and matches
 * the natural-language question. When a tx genuinely has no individual
 * subject (org-level: VP_REGISTERED, NODE_REGISTERED, AI_CLASSIFIER_RESULT,
 * APPEAL_RESULT) the helper returns null and the tx never appears in
 * any user's activity feed (correct — they're not "yours").
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES } = require("../../shared/constants");

/**
 * The per-tx_type "owner" for activity attribution. Covers every role
 * a user can play (subject, author, verifier, disputer, juror,
 * appellant). Returns null for org/system-level txs that don't belong
 * to any individual.
 *
 * Adding a new tx_type: pick the field whose value identifies "the
 * user this tx is about from a UI perspective." When ambiguous,
 * prefer the actor (the one performing the action) over passive
 * subjects — e.g. CONTENT_VERIFIED returns verifier_tip_id, not the
 * content author, because "I verified X" is the user's action.
 *
 * @param {Object} tx  Validated transaction
 * @returns {string|null}
 */
function subjectTipId(tx) {
  if (!tx || !tx.data) return null;
  const d = tx.data;
  switch (tx.tx_type) {

    // ── Subject IS the tip_id (self-affecting txs) ──────────────────────
    case TX_TYPES.REGISTER_IDENTITY:
    case TX_TYPES.SCORE_UPDATE:
    case TX_TYPES.LINK_PLATFORM:
    case TX_TYPES.UPDATE_DEVICE_BINDING:
    case TX_TYPES.REVOKE_VOLUNTARY:
    case TX_TYPES.REVOKE_VP:
    case TX_TYPES.REVOKE_DECEASED:
    case TX_TYPES.REVOKE_DEVICE:
      return d.tip_id || null;

    // ── Author actions on owned content ─────────────────────────────────
    case TX_TYPES.REGISTER_CONTENT:
      // CNA-2.2: signer_tip_id is the canonical field; in self-attribution
      // mode the signer is the author.
      return d.signer_tip_id || null;
    case TX_TYPES.UPDATE_ORIGIN:
    case TX_TYPES.CONTENT_RETRACTED:
      return d.author_tip_id || null;

    // ── ADJUDICATION_RESULT — the author being adjudicated owns the
    //    activity entry. The verdict is "about" them; jurors get their
    //    own JURY_VOTE_* entries.
    case TX_TYPES.ADJUDICATION_RESULT:
      return d.author_tip_id || null;

    // ── Active-role txs — actor is the subject ──────────────────────────
    case TX_TYPES.CONTENT_VERIFIED:
      return d.verifier_tip_id || null;

    case TX_TYPES.CONTENT_DISPUTED:
      // Auto-cascade disputes (REVOKE_VP fallout) have no human
      // disputer — leave them unattributed so they don't pollute any
      // user's feed.
      if (d.auto) return null;
      return d.disputer_tip_id || null;

    case TX_TYPES.JURY_VOTE_COMMIT:
    case TX_TYPES.JURY_VOTE_REVEAL:
    case TX_TYPES.JURY_SUMMONS:
      return d.juror_tip_id || null;

    case TX_TYPES.APPEAL_FILED:
      // User-filed appeals attribute to the appellant. Auto-escalation
      // (Stage 2 NO_QUORUM) leaves appellant_tip_id unset — falls
      // through to null.
      return d.appellant_tip_id || null;

    // ── No individual owner ─────────────────────────────────────────────
    // APPEAL_RESULT is orchestration; the score effects are emitted
    // as separate SCORE_UPDATE txs which DO get attributed.
    // VP_REGISTERED / NODE_REGISTERED are about organizations.
    // AI_CLASSIFIER_RESULT is system-generated, ties to ctid only.
    case TX_TYPES.APPEAL_RESULT:
    case TX_TYPES.VP_REGISTERED:
    case TX_TYPES.NODE_REGISTERED:
    case TX_TYPES.AI_CLASSIFIER_RESULT:
      return null;

    default:
      return null;
  }
}

module.exports = { subjectTipId };
