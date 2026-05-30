/**
 * @file @tip-protocol/node/src/consensus/commit-handler.js
 * @description Processes ordered transactions from Bullshark and commits to DAG.
 *
 * When Bullshark commits an anchor, it outputs a deterministically ordered
 * list of transactions. This handler:
 *   1. Validates each tx against current DAG state (may have changed since API time)
 *   2. Writes valid txs to DAG
 *   3. Updates derived state (identities, content, scores, revocations, etc.)
 *   4. Drops invalid txs with a log (e.g. content already registered by another node)
 *
 * This replaces the old replayDerivedState() from gossip.js with full validation
 * and support for all tx types including dispute, jury, and appeal.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs } = require("../../../shared/time");

const { TX_TYPES, CONTENT_STATUS, VERDICT, TX_REJECTION_REASON, DOMAIN_HEALTHY_EXPIRY_MS, PRESCAN_REVIEW_STATES } = require("../../../shared/constants");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const contentRegisterSchema = require("../schemas/content-register");
const registerIdentitySchema = require("../schemas/register-identity");
const bindDomainSchema = require("../schemas/bind-domain");
const updateProfileSchema = require("../schemas/update-profile");
const prescanReviewTriggeredSchema = require("../schemas/prescan-review-triggered");
const prescanReviewDismissedSchema = require("../schemas/prescan-review-dismissed");
const prescanReviewConfirmedSchema = require("../schemas/prescan-review-confirmed");
const prescanReviewRecusedSchema = require("../schemas/prescan-review-recused");
const prescanCompletedSchema = require("../schemas/prescan-completed");
const registerDomainSchema = require("../schemas/register-domain");
const prescanReviewAcceptCorrectionSchema = require("../schemas/prescan-review-accept-correction");
const prescanReviewDisputeSchema = require("../schemas/prescan-review-dispute");
const keyRotatedSchema = require("../schemas/key-rotated");
const keyRecoverySchema = require("../schemas/key-recovery");
const interestRegisteredSchema = require("../schemas/interest-registered");
const linkPlatformSchema = require("../schemas/link-platform");
const unlinkPlatformSchema = require("../schemas/unlink-platform");
const { verifyTxSignature: unifiedVerifyTxSignature, verifyCosignatures } = require("../schemas/_common");
const { TX_SIGNATURE_REGISTRY } = require("../schemas/_registry");

// GH #51 — tx_type to schema-module map for the unified signature
// dispatcher. tx types without a schema fall through to the registry
// (schemas/_registry.js) via verifyTxSignature's resolveSignatureContract.
const SCHEMA_FOR_TX_TYPE = Object.freeze({
  [TX_TYPES.REGISTER_CONTENT]: contentRegisterSchema,
  [TX_TYPES.REGISTER_IDENTITY]: registerIdentitySchema,
  [TX_TYPES.BIND_DOMAIN]: bindDomainSchema,
  [TX_TYPES.UPDATE_PROFILE]: updateProfileSchema,
  [TX_TYPES.PRESCAN_REVIEW_TRIGGERED]: prescanReviewTriggeredSchema,
  [TX_TYPES.PRESCAN_REVIEW_DISMISSED]: prescanReviewDismissedSchema,
  [TX_TYPES.PRESCAN_REVIEW_CONFIRMED]: prescanReviewConfirmedSchema,
  [TX_TYPES.PRESCAN_REVIEW_RECUSED]: prescanReviewRecusedSchema,
  [TX_TYPES.PRESCAN_COMPLETED]: prescanCompletedSchema,
  // GH #60 — key rotation + VP-attested recovery. Both append a new
  // entity_keys row + close the prior one atomically.
  [TX_TYPES.KEY_ROTATED]: keyRotatedSchema,
  [TX_TYPES.KEY_RECOVERY]: keyRecoverySchema,
  // Interest taxonomy registry — VP-attested.
  [TX_TYPES.INTEREST_REGISTERED]: interestRegisteredSchema,
  // Social account linking/unlinking — node-attested (SIGNED_BY=NODE, SCOPE=BODY).
  [TX_TYPES.LINK_PLATFORM]: linkPlatformSchema,
  [TX_TYPES.UNLINK_PLATFORM]: unlinkPlatformSchema,
});
// Sister schemas exist but their tx_type lives elsewhere or they share
// dispatch with another schema's TX_TYPE — keep imports so they're not
// orphaned by the linter, and so future tx_types that promote out of
// the registry can wire in here cleanly.
void registerDomainSchema; void prescanReviewAcceptCorrectionSchema; void prescanReviewDisputeSchema;
const { applyScoreEffect, scoreTargetTipId, initialState } = require("../score-effects");
const { verifyBodySignature, mldsaVerify, canonicalTx, canonicalJson, shake256 } = require("../../../shared/crypto");
const { createRejectionSink } = require("./tx-rejection-sink");
const { getLogger } = require("../logger");

const log = getLogger("tip.commit");

// Post-resolution content status for "author wins" verdicts (Stage-2
// DISMISSED / CONSERVATIVE_LABEL and Stage-3 overturn UPHELD→DISMISSED).
// If the dispute was filed while a prescan review was open, pre_dispute_status
// captured PENDING_REVIEW — but that review row is now terminal
// (ESCALATED_TO_DISPUTE) and no reviewer is waiting. The dispute answered
// the review's question conclusively in the author's favor, so the content
// is positively cleared → VERIFIED. For any other prior state we replay
// the pre-dispute status verbatim.
function _postResolutionStatus(preDisputeStatus) {
  if (preDisputeStatus === CONTENT_STATUS.PENDING_REVIEW) {
    return CONTENT_STATUS.VERIFIED;
  }
  return preDisputeStatus || CONTENT_STATUS.REGISTERED;
}

/**
 * Map a business-rule failure message to the most specific reason code.
 *
 * Coarse mapping by intent — the full message lives in `reason_detail`,
 * so callers/dashboards always have the precise text. Reason codes here
 * exist to give programmatic discriminability for the common cases users
 * are most likely to ask about.
 *
 * Lives in commit-handler (not the sink) because the input format —
 * stringified error messages from `validators/business-rules.js` — is
 * specific to this caller. A future drop site outside commit-handler
 * would have different inputs and need a different mapper.
 *
 * Add a new specific code only when (a) the failure is common AND
 * (b) the remediation differs meaningfully from the generic case.
 */
function _mapBusinessRuleReason(error) {
  if (!error) return TX_REJECTION_REASON.REVALIDATION_FAILED;
  if (error.includes("Identity already registered")) return TX_REJECTION_REASON.IDENTITY_ALREADY_REGISTERED;
  if (error.includes("Content already registered")) return TX_REJECTION_REASON.CONTENT_ALREADY_REGISTERED;
  if (error.includes("already bound to a different TIP-ID")) return TX_REJECTION_REASON.DOMAIN_ALREADY_CLAIMED;
  return TX_REJECTION_REASON.REVALIDATION_FAILED;
}

/**
 * Create a commit handler.
 *
 * Note: as of Commit 2 (#13/#15), commit-handler no longer needs the
 * `scoring` engine or the node `config` — score effects are applied via
 * the `SCORE_UPDATE` handler reading `tx.data.delta` directly, the
 * CONTENT_RETRACTED penalty inlines the cache mutation, and there's no
 * tx-signing or node-identity work left here. Existing callers can still
 * pass `{ dag, scoring, config }` — the extra props are harmlessly
 * ignored by destructure.
 *
 * Commit 3 adds optional `verdictTrigger` and `cleanRecordTrigger`
 * dependencies. They own their own state (heap / day-counter) and are
 * delegated to in two places:
 *   - per applied tx in `_applyDerivedState` (verdict-trigger only —
 *     cleans up its heap on verdict-relevant tx types)
 *   - once at the end of `commitOrderedTxs` (both triggers)
 * When omitted (unit tests, replay-only paths) the delegation is silently
 * skipped — useful for exercising commit semantics without wiring the
 * full consensus stack.
 *
 * @param {Object} options
 * @param {Object} options.dag                   DAG store
 * @param {Object} [options.verdictTrigger]      Post-round verdict scheduler (Commit 3)
 * @param {Object} [options.cleanRecordTrigger]  Post-round clean-record bonus scheduler
 * @returns {Object} Commit handler
 */
function createCommitHandler({ dag, scoring, verdictTrigger, cleanRecordTrigger, prescanReviewTrigger, prescanCompletionTrigger, config, nodeId }) {
  // tx_rejections sink (#64) — every drop site below records to the
  // shared sink so commit-handler rejections share the same row shape
  // as mempool rejections. nodeId precedence: explicit option →
  // config.nodeRegisteredId → config.nodeId → "unknown" sentinel.
  const droppingNodeId = nodeId
    || (config && (config.nodeRegisteredId || config.nodeId))
    || "unknown";
  const _persistRejection = createRejectionSink({ dag, nodeId: droppingNodeId });


  /**
   * Process an ordered batch of txs from Bullshark.
   * Each tx is validated against current state, written to DAG, and derived state updated.
   *
   * @param {Array<Object>} orderedTxs   Deterministically ordered txs from Bullshark
   * @param {number} round               The round number that committed these txs
   * @param {Object} [opts]
   * @param {number}  [opts.certTimestamp] BFT-Time canonical wall-clock for this round
   *                                     (median of anchor cert's acks.signed_at, integer epoch
   *                                     ms). Deterministic across nodes. Currently flowed
   *                                     through unused — Commit 3 will use it as the trigger
   *                                     clock for post-round verdict logic and clean-record
   *                                     bonus eligibility, replacing scheduler-driven nowMs().
   * @returns {{ committed: number, dropped: number }}
   */
  function commitOrderedTxs(orderedTxs, round, opts = {}) {
    const { certTimestamp = 0 } = opts;
    // Phase 1: Validate all txs BEFORE writing anything.
    //
    // `validated` is also passed to the business-rule guard so first-wins
    // dedup catches duplicates inside this same round (e.g. two competing
    // schedulers' ADJUDICATION_RESULTs for the same ctid both ordered into
    // the same anchor commit — only the first one in the canonical order
    // is admitted).
    const validated = [];
    let dropped = 0;

    for (const tx of orderedTxs) {
      if (!tx || !tx.tx_id || !tx.tx_type) {
        dropped++;
        continue;
      }

      // Skip if already in DAG
      if (dag.getTx(tx.tx_id)) continue;

      // Validate structure. prev-existence check is enforced — every tx
      // that touches the `_prev` ring now flows through consensus (#13),
      // so by the time a replaying node processes tx N, all txs N's prev
      // references point at have already been committed in earlier rounds.
      const validation = validateTransaction(tx, dag, { skipState: true });
      if (!validation.valid) {
        const detail = validation.errors.join("; ");
        log.warn(`Round ${round}: rejected tx ${tx.tx_id.slice(0, 16)} (${tx.tx_type}) — ${detail}`);
        _persistRejection(tx, TX_REJECTION_REASON.REVALIDATION_FAILED, detail, { round });
        dropped++;
        continue;
      }

      // Verify signature
      if (!_verifyTxSignature(tx)) {
        log.warn(`Round ${round}: rejected tx ${tx.tx_id.slice(0, 16)} (${tx.tx_type}) — signature failed`);
        _persistRejection(tx, TX_REJECTION_REASON.REVALIDATION_FAILED, "signature failed", { round });
        dropped++;
        continue;
      }

      // Business-rule guard — first-wins dedup for verdict txs and
      // reveal-window enforcement for jury reveals. Closes #15 (and the
      // multi-submitter race in #13: when N nodes' schedulers each
      // produce a verdict batch for the same dispute, only the first
      // ordered ADJUDICATION_RESULT/APPEAL_RESULT lands per ctid; later
      // duplicates and their score-update effects are dropped silently).
      const business = _validateBusinessRules(tx, validated, certTimestamp);
      if (!business.valid) {
        log.debug(`Round ${round}: dropped ${tx.tx_type} ${tx.tx_id.slice(0, 16)} — ${business.error}`);
        _persistRejection(tx, _mapBusinessRuleReason(business.error), business.error, { round });
        dropped++;
        continue;
      }

      validated.push(tx);
    }

    // Phase 2: Write all validated txs in one atomic SQLite transaction
    let committed = 0;
    if (validated.length > 0) {
      try {
        dag.runInTransaction(() => {
          for (const tx of validated) {
            dag.addTx(tx);
            _applyDerivedState(tx, certTimestamp, round);
            committed++;
          }
          // Remove committed txs from mempool in the same transaction
          const txIds = validated.map(t => t.tx_id);
          dag.deleteMempoolTxs(txIds);
        });
      } catch (err) {
        log.error(`Round ${round}: transaction commit failed — rolled back ${validated.length} txs: ${err.message}`);
        // Every rolled-back tx is silently lost: it passed phase-1
        // validation, never reached dag.txs, and the user has the
        // tip_id. Record each one so the outcome endpoint can answer.
        // Detail carries the underlying error for ops triage.
        const detail = `transaction rollback: ${err.message}`;
        for (const tx of validated) {
          _persistRejection(tx, TX_REJECTION_REASON.REVALIDATION_FAILED, detail, { round });
        }
        committed = 0;
        dropped += validated.length;
      }
    }

    // Phase 3 (Commit 3): post-round triggers. Run once per round,
    // OUTSIDE the SQLite transaction above — both triggers submit
    // batches to mempool that land in a future round. Delegated to
    // dedicated modules so commit-handler stays focused on tx
    // application. Each trigger's failures are non-fatal — they don't
    // invalidate the round's tx commits; next round retries.
    if (verdictTrigger && certTimestamp > 0) {
      try {
        verdictTrigger.checkPending(certTimestamp, round);
      } catch (err) {
        log.warn(`Round ${round}: post-round verdict trigger failed: ${err.message}`);
      }
    }
    if (cleanRecordTrigger && certTimestamp > 0) {
      try {
        cleanRecordTrigger.checkPending(certTimestamp);
      } catch (err) {
        log.warn(`Round ${round}: post-round clean-record trigger failed: ${err.message}`);
      }
    }
    if (prescanReviewTrigger && certTimestamp > 0) {
      try {
        prescanReviewTrigger.checkPending(certTimestamp, round);
      } catch (err) {
        log.warn(`Round ${round}: post-round prescan-review trigger failed: ${err.message}`);
      }
    }
    if (prescanCompletionTrigger && certTimestamp > 0) {
      try {
        prescanCompletionTrigger.checkPending(certTimestamp, round);
      } catch (err) {
        log.warn(`Round ${round}: post-round prescan-completion failover trigger failed: ${err.message}`);
      }
    }

    if (committed > 0 || dropped > 0) {
      log.info(`Round ${round}: committed ${committed} txs, dropped ${dropped}`);
    }

    return { committed, dropped };
  }

  // ─── Business-rule guards (#13 + #15) ──────────────────────────────────

  /**
   * Apply tx-type-specific business rules at commit time. First-wins dedup
   * across `dag` (already-committed txs) and `validated` (txs in this same
   * round that have already passed all checks above). Returns `{valid: true}`
   * for accepted txs, `{valid: false, error: "..."}` for rejected ones.
   */
  function _validateBusinessRules(tx, validated, certTimestamp) {
    const d = tx.data || {};

    // Phase A — first-wins dedup against committed history + same-batch siblings.
    const dedup = _dedupCheck(tx, validated);
    if (!dedup.valid) return dedup;

    // Phase B — stateful pre-conditions (same predicate as the API service).
    // Time-window rules use `tx.timestamp` (user submit time, frozen in the
    // signed payload) so the accept/reject decision is identical on every
    // node. `certTimestamp` is plumbed through for rules that need the
    // round's BFT clock instead — none today, but keep the wire so future
    // rules can opt in without changing the signature.
    void certTimestamp;
    const txMs = tx.timestamp;
    return _statefulCheck(tx, txMs);
  }

  /** First-wins dedup over verdict / appeal / score / appeal-filed records. */
  function _dedupCheck(tx, validated) {
    const d = tx.data || {};
    switch (tx.tx_type) {

      case TX_TYPES.ADJUDICATION_RESULT: {
        if (!d.ctid) return { valid: false, error: "missing ctid" };
        const existing = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, d.ctid);
        if (existing.length > 0) return { valid: false, error: `ADJUDICATION_RESULT already exists for ${d.ctid}` };
        const inBatch = validated.find(t =>
          t.tx_type === TX_TYPES.ADJUDICATION_RESULT && t.data?.ctid === d.ctid
        );
        if (inBatch) return { valid: false, error: `ADJUDICATION_RESULT already in this batch for ${d.ctid}` };
        return { valid: true };
      }

      case TX_TYPES.APPEAL_RESULT: {
        if (!d.ctid) return { valid: false, error: "missing ctid" };
        const existing = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_RESULT, d.ctid);
        if (existing.length > 0) return { valid: false, error: `APPEAL_RESULT already exists for ${d.ctid}` };
        const inBatch = validated.find(t =>
          t.tx_type === TX_TYPES.APPEAL_RESULT && t.data?.ctid === d.ctid
        );
        if (inBatch) return { valid: false, error: `APPEAL_RESULT already in this batch for ${d.ctid}` };
        return { valid: true };
      }

      case TX_TYPES.APPEAL_FILED: {
        // Only the FIRST APPEAL_FILED per ctid is canonical. Auto-escalation
        // (Stage 2 NO_QUORUM) and user-filed appeals both go through this
        // gate; whichever lands first wins.
        if (!d.ctid) return { valid: true };
        const existing = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, d.ctid);
        if (existing.length > 0) return { valid: false, error: `APPEAL_FILED already exists for ${d.ctid}` };
        const inBatch = validated.find(t =>
          t.tx_type === TX_TYPES.APPEAL_FILED && t.data?.ctid === d.ctid
        );
        if (inBatch) return { valid: false, error: `APPEAL_FILED already in this batch for ${d.ctid}` };
        return { valid: true };
      }

      case TX_TYPES.SCORE_UPDATE: {
        // Dedup by (tip_id, ctid, reason). When N nodes' schedulers each
        // submit a verdict batch, the per-juror SCORE_UPDATEs all share
        // the same (tip_id, ctid, reason) tuple — only the first lands.
        // For non-jury SCORE_UPDATEs (clean-record bonus, content-retracted)
        // the same dedup key catches accidental duplicates without affecting
        // legitimate single-submitter calls.
        if (!d.tip_id || !d.reason) return { valid: true };
        const tipMatch = (t) => t.data?.tip_id === d.tip_id
          && (t.data?.ctid || null) === (d.ctid || null)
          && t.data?.reason === d.reason;
        const existing = dag.getTxsByType(TX_TYPES.SCORE_UPDATE).find(tipMatch);
        if (existing) return { valid: false, error: `SCORE_UPDATE for (${d.tip_id}, ${d.ctid || "—"}, ${d.reason}) already applied` };
        const inBatch = validated.find(t => t.tx_type === TX_TYPES.SCORE_UPDATE && tipMatch(t));
        if (inBatch) return { valid: false, error: `SCORE_UPDATE for (${d.tip_id}, ${d.ctid || "—"}, ${d.reason}) already in this batch` };
        return { valid: true };
      }

      case TX_TYPES.JURY_VOTE_COMMIT: {
        // In-batch dedup. canCommitVote (in _statefulCheck) checks DAG state,
        // but two commits from the same juror landed in the same round both
        // see "no existing commit" pre-batch. Drop the second so verdict
        // tally and score effects can't double-count a juror.
        if (!d.ctid || !d.juror_tip_id) return { valid: true };
        const inBatch = validated.find(t =>
          t.tx_type === TX_TYPES.JURY_VOTE_COMMIT
          && t.data?.ctid === d.ctid
          && t.data?.juror_tip_id === d.juror_tip_id
          && (!!t.data?.is_appeal) === (!!d.is_appeal));
        if (inBatch) return { valid: false, error: `duplicate JURY_VOTE_COMMIT in batch for (${d.ctid}, ${d.juror_tip_id})` };
        return { valid: true };
      }

      case TX_TYPES.JURY_VOTE_REVEAL: {
        if (!d.ctid || !d.juror_tip_id) return { valid: true };
        const inBatch = validated.find(t =>
          t.tx_type === TX_TYPES.JURY_VOTE_REVEAL
          && t.data?.ctid === d.ctid
          && t.data?.juror_tip_id === d.juror_tip_id
          && (!!t.data?.is_appeal) === (!!d.is_appeal));
        if (inBatch) return { valid: false, error: `duplicate JURY_VOTE_REVEAL in batch for (${d.ctid}, ${d.juror_tip_id})` };
        return { valid: true };
      }

      case TX_TYPES.COMMITTEE_ROTATION: {
        // §4 + #34: in-batch dedup only — the rest of the rotation-validity
        // checks (monotonic rotation_number, effective_round, structural,
        // crypto) live in `rules.canCommitteeRotation` which runs from
        // `_statefulCheck` so the proposer side and commit-handler share
        // one predicate (issue #14 pattern).
        const inBatch = validated.find(t =>
          t.tx_type === TX_TYPES.COMMITTEE_ROTATION && t.data?.rotation_number === d.rotation_number
        );
        if (inBatch) return { valid: false, error: `rotation_number ${d.rotation_number} already in this batch` };
        return { valid: true };
      }

      case TX_TYPES.LINK_PLATFORM: {
        // In-batch dedup. The committed-history first-wins guard lives in
        // linkPlatformSchema.verifyTx (active-link check); two siblings in
        // the same batch both see no committed row, so drop the second
        // here before _applyDerivedState's upsert silently overwrites.
        if (!d.tip_id || !d.platform) return { valid: true };
        const inBatch = validated.find(t =>
          t.tx_type === TX_TYPES.LINK_PLATFORM
          && t.data?.tip_id === d.tip_id
          && t.data?.platform === d.platform);
        if (inBatch) return { valid: false, error: `duplicate LINK_PLATFORM in batch for (${d.tip_id}, ${d.platform})` };
        return { valid: true };
      }

      case TX_TYPES.UNLINK_PLATFORM: {
        if (!d.tip_id || !d.platform) return { valid: true };
        const inBatch = validated.find(t =>
          t.tx_type === TX_TYPES.UNLINK_PLATFORM
          && t.data?.tip_id === d.tip_id
          && t.data?.platform === d.platform);
        if (inBatch) return { valid: false, error: `duplicate UNLINK_PLATFORM in batch for (${d.tip_id}, ${d.platform})` };
        return { valid: true };
      }

      default:
        return { valid: true };
    }
  }

  /**
   * State-dependent + time-window pre-condition re-check using the same
   * `validators/business-rules` predicates the API service called.
   *
   * Identical predicate at both call sites is the whole point: API rejects
   * fast at submission; commit-handler drops silently if state changed
   * between submit and commit (e.g. content disputed or author revoked
   * mid-flight). Closes the silent-divergence gap multi-node #14.
   */
  function _statefulCheck(tx, now) {
    const d = tx.data || {};
    switch (tx.tx_type) {

      case TX_TYPES.REGISTER_IDENTITY: {
        const r = rules.canRegisterIdentity(dag, { tip_id: d.tip_id, dedup_hash: d.dedup_hash, vp_id: d.vp_id });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.VP_REGISTERED: {
        const r = rules.canRegisterVp(dag, { vp_id: d.vp_id });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.NODE_REGISTERED: {
        const r = rules.canRegisterNode(dag, { node_id: d.node_id });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.REGISTER_CONTENT: {
        const r = rules.canRegisterContent(dag, {
          signer_tip_id: d.signer_tip_id, ctid: d.ctid, origin_code: d.origin_code,
        });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.CONTENT_VERIFIED: {
        const r = rules.canVerify(dag, { ctid: d.ctid, verifier_tip_id: d.verifier_tip_id });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.UPDATE_ORIGIN: {
        const r = rules.canUpdateOrigin(dag, {
          ctid: d.ctid, author_tip_id: d.author_tip_id, new_origin_code: d.new_origin_code,
        }, { now });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.CONTENT_RETRACTED: {
        const r = rules.canRetract(dag, { ctid: d.ctid, author_tip_id: d.author_tip_id });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.BIND_DOMAIN: {
        // Closes the gossip-bypass gap: a peer-submitted tx that didn't go
        // through the API service's 409 still hits the same predicate here.
        const r = rules.canBindDomain(dag, { tip_id: d.tip_id, domain: d.domain });
        if (!r.valid) return { valid: false, error: r.error.message };
        // Schema-level state checks: node active, claimant is an active
        // organization, user's claim_signature attestation still verifies.
        // GH #51 split — node binding signature is verified by the
        // unified dispatcher; this is the non-signature state piece.
        const s = bindDomainSchema.verifyTx(tx, dag);
        return s.ok ? { valid: true } : { valid: false, error: s.error };
      }

      case TX_TYPES.UNBIND_DOMAIN: {
        // Schema's verifyUnbindTx checks emitting node is active, payload
        // shape, and that the domain has a current binding to unbind. Node
        // signature itself is verified by the unified dispatcher.
        const s = bindDomainSchema.verifyUnbindTx(tx, dag);
        return s.ok ? { valid: true } : { valid: false, error: s.error };
      }

      case TX_TYPES.CONTENT_DISPUTED: {
        // Cascade-issued disputes (auto: true, e.g. REVOKE_VP cascade) bypass
        // the disputer-score / state predicates because the issuer is the node
        // itself, not a TIP-ID with a score. They still pass through dedup.
        if (d.auto) return { valid: true };
        const r = rules.canDispute(dag, scoring, { ctid: d.ctid, disputer_tip_id: d.disputer_tip_id });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.JURY_VOTE_COMMIT: {
        const r = rules.canCommitVote(dag, {
          ctid: d.ctid, juror_tip_id: d.juror_tip_id, is_appeal: !!d.is_appeal,
        }, { now });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.JURY_VOTE_REVEAL: {
        const r = rules.canRevealVote(dag, {
          ctid: d.ctid, juror_tip_id: d.juror_tip_id, is_appeal: !!d.is_appeal,
          vote: d.vote, salt: d.salt,
        }, { now, shake256 });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.APPEAL_FILED: {
        // SYSTEM_AUTO_ESCALATION (Stage-2 NO_QUORUM) bypasses canFileAppeal:
        // the prereq ADJUDICATION_RESULT is in the SAME atomic batch (built
        // by jury.buildAdjudicationBatch's NO_QUORUM path), and validation
        // runs before application — so dag.getTxsByTypeAndCtid would not
        // see the in-batch verdict tx. The user-filed appeal path keeps
        // the prereq check.
        if (d.appellant_tip_id === "SYSTEM_AUTO_ESCALATION") return { valid: true };
        if (d.appellant_tip_id) {
          const r = rules.canFileAppeal(dag, {
            ctid: d.ctid, appellant_tip_id: d.appellant_tip_id,
          }, { now });
          if (!r.valid) return { valid: false, error: r.error.message };
        }
        return { valid: true };
      }

      case TX_TYPES.REVOKE_VOLUNTARY:
      case TX_TYPES.REVOKE_VP:
      case TX_TYPES.REVOKE_DECEASED:
      case TX_TYPES.REVOKE_DEVICE: {
        if (d.issuing_vp_id) {
          const r = rules.canRevoke(dag, {
            tx_type: tx.tx_type, tip_id: d.tip_id, issuing_vp_id: d.issuing_vp_id,
          });
          if (!r.valid) return { valid: false, error: r.error.message };
        }
        return { valid: true };
      }

      case TX_TYPES.COMMITTEE_ROTATION: {
        // §4 + #34: full rotation validity — structural, monotonic, and
        // cryptographic (≥2f+1 sigs from previous committee) — through the
        // shared business-rules predicate. Same call shape as the bullshark
        // proposer (see step 6) so accept/reject decisions are identical.
        const r = rules.canCommitteeRotation(dag, d, { shake256, canonicalJson, mldsaVerify });
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
      }

      case TX_TYPES.PRESCAN_REVIEW_TRIGGERED: {
        // Content must exist + no duplicate open review per CTID. The
        // scheduler guards this when emitting, but consensus-replay must
        // enforce too — a malicious or buggy node emitting a second
        // trigger after another node already triggered is byzantine.
        if (!dag.getContent(d.ctid)) {
          return { valid: false, error: `Content not found: ${d.ctid}` };
        }
        const existing = dag.getOpenPrescanReviewByCtid(d.ctid);
        if (existing && existing.review_id !== d.review_id) {
          return {
            valid: false,
            error: `Cannot trigger review: an open review already exists for ${d.ctid} (review_id=${existing.review_id})`,
          };
        }
        return { valid: true };
      }

      // Prescan-review reviewer-assigned + state-machine checks. GH #51
      // split: signature is verified by `_verifyTxSignature` via the
      // unified dispatcher; state-machine invariants (assigned-reviewer
      // match, review state, auto-recuse node-registration) live in the
      // schema's `verifyTx` so the same code runs at API time too.
      case TX_TYPES.PRESCAN_REVIEW_DISMISSED: {
        const r = prescanReviewDismissedSchema.verifyTx(tx, dag);
        return r.ok ? { valid: true } : { valid: false, error: r.error };
      }
      case TX_TYPES.PRESCAN_REVIEW_CONFIRMED: {
        const r = prescanReviewConfirmedSchema.verifyTx(tx, dag);
        return r.ok ? { valid: true } : { valid: false, error: r.error };
      }
      case TX_TYPES.PRESCAN_REVIEW_RECUSED: {
        const r = prescanReviewRecusedSchema.verifyTx(tx, dag);
        return r.ok ? { valid: true } : { valid: false, error: r.error };
      }

      // GH #60 — key rotation + recovery state checks. Signature is
      // verified by the unified dispatcher (OLD key for KEY_ROTATED;
      // VP key for KEY_RECOVERY). These predicates enforce the
      // state-machine invariants (active identity, valid effective_at,
      // VP authorisation, rate limits).
      case TX_TYPES.KEY_ROTATED: {
        const r = keyRotatedSchema.verifyTx(tx, dag);
        return r.ok ? { valid: true } : { valid: false, error: r.error };
      }
      case TX_TYPES.KEY_RECOVERY: {
        const r = keyRecoverySchema.verifyTx(tx, dag);
        return r.ok ? { valid: true } : { valid: false, error: r.error };
      }

      case TX_TYPES.INTEREST_REGISTERED: {
        // VP active + slug uniqueness + category enum + slug/label syntax.
        // First-wins dedup: if two VPs race to register the same slug, the
        // second one 409s here in canonical consensus order.
        const r = interestRegisteredSchema.verifyTx(tx, dag);
        return r.ok ? { valid: true } : { valid: false, error: r.error };
      }

      // Social account linking — schema enforces verifying-node active,
      // subject registered + unrevoked, no existing active link, and the
      // user's claim_signature attestation. Closes the gossip-bypass gap
      // for peer-submitted txs that never hit the API service's predicates.
      case TX_TYPES.LINK_PLATFORM: {
        const r = linkPlatformSchema.verifyTx(tx, dag);
        return r.ok ? { valid: true } : { valid: false, error: r.error };
      }

      case TX_TYPES.UNLINK_PLATFORM: {
        const r = unlinkPlatformSchema.verifyTx(tx, dag);
        return r.ok ? { valid: true } : { valid: false, error: r.error };
      }

      default:
        return { valid: true };
    }
  }

  /**
   * Apply derived state updates for a committed transaction.
   * Handles all tx types — identity, content, dispute, jury, appeal, revocation, governance.
   */
  function _applyDerivedState(tx, _committedCertTimestamp = 0, round = 0) {
    const d = tx.data || {};

    switch (tx.tx_type) {

      // ── Identity ──────────────────────────────────────────────────────
      case TX_TYPES.REGISTER_IDENTITY:
        if (d.dedup_hash && !dag.hasDedupHash(d.dedup_hash)) {
          // Unix seconds derived from the tx timestamp (deterministic across nodes).
          // tip_id denormalized so /v1/identity/by-dedup-hash is a single read.
          dag.addDedupHash(d.dedup_hash, Math.floor(tx.timestamp / 1000), d.tip_id);
        }
        if (d.tip_id && !dag.getIdentity(d.tip_id)) {
          // GH #60: public_key + algorithm auto-route to entity_keys via
          // saveIdentity (DID-style single source of truth — the keys
          // table holds every key across all time, identities holds
          // mutable non-cryptographic attributes only). root_public_key
          // dropped (orphaned scaffold; never wired in any service).
          dag.saveIdentity({
            tip_id: d.tip_id,
            region: d.region || "US",
            public_key: d.public_key || "",
            algorithm: d.algorithm || "ml-dsa-65",
            vp_id: d.vp_id || "",
            verification_tier: d.verification_tier || "T1",
            tip_id_type: d.tip_id_type || "personal",
            founding: d.founding || false,
            status: "active",
            registered_at: tx.timestamp,
            tx_id: tx.tx_id,
            creator_name: d.creator_name || null,
          });
        }
        // Score effect (initial score for new identity) is applied in
        // the unified `_applyScoreEffect(tx)` pass below — single source
        // of truth shared with computeScore replay (#38).
        break;

      case TX_TYPES.UPDATE_PROFILE: {
        // Sparse merge — only fields present on tx.data update the
        // identity row; missing fields preserve previous value. Schema
        // module enforces strict field set + types in verifyTx, so by
        // the time we reach here d.<known_field> is guaranteed to be
        // a boolean / declared type when present.
        const current = dag.getIdentity(d.tip_id);
        if (current) {
          const merged = { ...current };
          for (const field of updateProfileSchema.KNOWN_FIELD_NAMES) {
            if (d[field] !== undefined) merged[field] = d[field];
          }
          dag.saveIdentity(merged);
        }
        break;
      }

      case TX_TYPES.PRESCAN_REVIEW_TRIGGERED: {
        // Scheduler-emitted; signature already validated. Create the
        // prescan_reviews row with state=triggered + reviewer assignment,
        // and flip content.status REGISTERED → PENDING_REVIEW (amber
        // badge goes live now, not at registration). Idempotent: if a
        // review already exists for this review_id, savePrescanReview
        // replaces it; updateContentStatus is a no-op when status is
        // already PENDING_REVIEW.
        dag.savePrescanReview({
          review_id: d.review_id,
          ctid: d.ctid,
          creator_tip_id: d.creator_tip_id,
          assigned_reviewer: d.assigned_reviewer_tip_id,
          triggered_at_round: d.triggered_at_round,
          triggered_at_ms: _committedCertTimestamp || null,
          state: PRESCAN_REVIEW_STATES.TRIGGERED,
        });
        if (dag.getContent(d.ctid)) {
          dag.updateContentStatus(d.ctid, CONTENT_STATUS.PENDING_REVIEW);
        }
        break;
      }

      case TX_TYPES.PRESCAN_COMPLETED: {
        // Worker-emitted (assigned API node or failover leader) once the
        // classifier returns. Persist the verdict onto the content row
        // and flip status PENDING_PRESCAN → REGISTERED/PENDING_REVIEW.
        //
        // First-wins dedup: if PRESCAN_COMPLETED already applied for
        // this ctid (race between original assignee + failover leader),
        // skip — the chronologically-first tx_id wins per consensus
        // ordering.
        const existing = dag.getContent(d.ctid);
        if (!existing) {
          // REGISTER_CONTENT hasn't applied yet (network reordering).
          // Defer by no-op; the failover trigger will re-emit when it
          // sees this ctid stuck in pending past takeover_after_ms.
          break;
        }
        if (existing.prescan_status === "completed") {
          // Already settled; honour first-wins.
          break;
        }
        // Degraded verdicts must not flag content — even if tier is
        // HIGH/CRITICAL, signal quality is too low to act on. See
        // ASYNC_PRESCAN_ARCHITECTURE.md § Degraded handling.
        const shouldFlag = !!d.flagged && !d.overall_degraded;
        const nextStatus = shouldFlag ? CONTENT_STATUS.PENDING_REVIEW : CONTENT_STATUS.REGISTERED;
        dag.saveContent({
          ...existing,
          prescan_flagged: shouldFlag ? 1 : 0,
          prescan_probability: d.probability,
          prescan_tier: d.tier,
          prescan_status: "completed",
          prescan_completed_at: d.completed_at,
          prescan_content_type: d.content_type,
          prescan_overall_degraded: d.overall_degraded ? 1 : 0,
          status: nextStatus,
        });
        break;
      }

      case TX_TYPES.PRESCAN_REVIEW_DISMISSED: {
        // Reviewer said "AI's flag was wrong". Close the review and
        // restore content.status to REGISTERED — green badge comes back,
        // no public dispute, no penalty. Schema module enforced that the
        // review is in state=triggered and assigned to this reviewer.
        const review = dag.getPrescanReview(d.review_id);
        if (review) {
          dag.savePrescanReview({
            ...review,
            state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
            decided_at_round: round,
            decision_note: d.decision_note || null,
          });
          if (dag.getContent(review.ctid)) {
            dag.updateContentStatus(review.ctid, CONTENT_STATUS.REGISTERED);
          }
        }
        break;
      }

      case TX_TYPES.PRESCAN_REVIEW_RECUSED: {
        // Reviewer bowed out of the case. Close the review with
        // state=RECUSED and flip content.status back to REGISTERED so
        // the prescan-review-trigger re-picks-up this content on the
        // next round and emits a fresh PRESCAN_REVIEW_TRIGGERED with
        // a new assignment. The original assigned_reviewer stays on
        // the row for audit; getOpenPrescanReviewByCtid won't return
        // it (RECUSED is a closed state), so the trigger's "no open
        // review" predicate passes.
        const review = dag.getPrescanReview(d.review_id);
        if (review) {
          dag.savePrescanReview({
            ...review,
            state: PRESCAN_REVIEW_STATES.RECUSED,
            decided_at_round: round,
            decision_note: d.recusal_reason || null,
          });
          if (dag.getContent(review.ctid)) {
            dag.updateContentStatus(review.ctid, CONTENT_STATUS.REGISTERED);
          }
        }
        break;
      }

      case TX_TYPES.PRESCAN_REVIEW_CONFIRMED: {
        // Reviewer said "AI's flag was right". Transition to state=confirmed
        // + record suggested_origin + start the creator's 24h decision
        // window. confirmed_at_ms uses cert.ts so the auto-escalation
        // trigger can compute the window deterministically across nodes.
        // content.status stays PENDING_REVIEW — the creator is now deciding
        // accept-private (Option 1) vs auto-escalation at h=R+24 (Option 2).
        const review = dag.getPrescanReview(d.review_id);
        if (review) {
          dag.savePrescanReview({
            ...review,
            state: PRESCAN_REVIEW_STATES.CONFIRMED,
            decided_at_round: round,
            confirmed_at_round: round,
            confirmed_at_ms: _committedCertTimestamp || null,
            decision_note: d.decision_note || null,
            suggested_origin: d.suggested_origin,
          });
        }
        break;
      }

      // ── Content ───────────────────────────────────────────────────────
      case TX_TYPES.REGISTER_CONTENT:
        if (d.ctid && !dag.getContent(d.ctid)) {
          // author_tip_id = primary byline (authors[0].tip_id). In
          // self-attribution mode the signer IS the primary byline so
          // this equals signer_tip_id; in employed / hosted modes the
          // signer is the publisher and the byline is a separate human.
          // Fall back to signer_tip_id only if authors[] is missing.
          const primaryByline = Array.isArray(d.authors) && d.authors[0] && d.authors[0].tip_id
            ? d.authors[0].tip_id
            : d.signer_tip_id;
          dag.saveContent({
            ctid: d.ctid,
            origin_code: d.origin_code,
            content_hash: d.content_hash,
            perceptual_hash: d.perceptual_hash || null,
            author_tip_id: primaryByline,
            signer_tip_id: d.signer_tip_id,
            authors: Array.isArray(d.authors) ? d.authors : [],
            attribution_mode: d.attribution_mode || "self",
            extras: (d.extras && typeof d.extras === "object" && !Array.isArray(d.extras)) ? d.extras : {},
            cna_version: d.cna_version,
            // Async-prescan: when REGISTER_CONTENT carries
            // prescan_status='pending' the row lands as PENDING_PRESCAN
            // and waits for PRESCAN_COMPLETED to flip it to
            // REGISTERED/PENDING_REVIEW. Legacy (sync-prescan) txs that
            // didn't carry the field default to "completed", preserving
            // pre-async behaviour where the row is immediately usable.
            status: d.prescan_status === "pending"
              ? CONTENT_STATUS.PENDING_PRESCAN
              : CONTENT_STATUS.REGISTERED,
            prescan_flagged: !!d.prescan_flagged,
            prescan_probability: typeof d.prescan_probability === "number" ? d.prescan_probability : 0,
            prescan_tier: d.prescan_tier || "low",
            prescan_status: d.prescan_status || "completed",
            prescan_assigned_node_id: d.prescan_assigned_node_id || null,
            content_type_hint: d.content_type_hint || null,
            override: !!d.override,
            registered_at: tx.timestamp,
            tx_id: tx.tx_id,
            registered_urls: Array.isArray(d.registered_urls) ? d.registered_urls : [],
          });
        }
        break;

      case TX_TYPES.UPDATE_ORIGIN:
        if (d.ctid && d.new_origin_code) {
          dag.updateContentOrigin(d.ctid, d.new_origin_code, CONTENT_STATUS.REGISTERED);
          // Closing an open review by UPDATE_ORIGIN branches on the
          // review's state at apply time:
          //   - TRIGGERED → CLOSED_SELF_CORRECT (creator beat the
          //     reviewer; reviewer's call was never made).
          //   - CONFIRMED → CLOSED_ACCEPTED_PRIVATE (creator agreed
          //     with the reviewer's finding inside the 24h
          //     accept-private window; reviewer's call counts as
          //     correct for accuracy purposes).
          // Single source of truth: commit-handler decides, route
          // handlers don't need a per-endpoint flag.
          const openReview = dag.getOpenPrescanReviewByCtid(d.ctid);
          if (openReview) {
            const closedState = openReview.state === PRESCAN_REVIEW_STATES.CONFIRMED
              ? PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE
              : PRESCAN_REVIEW_STATES.CLOSED_SELF_CORRECT;
            dag.savePrescanReview({
              ...openReview,
              state: closedState,
              decided_at_round: round,
            });
          }
        }
        break;

      case TX_TYPES.CONTENT_RETRACTED:
        if (d.ctid) {
          dag.updateContentStatus(d.ctid, CONTENT_STATUS.RETRACTED);
        }
        // Author retraction penalty is applied via the unified
        // `_applyScoreEffect(tx)` pass below.
        break;

      // ── Domain binding (org-only) ────────────────────────────────────
      // BIND_DOMAIN is node-attested. The node's attestation lives at
      // tx.signature (verified by the unified dispatcher). The user's
      // prior REGISTER_DOMAIN claim sig rides as a cosignature on
      // tx.data.cosignatures (verified by bind-domain schema verifyTx).
      // Apply the canonical row to domain_bindings; commit-handler is
      // the sole writer so the table stays deterministic and
      // participates in state_merkle_root. The off-chain `evidence`
      // blob is NOT persisted on the binding row — it lives on tx.data
      // for audit replay only.
      case TX_TYPES.BIND_DOMAIN:
        if (d.domain && d.tip_id) {
          // expires_at + consecutive_failures are v2 renewal prep slots
          // (adaptive-expiry RENEW_DOMAIN, deferred). Set deterministically
          // from verified_at — every replicating node computes the same
          // value, so the column stays merkle-consistent across nodes.
          const verifiedMs = d.verified_at;
          const expiresAt = Number.isFinite(verifiedMs)
            ? verifiedMs + DOMAIN_HEALTHY_EXPIRY_MS
            : null;
          // Extract the user's claim sig from the cosignatures entry
          // (signer_kind=subject, signer_ref=tip_id). Stored verbatim on
          // the derived row so reverse-lookup callers get the same flat
          // shape as before.
          const claimCosig = Array.isArray(d.cosignatures)
            ? d.cosignatures.find(c => c && c.signer_kind === "subject" && c.signer_ref === d.tip_id)
            : null;
          dag.saveDomainBinding({
            domain: d.domain,
            tip_id: d.tip_id,
            binding_state: d.binding_state,
            method: d.method,
            claimed_at: d.claimed_at,
            verified_at: d.verified_at,
            expires_at: expiresAt,
            consecutive_failures: 0,
            node_id: d.node_id,
            claim_signature: claimCosig ? claimCosig.signature : null,
            binding_signature: tx.signature,
            tx_id: tx.tx_id,
          });
          // Drop the pending claim on whichever node was holding it.
          // Safe no-op on other nodes (delete-by-key, no-op if absent).
          if (typeof dag.deletePendingDomainClaim === "function") {
            dag.deletePendingDomainClaim(d.domain);
          }
        }
        break;

      // UNBIND_DOMAIN reserved (revocation cascade or explicit owner
      // revoke). No-op until the path is wired in v2 — having the case
      // here keeps the switch exhaustive.
      case TX_TYPES.UNBIND_DOMAIN:
        if (d.domain) {
          const existing = dag.getDomainBinding(d.domain);
          if (existing) {
            dag.saveDomainBinding({ ...existing, binding_state: "revoked" });
          }
        }
        break;

      // ── Social account linking / unlinking ───────────────────────────
      case TX_TYPES.LINK_PLATFORM: {
        if (d.tip_id && d.platform) {
          // Signatures live on the tx envelope (tx.signature = node body
          // sig; tx.data.cosignatures[] = user claim sig). The row stores
          // only display state + tx_id so verifiers can join back.
          dag.savePlatformLink({
            id: `${d.tip_id}::${d.platform}`,
            tip_id: d.tip_id,
            platform: d.platform,
            handle: d.handle ?? null,
            profile_url: d.profile_url,
            status: "active",
            linked_at: d.claimed_at,
            verified_at: d.verified_at,
            unlinked_at: null,
            unlink_tx_id: null,
            node_id: d.node_id,
            tx_id: tx.tx_id,
          });
        }
        break;
      }

      case TX_TYPES.UNLINK_PLATFORM: {
        if (d.tip_id && d.platform) {
          // SUBJECT-signed: the canonical body has no unlinked_at field
          // (only claimed_at, platform, tip_id). tx.timestamp is the
          // user-signed envelope time — use it as the on-chain unlink
          // moment so platform_links carries a deterministic value.
          dag.updatePlatformLinkStatus(d.tip_id, d.platform, {
            status: "unlinked",
            unlinked_at: tx.timestamp,
            unlink_tx_id: tx.tx_id,
          });
        }
        break;
      }

      // ── Verification ──────────────────────────────────────────────────
      case TX_TYPES.CONTENT_VERIFIED:
        // Score effect handled by scoring.computeScore() replay (reads weighted_delta from tx.data)
        // Update content status: registered → verified on first verification
        if (d.ctid) {
          const content = dag.getContent(d.ctid);
          if (content && content.status === CONTENT_STATUS.REGISTERED) {
            dag.updateContentStatus(d.ctid, CONTENT_STATUS.VERIFIED);
          }
        }
        break;

      // ── Dispute ───────────────────────────────────────────────────────
      case TX_TYPES.CONTENT_DISPUTED:
        if (d.ctid) {
          dag.updateContentStatus(d.ctid, CONTENT_STATUS.DISPUTED);
          // Phase 2.5: if this dispute lands while a review is in
          // state=confirmed (the creator's 24h decision window), the
          // review is now resolved by auto-escalation. Flip its state
          // so the trigger module won't re-escalate next round.
          // Applies to both auto-cascade (h=R+24 system) and
          // user-initiated disputes that arrive during the window.
          const openReview = dag.getOpenPrescanReviewByCtid(d.ctid);
          if (openReview && openReview.state === PRESCAN_REVIEW_STATES.CONFIRMED) {
            dag.savePrescanReview({
              ...openReview,
              state: PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE,
              decided_at_round: round,
            });
          }
        }
        break;

      // ── Adjudication ──────────────────────────────────────────────────
      case TX_TYPES.ADJUDICATION_RESULT:
        if (d.ctid) {
          if (d.verdict === VERDICT.DISMISSED || d.verdict === VERDICT.CONSERVATIVE_LABEL) {
            dag.updateContentStatus(d.ctid, _postResolutionStatus(d.pre_dispute_status));
          } else if (d.verdict === VERDICT.UPHELD && d.confirmed_origin) {
            dag.updateContentOrigin(d.ctid, d.confirmed_origin, CONTENT_STATUS.VERIFIED);
          }
        }
        // Author-penalty side-effects (juror bonuses, no-show penalties,
        // disputer outcome) ride on the SCORE_UPDATE txs in the same batch
        // produced by `jury.buildAdjudicationBatch`. Author penalty itself
        // is applied via computeScore replay reading author_score_delta.
        break;

      case TX_TYPES.APPEAL_RESULT:
        if (d.ctid) {
          // #15 — appeal content-state effects extracted from jury.js
          // (which used to mutate dag directly). Carries enough state in
          // tx.data to be deterministic across all nodes.
          if (d.overturned) {
            if (d.stage2_verdict === VERDICT.UPHELD && d.declared_origin) {
              // Stage 2 said UPHELD; experts say DISMISSED → restore original
              // origin + pre-dispute status.
              dag.updateContentOrigin(d.ctid, d.declared_origin, _postResolutionStatus(d.pre_dispute_status));
            } else if (d.stage2_verdict === VERDICT.DISMISSED && d.confirmed_origin) {
              // Stage 2 said DISMISSED; experts say UPHELD → set verified
              // with the experts' confirmed origin.
              dag.updateContentOrigin(d.ctid, d.confirmed_origin, CONTENT_STATUS.VERIFIED);
            }
          } else {
            // Appeal confirmed Stage 2.
            if (d.verdict === VERDICT.UPHELD && d.confirmed_origin) {
              dag.updateContentOrigin(d.ctid, d.confirmed_origin, CONTENT_STATUS.VERIFIED);
            } else if (d.verdict === VERDICT.DISMISSED) {
              dag.updateContentStatus(d.ctid, _postResolutionStatus(d.pre_dispute_status));
            }
          }
        }
        // Score-effects for appellant/disputer/experts/author-reversal are
        // emitted as SCORE_UPDATE txs in the same batch by
        // `jury.buildAppealBatch`, and applied by the SCORE_UPDATE case
        // below. Stage-2 adjudication offense reversal (offense_count--)
        // is handled by computeScore on replay (reads `overturned` flag).
        break;

      // ── Revocations ───────────────────────────────────────────────────
      case TX_TYPES.REVOKE_VOLUNTARY:
      case TX_TYPES.REVOKE_VP:
      case TX_TYPES.REVOKE_DECEASED:
      case TX_TYPES.REVOKE_DEVICE:
        if (d.tip_id && !dag.isRevoked(d.tip_id)) {
          dag.addRevocation(d.tip_id, tx.tx_type, tx.timestamp, tx.tx_id);
        }
        break;

      // ── Governance ────────────────────────────────────────────────────
      // GH #60: public_key + algorithm auto-route to entity_keys via
      // saveVP / saveNode. tx_id is passed (accepted-but-ignored by
      // the main row, used by the auto-router as entity_keys.source_tx_id
      // so the key history can be traced back to the registration tx).
      case TX_TYPES.VP_REGISTERED:
        if (d.vp_id && !dag.getVP(d.vp_id)) {
          dag.saveVP({
            vp_id: d.vp_id,
            name: d.name || "",
            jurisdiction: d.jurisdiction || "US",
            jurisdiction_tier: d.jurisdiction_tier || "green",
            public_key: d.public_key || "",
            algorithm: d.algorithm || "ml-dsa-65",
            status: "active",
            registered_at: tx.timestamp,
            tx_id: tx.tx_id,
          });
        }
        break;

      case TX_TYPES.NODE_REGISTERED:
        if (d.node_id && !dag.getNode(d.node_id)) {
          dag.saveNode({
            node_id: d.node_id,
            name: d.name || "",
            public_key: d.public_key || "",
            algorithm: d.algorithm || "ml-dsa-65",
            status: "active",
            registered_at: tx.timestamp,
            tx_id: tx.tx_id,
          });
        }
        break;

      // Interest taxonomy extension. Slug uniqueness already enforced by
      // schemas/interest-registered.verifyTx in _statefulCheck — by the
      // time we land here, the slug is guaranteed new. saveInterest is
      // INSERT OR REPLACE / merge so a duplicate replay is a no-op.
      case TX_TYPES.INTEREST_REGISTERED:
        if (d.slug && d.label && d.category && d.approving_vp_id) {
          dag.saveInterest({
            slug:                d.slug,
            label:               d.label,
            category:            d.category,
            registered_at:       tx.timestamp,
            registered_by_vp_id: d.approving_vp_id,
            tx_id:               tx.tx_id,
          });
        }
        break;

      // SCORE_UPDATE has no derived state beyond the score itself; the
      // row write lands via the unified `_applyScoreEffect(tx)` pass
      // below. First-wins dedup (tip_id + ctid + reason) gates upstream
      // in `_validateBusinessRules`.
      case TX_TYPES.SCORE_UPDATE:
        break;

      // ── Key rotation + recovery (GH #60) ─────────────────────────────
      // Close the prior active entity_keys row (set valid_to_ts =
      // effective_at) and append the NEW active row. Both writes happen
      // inside the surrounding commit-handler transaction so the
      // identity always has exactly one active key. For KEY_ROTATED the
      // old key signed the tx (dispatcher resolved it via
      // getKeyValidAt at tx.timestamp, when the OLD key was still
      // active). For KEY_RECOVERY the VP signed.
      case TX_TYPES.KEY_ROTATED:
      case TX_TYPES.KEY_RECOVERY:
        if (d.tip_id && d.new_public_key) {
          const prev = dag.getActiveKey("identity", d.tip_id);
          const algorithm = d.algorithm || "ml-dsa-65";
          const effectiveAt = Number(d.effective_at);
          // Close the prior active row at effective_at.
          if (prev) {
            // We don't have a direct closeActiveKey API on the public
            // dag handle (intentional — auto-router handles new key
            // rotation transparently). Use saveEntityKey to write a
            // replacement row with valid_to_ts set. We need the prior
            // row's valid_from_ts to re-write its primary key — pull
            // it via iterateEntityKeys.
            for (const r of dag.iterateEntityKeys()) {
              if (r.entity_type === "identity"
                && r.entity_id === d.tip_id
                && r.valid_to_ts == null) {
                dag.saveEntityKey({
                  entity_type: "identity",
                  entity_id: d.tip_id,
                  public_key: r.public_key,
                  algorithm: r.algorithm,
                  valid_from_ts: r.valid_from_ts,
                  valid_to_ts: effectiveAt,
                  source_tx_id: r.source_tx_id,
                });
                break;
              }
            }
          }
          // Insert the new active row.
          dag.saveEntityKey({
            entity_type: "identity",
            entity_id: d.tip_id,
            public_key: d.new_public_key,
            algorithm,
            valid_from_ts: effectiveAt,
            valid_to_ts: null,
            source_tx_id: tx.tx_id,
          });
        }
        break;

      // ── Committee rotation (§4 + #34 — chain-of-trust) ───────────────
      // Tx already passed _verifyTxSignature (≥2f+1 sigs from previous
      // committee) and _dedupCheck (rotation_number monotonic) and
      // _statefulCheck (effective_round monotonic, well-formed committee).
      // All that's left is to persist the row to committee_history.
      // saveCommitteeRotation uses INSERT OR IGNORE so a re-replay of
      // the same tx is a no-op (matches replay semantics elsewhere).
      //
      // committed_at: prefer the BFT-Time `_committedCertTimestamp`
      // (median of acks.signed_at at this anchor commit, deterministic
      // across nodes) over `tx.timestamp`. Post-#81 tx.timestamp is a
      // synthetic value derived from effective_round (deterministic but
      // not a meaningful wall-clock — would log "1970-01-01..." in
      // committee_history.committed_at). The cert timestamp gives a real
      // wall-clock that's STILL deterministic across nodes via BFT-Time
      // consensus. Falls back to tx.timestamp if certTimestamp wasn't
      // plumbed (test/legacy paths).
      case TX_TYPES.COMMITTEE_ROTATION: {
        // Split tx.data.cosignatures back into the parallel-array storage
        // shape (committee_history columns). Sort order on tx.data is
        // signer_ref ASC; preserve it here so the stored rows match.
        const cosigs = Array.isArray(d.cosignatures) ? d.cosignatures : [];
        const signer_node_ids = [];
        const signatures = [];
        for (const c of cosigs) {
          if (c && c.signer_kind === "node" && typeof c.signer_ref === "string" && typeof c.signature === "string") {
            signer_node_ids.push(c.signer_ref);
            signatures.push(c.signature);
          }
        }
        dag.saveCommitteeRotation({
          rotation_number: d.rotation_number,
          effective_round: d.effective_round,
          committee: d.new_committee,
          prev_rotation: d.rotation_number - 1,
          signer_node_ids,
          signatures,
          payload_hash: d.payload_hash,
          committed_at: _committedCertTimestamp > 0
            ? _committedCertTimestamp
            : tx.timestamp,
        });
        break;
      }

      // ── No additional derived state needed ──
      case TX_TYPES.JURY_SUMMONS:
      case TX_TYPES.JURY_VOTE_COMMIT:
      case TX_TYPES.JURY_VOTE_REVEAL:
      case TX_TYPES.AI_CLASSIFIER_RESULT:
      case TX_TYPES.APPEAL_FILED:
        break;

      default:
        log.debug(`No derived state handler for tx type: ${tx.tx_type}`);
        break;
    }

    // Unified score effect — single source of truth shared with
    // scoring.computeScore replay (#38). For tx types that don't
    // affect a score, scoreTargetTipId(tx) returns null and this is a
    // no-op. The scores table is part of state_merkle_root, so this
    // write must be deterministic across every node — hence it goes
    // through the same pure function as the read-only replay.
    _applyScoreEffect(tx);

    // Verdict-trigger heap maintenance. Single dispatch, no caller-side
    // tx-type filter — the trigger's own switch (with default: return)
    // decides relevance. Keeping the list in one place avoids drift:
    // the previous design buried this call inside _applyScoreEffect's
    // score-target gate, which silently skipped JURY_SUMMONS (no score
    // effect) and left the heap empty in steady state, so verdicts
    // never fired naturally between restarts.
    if (verdictTrigger) {
      try {
        verdictTrigger.onTxCommitted(tx);
      } catch (err) {
        // Heap-state update failure is non-fatal — the next checkPending
        // will rescan as needed. Log so we notice persistent issues.
        log.warn(`verdict-trigger.onTxCommitted(${tx.tx_type}) failed: ${err.message}`);
      }
    }
  }

  /**
   * Apply the tx's score effect to the scores table. Sole writer for
   * scores rows in commit-handler — closes the dual-writer divergence
   * documented in issues.md Node #38.
   */
  function _applyScoreEffect(tx) {
    const target = scoreTargetTipId(tx);
    if (!target) return;

    const row = dag.getScore(target);
    const cur = row
      ? { score: row.score, offense_count: row.offense_count, frozen: false }
      : initialState();

    const next = applyScoreEffect(tx, cur);

    // Skip a write only when (a) the row already exists AND (b) nothing
    // changed. REGISTER_IDENTITY for a brand-new identity leaves the
    // score at score.initial_identity unchanged from cur.score, but the
    // row still has to be written so the scores table contains every
    // registered tip_id (state_merkle_root determinism, #31).
    if (row && next.score === cur.score && next.offense_count === cur.offense_count) {
      return;
    }
    // last_updated from tx.timestamp — same value on every node so the
    // scores row stays in state_merkle_root (issues.md Consensus #31).
    dag.setScore(target, next.score, next.offense_count, tx.timestamp);
  }

  /**
   * Verify the signature on a transaction.
   *
   * GH #51 — single dispatch path: every tx type's signature contract
   * (scope, signer kind, canonical payload) lives in ONE place:
   *
   *   - a per-tx-type schema module in `node/src/schemas/` for tx types
   *     with non-trivial logic (validateRequest, resolveSubject, etc.)
   *   - the registry in `node/src/schemas/_registry.js` for tx types
   *     without a full schema module (most node-emitted envelopes plus
   *     trivial body-signed shapes)
   *
   * The unified `verifyTxSignature(tx, schema, dag)` helper resolves the
   * contract and verifies `tx.signature` against the right key /
   * payload / algorithm. Returns false here on any failure so the caller
   * (`commitOrderedTxs`) treats it as a rejection.
   *
   * Two tx types diverge from the unified single-signature model:
   *
   *   - COMMITTEE_ROTATION is structurally aggregate-signed. The 2f+1
   *     previous-committee sigs over `data.payload_hash` ride as
   *     cosignatures on `tx.data.cosignatures` (signer_kind=node,
   *     signer_ref=node_id). Full cryptographic verification (each sig
   *     valid, signer is in previous committee, quorum reached) runs in
   *     `rules.canCommitteeRotation` from `_statefulCheck` — that layer
   *     has the inputs the generic cosignatures dispatcher doesn't:
   *     previous-committee composition from `committee_history`.
   *     `tx.signature` is NOT used because:
   *       (a) `tx_id` must be byte-identical across all honest
   *           submitters; placing a submitter-derived sig on the
   *           envelope would break that contract under multi-aggregator
   *           submission;
   *       (b) the proposer's signature already lives in
   *           `data.cosignatures` — adding it to `tx.signature`
   *           duplicates state.
   *     So this case gates only on `cosignatures.length > 0` here; the
   *     real check is in `_statefulCheck`.
   *
   *   - Cosignatures (tx.data.cosignatures[]) — additional signers
   *     beyond `tx.signature`. The schema (module or registry entry)
   *     declares the contract via `getCosignatureContract(tx)` and
   *     verifyCosignatures from `_common` resolves each cosigner's key
   *     via dag.getKeyValidAt at tx.timestamp. Used today by
   *     BIND_DOMAIN (user's claim sig) and CONTENT_DISPUTED auto+manual
   *     (creator's escalation authorisation).
   */
  function _verifyTxSignature(tx) {
    const tt = tx.tx_type;
    const d = tx.data || {};

    if (tt === TX_TYPES.COMMITTEE_ROTATION) {
      return Array.isArray(d.cosignatures) && d.cosignatures.length > 0;
    }

    try {
      const schema = SCHEMA_FOR_TX_TYPE[tt] || null;
      const result = unifiedVerifyTxSignature(tx, schema, dag);
      if (!result.ok) {
        log.warn(`Round-replay signature check failed for ${tt} tx ${tx.tx_id?.slice(0, 16)}: ${result.error}`);
        return false;
      }

      // Cosignatures: schema declares the contract (per-tx_type, may be
      // empty). Dispatcher resolves keys and verifies each entry.
      const cosigSource = schema && typeof schema.getCosignatureContract === "function"
        ? schema
        : (TX_SIGNATURE_REGISTRY[tt] && typeof TX_SIGNATURE_REGISTRY[tt].getCosignatureContract === "function"
            ? TX_SIGNATURE_REGISTRY[tt]
            : null);
      if (cosigSource) {
        const contract = cosigSource.getCosignatureContract(tx) || [];
        if (contract.length > 0) {
          const cosigResult = verifyCosignatures(tx, contract, dag);
          if (!cosigResult.ok) {
            log.warn(`Cosignature check failed for ${tt} tx ${tx.tx_id?.slice(0, 16)}: ${cosigResult.error}`);
            return false;
          }
        }
      }

      return true;
    } catch (err) {
      log.warn(`Signature verification error for ${tt} tx ${tx.tx_id?.slice(0, 16)}: ${err.message}`);
      return false;
    }
  }

  return { commitOrderedTxs };
}

module.exports = { createCommitHandler };
