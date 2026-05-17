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

const { TX_TYPES, CONTENT_STATUS, VERDICT, TX_REJECTION_REASON, DOMAIN_HEALTHY_EXPIRY_MS } = require("../../../shared/constants");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const contentRegisterSchema = require("../schemas/content-register");
const registerIdentitySchema = require("../schemas/register-identity");
const bindDomainSchema = require("../schemas/bind-domain");
const updateProfileSchema = require("../schemas/update-profile");
const { applyScoreEffect, scoreTargetTipId, initialState } = require("../score-effects");
const { verifyBodySignature, mldsaVerify, canonicalTx, canonicalJson, shake256 } = require("../../../shared/crypto");
const { createRejectionSink } = require("./tx-rejection-sink");
const { getLogger } = require("../logger");

const log = getLogger("tip.commit");

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
function createCommitHandler({ dag, scoring, verdictTrigger, cleanRecordTrigger, config, nodeId }) {
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
   *                                     bonus eligibility, replacing scheduler-driven Date.now().
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
            _applyDerivedState(tx, certTimestamp);
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
    const txMs = new Date(tx.timestamp).getTime();
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
        const r = rules.canRegisterIdentity(dag, { dedup_hash: d.dedup_hash, vp_id: d.vp_id });
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
        return r.valid ? { valid: true } : { valid: false, error: r.error.message };
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

      default:
        return { valid: true };
    }
  }

  /**
   * Apply derived state updates for a committed transaction.
   * Handles all tx types — identity, content, dispute, jury, appeal, revocation, governance.
   */
  function _applyDerivedState(tx, _committedCertTimestamp = 0) {
    const d = tx.data || {};

    switch (tx.tx_type) {

      // ── Identity ──────────────────────────────────────────────────────
      case TX_TYPES.REGISTER_IDENTITY:
        if (d.dedup_hash && !dag.hasDedupHash(d.dedup_hash)) {
          // Unix seconds derived from the tx timestamp (deterministic across nodes).
          dag.addDedupHash(d.dedup_hash, Math.floor(new Date(tx.timestamp).getTime() / 1000));
        }
        if (d.tip_id && !dag.getIdentity(d.tip_id)) {
          dag.saveIdentity({
            tip_id: d.tip_id,
            region: d.region || "US",
            public_key: d.public_key || "",
            root_public_key: d.root_public_key || "",
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
            status: d.prescan_flagged ? CONTENT_STATUS.PENDING_REVIEW : CONTENT_STATUS.REGISTERED,
            prescan_flagged: !!d.prescan_flagged,
            prescan_probability: typeof d.prescan_probability === "number" ? d.prescan_probability : 0,
            prescan_tier: d.prescan_tier || "low",
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
      // BIND_DOMAIN is node-attested (binding_signature in tx.data).
      // _verifyTxSignature has already validated both the node sig and
      // the embedded user claim sig. Apply the canonical row to
      // domain_bindings; commit-handler is the sole writer so the table
      // stays deterministic and participates in state_merkle_root. The
      // off-chain `evidence` blob is NOT persisted on the binding row —
      // it lives on tx.data for audit replay only.
      case TX_TYPES.BIND_DOMAIN:
        if (d.domain && d.tip_id) {
          // expires_at + consecutive_failures are v2 renewal prep slots
          // (adaptive-expiry RENEW_DOMAIN, deferred). Set deterministically
          // from verified_at — every replicating node computes the same
          // value, so the column stays merkle-consistent across nodes.
          const verifiedMs = Date.parse(d.verified_at);
          const expiresAt = Number.isFinite(verifiedMs)
            ? new Date(verifiedMs + DOMAIN_HEALTHY_EXPIRY_MS).toISOString()
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
            claim_signature: d.claim_signature,
            binding_signature: d.binding_signature,
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
        }
        break;

      // ── Adjudication ──────────────────────────────────────────────────
      case TX_TYPES.ADJUDICATION_RESULT:
        if (d.ctid) {
          if (d.verdict === VERDICT.DISMISSED || d.verdict === VERDICT.CONSERVATIVE_LABEL) {
            dag.updateContentStatus(d.ctid, d.pre_dispute_status || CONTENT_STATUS.REGISTERED);
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
              dag.updateContentOrigin(d.ctid, d.declared_origin, d.pre_dispute_status || CONTENT_STATUS.REGISTERED);
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
              dag.updateContentStatus(d.ctid, d.pre_dispute_status || CONTENT_STATUS.REGISTERED);
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
      case TX_TYPES.VP_REGISTERED:
        if (d.vp_id && !dag.getVP(d.vp_id)) {
          dag.saveVP({
            vp_id: d.vp_id,
            name: d.name || "",
            jurisdiction: d.jurisdiction || "US",
            jurisdiction_tier: d.jurisdiction_tier || "green",
            public_key: d.public_key || "",
            status: "active",
            registered_at: tx.timestamp,
          });
        }
        break;

      case TX_TYPES.NODE_REGISTERED:
        if (d.node_id && !dag.getNode(d.node_id)) {
          dag.saveNode({
            node_id: d.node_id,
            name: d.name || "",
            public_key: d.public_key || "",
            status: "active",
            registered_at: tx.timestamp,
          });
        }
        break;

      // SCORE_UPDATE has no derived state beyond the score itself; the
      // row write lands via the unified `_applyScoreEffect(tx)` pass
      // below. First-wins dedup (tip_id + ctid + reason) gates upstream
      // in `_validateBusinessRules`.
      case TX_TYPES.SCORE_UPDATE:
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
      case TX_TYPES.COMMITTEE_ROTATION:
        dag.saveCommitteeRotation({
          rotation_number: d.rotation_number,
          effective_round: d.effective_round,
          committee: d.new_committee,
          prev_rotation: d.rotation_number - 1,
          signer_node_ids: d.signer_node_ids || [],
          signatures: d.signatures || [],
          payload_hash: d.payload_hash,
          committed_at: _committedCertTimestamp > 0
            ? new Date(_committedCertTimestamp).toISOString()
            : tx.timestamp,
        });
        break;

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
   * Verify body/node signature on a transaction.
   * Returns true only if the signature is verified against a known signer from our registry.
   * Returns false if unknown tx type, missing signer, or invalid signature.
   */
  function _verifyTxSignature(tx) {
    const d = tx.data || {};
    const tt = tx.tx_type;

    try {
      if (tt === TX_TYPES.REGISTER_CONTENT) {
        // Single canonical path (CNA-2.2). The schemas/content-register
        // module owns the field list, canonical-payload builder, and
        // verifier. Same module the API used at submit time, so the two
        // sides cannot drift. Spec: docs/CONTENT_SIGNING.md.
        return contentRegisterSchema.verifyTx(tx, dag).ok;
      }

      if (tt === TX_TYPES.REGISTER_IDENTITY) {
        // Single canonical path. The schemas/register-identity module
        // owns the canonical payload, builder, and verifier — same
        // module identity-service.register uses at API time.
        return registerIdentitySchema.verifyTx(tx, dag).ok;
      }

      if (tt === TX_TYPES.UPDATE_PROFILE) {
        // Sparse update of user-settable identity fields. The schema
        // module owns the canonical payload (tip_id + present known
        // fields) and signature verification against the user's own
        // identity public key.
        return updateProfileSchema.verifyTx(tx, dag).ok;
      }

      if (tt === TX_TYPES.BIND_DOMAIN) {
        // Dual-signature: schemas/bind-domain.verifyTx checks both the
        // verifying node's ML-DSA-65 attestation AND the embedded user
        // claim signature. Replicating nodes do NOT re-perform DNS / HTTP
        // (would diverge across nodes / time).
        return bindDomainSchema.verifyTx(tx, dag).ok;
      }

      if (tt === TX_TYPES.UNBIND_DOMAIN) {
        return bindDomainSchema.verifyUnbindTx(tx, dag).ok;
      }

      if (tt === TX_TYPES.CONTENT_VERIFIED) {
        const verifier = dag.getIdentity(d.verifier_tip_id);
        if (!verifier || !d.signature) return false;
        return verifyBodySignature(d, d.signature, verifier.public_key, ["verifier_tip_id", "verdict"]);
      }

      if (tt === TX_TYPES.UPDATE_ORIGIN) {
        const author = dag.getIdentity(d.author_tip_id);
        if (!author || !d.signature) return false;
        return verifyBodySignature(d, d.signature, author.public_key, ["author_tip_id", "new_origin_code"]);
      }

      if (tt === TX_TYPES.CONTENT_RETRACTED) {
        const author = dag.getIdentity(d.author_tip_id);
        if (!author || !d.signature) return false;
        return verifyBodySignature(d, d.signature, author.public_key, ["author_tip_id"]);
      }

      if (tt === TX_TYPES.CONTENT_DISPUTED) {
        if (d.auto) {
          const node = dag.getNode(d.node_id);
          if (!node || !tx.signature) return false;
          return mldsaVerify(canonicalTx(tx), tx.signature, node.public_key);
        }
        const disputer = dag.getIdentity(d.disputer_tip_id);
        if (!disputer || !d.signature) return false;
        // Mirror dispute-service.fileDispute and the UI: claimed_origin and
        // evidence_hash are only in the signed fields when truthy. The on-wire
        // tx data carries them as `null` when absent, but verifyBodySignature
        // treats `null !== undefined` as "defined", so listing them
        // unconditionally would diverge from the signer. Same drift class as
        // #54 / #55 / #56.
        const disputeFields = ["disputer_tip_id", "reason"];
        if (d.claimed_origin) disputeFields.push("claimed_origin");
        if (d.evidence_hash) disputeFields.push("evidence_hash");
        return verifyBodySignature(d, d.signature, disputer.public_key, disputeFields);
      }

      if (tt === TX_TYPES.JURY_VOTE_COMMIT) {
        const juror = dag.getIdentity(d.juror_tip_id);
        if (!juror || !d.signature) return false;
        return verifyBodySignature(d, d.signature, juror.public_key, ["juror_tip_id", "commitment"]);
      }

      if (tt === TX_TYPES.JURY_VOTE_REVEAL) {
        const juror = dag.getIdentity(d.juror_tip_id);
        if (!juror || !d.signature) return false;
        const fields = d.confirmed_origin ? ["juror_tip_id", "vote", "salt", "confirmed_origin"] : ["juror_tip_id", "vote", "salt"];
        return verifyBodySignature(d, d.signature, juror.public_key, fields);
      }

      if (tt === TX_TYPES.APPEAL_FILED) {
        if (d.appellant_tip_id === "SYSTEM_AUTO_ESCALATION") {
          // Auto-escalated by node on NO_QUORUM — verify node signature
          const node = dag.getNode(d.node_id);
          if (!node || !tx.signature) return false;
          return mldsaVerify(canonicalTx(tx), tx.signature, node.public_key);
        }
        // User-filed appeal — verify appellant signature
        const appellant = dag.getIdentity(d.appellant_tip_id);
        if (!appellant || !d.signature) return false;
        return verifyBodySignature(d, d.signature, appellant.public_key, ["appellant_tip_id"]);
      }

      if ([TX_TYPES.REVOKE_VOLUNTARY, TX_TYPES.REVOKE_VP, TX_TYPES.REVOKE_DECEASED, TX_TYPES.REVOKE_DEVICE].includes(tt)) {
        const vp = dag.getVP(d.issuing_vp_id);
        if (!vp || !d.signature) return false;
        return verifyBodySignature(d, d.signature, vp.public_key,
          ["tx_type", "tip_id", "reason_code", "evidence_hash", "issuing_vp_id"]);
      }

      if (tt === TX_TYPES.VP_REGISTERED || tt === TX_TYPES.NODE_REGISTERED) {
        const vp = dag.getVP(d.approving_vp_id);
        if (!vp || !d.council_signature) return false;
        const fields = tt === TX_TYPES.VP_REGISTERED
          ? ["name", "jurisdiction", "jurisdiction_tier", "public_key", "approving_vp_id"]
          : ["name", "public_key", "approving_vp_id"];
        return verifyBodySignature(d, d.council_signature, vp.public_key, fields);
      }

      const NODE_SIGNED = [TX_TYPES.SCORE_UPDATE, TX_TYPES.ADJUDICATION_RESULT, TX_TYPES.APPEAL_RESULT,
      TX_TYPES.JURY_SUMMONS, TX_TYPES.AI_CLASSIFIER_RESULT];
      if (NODE_SIGNED.includes(tt)) {
        const node = dag.getNode(d.node_id);
        if (!node || !tx.signature) return false;
        return mldsaVerify(canonicalTx(tx), tx.signature, node.public_key);
      }

      if (tt === TX_TYPES.COMMITTEE_ROTATION) {
        // §4 + #34: signatures + payload_hash + previous-committee quorum
        // are validated by `rules.canCommitteeRotation` from `_statefulCheck`.
        // Treat presence-of-signatures as enough at the signature-verify
        // stage; the real crypto check runs alongside the other rotation
        // invariants in the shared predicate so accept/reject is one place.
        return Array.isArray(d.signatures) && d.signatures.length > 0;
      }

    } catch (err) {
      log.warn(`Signature verification error for ${tt} tx ${tx.tx_id?.slice(0, 16)}: ${err.message}`);
      return false;
    }

    // Unknown tx type — reject
    log.warn(`Rejected unknown tx type: ${tt}`);
    return false;
  }

  return { commitOrderedTxs };
}

module.exports = { createCommitHandler };
