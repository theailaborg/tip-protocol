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

const { TX_TYPES, CONTENT_STATUS, VERDICT } = require("../../../shared/constants");
const { SCORE_EVENTS } = require("../../../shared/protocol-constants");
const { validateTransaction } = require("../validators/tx-validator");
const { verifyBodySignature, mldsaVerify, canonicalTx } = require("../../../shared/crypto");
const { getLogger } = require("../logger");

const log = getLogger("tip.commit");

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
function createCommitHandler({ dag, verdictTrigger, cleanRecordTrigger }) {

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
        log.warn(`Round ${round}: rejected tx ${tx.tx_id.slice(0, 16)} (${tx.tx_type}) — ${validation.errors.join("; ")}`);
        dropped++;
        continue;
      }

      // Verify signature
      if (!_verifyTxSignature(tx)) {
        log.warn(`Round ${round}: rejected tx ${tx.tx_id.slice(0, 16)} (${tx.tx_type}) — signature failed`);
        dropped++;
        continue;
      }

      // Business-rule guard — first-wins dedup for verdict txs and
      // reveal-window enforcement for jury reveals. Closes #15 (and the
      // multi-submitter race in #13: when N nodes' schedulers each
      // produce a verdict batch for the same dispute, only the first
      // ordered ADJUDICATION_RESULT/APPEAL_RESULT lands per ctid; later
      // duplicates and their score-update effects are dropped silently).
      const business = _validateBusinessRules(tx, validated);
      if (!business.valid) {
        log.debug(`Round ${round}: dropped duplicate ${tx.tx_type} ${tx.tx_id.slice(0, 16)} — ${business.error}`);
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
            _applyDerivedState(tx);
            committed++;
          }
          // Remove committed txs from mempool in the same transaction
          const txIds = validated.map(t => t.tx_id);
          dag.deleteMempoolTxs(txIds);
        });
      } catch (err) {
        log.error(`Round ${round}: transaction commit failed — rolled back ${validated.length} txs: ${err.message}`);
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
  function _validateBusinessRules(tx, validated) {
    const d = tx.data || {};
    switch (tx.tx_type) {

      case TX_TYPES.ADJUDICATION_RESULT: {
        if (!d.ctid) return { valid: false, error: "missing ctid" };
        const existing = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, d.ctid);
        if (existing.length > 0) {
          return { valid: false, error: `ADJUDICATION_RESULT already exists for ${d.ctid}` };
        }
        const inBatch = validated.find(t =>
          t.tx_type === TX_TYPES.ADJUDICATION_RESULT && t.data?.ctid === d.ctid
        );
        if (inBatch) return { valid: false, error: `ADJUDICATION_RESULT already in this batch for ${d.ctid}` };
        return { valid: true };
      }

      case TX_TYPES.APPEAL_RESULT: {
        if (!d.ctid) return { valid: false, error: "missing ctid" };
        const existing = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_RESULT, d.ctid);
        if (existing.length > 0) {
          return { valid: false, error: `APPEAL_RESULT already exists for ${d.ctid}` };
        }
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

      case TX_TYPES.JURY_VOTE_REVEAL: {
        // Reveal-window enforcement — every honest node sees the same
        // tx.timestamp and the same JURY_SUMMONS.reveal_deadline (both
        // frozen consensus state), so the accept/reject decision is
        // deterministic. This is the third guard from issue #13's design:
        // verdict batches built later read only in-window reveals, so
        // every node ends up with the same reveal set even when reveals
        // arrive at different wall-clock instants.
        if (!d.ctid || !d.juror_tip_id) return { valid: true };
        // Coerce both `is_appeal` values to booleans — `undefined` and
        // `false` are semantically equivalent here but strict `===` would
        // treat them as different, causing the matching summons to be
        // missed (and the guard to silently no-op).
        const isAppealReveal = !!d.is_appeal;
        const summons = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, d.ctid)
          .find(s => s.data?.juror_tip_id === d.juror_tip_id
            && (!!s.data?.is_appeal) === isAppealReveal);
        if (!summons) return { valid: true };  // no summons → schema layer rejects elsewhere
        const deadlineMs = new Date(summons.data.reveal_deadline).getTime();
        const txMs = new Date(tx.timestamp).getTime();
        if (Number.isFinite(deadlineMs) && Number.isFinite(txMs) && txMs > deadlineMs) {
          return { valid: false, error: `reveal arrived after deadline (${tx.timestamp} > ${summons.data.reveal_deadline})` };
        }
        return { valid: true };
      }

      default:
        return { valid: true };
    }
  }

  /**
   * Apply derived state updates for a committed transaction.
   * Handles all tx types — identity, content, dispute, jury, appeal, revocation, governance.
   */
  function _applyDerivedState(tx) {
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
            founding: d.founding || false,
            status: "active",
            registered_at: tx.timestamp,
            tx_id: tx.tx_id,
            // #55: forward creator_name from tx.data so the VP-attested
            // display name persists in the DAG row. Column already exists
            // on `identities` (dag.js); this was the missing forward-through.
            creator_name: d.creator_name || null,
          });
          // Initial score. last_updated is sourced from tx.timestamp so
          // every node writes the same row and the scores table is part
          // of state_merkle_root (issues.md Consensus #31).
          if (d.tip_id) {
            const initial = d.social_attested || d.attested ? 550 : 500;
            dag.setScore(d.tip_id, initial, 0, tx.timestamp);
          }
        }
        break;

      // ── Content ───────────────────────────────────────────────────────
      case TX_TYPES.REGISTER_CONTENT:
        if (d.ctid && !dag.getContent(d.ctid)) {
          dag.saveContent({
            ctid: d.ctid,
            origin_code: d.origin_code,
            content_hash: d.content_hash,
            perceptual_hash: d.perceptual_hash || null,
            author_tip_id: d.author_tip_id,
            status: d.prescan_flagged ? CONTENT_STATUS.PENDING_REVIEW : CONTENT_STATUS.REGISTERED,
            registered_at: tx.timestamp,
            tx_id: tx.tx_id,
            // #54: forward registered_url so the URL persists in the DAG row.
            // The column already exists on `content` (dag.js); this was the
            // missing forward-through from tx.data.
            registered_url: d.registered_url || null,
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
          if (d.author_tip_id) {
            // Apply the retraction penalty directly to the score cache —
            // every node runs this on the same committed CONTENT_RETRACTED
            // tx, so the cache mutation is deterministic. computeScore()
            // replays the same delta from CONTENT_RETRACTED on a from-
            // scratch recompute. Used to call `scoring.applyScoreEvent`,
            // which wrote a synthetic SCORE_UPDATE tx with a non-
            // deterministic timestamp from inside commit-handler — that's
            // the path that forced the `fromSync=true` prev-skip workaround.
            const cur = dag.getScore(d.author_tip_id) || { score: 500, offense_count: 0 };
            const next = Math.max(0, Math.min(1000, cur.score + SCORE_EVENTS.CONTENT_RETRACTION.delta));
            dag.setScore(d.author_tip_id, next, cur.offense_count, tx.timestamp);
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

      // ── Score update — applies cache mutation deterministically (#15) ──
      // Replaces the in-line scoring.applyScoreEvent calls that
      // jury.tallyVerdictAndApply / applyAppealVerdict used to make.
      // First-wins dedup happens upstream in `_validateBusinessRules`
      // (by tip_id + ctid + reason), so reaching this case means this is
      // the authoritative SCORE_UPDATE for that (tip_id, ctid, reason).
      case TX_TYPES.SCORE_UPDATE:
        if (d.tip_id && Number.isFinite(d.delta)) {
          const cur = dag.getScore(d.tip_id) || { score: 500, offense_count: 0 };
          const nextScore = Math.max(0, Math.min(1000, cur.score + d.delta));
          // last_updated from tx.timestamp — see issue #31. Same value
          // on every node so the scores row stays in state_merkle_root.
          dag.setScore(d.tip_id, nextScore, cur.offense_count, tx.timestamp);
        }
        break;

      // ── No additional derived state needed ──
      // computeScore() replays these from the DAG history when needed.
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

    // Commit 3 — notify the verdict-trigger of any verdict-relevant
    // tx commit so it can update its pending-deadline heap. Delegation
    // only; commit-handler holds no heap state of its own.
    if (verdictTrigger
      && (tx.tx_type === TX_TYPES.JURY_SUMMONS
        || tx.tx_type === TX_TYPES.ADJUDICATION_RESULT
        || tx.tx_type === TX_TYPES.APPEAL_RESULT
        || tx.tx_type === TX_TYPES.APPEAL_FILED)) {
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
   * Verify body/node signature on a transaction.
   * Returns true only if the signature is verified against a known signer from our registry.
   * Returns false if unknown tx type, missing signer, or invalid signature.
   */
  function _verifyTxSignature(tx) {
    const d = tx.data || {};
    const tt = tx.tx_type;

    try {
      if (tt === TX_TYPES.REGISTER_CONTENT) {
        const identity = dag.getIdentity(d.author_tip_id);
        if (!identity || !d.signature) return false;
        // Mirror content-service.js — include registered_url in the
        // signed-fields list when the client included it. Field list
        // drift between API and commit-handler is the #56 systemic
        // class; this case is #54.
        const fields = d.registered_url
          ? ["author_tip_id", "origin_code", "content_hash", "registered_url"]
          : ["author_tip_id", "origin_code", "content_hash"];
        return verifyBodySignature(d, d.signature, identity.public_key, fields);
      }

      if (tt === TX_TYPES.REGISTER_IDENTITY) {
        const vp = dag.getVP(d.vp_id);
        if (!vp || !d.vp_signature) return false;
        // Mirror identity-service.js — include creator_name when the VP
        // attested a display name. Same drift class as #54; tracked
        // separately as #55.
        const BASE_FIELDS = ["region", "public_key", "dedup_hash", "zk_proof", "verification_tier", "vp_id", "social_attested"];
        const fields = d.creator_name ? [...BASE_FIELDS, "creator_name"] : BASE_FIELDS;
        return verifyBodySignature(d, d.vp_signature, vp.public_key, fields);
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
        const disputeFields = d.claimed_origin ? ["disputer_tip_id", "reason", "claimed_origin", "evidence_hash"] : ["disputer_tip_id", "reason", "evidence_hash"];
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
