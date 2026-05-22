"use strict";

const { shake256, verifyBodySignature } = require("../../../shared/crypto");
const { nowMs, nowPlusMs, toIso } = require("../../../shared/time");
const {
  TX_TYPES, ORIGIN, ORIGIN_LABELS, JURY_VOTES, VOTE, VERDICT, CONTENT_STATUS, PRESCAN_TIERS,
  PRESCAN_REVIEW_STATES,
  DISPUTE_REASON, DISPUTE_REASONS,
  DISPUTE_SHORT_ID_LEN, DISPUTE_EPISODE_TX_TYPES, DISPUTE_EVENT_PRIORITY,
} = require("../../../shared/constants");
const { DISPUTE, JURY, APPEAL, AI_CLASSIFIER, CONTENT_GRACE, REVIEWER } = require("../../../shared/protocol-constants");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { selectJury, selectExperts } = require("../jury");
const { withTxId, nodeSignedAuto, preScanContent } = require("./helpers");
const { validate } = require("../middleware/validate");
const { getLogger } = require("../logger");

const log = getLogger("tip.dispute");

const ORIGIN_CODES = Object.keys(ORIGIN);

// Trivial helpers over the timeline constants in shared/constants.js.
// Module-level rather than closure-scoped because they have no factory-arg
// dependency. Constants themselves live in shared/constants.js so other
// services / tests can reuse them.
// Stage-3 (is_appeal=true) jury txs are the CONSEQUENCE of APPEAL_FILED
// (priority 6). When they share an atomic-batch timestamp with APPEAL_FILED
// — true for the auto-escalation batch (ADJUDICATION_RESULT + APPEAL_FILED
// + 3 expert SUMMONS all at the same ms) — the base priority of 2 would
// sort the summons BEFORE APPEAL_FILED, breaking the cause→effect read.
// Adding 5 to is_appeal Stage-3 events bumps them past APPEAL_FILED so the
// timeline reads: ADJUDICATION_RESULT (5) → APPEAL_FILED (6) → expert
// summons (7) → expert commits (8) → expert reveals (9) → APPEAL_RESULT (7).
const _eventPrio = (tx) => {
  const base = DISPUTE_EVENT_PRIORITY[tx.tx_type] ?? 99;
  if (tx.data?.is_appeal && (
    tx.tx_type === TX_TYPES.JURY_SUMMONS
    || tx.tx_type === TX_TYPES.JURY_VOTE_COMMIT
    || tx.tx_type === TX_TYPES.JURY_VOTE_REVEAL
  )) {
    return base + 5;
  }
  return base;
};
const shortDisputeId = (disputeTxId) => disputeTxId.slice(0, DISPUTE_SHORT_ID_LEN);

// Resolver accepts either the short form (DISPUTE_SHORT_ID_LEN hex chars)
// or the full dispute_tx_id (64 hex chars). Single length floor — no
// "minimum 8 vs display 12" split — keeps the contract obvious: "dispute
// ids are always at least DISPUTE_SHORT_ID_LEN hex chars."
const DISPUTE_ID_RE = new RegExp(`^[0-9a-f]{${DISPUTE_SHORT_ID_LEN},}$`, "i");

function createDisputeService({ dag, scoring, config, submitTx, submitBatch, disputeDetailsService }) {

  // Persist the off-chain body when fileDispute is called with an
  // `evidence: { payload, signature }` block. Returns
  // `{ hash, fresh }` — `fresh` is true only when this call wrote
  // a new row (so the catch block can roll back without clobbering
  // a body that was already legitimately stored by an earlier call).
  // Throws structured errors that bubble straight to the API caller —
  // never reaches submitBatch with a half-validated body.
  function _persistAttachedEvidence(disputerTipId, evidence) {
    if (evidence === undefined || evidence === null) return { hash: null, fresh: false };
    if (typeof evidence !== "object" || Array.isArray(evidence)) {
      throw { status: 400, error: "evidence must be an object" };
    }
    if (!disputeDetailsService) {
      throw { status: 500, error: "evidence support not wired (disputeDetailsService missing)" };
    }
    const { evidence_hash, idempotent } = disputeDetailsService.persistEvidence({
      disputer_tip_id: disputerTipId,
      payload: evidence.payload,
      signature: evidence.signature,
    });
    return { hash: evidence_hash, fresh: !idempotent };
  }

  function fileDispute(ctid, body) {
    validate(body, {
      disputer_tip_id: { required: true },
      signature: { required: true },
      reason: { required: true, oneOf: DISPUTE_REASONS },
      evidence: { required: true },
    });
    const { disputer_tip_id, reason, claimed_origin, signature, evidence } = body;
    if (reason === DISPUTE_REASON.ORIGIN_MISMATCH && !claimed_origin) throw { status: 400, error: "claimed_origin required for origin_mismatch disputes" };
    if (claimed_origin && !ORIGIN_CODES.includes(claimed_origin)) throw { status: 400, error: `Invalid claimed_origin. Must be one of: ${ORIGIN_CODES.join(", ")}` };

    // Disallow client-supplied evidence_hash without an evidence body.
    // (Belt-and-suspenders — `evidence` is now required above, but the
    // explicit check stays so the error is precise if someone bypasses
    // the validator.)
    if (body.evidence_hash !== undefined && evidence === undefined) {
      throw { status: 400, error: "evidence_hash provided without an evidence body — attach `evidence: { payload, signature }` instead" };
    }

    // Persist the body first so the subsequent canDispute uniqueness check
    // sees the right hash and so the on-chain tx can carry it. If the
    // dispute fails downstream, we discard the row in the catch block —
    // but only when this call actually wrote it (not on idempotent re-persist).
    const { hash: evidence_hash, fresh: evidenceFresh } = _persistAttachedEvidence(disputer_tip_id, evidence);

    try {
      {
        const r = rules.canDispute(dag, scoring, { ctid, disputer_tip_id, evidence_hash, reason, claimed_origin });
        if (!r.valid) throw { status: r.error.status, error: r.error.message };
      }
      const rec = dag.getContent(ctid);
      const disputer = dag.getIdentity(disputer_tip_id);

      // Disputer's signature covers the on-chain dispute fields. The
      // evidence_hash (when present) is one of those fields, so the
      // disputer commits to a specific body via this signature.
      const sigBody = { disputer_tip_id, reason };
      if (claimed_origin) sigBody.claimed_origin = claimed_origin;
      if (evidence_hash) sigBody.evidence_hash = evidence_hash;
      const DISPUTE_FIELDS = Object.keys(sigBody);
      if (!verifyBodySignature(sigBody, signature, disputer.public_key, DISPUTE_FIELDS)) {
        throw { status: 403, error: "Disputer signature verification failed" };
      }

      const disputeTx = withTxId({
        tx_type: TX_TYPES.CONTENT_DISPUTED, timestamp: nowMs(), prev: dag.getRecentPrev(),
        data: {
          ctid, disputer_tip_id, reason, claimed_origin: claimed_origin || null,
          declared_origin: rec.origin_code, evidence_hash: evidence_hash || null,
          author_tip_id: rec.author_tip_id,
          pre_dispute_status: rec.status, stake: DISPUTE.DISPUTER_STAKE,
        },
        signature,
      });
      const validation = validateTransaction(disputeTx, dag, {});
      if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

      // Collect all txs for atomic batch: dispute + stake + AI classifier + jury summons
      const batchTxs = [disputeTx];

      // Disputer stake (escrow) — deducted at filing time. Refunded on
      // UPHELD / CONSERVATIVE_LABEL, forfeited on DISMISSED. Matches the
      // intent of `DISPUTE.DISPUTER_STAKE` (it's a stake, not a "loser
      // penalty"), aligns with dispute-systems convention, and gives spam
      // resistance — a low-trust disputer can't file many disputes
      // simultaneously without their score dropping below
      // `dispute_filing_min_score`.
      batchTxs.push(scoring.buildScoreUpdateTx({
        tipId: disputer_tip_id, delta: -DISPUTE.DISPUTER_STAKE,
        reason: `Dispute filing stake on ${ctid}`,
        ctid, relatedTxId: disputeTx.tx_id,
        timestamp: disputeTx.timestamp,
        getRecentPrev: () => dag.getRecentPrev(),
        config,
      }));

      // Stage 1: AI Classifier (always escalates for now)
      const aiResult = preScanContent(rec.content_hash || "", rec.origin_code, {});
      const confidence = aiResult.probability || 0;
      const routing = confidence >= AI_CLASSIFIER.HIGH_CONFIDENCE ? "escalate_high" : "escalate";

      const classifierTx = nodeSignedAuto({
        tx_type: TX_TYPES.AI_CLASSIFIER_RESULT, timestamp: nowMs(), prev: dag.getRecentPrev(),
        data: { ctid, dispute_tx_id: disputeTx.tx_id, confidence, routing },
      }, config);
      batchTxs.push(classifierTx);

      // Stage 2: Jury Selection
      const jury = selectJury(dag, scoring, disputeTx.tx_id, rec.author_tip_id, disputer_tip_id);
      if (jury.insufficient) log.warn(`Jury selection: insufficient jurors for ${ctid} (${jury.jurors.length}/${JURY.SIZE})`);

      const commitDeadline = nowPlusMs(JURY.COMMIT_WINDOW_HOURS * 3600000);
      const revealDeadline = nowPlusMs((JURY.COMMIT_WINDOW_HOURS + JURY.REVEAL_WINDOW_HOURS) * 3600000);

      for (const jurorTipId of jury.jurors) {
        const summonsTx = nodeSignedAuto({
          tx_type: TX_TYPES.JURY_SUMMONS, timestamp: nowMs(), prev: dag.getRecentPrev(),
          data: { ctid, dispute_tx_id: disputeTx.tx_id, juror_tip_id: jurorTipId, stake: JURY.JUROR_STAKE, seed: jury.seed, identity_count: jury.identityCount, commit_deadline: commitDeadline, reveal_deadline: revealDeadline },
        }, config);
        batchTxs.push(summonsTx);
      }

      // Submit entire dispute as atomic batch
      submitBatch(batchTxs);

      log.info(`Dispute proposed: ${ctid} (${batchTxs.length} txs in batch, ${jury.jurors.length} jurors${evidence_hash ? `, evidence ${evidence_hash.slice(0, 12)}` : ""})`);

      return {
        success: true, message: "Dispute filed.",
        dispute_tx_id: disputeTx.tx_id,
        evidence_hash: evidence_hash || null,
        stake_at_risk: DISPUTE.DISPUTER_STAKE,
        stage1: { routing, confidence },
        stage2: { jurors: jury.jurors, count: jury.jurors.length, insufficient: jury.insufficient, commit_deadline: commitDeadline, reveal_deadline: revealDeadline },
        confirmation: "proposed",
      };
    } catch (err) {
      // Roll back ONLY when this call wrote the row. Idempotent re-persists
      // shouldn't clobber a body a previous successful dispute already
      // committed to.
      if (evidenceFresh && evidence_hash && disputeDetailsService) {
        disputeDetailsService.discardEvidence(evidence_hash);
      }
      throw err;
    }
  }

  function juryCommit(ctid, body) {
    const { juror_tip_id, commitment, signature } = body;
    validate(body, { juror_tip_id: { required: true }, commitment: { required: true }, signature: { required: true } });

    {
      const r = rules.canCommitVote(dag, { ctid, juror_tip_id, is_appeal: false }, { now: nowMs() });
      if (!r.valid) throw { status: r.error.status, error: r.error.message };
    }
    const juror = dag.getIdentity(juror_tip_id);

    if (!verifyBodySignature(body, signature, juror.public_key, ["juror_tip_id", "commitment"])) throw { status: 403, error: "Juror signature verification failed" };

    const commitTx = withTxId({ tx_type: TX_TYPES.JURY_VOTE_COMMIT, timestamp: nowMs(), prev: dag.getRecentPrev(), data: { ctid, juror_tip_id, commitment }, signature });
    submitTx(commitTx);
    return { success: true, tx_id: commitTx.tx_id, confirmation: "proposed" };
  }

  function juryReveal(ctid, body) {
    const { juror_tip_id, vote, salt, confirmed_origin, signature } = body;
    validate(body, { juror_tip_id: { required: true }, vote: { required: true, oneOf: JURY_VOTES }, salt: { required: true }, signature: { required: true } });
    if (vote === VOTE.MISMATCH && !confirmed_origin) throw { status: 400, error: "confirmed_origin required when voting MISMATCH" };
    if (confirmed_origin && !ORIGIN_CODES.includes(confirmed_origin)) throw { status: 400, error: "Invalid confirmed_origin" };

    {
      const r = rules.canRevealVote(dag, { ctid, juror_tip_id, is_appeal: false, vote, salt }, { now: nowMs(), shake256 });
      if (!r.valid) throw { status: r.error.status, error: r.error.message };
    }
    const juror = dag.getIdentity(juror_tip_id);

    const REVEAL_FIELDS = confirmed_origin ? ["juror_tip_id", "vote", "salt", "confirmed_origin"] : ["juror_tip_id", "vote", "salt"];
    if (!verifyBodySignature(body, signature, juror.public_key, REVEAL_FIELDS)) throw { status: 403, error: "Juror signature verification failed" };

    const revealTx = withTxId({ tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: nowMs(), prev: dag.getRecentPrev(), data: { ctid, juror_tip_id, vote, salt, confirmed_origin: vote === VOTE.MISMATCH ? confirmed_origin : null }, signature });
    submitTx(revealTx);

    // Verdict triggered post-round by verdict-trigger when reveal_deadline crosses cert.timestamp.
    return { success: true, tx_id: revealTx.tx_id, confirmation: "proposed" };
  }

  function getDisputeCase(ctid) {
    const rec = dag.getContent(ctid);
    if (!rec) throw { status: 404, error: "Content record not found" };

    const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
    const classifierTxs = dag.getTxsByTypeAndCtid(TX_TYPES.AI_CLASSIFIER_RESULT, ctid);
    const authorContent = dag.getContentByAuthor(rec.author_tip_id);
    const authorScore = scoring.getScore(rec.author_tip_id);
    const priorDisputes = dag.getTxsByType(TX_TYPES.CONTENT_DISPUTED).filter(t => t.data?.author_tip_id === rec.author_tip_id);
    const priorAdj = dag.getTxsByType(TX_TYPES.ADJUDICATION_RESULT).filter(t => t.data?.author_tip_id === rec.author_tip_id);

    // Stage-2 (jury) txs only — `is_appeal=false`. Without this filter the
    // jury counts get inflated by Stage-3 expert summons after an appeal
    // is filed.
    const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid).filter(t => !t.data?.is_appeal);
    const commitTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid).filter(t => !t.data?.is_appeal);
    const revealTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid).filter(t => !t.data?.is_appeal);
    const adjTxs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid);

    // Stage-3 (expert/appeal) txs — `is_appeal=true`. Only populated once
    // an APPEAL_FILED has been issued; absent → `appeal: null` in response.
    const appealFiledTxs = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, ctid);
    const expSummonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid).filter(t => !!t.data?.is_appeal);
    const expCommitTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid).filter(t => !!t.data?.is_appeal);
    const expRevealTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid).filter(t => !!t.data?.is_appeal);
    const appealResultTxs = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_RESULT, ctid);

    const committedIds = new Set(commitTxs.map(t => t.data.juror_tip_id));
    const revealedIds = new Set(revealTxs.map(t => t.data.juror_tip_id));
    const expCommittedIds = new Set(expCommitTxs.map(t => t.data.juror_tip_id));
    const expRevealedIds = new Set(expRevealTxs.map(t => t.data.juror_tip_id));

    return {
      content: { ctid, origin_code: rec.origin_code, origin_label: ORIGIN_LABELS[rec.origin_code] || rec.origin_code, content_hash: rec.content_hash, author_tip_id: rec.author_tip_id, status: rec.status, registered_at: rec.registered_at },
      dispute: disputeTxs.length ? { disputer_tip_id: disputeTxs[0].data.disputer_tip_id, reason: disputeTxs[0].data.reason, claimed_origin: disputeTxs[0].data.claimed_origin, declared_origin: disputeTxs[0].data.declared_origin, evidence_hash: disputeTxs[0].data.evidence_hash, filed_at: disputeTxs[0].timestamp, dispute_tx_id: disputeTxs[0].tx_id } : null,
      ai_classifier: classifierTxs.length ? { confidence: classifierTxs[0].data.confidence, routing: classifierTxs[0].data.routing } : null,
      creator_history: { total_content: authorContent.length, verified_count: authorContent.filter(c => c.status === CONTENT_STATUS.VERIFIED).length, prior_disputes: priorDisputes.length, prior_upheld: priorAdj.filter(t => t.data?.verdict === VERDICT.UPHELD).length, prior_dismissed: priorAdj.filter(t => t.data?.verdict === VERDICT.DISMISSED).length, current_score: authorScore.score, current_tier: authorScore.tier.name, offense_count: authorScore.offense_count },
      jury: {
        jurors: summonsTxs.map(s => {
          const id = dag.getIdentity(s.data.juror_tip_id);
          return {
            juror_tip_id: s.data.juror_tip_id,
            creator_name: id?.creator_name || null,
            status: revealedIds.has(s.data.juror_tip_id) ? "revealed"
              : committedIds.has(s.data.juror_tip_id) ? "committed"
                : "summoned",
          };
        }),
        commit_deadline: summonsTxs[0]?.data?.commit_deadline,
        reveal_deadline: summonsTxs[0]?.data?.reveal_deadline,
        total_summoned: summonsTxs.length,
        total_committed: commitTxs.length,
        total_revealed: revealTxs.length,
      },
      verdict: adjTxs.length ? {
        verdict: adjTxs[0].data.verdict,
        declared_origin: adjTxs[0].data.declared_origin,
        confirmed_origin: adjTxs[0].data.confirmed_origin,
        match_count: adjTxs[0].data.match_count,
        mismatch_count: adjTxs[0].data.mismatch_count,
        abstain_count: adjTxs[0].data.abstain_count,
        resolved_at: adjTxs[0].timestamp,
        // Loser-party identification for the FE's "show appeal button?" logic.
        // Same rule as /v1/disputes appealable[] and dashboard.appeal_available:
        // UPHELD → author lost; DISMISSED → disputer lost. CONSERVATIVE_LABEL
        // and NO_QUORUM have no clear loser → both null.
        losing_party: adjTxs[0].data.verdict === VERDICT.UPHELD ? "author"
          : adjTxs[0].data.verdict === VERDICT.DISMISSED ? "disputer"
            : null,
        losing_tip_id: adjTxs[0].data.verdict === VERDICT.UPHELD ? rec.author_tip_id
          : adjTxs[0].data.verdict === VERDICT.DISMISSED ? disputeTxs[0]?.data?.disputer_tip_id
            : null,
      } : null,
      appeal: appealFiledTxs.length ? {
        filed_at: appealFiledTxs[0].timestamp,
        appellant_tip_id: appealFiledTxs[0].data.appellant_tip_id,
        appellant_name: dag.getIdentity(appealFiledTxs[0].data.appellant_tip_id)?.creator_name || null,
        experts: expSummonsTxs.map(s => {
          const id = dag.getIdentity(s.data.juror_tip_id);
          return {
            expert_tip_id: s.data.juror_tip_id,
            creator_name: id?.creator_name || null,
            status: expRevealedIds.has(s.data.juror_tip_id) ? "revealed"
              : expCommittedIds.has(s.data.juror_tip_id) ? "committed"
                : "summoned",
          };
        }),
        commit_deadline: expSummonsTxs[0]?.data?.commit_deadline,
        reveal_deadline: expSummonsTxs[0]?.data?.reveal_deadline,
        total_summoned: expSummonsTxs.length,
        total_committed: expCommitTxs.length,
        total_revealed: expRevealTxs.length,
        verdict: appealResultTxs.length ? appealResultTxs[0].data.verdict : null,
        overturned: appealResultTxs.length ? appealResultTxs[0].data.overturned : null,
        resolved_at: appealResultTxs.length ? appealResultTxs[0].timestamp : null,
      } : null,
    };
  }

  // ── Appeal endpoints ──────────────────────────────────────────────────────

  function fileAppeal(ctid, body) {
    validate(body, { appellant_tip_id: { required: true }, signature: { required: true } });
    const { appellant_tip_id, signature } = body;

    {
      const r = rules.canFileAppeal(dag, { ctid, appellant_tip_id }, { now: nowMs() });
      if (!r.valid) throw { status: r.error.status, error: r.error.message };
    }
    const adjTxs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid);
    const rec = dag.getContent(ctid);
    const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
    const disputerTipId = disputeTxs[0]?.data?.disputer_tip_id;
    const authorTipId = rec?.author_tip_id;

    const appellant = dag.getIdentity(appellant_tip_id);
    if (!verifyBodySignature(body, signature, appellant.public_key, ["appellant_tip_id"])) throw { status: 403, error: "Appellant signature verification failed" };

    const appealTx = withTxId({ tx_type: TX_TYPES.APPEAL_FILED, timestamp: nowMs(), prev: dag.getRecentPrev(), data: { ctid, appellant_tip_id, stage2_verdict: adjTxs[0].data.verdict, stake: APPEAL.APPELLANT_STAKE }, signature });

    // Collect batch: appeal + stake + expert summons
    const batchTxs = [appealTx];

    // Appellant stake (escrow) — deducted at filing time, mirroring the
    // disputer stake-on-file model in fileDispute. Refunded with bonus
    // on overturn, forfeited on appeal-failure. The settlement deltas
    // live in jury.buildAppealBatch.
    batchTxs.push(scoring.buildScoreUpdateTx({
      tipId: appellant_tip_id, delta: -APPEAL.APPELLANT_STAKE,
      reason: `Appeal filing stake on ${ctid}`,
      ctid, relatedTxId: appealTx.tx_id,
      timestamp: appealTx.timestamp,
      getRecentPrev: () => dag.getRecentPrev(),
      config,
    }));

    const experts = selectExperts(dag, scoring, appealTx.tx_id, authorTipId, disputerTipId, ctid);
    const commitDeadline = nowPlusMs(APPEAL.COMMIT_WINDOW_HOURS * 3600000);
    const revealDeadline = nowPlusMs((APPEAL.COMMIT_WINDOW_HOURS + APPEAL.REVEAL_WINDOW_HOURS) * 3600000);

    for (const expertTipId of experts.experts) {
      const summonsTx = nodeSignedAuto({ tx_type: TX_TYPES.JURY_SUMMONS, timestamp: nowMs(), prev: dag.getRecentPrev(), data: { ctid, dispute_tx_id: appealTx.tx_id, juror_tip_id: expertTipId, stake: JURY.JUROR_STAKE, seed: experts.seed, identity_count: experts.identityCount, commit_deadline: commitDeadline, reveal_deadline: revealDeadline, is_appeal: true } }, config);
      batchTxs.push(summonsTx);
    }

    submitBatch(batchTxs);

    log.info(`Appeal proposed: ${ctid} by ${appellant_tip_id} (${batchTxs.length} txs)`);
    return {
      success: true, appeal_tx_id: appealTx.tx_id, stake_at_risk: APPEAL.APPELLANT_STAKE,
      experts: { selected: experts.experts, count: experts.experts.length, insufficient: experts.insufficient, commit_deadline: commitDeadline, reveal_deadline: revealDeadline },
      confirmation: "proposed",
    };
  }

  function appealCommit(ctid, body) {
    const { juror_tip_id, commitment, signature } = body;
    validate(body, { juror_tip_id: { required: true }, commitment: { required: true }, signature: { required: true } });

    {
      const r = rules.canCommitVote(dag, { ctid, juror_tip_id, is_appeal: true }, { now: nowMs() });
      if (!r.valid) throw { status: r.error.status, error: r.error.message };
    }
    const juror = dag.getIdentity(juror_tip_id);
    if (!verifyBodySignature(body, signature, juror.public_key, ["juror_tip_id", "commitment"])) throw { status: 403, error: "Expert signature verification failed" };

    const commitTx = withTxId({ tx_type: TX_TYPES.JURY_VOTE_COMMIT, timestamp: nowMs(), prev: dag.getRecentPrev(), data: { ctid, juror_tip_id, commitment, is_appeal: true }, signature });
    submitTx(commitTx);
    return { success: true, tx_id: commitTx.tx_id, confirmation: "proposed" };
  }

  function appealReveal(ctid, body) {
    const { juror_tip_id, vote, salt, confirmed_origin, signature } = body;
    if (!juror_tip_id) throw { status: 400, error: "juror_tip_id required" };
    if (!vote) throw { status: 400, error: "vote required" };
    if (!salt) throw { status: 400, error: "salt required" };
    if (!signature) throw { status: 400, error: "signature required" };
    if (![VOTE.MATCH, VOTE.MISMATCH, VOTE.ABSTAIN].includes(vote)) throw { status: 400, error: "Invalid vote" };
    if (vote === VOTE.MISMATCH && !confirmed_origin) throw { status: 400, error: "confirmed_origin required when voting MISMATCH" };
    if (confirmed_origin && !ORIGIN[confirmed_origin]) throw { status: 400, error: "Invalid confirmed_origin" };

    {
      const r = rules.canRevealVote(dag, { ctid, juror_tip_id, is_appeal: true, vote, salt }, { now: nowMs(), shake256 });
      if (!r.valid) throw { status: r.error.status, error: r.error.message };
    }
    const juror = dag.getIdentity(juror_tip_id);
    const REVEAL_FIELDS = confirmed_origin ? ["juror_tip_id", "vote", "salt", "confirmed_origin"] : ["juror_tip_id", "vote", "salt"];
    if (!verifyBodySignature(body, signature, juror.public_key, REVEAL_FIELDS)) throw { status: 403, error: "Expert signature verification failed" };

    const revealTx = withTxId({ tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: nowMs(), prev: dag.getRecentPrev(), data: { ctid, juror_tip_id, vote, salt, confirmed_origin: vote === VOTE.MISMATCH ? confirmed_origin : null, is_appeal: true }, signature });
    submitTx(revealTx);

    // Appeal verdict triggered post-round by verdict-trigger when reveal_deadline crosses cert.timestamp.
    return { success: true, tx_id: revealTx.tx_id, confirmation: "proposed" };
  }

  // ── Listing / lookup / timeline ───────────────────────────────────────────
  // Pure-data constants (DISPUTE_SHORT_ID_LEN, DISPUTE_EPISODE_TX_TYPES,
  // DISPUTE_EVENT_PRIORITY) live in shared/constants.js. Trivial helpers
  // (_eventPrio, shortDisputeId) are at module level above the factory.

  function resolveDispute(idOrPrefix) {
    validate({ dispute_id: idOrPrefix }, { dispute_id: { required: true, type: "string", match: DISPUTE_ID_RE } });
    const prefix = idOrPrefix.toLowerCase();
    const matches = dag.getTxsByType(TX_TYPES.CONTENT_DISPUTED).filter(t => t.tx_id.startsWith(prefix));
    if (matches.length === 0) throw { status: 404, error: "Dispute not found" };
    if (matches.length > 1) throw { status: 409, error: `Ambiguous dispute_id (${matches.length} matches) — provide more characters` };
    return matches[0];
  }

  // An episode is the slice of tx history bounded by this CONTENT_DISPUTED
  // and the next one for the same ctid (exclusive). Multiple disputes per
  // ctid are rare but possible after a prior resolution — using a temporal
  // window keeps the projection correct even then.
  function collectEpisodeEvents(disputeTx) {
    const ctid = disputeTx.data.ctid;
    const startTs = disputeTx.timestamp;
    const sameCtidDisputes = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid)
      .sort((a, b) => a.timestamp - b.timestamp);
    const myIx = sameCtidDisputes.findIndex(t => t.tx_id === disputeTx.tx_id);
    const endTs = myIx >= 0 && sameCtidDisputes[myIx + 1] ? sameCtidDisputes[myIx + 1].timestamp : null;

    const events = [disputeTx];
    for (const type of DISPUTE_EPISODE_TX_TYPES) {
      for (const t of dag.getTxsByTypeAndCtid(type, ctid)) {
        if (t.timestamp < startTs) continue;
        if (endTs !== null && t.timestamp >= endTs) continue;
        events.push(t);
      }
    }
    return events.sort((a, b) =>
      (a.timestamp - b.timestamp) ||
      _eventPrio(a) - _eventPrio(b) ||
      a.tx_id.localeCompare(b.tx_id)
    );
  }

  function projectStatus(events, now) {
    const find = (type) => events.find(e => e.tx_type === type);
    const findByAppealFlag = (type, isAppeal) =>
      events.find(e => e.tx_type === type && (!!e.data?.is_appeal) === isAppeal);

    const appealResult = find(TX_TYPES.APPEAL_RESULT);
    if (appealResult) return `appeal_${(appealResult.data.verdict || "resolved").toLowerCase()}`;

    if (find(TX_TYPES.APPEAL_FILED)) {
      const exp = findByAppealFlag(TX_TYPES.JURY_SUMMONS, true);
      if (exp) {
        const c = exp.data.commit_deadline;
        const r = exp.data.reveal_deadline;
        if (now < c) return "appeal_commit_phase";
        if (now < r) return "appeal_reveal_phase";
        return "appeal_awaiting_verdict";
      }
      return "appealed";
    }

    const adj = find(TX_TYPES.ADJUDICATION_RESULT);
    if (adj) {
      const v = (adj.data.verdict || "").toLowerCase();
      if (v === "no_quorum") return "no_quorum";
      return `resolved_${v || "unknown"}`;
    }

    const summons = findByAppealFlag(TX_TYPES.JURY_SUMMONS, false);
    if (summons) {
      const c = summons.data.commit_deadline;
      const r = summons.data.reveal_deadline;
      if (now < c) return "commit_phase";
      if (now < r) return "reveal_phase";
      return "awaiting_verdict";
    }

    if (find(TX_TYPES.AI_CLASSIFIER_RESULT)) return "screening";
    return "submitted";
  }

  function formatTimelineEvent(tx) {
    const d = tx.data || {};
    switch (tx.tx_type) {
      case TX_TYPES.CONTENT_DISPUTED:
        return { event: "filed", label: "Dispute filed", ts: tx.timestamp, actor_tip_id: d.disputer_tip_id, data: { reason: d.reason, claimed_origin: d.claimed_origin, declared_origin: d.declared_origin, evidence_hash: d.evidence_hash } };
      case TX_TYPES.AI_CLASSIFIER_RESULT:
        return { event: "ai_screening", label: `AI screening: ${d.routing}`, ts: tx.timestamp, data: { confidence: d.confidence, routing: d.routing } };
      case TX_TYPES.JURY_SUMMONS:
        return { event: d.is_appeal ? "expert_summoned" : "juror_summoned", label: d.is_appeal ? "Expert summoned" : "Juror summoned", ts: tx.timestamp, actor_tip_id: d.juror_tip_id };
      case TX_TYPES.JURY_VOTE_COMMIT:
        return { event: d.is_appeal ? "expert_committed" : "juror_committed", label: d.is_appeal ? "Expert committed" : "Juror committed", ts: tx.timestamp, actor_tip_id: d.juror_tip_id };
      case TX_TYPES.JURY_VOTE_REVEAL:
        return { event: d.is_appeal ? "expert_revealed" : "juror_revealed", label: d.is_appeal ? `Expert vote: ${d.vote}` : `Juror vote: ${d.vote}`, ts: tx.timestamp, actor_tip_id: d.juror_tip_id, data: { vote: d.vote, confirmed_origin: d.confirmed_origin } };
      case TX_TYPES.ADJUDICATION_RESULT:
        return { event: "verdict", label: `Verdict: ${d.verdict}`, ts: tx.timestamp, data: { verdict: d.verdict, confirmed_origin: d.confirmed_origin, match_count: d.match_count, mismatch_count: d.mismatch_count, abstain_count: d.abstain_count } };
      case TX_TYPES.APPEAL_FILED:
        return { event: "appeal_filed", label: "Appeal filed", ts: tx.timestamp, actor_tip_id: d.appellant_tip_id };
      case TX_TYPES.APPEAL_RESULT:
        return { event: "appeal_verdict", label: `Appeal verdict: ${d.verdict}${d.overturned ? " (overturned)" : ""}`, ts: tx.timestamp, data: { verdict: d.verdict, overturned: d.overturned, stage2_verdict: d.stage2_verdict } };
      default:
        return { event: tx.tx_type.toLowerCase(), label: tx.tx_type, ts: tx.timestamp };
    }
  }

  // Batch-resolve creator_name for every actor referenced in an episode.
  // One dag.getIdentity() call per unique tip_id — much cheaper than
  // resolving per timeline entry, and the same identity often appears in
  // multiple events (juror_summoned + juror_committed + juror_revealed).
  function _resolveActorNames(events) {
    const tipIds = new Set();
    for (const tx of events) {
      const d = tx.data || {};
      if (d.disputer_tip_id) tipIds.add(d.disputer_tip_id);
      if (d.juror_tip_id) tipIds.add(d.juror_tip_id);
      if (d.appellant_tip_id) tipIds.add(d.appellant_tip_id);
    }
    const map = {};
    for (const tipId of tipIds) {
      const id = dag.getIdentity(tipId);
      if (id?.creator_name) map[tipId] = id.creator_name;
    }
    return map;
  }

  function buildTimeline(events) {
    const nameByTipId = _resolveActorNames(events);
    return events.map(tx => {
      const out = formatTimelineEvent(tx);
      if (out.actor_tip_id && nameByTipId[out.actor_tip_id]) {
        out.actor_name = nameByTipId[out.actor_tip_id];
      }
      return out;
    });
  }

  function summarizeDispute(disputeTx, events, now) {
    const adj = events.find(e => e.tx_type === TX_TYPES.ADJUDICATION_RESULT);
    const appealFiled = events.some(e => e.tx_type === TX_TYPES.APPEAL_FILED);
    return {
      dispute_id: shortDisputeId(disputeTx.tx_id),
      dispute_tx_id: disputeTx.tx_id,
      ctid: disputeTx.data.ctid,
      status: projectStatus(events, now),
      reason: disputeTx.data.reason,
      declared_origin: disputeTx.data.declared_origin,
      claimed_origin: disputeTx.data.claimed_origin,
      disputer_tip_id: disputeTx.data.disputer_tip_id,
      author_tip_id: disputeTx.data.author_tip_id,
      filed_at: disputeTx.timestamp,
      verdict: adj ? adj.data.verdict : null,
      appeal_filed: appealFiled,
    };
  }

  function listDisputesForTipId(tipId) {
    validate({ tip_id: tipId }, { tip_id: { required: true, type: "string", match: /^tip:\/\/id\// } });
    const now = nowMs();

    const allDisputes = dag.getTxsByType(TX_TYPES.CONTENT_DISPUTED);
    const filed_by_me = allDisputes
      .filter(t => t.data?.disputer_tip_id === tipId)
      .map(t => summarizeDispute(t, collectEpisodeEvents(t), now));
    const against_me = allDisputes
      .filter(t => t.data?.author_tip_id === tipId)
      .map(t => summarizeDispute(t, collectEpisodeEvents(t), now));

    const juror_active = [];
    const summonsForMe = dag.getTxsByType(TX_TYPES.JURY_SUMMONS)
      .filter(t => t.data?.juror_tip_id === tipId);
    for (const s of summonsForMe) {
      const ctid = s.data.ctid;
      const isAppeal = !!s.data.is_appeal;
      const revealDeadline = s.data.reveal_deadline;
      if (now > revealDeadline) continue;

      const committed = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid)
        .some(t => t.data?.juror_tip_id === tipId && (!!t.data?.is_appeal) === isAppeal);
      const revealed = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid)
        .some(t => t.data?.juror_tip_id === tipId && (!!t.data?.is_appeal) === isAppeal);
      if (revealed) continue;

      const commitDeadline = s.data.commit_deadline;
      const action = now < commitDeadline
        ? (committed ? "wait_for_reveal" : "commit_required")
        : (committed ? "reveal_required" : "missed_commit");

      juror_active.push({
        ctid,
        dispute_tx_id: s.data.dispute_tx_id,
        dispute_id: s.data.dispute_tx_id ? shortDisputeId(s.data.dispute_tx_id) : null,
        role: isAppeal ? "expert" : "juror",
        committed,
        revealed,
        commit_deadline: s.data.commit_deadline,
        reveal_deadline: s.data.reveal_deadline,
        action,
      });
    }

    const appealable = [];
    const appealWindowMs = APPEAL.FILING_WINDOW_HOURS * 3600000;
    for (const adj of dag.getTxsByType(TX_TYPES.ADJUDICATION_RESULT)) {
      const ctid = adj.data?.ctid;
      if (!ctid) continue;
      const verdictMs = adj.timestamp;
      if (now - verdictMs > appealWindowMs) continue;
      if (dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, ctid).length > 0) continue;

      const rec = dag.getContent(ctid);
      if (!rec) continue;
      const ctidDisputes = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid)
        .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      const latestDispute = ctidDisputes[0];
      const disputerTipId = latestDispute?.data?.disputer_tip_id;
      const isAuthor = rec.author_tip_id === tipId;
      const isDisputer = disputerTipId === tipId;
      if (!isAuthor && !isDisputer) continue;

      // Surface only to the LOSING party — the one with standing to appeal.
      // UPHELD = disputer won → author lost. DISMISSED = author won →
      // disputer lost. CONSERVATIVE_LABEL / NO_QUORUM have no clear loser
      // and don't trigger an appeal CTA. Mirrors the dashboard endpoint's
      // `appeal_available` rule so both feeds stay consistent.
      const verdict = adj.data?.verdict;
      const isLoser = (verdict === VERDICT.UPHELD && isAuthor)
        || (verdict === VERDICT.DISMISSED && isDisputer);
      if (!isLoser) continue;

      appealable.push({
        ctid,
        dispute_id: latestDispute ? shortDisputeId(latestDispute.tx_id) : null,
        dispute_tx_id: latestDispute?.tx_id || null,
        verdict,
        verdict_at: adj.timestamp,
        filing_deadline: verdictMs + appealWindowMs,
        role: isAuthor ? "author" : "disputer",
      });
    }

    return { tip_id: tipId, filed_by_me, against_me, juror_active, appealable };
  }

  // ─── Dashboard ──────────────────────────────────────────────────────────
  // Per-user "what needs my attention" feed. Open / unauthenticated — every
  // input is already enumerable on-chain via /v1/disputes?tip_id=... etc;
  // this endpoint just centralises the projection so the FE doesn't have to
  // walk five endpoints to render an inbox. See my-notes/USER_DASHBOARD_API.md
  // for the full contract.

  function _priorityForDeadline(deadlineMs, now) {
    if (!Number.isFinite(deadlineMs)) return "info";
    const remainingMs = deadlineMs - now;
    if (remainingMs <= 0) return "info";  // expired — caller usually skips
    if (remainingMs < 6 * 3600000) return "urgent";
    if (remainingMs < 24 * 3600000) return "high";
    if (remainingMs < 3 * 24 * 3600000) return "normal";
    return "normal";
  }

  // Order: urgent (0) > high (1) > normal (2) > info (3). Sort key.
  const _PRIORITY_ORDER = { urgent: 0, high: 1, normal: 2, info: 3 };

  // Compact "4h" / "2d" / "30m" remaining-time string for FE-ready titles —
  // saves the FE from doing date math. Callers add the qualifier ("left" or
  // "in" or none) so phrasing reads naturally in different contexts.
  function _shortRemaining(deadlineMs, now) {
    const remaining = deadlineMs - now;
    if (remaining <= 0) return "expired";
    const h = Math.floor(remaining / 3600000);
    if (h < 1) return `${Math.max(1, Math.round(remaining / 60000))}m`;
    if (h < 48) return `${h}h`;
    return `${Math.floor(h / 24)}d`;
  }

  function _ctidLabel(ctid) {
    // Shorten "tip://c/AA-3356172f3297aa-4c0b" → "tip://c/AA-…" for titles.
    const m = /^tip:\/\/c\/([A-Z]{2})-/.exec(ctid || "");
    return m ? `tip://c/${m[1]}-…` : (ctid || "");
  }

  // Recency window for purely-informational notifications. Items older than
  // this drop off the feed regardless of state — keeps the dashboard from
  // accumulating stale "verdict landed 3 weeks ago" entries.
  const DASHBOARD_RECENCY_MS = 24 * 3600000;

  function getUserDashboard(tipId) {
    validate({ tip_id: tipId }, { tip_id: { required: true, type: "string", match: /^tip:\/\/id\// } });

    const identity = dag.getIdentity(tipId);
    if (!identity) throw { status: 404, error: "TIP-ID not found" };

    const now = nowMs();
    const items = [];

    // Pre-index final-result txs once so the summons loop and the
    // verdict_on_my_jury block can both look up by ctid in O(1) without
    // re-walking the DAG per row.
    const _adjByCtid = new Map();
    for (const t of dag.getTxsByType(TX_TYPES.ADJUDICATION_RESULT)) {
      const ctid = t.data?.ctid;
      if (ctid) _adjByCtid.set(ctid, t);
    }
    const _appealResByCtid = new Map();
    for (const t of dag.getTxsByType(TX_TYPES.APPEAL_RESULT)) {
      const ctid = t.data?.ctid;
      if (ctid) _appealResByCtid.set(ctid, t);
    }

    // ── Juror / expert: phase-aware notifications ────────────────────────
    // Four states surface here, two actionable + two informational:
    //   1. *_commit_required          — actionable: I need to commit
    //   2. *_awaiting_reveal_window   — info: I committed; reveal opens at X
    //   3. *_reveal_required          — actionable: reveal window open + I haven't
    //   4. *_awaiting_verdict         — info: I revealed; waiting for tally
    // Resolved + recent-24h goes through verdict_on_my_jury below; resolved + old
    // is in jury-history. So this loop never emits anything for already-resolved
    // disputes.
    const summonsForMe = dag.getTxsByType(TX_TYPES.JURY_SUMMONS)
      .filter(t => t.data?.juror_tip_id === tipId);
    for (const s of summonsForMe) {
      const ctid = s.data.ctid;
      const isAppeal = !!s.data.is_appeal;
      const role = isAppeal ? "expert" : "juror";
      const commitDeadlineMs = s.data.commit_deadline;
      const revealDeadlineMs = s.data.reveal_deadline;

      const myCommit = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid)
        .find(t => t.data?.juror_tip_id === tipId && (!!t.data?.is_appeal) === isAppeal);
      const myReveal = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid)
        .find(t => t.data?.juror_tip_id === tipId && (!!t.data?.is_appeal) === isAppeal);
      const result = isAppeal ? _appealResByCtid.get(ctid) : _adjByCtid.get(ctid);

      // Already resolved → leave it to verdict_on_my_jury (recent) or
      // jury-history (older). This loop is for pre-verdict states only.
      if (result) continue;

      const disputeTxId = s.data.dispute_tx_id;
      const disputeId = disputeTxId ? shortDisputeId(disputeTxId) : null;

      if (myReveal) {
        // State 4: revealed, awaiting verdict. Info — no action, just
        // confirms the user's vote landed. Drops off when result arrives.
        const type = isAppeal ? "expert_awaiting_verdict" : "juror_awaiting_verdict";
        items.push({
          id: `${type}:dispute:${disputeId}`,
          type,
          priority: "info",
          title: `${role === "expert" ? "Expert" : "Jury"} vote revealed — awaiting verdict`,
          summary: `${_ctidLabel(ctid)} reveal phase ${now > revealDeadlineMs ? "closed" : "open until " + revealDeadlineMs}; tally pending.`,
          role,
          ctid,
          dispute_id: disputeId,
          deadline: null,
          action: disputeId ? { kind: "view_dispute", label: "View dispute", href: `/disputes/${disputeId}` } : null,
          metadata: {
            my_vote: myReveal.data?.vote || null,
            reveal_deadline: s.data.reveal_deadline,
          },
        });
        continue;
      }

      // No reveal yet — three pre-reveal sub-states based on commit + clock.
      if (!myCommit && now < commitDeadlineMs) {
        // State 1: actionable commit.
        const type = isAppeal ? "expert_commit_required" : "juror_commit_required";
        const actionKind = isAppeal ? "commit_expert_vote" : "commit_vote";
        const hrefSuffix = isAppeal ? "/appeal/commit" : "/commit";
        items.push({
          id: `${type}:dispute:${disputeId}`,
          type,
          priority: _priorityForDeadline(commitDeadlineMs, now),
          title: `Commit your ${role} vote (${_shortRemaining(commitDeadlineMs, now)} left)`,
          summary: `Dispute on ${_ctidLabel(ctid)} is in commit phase.`,
          role,
          ctid,
          dispute_id: disputeId,
          deadline: s.data.commit_deadline,
          action: disputeId ? { kind: actionKind, label: `Commit vote`, href: `/disputes/${disputeId}${hrefSuffix}` } : null,
          metadata: {},
        });
      } else if (myCommit && now < commitDeadlineMs) {
        // State 2: committed, reveal window not yet open. Info — tells the
        // user when to come back. Drops off the moment the reveal window
        // opens (then *_reveal_required takes over).
        const type = isAppeal ? "expert_awaiting_reveal_window" : "juror_awaiting_reveal_window";
        items.push({
          id: `${type}:dispute:${disputeId}`,
          type,
          priority: "info",
          title: `${role === "expert" ? "Expert" : "Jury"} vote committed — reveal opens in ${_shortRemaining(commitDeadlineMs, now)}`,
          summary: `${_ctidLabel(ctid)}: commit phase ends at ${commitDeadlineMs}, reveal window then opens for ${Math.round((revealDeadlineMs - commitDeadlineMs) / 3600000)}h.`,
          role,
          ctid,
          dispute_id: disputeId,
          deadline: s.data.commit_deadline,
          action: disputeId ? { kind: "view_dispute", label: "View dispute", href: `/disputes/${disputeId}` } : null,
          metadata: {
            commitment: myCommit.data?.commitment || null,
            reveal_window_opens_at: s.data.commit_deadline,
            reveal_window_closes_at: s.data.reveal_deadline,
          },
        });
      } else if (myCommit && now < revealDeadlineMs) {
        // State 3: actionable reveal.
        const type = isAppeal ? "expert_reveal_required" : "juror_reveal_required";
        const actionKind = isAppeal ? "reveal_expert_vote" : "reveal_vote";
        const hrefSuffix = isAppeal ? "/appeal/reveal" : "/reveal";
        items.push({
          id: `${type}:dispute:${disputeId}`,
          type,
          priority: _priorityForDeadline(revealDeadlineMs, now),
          title: `Reveal your ${role} vote (${_shortRemaining(revealDeadlineMs, now)} left)`,
          summary: `Dispute on ${_ctidLabel(ctid)} is in reveal phase.`,
          role,
          ctid,
          dispute_id: disputeId,
          deadline: s.data.reveal_deadline,
          action: disputeId ? { kind: actionKind, label: `Reveal vote`, href: `/disputes/${disputeId}${hrefSuffix}` } : null,
          metadata: { commitment: myCommit.data?.commitment || null },
        });
      }
      // else: missed_commit (commit window closed, never committed) or
      // missed_reveal (committed, reveal window closed). Silent here —
      // those are dead-end states the user can't recover from. The
      // jury-history endpoint surfaces them with status=missed_*.
    }

    // ── Appeal available + verdict landed ────────────────────────────────
    const appealWindowMs = APPEAL.FILING_WINDOW_HOURS * 3600000;
    for (const adj of dag.getTxsByType(TX_TYPES.ADJUDICATION_RESULT)) {
      const ctid = adj.data?.ctid;
      if (!ctid) continue;
      const rec = dag.getContent(ctid);
      if (!rec) continue;

      const ctidDisputes = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid)
        .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      const latestDispute = ctidDisputes[0];
      const disputerTipId = latestDispute?.data?.disputer_tip_id;
      const isAuthor = rec.author_tip_id === tipId;
      const isDisputer = disputerTipId === tipId;
      if (!isAuthor && !isDisputer) continue;

      const role = isAuthor ? "author" : "disputer";
      const disputeId = latestDispute ? shortDisputeId(latestDispute.tx_id) : null;
      const verdictMs = adj.timestamp;
      const filingDeadlineMs = verdictMs + appealWindowMs;
      const appealAlreadyFiled = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, ctid).length > 0;

      // appeal_available — only surfaced to the LOSING party (the one who'd
      // actually file). UPHELD = disputer won → author lost → CTA to author.
      // DISMISSED = author won → disputer lost → CTA to disputer.
      // CONSERVATIVE_LABEL / NO_QUORUM = no clear loser; surface to neither
      // (NO_QUORUM auto-escalates internally; CONSERVATIVE_LABEL is a label
      // adjustment, not a penalty). canFileAppeal at the protocol layer
      // doesn't restrict by role — this is a UX choice, not enforcement.
      const verdict = adj.data?.verdict;
      const isLoser = (verdict === VERDICT.UPHELD && isAuthor)
        || (verdict === VERDICT.DISMISSED && isDisputer);

      if (isLoser && !appealAlreadyFiled && now < filingDeadlineMs) {
        const appealTitle = isAuthor
          ? `Your content's verdict was ${verdict} — appeal closes in ${_shortRemaining(filingDeadlineMs, now)}`
          : `Your dispute was ${verdict} — appeal closes in ${_shortRemaining(filingDeadlineMs, now)}`;
        items.push({
          id: `appeal_available:dispute:${disputeId}`,
          type: "appeal_available",
          priority: _priorityForDeadline(filingDeadlineMs, now),
          title: appealTitle,
          summary: `Verdict on ${_ctidLabel(ctid)} (${verdict}). You can file an appeal.`,
          role,
          ctid,
          dispute_id: disputeId,
          deadline: filingDeadlineMs,
          action: disputeId ? { kind: "file_appeal", label: "File appeal", href: `/disputes/${disputeId}/appeal` } : null,
          metadata: {
            verdict,
            confirmed_origin: adj.data?.confirmed_origin || null,
            stake_at_risk_for_appeal: APPEAL.APPELLANT_STAKE,
          },
        });
      }

      // verdict_landed — informational, recent only
      if (now - verdictMs <= DASHBOARD_RECENCY_MS) {
        items.push({
          id: `verdict_landed:dispute:${disputeId}`,
          type: "verdict_landed",
          priority: "info",
          title: `Verdict landed on dispute you're party to`,
          summary: `${_ctidLabel(ctid)} ${verdict}.`,
          role,
          ctid,
          dispute_id: disputeId,
          deadline: null,
          action: disputeId ? { kind: "view_dispute", label: "View dispute", href: `/disputes/${disputeId}` } : null,
          metadata: {
            verdict,
            confirmed_origin: adj.data?.confirmed_origin || null,
            resolved_at: adj.timestamp,
          },
        });
      }
    }

    // ── verdict_on_my_jury — recent verdicts on disputes I served on ──────
    // Surfaces ADJUDICATION_RESULT (Stage-2 jury) and APPEAL_RESULT (Stage-3
    // expert) for ctids where I was summoned. Read-only, info priority,
    // 24h recency. Lets a juror confirm the outcome + their score impact
    // without paging the full history endpoint.
    {
      const myCtidRoles = new Map();   // ctid → { role, isAppeal }
      for (const s of summonsForMe) {
        const ctid = s.data?.ctid;
        if (!ctid) continue;
        const isAppeal = !!s.data.is_appeal;
        // Last write wins is fine — same juror serving twice on the same
        // ctid should not happen; if it did (legacy state), the dedup at
        // selectExperts now blocks it going forward.
        myCtidRoles.set(`${ctid}:${isAppeal ? "expert" : "juror"}`, { ctid, isAppeal });
      }

      for (const { ctid, isAppeal } of myCtidRoles.values()) {
        const result = isAppeal ? _appealResByCtid.get(ctid) : _adjByCtid.get(ctid);
        if (!result) continue;
        const resolvedMs = result.timestamp;
        if (now - resolvedMs > DASHBOARD_RECENCY_MS) continue;

        const myReveal = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid)
          .find(r => r.data?.juror_tip_id === tipId && (!!r.data?.is_appeal) === isAppeal);
        const myVote = myReveal?.data?.vote || null;
        const verdict = result.data?.verdict;

        // Outcome derivation: replicate jury.js's score-effect logic so the
        // FE doesn't have to run it. UPHELD = mismatch majority; DISMISSED
        // = match majority. CONSERVATIVE_LABEL counts as mismatch-side.
        // ABSTAIN is neither side; no reveal at all is no-show.
        let outcome = "no_show";
        let scoreImpact = -JURY.NO_SHOW_PENALTY;
        if (myVote === VOTE.ABSTAIN) {
          outcome = "abstain";
          scoreImpact = 0;
        } else if (myVote) {
          const isMismatchSide = (verdict === VERDICT.UPHELD) || (verdict === VERDICT.CONSERVATIVE_LABEL);
          const votedMajority = isMismatchSide ? myVote === VOTE.MISMATCH : myVote === VOTE.MATCH;
          outcome = votedMajority ? "majority" : "minority";
          scoreImpact = votedMajority ? JURY.MAJORITY_BONUS : -JURY.MINORITY_PENALTY;
        }
        // NO_QUORUM resolution doesn't penalise/reward — it auto-escalates.
        if (verdict === VERDICT.NO_QUORUM) {
          outcome = "no_quorum";
          scoreImpact = 0;
        }

        const role = isAppeal ? "expert" : "juror";
        const ctidDisputes = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid)
          .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
        const disputeId = ctidDisputes[0] ? shortDisputeId(ctidDisputes[0].tx_id) : null;

        const summaryParts = [`${_ctidLabel(ctid)} ${verdict}.`];
        if (myVote) summaryParts.push(`You voted ${myVote}.`);
        if (scoreImpact !== 0) summaryParts.push(`Score ${scoreImpact > 0 ? "+" : ""}${scoreImpact}.`);

        items.push({
          id: `verdict_on_my_jury:${role}:${ctid}`,
          type: "verdict_on_my_jury",
          priority: "info",
          title: `${role === "expert" ? "Appeal" : "Jury"} verdict on a dispute you served in: ${verdict}`,
          summary: summaryParts.join(" "),
          role,
          ctid,
          dispute_id: disputeId,
          deadline: null,
          action: disputeId ? { kind: "view_dispute", label: "View dispute", href: `/disputes/${disputeId}` } : null,
          metadata: {
            verdict,
            my_vote: myVote,
            outcome,
            score_impact: scoreImpact,
            resolved_at: result.timestamp,
          },
        });
      }
    }

    // ── review_assignment_pending ────────────────────────────────────────
    // Reviewer-facing reminder for open TRIGGERED assignments. Surfaces
    // the assigned_reviewer's outstanding cases with hours remaining
    // until REVIEWER.AUTO_RECUSE_AGE_MS triggers the system-emitted
    // recuse. Once the reviewer dismisses / confirms / recuses (or the
    // auto-recuse fires), the review row leaves TRIGGERED state and the
    // item disappears.
    if (typeof dag.getPrescanReviewsByReviewer === "function") {
      const myReviews = dag.getPrescanReviewsByReviewer(tipId) || [];
      for (const r of myReviews) {
        if (r.state !== "triggered") continue;
        if (r.triggered_at_ms == null) continue;
        const deadlineMs = r.triggered_at_ms + REVIEWER.AUTO_RECUSE_AGE_MS;
        const remainingMs = deadlineMs - now;
        const hoursRemaining = Math.max(0, Math.round(remainingMs / 3600000));
        const overdue = remainingMs <= 0;
        items.push({
          id: `review_assignment_pending:${r.review_id}`,
          type: "review_assignment_pending",
          priority: overdue ? "urgent" : (hoursRemaining <= 6 ? "urgent" : "high"),
          title: overdue
            ? `Review assignment past SLA — auto-recuse imminent`
            : `Review assignment open — ${hoursRemaining}h to decide or recuse`,
          summary: `${_ctidLabel(r.ctid)} is awaiting your decision. Dismiss, confirm, or recuse before the assignment auto-recuses and reassigns.`,
          role: "reviewer",
          ctid: r.ctid,
          dispute_id: null,
          deadline: deadlineMs,
          action: {
            kind: "view_review",
            label: "Open review",
            href: `/reviews/${r.review_id}`,
          },
          metadata: {
            review_id: r.review_id,
            creator_tip_id: r.creator_tip_id,
            triggered_at_ms: r.triggered_at_ms,
            hours_remaining: hoursRemaining,
          },
        });
      }
    }

    // ── Flagged-content notifications (3 phases) ─────────────────────────
    // Three creator-facing states are surfaced as separate notification
    // types so the FE can render distinct copy / actions for each:
    //
    //   A. content_flagged_for_review          (h=0 → h=48, no review yet)
    //   B. content_under_review                (TRIGGERED — reviewer evaluating)
    //   C. prescan_review_decision_required    (CONFIRMED — creator has 24h)
    //
    // All three derive from current DAG state — no notification table.
    // A flagged content row transitions through them as its prescan_review
    // row advances; the FE renders whichever is currently emitted.
    if (typeof dag.getContentByAuthor === "function") {
      for (const c of dag.getContentByAuthor(tipId)) {
        // Pre-filter — only HIGH/CRITICAL OH content of this author is
        // a candidate for any of the three notifications.
        if (c.origin_code !== ORIGIN.OH) continue;
        if (c.prescan_tier !== PRESCAN_TIERS.HIGH && c.prescan_tier !== PRESCAN_TIERS.CRITICAL) continue;

        const registeredMs = c.registered_at ? c.registered_at : NaN;
        if (!Number.isFinite(registeredMs)) continue;

        const openReview = typeof dag.getOpenPrescanReviewByCtid === "function"
          ? dag.getOpenPrescanReviewByCtid(c.ctid)
          : null;

        // ── C. prescan_review_decision_required (CONFIRMED) ─────────────
        // Reviewer agreed with the AI. Creator has 24h to accept the
        // suggested correction privately or file a public dispute.
        if (openReview && openReview.state === PRESCAN_REVIEW_STATES.CONFIRMED) {
          const confirmedAtMs = openReview.confirmed_at_ms || now;
          const decisionDeadlineMs = confirmedAtMs + REVIEWER.CREATOR_DECISION_WINDOW_MS;
          const remainingMs = Math.max(0, decisionDeadlineMs - now);
          const remainingHours = Math.max(0, Math.round(remainingMs / 3600000));
          items.push({
            id: `prescan_review_decision_required:${c.ctid}`,
            type: "prescan_review_decision_required",
            priority: "high",
            title: remainingMs > 0
              ? `Reviewer confirmed the AI flag — ${remainingHours}h to respond.`
              : `Reviewer confirmed the AI flag — decision window elapsed.`,
            summary: `${_ctidLabel(c.ctid)}: an independent reviewer agreed with the ${c.prescan_tier.toUpperCase()} AI assessment${openReview.suggested_origin ? ` and suggested ${openReview.suggested_origin}` : ""}. Accept the correction privately (-10 reputation) or escalate to a public dispute.`,
            role: "author",
            ctid: c.ctid,
            dispute_id: null,
            deadline: decisionDeadlineMs,
            action: {
              kind: "review_decision",
              label: "Respond to reviewer",
              href: `/reviews/${openReview.review_id}`,
            },
            metadata: {
              review_id: openReview.review_id,
              review_state: openReview.state,
              prescan_tier: c.prescan_tier,
              prescan_probability: c.prescan_probability,
              declared_origin: c.origin_code,
              suggested_origin: openReview.suggested_origin || null,
              decision_note: openReview.decision_note || null,
              confirmed_at_ms: confirmedAtMs,
              decision_window_ends_at: decisionDeadlineMs,
              hours_remaining: remainingHours,
            },
          });
          continue;
        }

        // ── B. content_under_review (TRIGGERED) ─────────────────────────
        // Reviewer assigned and evaluating. Creator can still self-correct
        // (closes the review as CLOSED_SELF_CORRECT). No hard deadline
        // exposed here — the reviewer SLA bounds it server-side.
        if (openReview && openReview.state === PRESCAN_REVIEW_STATES.TRIGGERED) {
          items.push({
            id: `content_under_review:${c.ctid}`,
            type: "content_under_review",
            priority: "high",
            title: `Independent reviewer is examining your content.`,
            summary: `${_ctidLabel(c.ctid)}: a reviewer was assigned at ${toIso(openReview.triggered_at_ms || registeredMs + CONTENT_GRACE.FLAGGED_MS)}. You can still update the origin at zero penalty until they decide.`,
            role: "author",
            ctid: c.ctid,
            dispute_id: null,
            deadline: null,
            action: {
              kind: "update_origin",
              label: "Update origin",
              href: `/content/${encodeURIComponent(c.ctid)}/update-origin`,
            },
            metadata: {
              review_id: openReview.review_id,
              review_state: openReview.state,
              prescan_tier: c.prescan_tier,
              prescan_probability: c.prescan_probability,
              declared_origin: c.origin_code,
              registered_at: c.registered_at,
              triggered_at_ms: openReview.triggered_at_ms || null,
              assigned_reviewer: openReview.assigned_reviewer || null,
            },
          });
          continue;
        }

        // ── A. content_flagged_for_review (no review yet) ───────────────
        // Pre-h=48 reconsideration window. Surfaces from h=0 onwards —
        // the FE renders this as the primary "your content was flagged"
        // notification on the dashboard, mirroring the post-registration
        // warning banner. Hidden once content age passes h=48 (the
        // trigger fires, B/C take over) or the creator self-corrects.
        if (c.status !== CONTENT_STATUS.REGISTERED) continue;
        const ageMs = now - registeredMs;
        if (ageMs >= CONTENT_GRACE.FLAGGED_MS) continue;

        const remainingMs = Math.max(0, CONTENT_GRACE.FLAGGED_MS - ageMs);
        const remainingHours = Math.max(1, Math.round(remainingMs / 3600000));
        const deadlineMs = registeredMs + CONTENT_GRACE.FLAGGED_MS;
        items.push({
          id: `content_flagged_for_review:${c.ctid}`,
          type: "content_flagged_for_review",
          priority: "high",
          title: `${remainingHours}h to reconsider — reviewer engages after that.`,
          summary: `${_ctidLabel(c.ctid)} was flagged at ${c.prescan_tier.toUpperCase()} AI confidence (${Math.round((c.prescan_probability || 0) * 100)}%). Update the origin to AA / AG / MX during this window for a clean exit, or do nothing and an independent reviewer will examine it at h=48.`,
          role: "author",
          ctid: c.ctid,
          dispute_id: null,
          deadline: deadlineMs,
          action: {
            kind: "update_origin",
            label: "Update origin",
            href: `/content/${encodeURIComponent(c.ctid)}/update-origin`,
          },
          metadata: {
            prescan_tier: c.prescan_tier,
            prescan_probability: c.prescan_probability,
            declared_origin: c.origin_code,
            registered_at: c.registered_at,
            hours_remaining: remainingHours,
            decision_window_ends_at: deadlineMs,
          },
        });
      }
    }

    // ── dispute_filed_against_me ─────────────────────────────────────────
    for (const dispute of dag.getTxsByType(TX_TYPES.CONTENT_DISPUTED)) {
      if (dispute.data?.author_tip_id !== tipId) continue;
      const filedMs = dispute.timestamp;
      if (now - filedMs > DASHBOARD_RECENCY_MS) continue;
      const disputeId = shortDisputeId(dispute.tx_id);
      items.push({
        id: `dispute_filed_against_me:dispute:${disputeId}`,
        type: "dispute_filed_against_me",
        priority: "info",
        title: `New dispute filed against your content`,
        summary: `${_ctidLabel(dispute.data.ctid)} — ${dispute.data?.declared_origin}→${dispute.data?.claimed_origin} claim.`,
        role: "author",
        ctid: dispute.data.ctid,
        dispute_id: disputeId,
        deadline: null,
        action: { kind: "view_dispute", label: "View dispute", href: `/disputes/${disputeId}` },
        metadata: {
          disputer_tip_id: dispute.data?.disputer_tip_id,
          claimed_origin: dispute.data?.claimed_origin,
          declared_origin: dispute.data?.declared_origin,
        },
      });
    }

    // ── Sort: priority desc, deadline asc (no-deadline items last in tier) ─
    items.sort((a, b) => {
      const pa = _PRIORITY_ORDER[a.priority] ?? 9;
      const pb = _PRIORITY_ORDER[b.priority] ?? 9;
      if (pa !== pb) return pa - pb;
      const da = a.deadline ? a.deadline : Number.POSITIVE_INFINITY;
      const db = b.deadline ? b.deadline : Number.POSITIVE_INFINITY;
      if (da !== db) return da - db;
      return a.id.localeCompare(b.id);  // stable across polls
    });

    const attentionCount = items.filter(i => i.priority === "urgent" || i.priority === "high").length;

    return {
      tip_id: tipId,
      creator_name: identity.creator_name || null,
      generated_at: now,
      attention_count: attentionCount,
      items,
    };
  }

  // ─── Jury history ─────────────────────────────────────────────────────────
  // All-time list of disputes the user was elected to (juror or expert),
  // with their commit/reveal state, vote, the final verdict (if any), and
  // the score impact. Paginated — clients query `/v1/users/:tip_id/jury-history`
  // with optional `?limit=…&offset=…&status=…&role=…` filters. The dashboard
  // surfaces only RECENT (24h) verdicts; this endpoint is for review.

  // Shared with verdict_on_my_jury — same outcome derivation rules so the
  // dashboard "score +3 majority" line matches what the history page shows.
  function _juryOutcome(myVote, verdict) {
    if (verdict === VERDICT.NO_QUORUM) return { outcome: "no_quorum", scoreImpact: 0 };
    if (!myVote) return { outcome: "no_show", scoreImpact: -JURY.NO_SHOW_PENALTY };
    if (myVote === VOTE.ABSTAIN) return { outcome: "abstain", scoreImpact: 0 };
    const isMismatchSide = verdict === VERDICT.UPHELD || verdict === VERDICT.CONSERVATIVE_LABEL;
    const votedMajority = isMismatchSide ? myVote === VOTE.MISMATCH : myVote === VOTE.MATCH;
    return {
      outcome: votedMajority ? "majority" : "minority",
      scoreImpact: votedMajority ? JURY.MAJORITY_BONUS : -JURY.MINORITY_PENALTY,
    };
  }

  // Status string captures where this juror is in the lifecycle, so the FE
  // can render "Awaiting your vote" / "Resolved" / "Missed" badges without
  // doing date math. Caller passes pre-resolved fields rather than re-walking
  // the DAG per item.
  function _juryStatus({ committed, revealed, hasResult, now, commitDeadlineMs, revealDeadlineMs }) {
    if (revealed && hasResult) return "resolved";
    if (revealed) return "revealed_pending_verdict";
    if (committed && now < revealDeadlineMs) return "committed";
    if (committed) return "missed_reveal";
    if (now < commitDeadlineMs) return "summoned";
    return "missed_commit";
  }

  function getJuryHistoryForTipId(tipId, opts = {}) {
    validate({ tip_id: tipId }, { tip_id: { required: true, type: "string", match: /^tip:\/\/id\// } });

    const identity = dag.getIdentity(tipId);
    if (!identity) throw { status: 404, error: "TIP-ID not found" };

    const limit = Math.min(Math.max(parseInt(opts.limit, 10) || 20, 1), 100);
    const offset = Math.max(parseInt(opts.offset, 10) || 0, 0);
    const filterStatus = opts.status || null;        // optional: resolved | committed | summoned | …
    const filterRole = opts.role || null;            // optional: juror | expert
    const now = nowMs();

    // Pre-index result txs once — saves a DAG scan per item.
    const adjByCtid = new Map();
    for (const t of dag.getTxsByType(TX_TYPES.ADJUDICATION_RESULT)) {
      const ctid = t.data?.ctid;
      if (ctid) adjByCtid.set(ctid, t);
    }
    const appealResByCtid = new Map();
    for (const t of dag.getTxsByType(TX_TYPES.APPEAL_RESULT)) {
      const ctid = t.data?.ctid;
      if (ctid) appealResByCtid.set(ctid, t);
    }

    // Collapse multiple JURY_SUMMONS for the same (ctid, role) into one
    // history row — the bug we just fixed in selectExperts could leave
    // legacy duplicates in the DAG, and an honest user shouldn't see two
    // rows for the same dispute either way.
    const seen = new Set();
    const rows = [];
    const summonsForMe = dag.getTxsByType(TX_TYPES.JURY_SUMMONS)
      .filter(s => s.data?.juror_tip_id === tipId)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp));   // newest first

    for (const s of summonsForMe) {
      const ctid = s.data?.ctid;
      if (!ctid) continue;
      const isAppeal = !!s.data.is_appeal;
      const role = isAppeal ? "expert" : "juror";
      const key = `${ctid}:${role}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (filterRole && filterRole !== role) continue;

      const myCommit = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid)
        .find(t => t.data?.juror_tip_id === tipId && (!!t.data?.is_appeal) === isAppeal);
      const myReveal = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid)
        .find(t => t.data?.juror_tip_id === tipId && (!!t.data?.is_appeal) === isAppeal);
      const result = isAppeal ? appealResByCtid.get(ctid) : adjByCtid.get(ctid);
      const myVote = myReveal?.data?.vote || null;
      const verdict = result?.data?.verdict || null;

      const status = _juryStatus({
        committed: !!myCommit,
        revealed: !!myReveal,
        hasResult: !!result,
        now,
        commitDeadlineMs: s.data.commit_deadline,
        revealDeadlineMs: s.data.reveal_deadline,
      });
      if (filterStatus && filterStatus !== status) continue;

      const { outcome, scoreImpact } = result
        ? _juryOutcome(myVote, verdict)
        : { outcome: null, scoreImpact: null };   // pre-verdict — outcome unknown

      const ctidDisputes = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid)
        .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      const latestDispute = ctidDisputes[0];
      const disputeId = latestDispute ? shortDisputeId(latestDispute.tx_id) : null;

      rows.push({
        ctid,
        dispute_id: disputeId,
        dispute_tx_id: latestDispute?.tx_id || null,
        role,
        status,
        summoned_at: s.timestamp,
        commit_deadline: s.data.commit_deadline,
        reveal_deadline: s.data.reveal_deadline,
        committed: !!myCommit,
        committed_at: myCommit?.timestamp || null,
        revealed: !!myReveal,
        revealed_at: myReveal?.timestamp || null,
        my_vote: myVote,
        confirmed_origin: myReveal?.data?.confirmed_origin || null,
        verdict,
        verdict_at: result?.timestamp || null,
        confirmed_origin_verdict: result?.data?.confirmed_origin || null,
        outcome,
        score_impact: scoreImpact,
      });
    }

    return {
      tip_id: tipId,
      creator_name: identity.creator_name || null,
      total: rows.length,
      limit,
      offset,
      items: rows.slice(offset, offset + limit),
    };
  }

  function getDisputeById(disputeIdOrPrefix) {
    const disputeTx = resolveDispute(disputeIdOrPrefix);
    const events = collectEpisodeEvents(disputeTx);
    const now = nowMs();

    const ctid = disputeTx.data.ctid;
    const rec = dag.getContent(ctid);
    if (!rec) throw { status: 404, error: "Content record not found" };

    const summary = summarizeDispute(disputeTx, events, now);

    const summonsTxs = events.filter(e => e.tx_type === TX_TYPES.JURY_SUMMONS && !e.data.is_appeal);
    const commitTxs = events.filter(e => e.tx_type === TX_TYPES.JURY_VOTE_COMMIT && !e.data.is_appeal);
    const revealTxs = events.filter(e => e.tx_type === TX_TYPES.JURY_VOTE_REVEAL && !e.data.is_appeal);
    const expSummonsTxs = events.filter(e => e.tx_type === TX_TYPES.JURY_SUMMONS && e.data.is_appeal);
    const expCommitTxs = events.filter(e => e.tx_type === TX_TYPES.JURY_VOTE_COMMIT && e.data.is_appeal);
    const expRevealTxs = events.filter(e => e.tx_type === TX_TYPES.JURY_VOTE_REVEAL && e.data.is_appeal);

    const committedSet = new Set(commitTxs.map(t => t.data.juror_tip_id));
    const revealedSet = new Set(revealTxs.map(t => t.data.juror_tip_id));
    const expCommittedSet = new Set(expCommitTxs.map(t => t.data.juror_tip_id));
    const expRevealedSet = new Set(expRevealTxs.map(t => t.data.juror_tip_id));

    const adj = events.find(e => e.tx_type === TX_TYPES.ADJUDICATION_RESULT);
    const appealResult = events.find(e => e.tx_type === TX_TYPES.APPEAL_RESULT);
    const appealFiled = events.find(e => e.tx_type === TX_TYPES.APPEAL_FILED);
    const classifier = events.find(e => e.tx_type === TX_TYPES.AI_CLASSIFIER_RESULT);

    const authorContent = dag.getContentByAuthor(rec.author_tip_id);
    const authorScore = scoring.getScore(rec.author_tip_id);
    const priorDisputes = dag.getTxsByType(TX_TYPES.CONTENT_DISPUTED).filter(t => t.data?.author_tip_id === rec.author_tip_id);
    const priorAdj = dag.getTxsByType(TX_TYPES.ADJUDICATION_RESULT).filter(t => t.data?.author_tip_id === rec.author_tip_id);

    return {
      ...summary,
      content: {
        ctid,
        origin_code: rec.origin_code,
        origin_label: ORIGIN_LABELS[rec.origin_code] || rec.origin_code,
        content_hash: rec.content_hash,
        author_tip_id: rec.author_tip_id,
        status: rec.status,
        registered_at: rec.registered_at,
      },
      dispute: {
        disputer_tip_id: disputeTx.data.disputer_tip_id,
        reason: disputeTx.data.reason,
        claimed_origin: disputeTx.data.claimed_origin,
        declared_origin: disputeTx.data.declared_origin,
        evidence_hash: disputeTx.data.evidence_hash,
        filed_at: disputeTx.timestamp,
        dispute_tx_id: disputeTx.tx_id,
      },
      ai_classifier: classifier ? { confidence: classifier.data.confidence, routing: classifier.data.routing } : null,
      creator_history: {
        total_content: authorContent.length,
        verified_count: authorContent.filter(c => c.status === CONTENT_STATUS.VERIFIED).length,
        prior_disputes: priorDisputes.length,
        prior_upheld: priorAdj.filter(t => t.data?.verdict === VERDICT.UPHELD).length,
        prior_dismissed: priorAdj.filter(t => t.data?.verdict === VERDICT.DISMISSED).length,
        current_score: authorScore.score,
        current_tier: authorScore.tier.name,
        offense_count: authorScore.offense_count,
      },
      jury: {
        jurors: summonsTxs.map(s => {
          const id = dag.getIdentity(s.data.juror_tip_id);
          return {
            juror_tip_id: s.data.juror_tip_id,
            creator_name: id?.creator_name || null,
            status: revealedSet.has(s.data.juror_tip_id) ? "revealed"
              : committedSet.has(s.data.juror_tip_id) ? "committed"
                : "summoned",
          };
        }),
        commit_deadline: summonsTxs[0]?.data?.commit_deadline,
        reveal_deadline: summonsTxs[0]?.data?.reveal_deadline,
        total_summoned: summonsTxs.length,
        total_committed: commitTxs.length,
        total_revealed: revealTxs.length,
      },
      verdict: adj ? {
        verdict: adj.data.verdict,
        declared_origin: adj.data.declared_origin,
        confirmed_origin: adj.data.confirmed_origin,
        match_count: adj.data.match_count,
        mismatch_count: adj.data.mismatch_count,
        abstain_count: adj.data.abstain_count,
        resolved_at: adj.timestamp,
        // appeal_filing_deadline is derivable from resolved_at + APPEAL.FILING_WINDOW_HOURS,
        // but the FE shouldn't have to know the genesis constant. Computed here so a
        // single field drives the "Appeal closes …" countdown in the status panel.
        // null after deadline passes (the appeal window itself is closed; UI hides
        // the countdown and surfaces "Appeal window closed").
        appeal_filing_deadline: appealResult || appealFiled
          ? null
          : adj.timestamp + APPEAL.FILING_WINDOW_HOURS * 3600000,
        // Loser-party info — drives the "Show Appeal button?" decision on
        // the FE. Same rule as /v1/disputes appealable[] and dashboard's
        // appeal_available: UPHELD → author lost; DISMISSED → disputer
        // lost; CONSERVATIVE_LABEL / NO_QUORUM → no clear loser, both null.
        // FE shows the appeal CTA iff `losing_tip_id === currentUser.tip_id`
        // AND `appeal_filing_deadline` is in the future.
        losing_party: adj.data.verdict === VERDICT.UPHELD ? "author"
          : adj.data.verdict === VERDICT.DISMISSED ? "disputer"
            : null,
        losing_tip_id: adj.data.verdict === VERDICT.UPHELD ? rec.author_tip_id
          : adj.data.verdict === VERDICT.DISMISSED ? disputeTx.data.disputer_tip_id
            : null,
      } : null,
      appeal: appealFiled ? {
        filed_at: appealFiled.timestamp,
        appellant_tip_id: appealFiled.data.appellant_tip_id,
        appellant_name: dag.getIdentity(appealFiled.data.appellant_tip_id)?.creator_name || null,
        experts: expSummonsTxs.map(s => {
          const id = dag.getIdentity(s.data.juror_tip_id);
          return {
            expert_tip_id: s.data.juror_tip_id,
            creator_name: id?.creator_name || null,
            status: expRevealedSet.has(s.data.juror_tip_id) ? "revealed"
              : expCommittedSet.has(s.data.juror_tip_id) ? "committed"
                : "summoned",
          };
        }),
        commit_deadline: expSummonsTxs[0]?.data?.commit_deadline,
        reveal_deadline: expSummonsTxs[0]?.data?.reveal_deadline,
        total_summoned: expSummonsTxs.length,
        total_committed: expCommitTxs.length,
        total_revealed: expRevealTxs.length,
        verdict: appealResult ? appealResult.data.verdict : null,
        overturned: appealResult ? appealResult.data.overturned : null,
        resolved_at: appealResult ? appealResult.timestamp : null,
      } : null,
      timeline: buildTimeline(events),
    };
  }

  function getDisputeTimeline(disputeIdOrPrefix) {
    const disputeTx = resolveDispute(disputeIdOrPrefix);
    const events = collectEpisodeEvents(disputeTx);
    return {
      dispute_id: shortDisputeId(disputeTx.tx_id),
      dispute_tx_id: disputeTx.tx_id,
      ctid: disputeTx.data.ctid,
      status: projectStatus(events, nowMs()),
      timeline: buildTimeline(events),
    };
  }

  return {
    fileDispute, juryCommit, juryReveal, getDisputeCase, fileAppeal, appealCommit, appealReveal,
    listDisputesForTipId, getUserDashboard, getJuryHistoryForTipId,
    getDisputeById, getDisputeTimeline,
  };
}

module.exports = { createDisputeService };
