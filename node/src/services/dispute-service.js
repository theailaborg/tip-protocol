"use strict";

const { shake256, verifyBodySignature } = require("../../../shared/crypto");
const { TX_TYPES, ORIGIN, JURY_VOTES, VOTE, VERDICT, CONTENT_STATUS } = require("../../../shared/constants");
const { DISPUTE, JURY, APPEAL, AI_CLASSIFIER } = require("../../../shared/protocol-constants");
const { validateTransaction } = require("../validators/tx-validator");
const { selectJury, selectExperts, tallyVerdictAndApply, applyAppealVerdict } = require("../jury");
const { withTxId, nodeSignedAuto, preScanContent } = require("./helpers");
const { validate } = require("../middleware/validate");
const { getLogger } = require("../logger");

const log = getLogger("tip.dispute");

const ORIGIN_CODES = Object.keys(ORIGIN);

function createDisputeService({ dag, scoring, config, broadcast }) {

  function fileDispute(ctid, body) {
    const rec = dag.getContent(ctid);
    if (!rec) throw { status: 404, error: "Content record not found" };
    if (rec.status === CONTENT_STATUS.RETRACTED) throw { status: 403, error: "Content has been retracted — dispute not allowed" };
    if (rec.status === CONTENT_STATUS.DISPUTED) throw { status: 403, error: "Content is already under dispute — wait for adjudication result" };
    if (rec.status === CONTENT_STATUS.PENDING_REVIEW) throw { status: 403, error: "Content is pending review — wait for 24-hour grace period" };

    validate(body, { disputer_tip_id: { required: true }, signature: { required: true }, reason: { required: true } });
    const { disputer_tip_id, reason, claimed_origin, evidence_hash, signature } = body;
    if (reason === "origin_mismatch" && !claimed_origin) throw { status: 400, error: "claimed_origin required for origin_mismatch disputes" };
    if (claimed_origin && !ORIGIN_CODES.includes(claimed_origin)) throw { status: 400, error: `Invalid claimed_origin. Must be one of: ${ORIGIN_CODES.join(", ")}` };

    const disputer = dag.getIdentity(disputer_tip_id);
    if (!disputer) throw { status: 404, error: "Disputer TIP-ID not found" };
    if (dag.isRevoked(disputer_tip_id)) throw { status: 403, error: "Disputer TIP-ID is revoked" };

    const disputerScore = scoring.getScore(disputer_tip_id).score;
    if (disputerScore < DISPUTE.MIN_SCORE_TO_DISPUTE) throw { status: 403, error: `Score must be >= ${DISPUTE.MIN_SCORE_TO_DISPUTE} to dispute (current: ${disputerScore})` };

    const DISPUTE_FIELDS = claimed_origin ? ["disputer_tip_id", "reason", "claimed_origin", "evidence_hash"] : ["disputer_tip_id", "reason", "evidence_hash"];
    if (!verifyBodySignature(body, signature, disputer.public_key, DISPUTE_FIELDS)) throw { status: 403, error: "Disputer signature verification failed" };
    if (dag.hasDispute(ctid, disputer_tip_id)) throw { status: 409, error: "You have already disputed this content" };

    const disputeTx = withTxId({
      tx_type: TX_TYPES.CONTENT_DISPUTED, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(),
      data: {
        ctid, disputer_tip_id, reason, claimed_origin: claimed_origin || null,
        declared_origin: rec.origin_code, evidence_hash, author_tip_id: rec.author_tip_id,
        pre_dispute_status: rec.status, stake: DISPUTE.DISPUTER_STAKE,
      },
    });
    const validation = validateTransaction(disputeTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    dag.addTx(disputeTx);
    broadcast(disputeTx);
    dag.updateContentStatus(ctid, CONTENT_STATUS.DISPUTED);

    // Stage 1: AI Classifier (always escalates for now)
    let stage1Result;
    try {
      const aiResult = preScanContent(rec.content_hash || "", rec.origin_code, {});
      const confidence = aiResult.probability || 0;
      const routing = confidence >= AI_CLASSIFIER.HIGH_CONFIDENCE ? "escalate_high" : "escalate";

      const classifierTx = nodeSignedAuto({
        tx_type: TX_TYPES.AI_CLASSIFIER_RESULT, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(),
        data: { ctid, dispute_tx_id: disputeTx.tx_id, confidence, routing },
      }, config);
      dag.addTx(classifierTx);
      broadcast(classifierTx);

      stage1Result = { routing, confidence, message: routing === "escalate_high" ? "High-confidence mismatch. Escalated to Stage 2 with flag." : "Escalated to Stage 2 for human review." };
      log.info(`Stage 1 AI: ${ctid} confidence=${confidence} routing=${routing}`);
    } catch (e) {
      log.error(`Stage 1 AI failed for ${ctid}:`, e.message);
      stage1Result = { routing: "escalate", confidence: 0, message: "AI classifier unavailable — escalated to Stage 2." };
    }

    // Stage 2: Jury Selection
    let juryResult = null;
    try {
      const jury = selectJury(dag, scoring, disputeTx.tx_id, rec.author_tip_id, disputer_tip_id);
      if (jury.insufficient) log.warn(`Jury selection: insufficient jurors for ${ctid} (${jury.jurors.length}/${JURY.SIZE})`);

      const commitDeadline = new Date(Date.now() + JURY.COMMIT_WINDOW_HOURS * 3600000).toISOString();
      const revealDeadline = new Date(Date.now() + (JURY.COMMIT_WINDOW_HOURS + JURY.REVEAL_WINDOW_HOURS) * 3600000).toISOString();

      for (const jurorTipId of jury.jurors) {
        const summonsTx = nodeSignedAuto({
          tx_type: TX_TYPES.JURY_SUMMONS, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(),
          data: { ctid, dispute_tx_id: disputeTx.tx_id, juror_tip_id: jurorTipId, stake: JURY.JUROR_STAKE, seed: jury.seed, identity_count: jury.identityCount, commit_deadline: commitDeadline, reveal_deadline: revealDeadline },
        }, config);
        dag.addTx(summonsTx);
        broadcast(summonsTx);
      }

      juryResult = { jurors: jury.jurors, count: jury.jurors.length, insufficient: jury.insufficient, seed: jury.seed, identity_count: jury.identityCount, commit_deadline: commitDeadline, reveal_deadline: revealDeadline };
      log.info(`Jury selected for ${ctid}: ${jury.jurors.length} jurors`);
    } catch (e) {
      log.error(`Jury selection failed for ${ctid}:`, e.message);
      juryResult = { error: "Jury selection failed", message: e.message };
    }

    return { success: true, message: "Dispute filed.", dispute_tx_id: disputeTx.tx_id, stake_at_risk: DISPUTE.DISPUTER_STAKE, stage1: stage1Result, stage2: juryResult };
  }

  function juryCommit(ctid, body) {
    const { juror_tip_id, commitment, signature } = body;
    validate(body, { juror_tip_id: { required: true }, commitment: { required: true }, signature: { required: true } });

    const juror = dag.getIdentity(juror_tip_id);
    if (!juror) throw { status: 404, error: "Juror TIP-ID not found" };
    if (dag.isRevoked(juror_tip_id)) throw { status: 403, error: "Juror TIP-ID is revoked" };

    if (!verifyBodySignature(body, signature, juror.public_key, ["juror_tip_id", "commitment"])) throw { status: 403, error: "Juror signature verification failed" };

    const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid).filter(t => t.data?.juror_tip_id === juror_tip_id && !t.data?.is_appeal);
    if (!summonsTxs.length) throw { status: 403, error: "You were not summoned as a juror for this dispute" };

    if (Date.now() > new Date(summonsTxs[0].data.commit_deadline).getTime()) throw { status: 403, error: "Commit window has closed" };

    const existing = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid).find(t => t.data?.juror_tip_id === juror_tip_id && !t.data?.is_appeal);
    if (existing) throw { status: 409, error: "You have already submitted a vote commitment" };

    const commitTx = withTxId({ tx_type: TX_TYPES.JURY_VOTE_COMMIT, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(), data: { ctid, juror_tip_id, commitment } });
    dag.addTx(commitTx);
    broadcast(commitTx);
    return { success: true, tx_id: commitTx.tx_id };
  }

  function juryReveal(ctid, body) {
    const { juror_tip_id, vote, salt, confirmed_origin, signature } = body;
    validate(body, { juror_tip_id: { required: true }, vote: { required: true, oneOf: JURY_VOTES }, salt: { required: true }, signature: { required: true } });
    if (vote === VOTE.MISMATCH && !confirmed_origin) throw { status: 400, error: "confirmed_origin required when voting MISMATCH" };
    if (confirmed_origin && !ORIGIN_CODES.includes(confirmed_origin)) throw { status: 400, error: "Invalid confirmed_origin" };

    const juror = dag.getIdentity(juror_tip_id);
    if (!juror) throw { status: 404, error: "Juror TIP-ID not found" };

    const REVEAL_FIELDS = confirmed_origin ? ["juror_tip_id", "vote", "salt", "confirmed_origin"] : ["juror_tip_id", "vote", "salt"];
    if (!verifyBodySignature(body, signature, juror.public_key, REVEAL_FIELDS)) throw { status: 403, error: "Juror signature verification failed" };

    const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid).filter(t => t.data?.juror_tip_id === juror_tip_id && !t.data?.is_appeal);
    if (!summonsTxs.length) throw { status: 403, error: "You were not summoned as a juror" };

    const commitDeadline = new Date(summonsTxs[0].data.commit_deadline).getTime();
    const revealDeadline = new Date(summonsTxs[0].data.reveal_deadline).getTime();
    if (Date.now() < commitDeadline) throw { status: 403, error: "Reveal window has not opened yet" };
    if (Date.now() > revealDeadline) throw { status: 403, error: "Reveal window has closed" };

    const commitTx = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid).find(t => t.data?.juror_tip_id === juror_tip_id && !t.data?.is_appeal);
    if (!commitTx) throw { status: 404, error: "No vote commitment found" };
    if (shake256(`${vote}:${salt}`) !== commitTx.data.commitment) throw { status: 403, error: "Vote does not match commitment" };

    const existingReveal = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid).find(t => t.data?.juror_tip_id === juror_tip_id && !t.data?.is_appeal);
    if (existingReveal) throw { status: 409, error: "You have already revealed your vote" };

    const revealTx = withTxId({ tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(), data: { ctid, juror_tip_id, vote, salt, confirmed_origin: vote === VOTE.MISMATCH ? confirmed_origin : null } });
    dag.addTx(revealTx);
    broadcast(revealTx);

    // Check if all jurors revealed → trigger verdict
    const allReveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid).filter(t => !t.data?.is_appeal);
    const allSummons = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid).filter(t => !t.data?.is_appeal);
    let verdict = null;
    if (allReveals.length >= allSummons.length) {
      verdict = tallyVerdictAndApply(ctid, allReveals, allSummons, dag, scoring, config);
    }
    return { success: true, tx_id: revealTx.tx_id, verdict };
  }

  function getDisputeCase(ctid) {
    const rec = dag.getContent(ctid);
    if (!rec) throw { status: 404, error: "Content record not found" };

    const { ORIGIN_LABELS } = require("../../../shared/constants");
    const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
    const classifierTxs = dag.getTxsByTypeAndCtid(TX_TYPES.AI_CLASSIFIER_RESULT, ctid);
    const authorContent = dag.getContentByAuthor(rec.author_tip_id);
    const authorScore = scoring.getScore(rec.author_tip_id);
    const priorDisputes = dag.getTxsByType(TX_TYPES.CONTENT_DISPUTED).filter(t => t.data?.author_tip_id === rec.author_tip_id);
    const priorAdj = dag.getTxsByType(TX_TYPES.ADJUDICATION_RESULT).filter(t => t.data?.author_tip_id === rec.author_tip_id);
    const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid);
    const commitTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid);
    const revealTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid);
    const adjTxs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid);

    const committedIds = new Set(commitTxs.map(t => t.data.juror_tip_id));
    const revealedIds = new Set(revealTxs.map(t => t.data.juror_tip_id));

    return {
      content: { ctid, origin_code: rec.origin_code, origin_label: ORIGIN_LABELS[rec.origin_code] || rec.origin_code, content_hash: rec.content_hash, author_tip_id: rec.author_tip_id, status: rec.status, registered_at: rec.registered_at },
      dispute: disputeTxs.length ? { disputer_tip_id: disputeTxs[0].data.disputer_tip_id, reason: disputeTxs[0].data.reason, claimed_origin: disputeTxs[0].data.claimed_origin, declared_origin: disputeTxs[0].data.declared_origin, evidence_hash: disputeTxs[0].data.evidence_hash, filed_at: disputeTxs[0].timestamp, dispute_tx_id: disputeTxs[0].tx_id } : null,
      ai_classifier: classifierTxs.length ? { confidence: classifierTxs[0].data.confidence, routing: classifierTxs[0].data.routing } : null,
      creator_history: { total_content: authorContent.length, verified_count: authorContent.filter(c => c.status === CONTENT_STATUS.VERIFIED).length, prior_disputes: priorDisputes.length, prior_upheld: priorAdj.filter(t => t.data?.verdict === VERDICT.UPHELD).length, prior_dismissed: priorAdj.filter(t => t.data?.verdict === VERDICT.DISMISSED).length, current_score: authorScore.score, current_tier: authorScore.tier.name, offense_count: authorScore.offense_count },
      jury: { jurors: summonsTxs.map(s => ({ juror_tip_id: s.data.juror_tip_id, status: revealedIds.has(s.data.juror_tip_id) ? "revealed" : committedIds.has(s.data.juror_tip_id) ? "committed" : "summoned" })), commit_deadline: summonsTxs[0]?.data?.commit_deadline, reveal_deadline: summonsTxs[0]?.data?.reveal_deadline, total_summoned: summonsTxs.length, total_committed: commitTxs.length, total_revealed: revealTxs.length },
      verdict: adjTxs.length ? { verdict: adjTxs[0].data.verdict, declared_origin: adjTxs[0].data.declared_origin, confirmed_origin: adjTxs[0].data.confirmed_origin, match_count: adjTxs[0].data.match_count, mismatch_count: adjTxs[0].data.mismatch_count, abstain_count: adjTxs[0].data.abstain_count, resolved_at: adjTxs[0].timestamp } : null,
    };
  }

  // ── Appeal endpoints ──────────────────────────────────────────────────────

  function fileAppeal(ctid, body) {
    validate(body, { appellant_tip_id: { required: true }, signature: { required: true } });
    const { appellant_tip_id, signature } = body;

    const adjTxs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid);
    if (!adjTxs.length) throw { status: 404, error: "No Stage 2 verdict found for this content" };

    const existingAppeal = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, ctid);
    if (existingAppeal.length) throw { status: 409, error: "Appeal already filed for this content" };

    const verdictTime = new Date(adjTxs[0].timestamp).getTime();
    if (Date.now() - verdictTime > APPEAL.FILING_WINDOW_HOURS * 3600000) throw { status: 403, error: "48-hour appeal window has expired" };

    const rec = dag.getContent(ctid);
    const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
    const disputerTipId = disputeTxs[0]?.data?.disputer_tip_id;
    const authorTipId = rec?.author_tip_id;
    if (appellant_tip_id !== authorTipId && appellant_tip_id !== disputerTipId) throw { status: 403, error: "Only the content author or the original disputer can file an appeal" };

    const appellant = dag.getIdentity(appellant_tip_id);
    if (!appellant) throw { status: 404, error: "Appellant TIP-ID not found" };
    if (dag.isRevoked(appellant_tip_id)) throw { status: 403, error: "Appellant TIP-ID is revoked" };
    if (!verifyBodySignature(body, signature, appellant.public_key, ["appellant_tip_id"])) throw { status: 403, error: "Appellant signature verification failed" };

    const appealTx = withTxId({ tx_type: TX_TYPES.APPEAL_FILED, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(), data: { ctid, appellant_tip_id, stage2_verdict: adjTxs[0].data.verdict, stake: APPEAL.APPELLANT_STAKE } });
    dag.addTx(appealTx);
    broadcast(appealTx);

    const experts = selectExperts(dag, scoring, appealTx.tx_id, authorTipId, disputerTipId);
    const commitDeadline = new Date(Date.now() + APPEAL.COMMIT_WINDOW_HOURS * 3600000).toISOString();
    const revealDeadline = new Date(Date.now() + (APPEAL.COMMIT_WINDOW_HOURS + APPEAL.REVEAL_WINDOW_HOURS) * 3600000).toISOString();

    for (const expertTipId of experts.experts) {
      const summonsTx = nodeSignedAuto({ tx_type: TX_TYPES.JURY_SUMMONS, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(), data: { ctid, dispute_tx_id: appealTx.tx_id, juror_tip_id: expertTipId, stake: JURY.JUROR_STAKE, seed: experts.seed, identity_count: experts.identityCount, commit_deadline: commitDeadline, reveal_deadline: revealDeadline, is_appeal: true } }, config);
      dag.addTx(summonsTx);
      broadcast(summonsTx);
    }

    dag.updateContentStatus(ctid, CONTENT_STATUS.DISPUTED);
    log.info(`Appeal filed for ${ctid} by ${appellant_tip_id}`);
    return { success: true, appeal_tx_id: appealTx.tx_id, stake_at_risk: APPEAL.APPELLANT_STAKE, experts: { selected: experts.experts, count: experts.experts.length, insufficient: experts.insufficient, commit_deadline: commitDeadline, reveal_deadline: revealDeadline } };
  }

  function appealCommit(ctid, body) {
    const { juror_tip_id, commitment, signature } = body;
    validate(body, { juror_tip_id: { required: true }, commitment: { required: true }, signature: { required: true } });

    const juror = dag.getIdentity(juror_tip_id);
    if (!juror) throw { status: 404, error: "Expert TIP-ID not found" };
    if (dag.isRevoked(juror_tip_id)) throw { status: 403, error: "Expert TIP-ID is revoked" };
    if (!verifyBodySignature(body, signature, juror.public_key, ["juror_tip_id", "commitment"])) throw { status: 403, error: "Expert signature verification failed" };

    const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid).filter(t => t.data?.juror_tip_id === juror_tip_id && t.data?.is_appeal === true);
    if (!summonsTxs.length) throw { status: 403, error: "You were not summoned as an expert for this appeal" };
    if (Date.now() > new Date(summonsTxs[0].data.commit_deadline).getTime()) throw { status: 403, error: "Commit window has closed" };

    const existing = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid).find(t => t.data?.juror_tip_id === juror_tip_id && t.data?.is_appeal === true);
    if (existing) throw { status: 409, error: "You have already submitted a vote commitment" };

    const commitTx = withTxId({ tx_type: TX_TYPES.JURY_VOTE_COMMIT, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(), data: { ctid, juror_tip_id, commitment, is_appeal: true } });
    dag.addTx(commitTx);
    broadcast(commitTx);
    return { success: true, tx_id: commitTx.tx_id };
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

    const juror = dag.getIdentity(juror_tip_id);
    if (!juror) throw { status: 404, error: "Expert TIP-ID not found" };
    const REVEAL_FIELDS = confirmed_origin ? ["juror_tip_id", "vote", "salt", "confirmed_origin"] : ["juror_tip_id", "vote", "salt"];
    if (!verifyBodySignature(body, signature, juror.public_key, REVEAL_FIELDS)) throw { status: 403, error: "Expert signature verification failed" };

    const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid).filter(t => t.data?.juror_tip_id === juror_tip_id && t.data?.is_appeal === true);
    if (!summonsTxs.length) throw { status: 403, error: "You were not summoned as an expert" };

    const commitDeadline = new Date(summonsTxs[0].data.commit_deadline).getTime();
    const revealDeadline = new Date(summonsTxs[0].data.reveal_deadline).getTime();
    if (Date.now() < commitDeadline) throw { status: 403, error: "Reveal window has not opened yet" };
    if (Date.now() > revealDeadline) throw { status: 403, error: "Reveal window has closed" };

    const commitTx = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid).find(t => t.data?.juror_tip_id === juror_tip_id && t.data?.is_appeal === true);
    if (!commitTx) throw { status: 404, error: "No vote commitment found" };
    if (shake256(`${vote}:${salt}`) !== commitTx.data.commitment) throw { status: 403, error: "Vote does not match commitment" };

    const existingReveal = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid).find(t => t.data?.juror_tip_id === juror_tip_id && t.data?.is_appeal === true);
    if (existingReveal) throw { status: 409, error: "You have already revealed your vote" };

    const revealTx = withTxId({ tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(), data: { ctid, juror_tip_id, vote, salt, confirmed_origin: vote === VOTE.MISMATCH ? confirmed_origin : null, is_appeal: true } });
    dag.addTx(revealTx);
    broadcast(revealTx);

    const allReveals = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid).filter(t => t.data?.is_appeal === true);
    const allSummons = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid).filter(t => t.data?.is_appeal === true);
    let appealVerdict = null;
    if (allReveals.length >= allSummons.length) {
      appealVerdict = applyAppealVerdict(ctid, allReveals, allSummons, dag, scoring, config);
    }
    return { success: true, tx_id: revealTx.tx_id, verdict: appealVerdict };
  }

  return { fileDispute, juryCommit, juryReveal, getDisputeCase, fileAppeal, appealCommit, appealReveal };
}

module.exports = { createDisputeService };
