/**
 * @file @tip-protocol/node/src/validators/business-rules.js
 * @description Single source of truth for stateful pre-condition checks.
 *
 * Every business rule that depends on DAG state or time lives here.
 * Two callers, identical predicate:
 *
 *   API service (CheckTx role):
 *     const r = rules.canVerify(dag, args, { now: Date.now() });
 *     if (!r.valid) throw r.error;            // 4xx response
 *
 *   commit-handler (DeliverTx role):
 *     const r = rules.canVerify(dag, args, { now: certTimestamp });
 *     if (!r.valid) { log.warn(r.error.message); drop; return; }
 *
 * `now` is the only difference between the two call sites:
 *   - API time uses local wall-clock (Date.now()) — fine for early
 *     rejection.
 *   - Commit time uses `cert.timestamp` (BFT-Time median of acks) so the
 *     accept/reject decision is identical on every node.
 *
 * Each rule returns `{ valid: true }` on success or
 * `{ valid: false, error: { status, message } }` on failure. `status` is
 * the HTTP code the API service should bubble; commit-handler ignores it.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES, ORIGIN, CONTENT_STATUS } = require("../../../shared/constants");
const { DISPUTE, APPEAL } = require("../../../shared/protocol-constants");

const ORIGIN_CODES = Object.keys(ORIGIN);
const ORIGIN_GRACE_MS = 24 * 60 * 60 * 1000;

function ok() {
  return { valid: true };
}

function fail(status, message) {
  return { valid: false, error: { status, message } };
}

// ─── Identity / VP ─────────────────────────────────────────────────────────

function canRegisterIdentity(dag, { dedup_hash, vp_id }) {
  const vp = dag.getVP && dag.getVP(vp_id);
  if (!vp || vp.status !== "active") {
    return fail(403, "Verification provider not found or suspended");
  }
  if (dedup_hash && dag.hasDedupHash(dedup_hash)) {
    return fail(409, "Identity already registered. Each human may hold exactly one TIP-ID.");
  }
  return ok();
}

// ─── Content ───────────────────────────────────────────────────────────────

function canRegisterContent(dag, { author_tip_id, ctid, origin_code }) {
  if (!ORIGIN_CODES.includes(origin_code)) {
    return fail(400, `Invalid origin_code. Must be one of: ${ORIGIN_CODES.join(", ")}`);
  }
  const author = dag.getIdentity(author_tip_id);
  if (!author) return fail(404, "Author TIP-ID not found");
  if (dag.isRevoked(author_tip_id)) return fail(403, "Author TIP-ID is revoked");
  if (ctid && dag.getContent(ctid)) {
    return fail(409, `Content already registered with this origin code (CTID: ${ctid})`);
  }
  return ok();
}

function canVerify(dag, { ctid, verifier_tip_id }) {
  const rec = dag.getContent(ctid);
  if (!rec) return fail(404, "Content record not found");

  const verifier = dag.getIdentity(verifier_tip_id);
  if (!verifier) return fail(404, "Verifier TIP-ID not found");
  if (dag.isRevoked(verifier_tip_id)) return fail(403, "Verifier TIP-ID is revoked");
  if (verifier_tip_id === rec.author_tip_id) return fail(403, "Cannot verify your own content");
  if (dag.isRevoked(rec.author_tip_id)) return fail(403, "Content author has been revoked — verification not allowed");
  if (rec.status === CONTENT_STATUS.RETRACTED) return fail(403, "Content has been retracted by the author — verification not allowed");
  if (rec.status === CONTENT_STATUS.DISPUTED) return fail(403, "Content is under dispute — verification blocked until resolved");
  if (rec.status === CONTENT_STATUS.PENDING_REVIEW) return fail(403, "Content is pending review — verification blocked until 24-hour grace period ends");
  if (dag.hasVerification(ctid, verifier_tip_id)) return fail(409, "You have already verified this content");

  return ok();
}

function canUpdateOrigin(dag, { ctid, author_tip_id, new_origin_code }, { now }) {
  const rec = dag.getContent(ctid);
  if (!rec) return fail(404, "Content record not found");
  if (author_tip_id !== rec.author_tip_id) return fail(403, "Only the content author can update the origin code");
  if (rec.status !== CONTENT_STATUS.REGISTERED && rec.status !== CONTENT_STATUS.PENDING_REVIEW) {
    return fail(403, `Cannot update origin — content status is '${rec.status}'`);
  }
  if (!ORIGIN_CODES.includes(new_origin_code)) {
    return fail(400, `Invalid origin_code. Must be one of: ${ORIGIN_CODES.join(", ")}`);
  }
  const existingUpdates = dag.getTxsByTypeAndCtid(TX_TYPES.UPDATE_ORIGIN, ctid);
  if (existingUpdates.length > 0) return fail(409, "Origin has already been updated once — no further changes allowed");
  const registeredAt = new Date(rec.registered_at).getTime();
  if (now - registeredAt > ORIGIN_GRACE_MS) return fail(403, "24-hour grace period has expired.");

  const author = dag.getIdentity(author_tip_id);
  if (!author) return fail(404, "Author identity not found");
  if (dag.isRevoked(author_tip_id)) return fail(403, "Author TIP-ID is revoked");

  return ok();
}

function canRetract(dag, { ctid, author_tip_id }) {
  const rec = dag.getContent(ctid);
  if (!rec) return fail(404, "Content record not found");
  if (author_tip_id !== rec.author_tip_id) return fail(403, "Only the content author can retract");
  if (rec.status === CONTENT_STATUS.RETRACTED) return fail(409, "Content is already retracted");
  if (rec.status === CONTENT_STATUS.DISPUTED) return fail(403, "Cannot retract content that is under dispute");

  const author = dag.getIdentity(author_tip_id);
  if (!author) return fail(404, "Author identity not found");
  if (dag.isRevoked(author_tip_id)) return fail(403, "Author TIP-ID is revoked");

  return ok();
}

// ─── Dispute / Jury ────────────────────────────────────────────────────────

function canDispute(dag, scoring, { ctid, disputer_tip_id }) {
  const rec = dag.getContent(ctid);
  if (!rec) return fail(404, "Content record not found");
  if (rec.status === CONTENT_STATUS.RETRACTED) return fail(403, "Content has been retracted — dispute not allowed");
  if (rec.status === CONTENT_STATUS.DISPUTED) return fail(403, "Content is already under dispute — wait for adjudication result");
  if (rec.status === CONTENT_STATUS.PENDING_REVIEW) return fail(403, "Content is pending review — wait for 24-hour grace period");

  const disputer = dag.getIdentity(disputer_tip_id);
  if (!disputer) return fail(404, "Disputer TIP-ID not found");
  if (dag.isRevoked(disputer_tip_id)) return fail(403, "Disputer TIP-ID is revoked");

  const disputerScore = scoring.getScore(disputer_tip_id).score;
  if (disputerScore < DISPUTE.MIN_SCORE_TO_DISPUTE) {
    return fail(403, `Score must be >= ${DISPUTE.MIN_SCORE_TO_DISPUTE} to dispute (current: ${disputerScore})`);
  }
  if (dag.hasDispute(ctid, disputer_tip_id)) return fail(409, "You have already disputed this content");

  return ok();
}

function canCommitVote(dag, { ctid, juror_tip_id, is_appeal = false }, { now }) {
  const juror = dag.getIdentity(juror_tip_id);
  if (!juror) return fail(404, is_appeal ? "Expert TIP-ID not found" : "Juror TIP-ID not found");
  if (dag.isRevoked(juror_tip_id)) return fail(403, is_appeal ? "Expert TIP-ID is revoked" : "Juror TIP-ID is revoked");

  const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid)
    .filter(t => t.data?.juror_tip_id === juror_tip_id && (!!t.data?.is_appeal) === is_appeal);
  if (!summonsTxs.length) {
    return fail(403, is_appeal ? "You were not summoned as an expert for this appeal" : "You were not summoned as a juror for this dispute");
  }

  const commitDeadline = new Date(summonsTxs[0].data.commit_deadline).getTime();
  if (now > commitDeadline) return fail(403, "Commit window has closed");

  const existing = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid)
    .find(t => t.data?.juror_tip_id === juror_tip_id && (!!t.data?.is_appeal) === is_appeal);
  if (existing) return fail(409, "You have already submitted a vote commitment");

  return ok();
}

function canRevealVote(dag, { ctid, juror_tip_id, is_appeal = false, vote, salt }, { now, shake256 }) {
  const juror = dag.getIdentity(juror_tip_id);
  if (!juror) return fail(404, is_appeal ? "Expert TIP-ID not found" : "Juror TIP-ID not found");

  const summonsTxs = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_SUMMONS, ctid)
    .filter(t => t.data?.juror_tip_id === juror_tip_id && (!!t.data?.is_appeal) === is_appeal);
  if (!summonsTxs.length) {
    return fail(403, is_appeal ? "You were not summoned as an expert" : "You were not summoned as a juror");
  }

  const commitDeadline = new Date(summonsTxs[0].data.commit_deadline).getTime();
  const revealDeadline = new Date(summonsTxs[0].data.reveal_deadline).getTime();
  if (now < commitDeadline) return fail(403, "Reveal window has not opened yet");
  if (now > revealDeadline) return fail(403, "Reveal window has closed");

  const commitTx = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_COMMIT, ctid)
    .find(t => t.data?.juror_tip_id === juror_tip_id && (!!t.data?.is_appeal) === is_appeal);
  if (!commitTx) return fail(404, "No vote commitment found");
  if (shake256(`${vote}:${salt}`) !== commitTx.data.commitment) return fail(403, "Vote does not match commitment");

  const existingReveal = dag.getTxsByTypeAndCtid(TX_TYPES.JURY_VOTE_REVEAL, ctid)
    .find(t => t.data?.juror_tip_id === juror_tip_id && (!!t.data?.is_appeal) === is_appeal);
  if (existingReveal) return fail(409, "You have already revealed your vote");

  return ok();
}

// ─── Appeal ────────────────────────────────────────────────────────────────

function canFileAppeal(dag, { ctid, appellant_tip_id }, { now }) {
  const adjTxs = dag.getTxsByTypeAndCtid(TX_TYPES.ADJUDICATION_RESULT, ctid);
  if (!adjTxs.length) return fail(404, "No Stage 2 verdict found for this content");

  const existingAppeal = dag.getTxsByTypeAndCtid(TX_TYPES.APPEAL_FILED, ctid);
  if (existingAppeal.length) return fail(409, "Appeal already filed for this content");

  const verdictTime = new Date(adjTxs[0].timestamp).getTime();
  if (now - verdictTime > APPEAL.FILING_WINDOW_HOURS * 3600000) {
    return fail(403, "Appeal filing window has expired");
  }

  const rec = dag.getContent(ctid);
  const disputeTxs = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid);
  const disputerTipId = disputeTxs[0]?.data?.disputer_tip_id;
  const authorTipId = rec?.author_tip_id;
  if (appellant_tip_id !== authorTipId && appellant_tip_id !== disputerTipId) {
    return fail(403, "Only the content author or the original disputer can file an appeal");
  }

  const appellant = dag.getIdentity(appellant_tip_id);
  if (!appellant) return fail(404, "Appellant TIP-ID not found");
  if (dag.isRevoked(appellant_tip_id)) return fail(403, "Appellant TIP-ID is revoked");

  return ok();
}

// ─── Revocation ────────────────────────────────────────────────────────────

const VALID_REVOKE_TYPES = [
  TX_TYPES.REVOKE_VOLUNTARY,
  TX_TYPES.REVOKE_VP,
  TX_TYPES.REVOKE_DECEASED,
  TX_TYPES.REVOKE_DEVICE,
];

function canRevoke(dag, { tx_type, tip_id, issuing_vp_id }) {
  if (!VALID_REVOKE_TYPES.includes(tx_type)) {
    return fail(400, `Invalid tx_type. Must be one of: ${VALID_REVOKE_TYPES.join(", ")}`);
  }
  const issuingVp = dag.getVP && dag.getVP(issuing_vp_id);
  if (!issuingVp) return fail(403, `Issuing VP not found: ${issuing_vp_id}`);
  if (issuingVp.status !== "active") return fail(403, `Issuing VP is not active: ${issuing_vp_id}`);

  const identity = dag.getIdentity(tip_id);
  if (!identity) return fail(404, "TIP-ID not found");

  return ok();
}

module.exports = {
  canRegisterIdentity,
  canRegisterContent,
  canVerify,
  canUpdateOrigin,
  canRetract,
  canDispute,
  canCommitVote,
  canRevealVote,
  canFileAppeal,
  canRevoke,
};
