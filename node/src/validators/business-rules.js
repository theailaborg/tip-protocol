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
const { computeQuorum } = require("../consensus/certificate");

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

// ─── Committee rotation (§4 + #34 — chain-of-trust) ─────────────────────────
//
// Validates a COMMITTEE_ROTATION tx for both call sites:
//   - bullshark proposer (before broadcasting): bail early if the would-be
//     rotation can't possibly land (e.g. rotation_number wrong, committee
//     malformed) so we don't waste a round
//   - commit-handler (DeliverTx): final gate before writing committee_history
//
// Crypto helpers (shake256, canonicalJson, mldsaVerify) are injected via opts
// so this module stays free of crypto-library import side effects (matches
// canRevealVote's pattern of injected shake256). All checks are deterministic
// over DAG state — same accept/reject decision on every node.
function canCommitteeRotation(dag, { rotation_number, effective_round, new_committee, payload_hash, signer_node_ids, signatures }, opts = {}) {
  const { shake256, canonicalJson, mldsaVerify } = opts;

  // Structural — invariants the wire schema doesn't enforce.
  if (typeof rotation_number !== "number" || !Number.isInteger(rotation_number) || rotation_number < 1) {
    return fail(400, `invalid rotation_number: ${rotation_number}`);
  }
  if (typeof effective_round !== "number" || !Number.isInteger(effective_round) || effective_round < 0) {
    return fail(400, `invalid effective_round: ${effective_round}`);
  }
  if (!Array.isArray(new_committee) || new_committee.length === 0) {
    return fail(400, "new_committee must be a non-empty array");
  }
  for (const m of new_committee) {
    if (!m || typeof m.node_id !== "string" || typeof m.public_key !== "string") {
      return fail(400, "new_committee entries must have {node_id, public_key} strings");
    }
  }

  // Monotonicity — rotation_number must be exactly latest + 1 (no gaps,
  // no duplicates). Chain-of-trust walker depends on this contiguity.
  const existing = dag.getCommitteeRotation(rotation_number);
  if (existing) return fail(409, `rotation_number ${rotation_number} already exists`);

  const latest = dag.getLatestRotation();
  const expected = (latest?.rotation_number ?? -1) + 1;
  if (rotation_number !== expected) {
    return fail(409, `rotation_number ${rotation_number} non-monotonic (expected ${expected})`);
  }
  if (latest && effective_round <= latest.effective_round) {
    return fail(409, `effective_round ${effective_round} not > prev rotation's ${latest.effective_round}`);
  }

  // Cryptographic — ≥ 2f+1 sigs from PREVIOUS committee endorsing the
  // payload_hash. Skipped when crypto helpers aren't injected (proposer
  // can run structural-only check before signing; commit-handler always
  // injects so signatures are checked at DeliverTx).
  if (!shake256 || !canonicalJson || !mldsaVerify) {
    return ok();
  }

  const prev = dag.getCommitteeRotation(rotation_number - 1);
  if (!prev || !Array.isArray(prev.committee) || prev.committee.length === 0) {
    return fail(409, `previous rotation ${rotation_number - 1} not found or empty`);
  }

  // Recompute payload_hash from the canonical claim — catches tampering
  // where signers signed a different hash than the tx now carries.
  const expectedHash = shake256(canonicalJson({
    rotation_number, effective_round, committee: new_committee,
  }));
  if (payload_hash !== expectedHash) {
    return fail(400, "payload_hash does not match canonical(rotation_number, effective_round, new_committee)");
  }

  if (!Array.isArray(signer_node_ids) || !Array.isArray(signatures)
      || signer_node_ids.length === 0 || signer_node_ids.length !== signatures.length) {
    return fail(400, "signer_node_ids and signatures must be parallel non-empty arrays");
  }

  // Pubkey lookup from previous rotation's committee — NOT from peer-
  // provided nodes table. This is what closes the chicken-and-egg in
  // fresh-joiner verification (#34).
  const prevPubkeys = Object.create(null);
  for (const m of prev.committee) {
    if (m && m.node_id && m.public_key) prevPubkeys[m.node_id] = m.public_key;
  }

  let validSigs = 0;
  const seen = new Set();
  for (let i = 0; i < signer_node_ids.length; i++) {
    const signerId = signer_node_ids[i];
    if (seen.has(signerId)) continue;          // duplicate signers count once
    seen.add(signerId);
    const pubkey = prevPubkeys[signerId];
    if (!pubkey) continue;                     // signer outside previous committee
    const message = `rotation:${payload_hash}:${signerId}`;
    if (mldsaVerify(message, signatures[i], pubkey)) {
      validSigs++;
    }
  }

  // #68 Part A — tighten quorum to ceil(2n/3), the same formula used for
  // cert quorum. The pre-fix BFT 2f+1 formula degenerated to quorum=1 for
  // prevSize ≤ 3, letting any single member of the previous committee
  // unilaterally rotate membership. ceil(2n/3) gives prevSize=2→2,
  // prevSize=3→2, prevSize=4→3, prevSize=5→4, prevSize=6→4 — i.e., a true
  // honest-majority threshold for membership change. Pairs with #68 Part B
  // (multi-sig coordinator in consensus/rotation-coordinator.js) which
  // produces the aggregated signatures this gate now requires.
  const prevSize = prev.committee.length;
  const quorum = computeQuorum(prevSize);
  if (validSigs < quorum) {
    return fail(403, `insufficient sigs: ${validSigs}/${prevSize} from previous committee, need ${quorum}`);
  }
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
  canCommitteeRotation,
};
