"use strict";

const {
  shake256, hashContent, perceptualHashText,
  generateCTID, verifyBodySignature, verifyTxId,
} = require("../../../shared/crypto");
const { TX_TYPES, ORIGIN, ORIGIN_LABELS, HTTP_HEADERS, CONTENT_STATUS } = require("../../../shared/constants");
const { VERIFY_CAPS, SCORE_EVENTS } = require("../../../shared/protocol-constants");
const { validateTransaction } = require("../validators/tx-validator");
const { withTxId } = require("./helpers");
const { preScanContent } = require("./helpers");
const { validate, validateContentSize } = require("../middleware/validate");
const { log } = require("../logger");

const ORIGIN_CODES = Object.keys(ORIGIN);

function createContentService({ dag, scoring, config, submitTx }) {

  function register(body) {
    validate(body, {
      author_tip_id: { required: true },
      origin_code: { required: true, oneOf: ORIGIN_CODES },
      content: { required: true },
      signature: { required: true },
    });
    const { author_tip_id, origin_code, content, content_type, signature } = body;
    validateContentSize(content, content_type, config.mediaLimits);

    const identity = dag.getIdentity(author_tip_id);
    if (!identity) throw { status: 404, error: "Author TIP-ID not found" };
    if (dag.isRevoked(author_tip_id)) throw { status: 403, error: "Author TIP-ID is revoked" };

    const contentHashFull = shake256(content);
    const contentHashShort = hashContent(content);

    const CONTENT_FIELDS = ["author_tip_id", "origin_code", "content_hash"];
    const sigBody = { author_tip_id, origin_code, content_hash: contentHashFull };
    if (!verifyBodySignature(sigBody, signature, identity.public_key, CONTENT_FIELDS)) {
      throw { status: 403, error: "Content signature verification failed" };
    }

    const perceptHash = content ? perceptualHashText(content) : null;
    const contentHistory = { verified_oh_count: dag.getContentByAuthor(author_tip_id).filter(c => c.origin_code === ORIGIN.OH && c.status === CONTENT_STATUS.VERIFIED).length };
    const preScan = preScanContent(content || "", origin_code, contentHistory);

    const registeredAt = new Date().toISOString();
    const ctid = generateCTID(origin_code, contentHashShort, author_tip_id);

    const existing = dag.getContent(ctid);
    if (existing) throw { status: 409, error: `Content already registered with this origin code (CTID: ${ctid})`, ctid };

    const txBody = {
      tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: {
        ctid, origin_code, origin_label: ORIGIN_LABELS[origin_code],
        content_hash: contentHashFull, perceptual_hash: perceptHash,
        author_tip_id, signature,
        prescan_flagged: preScan.flagged, prescan_probability: preScan.probability,
      },
    };
    const signedTx = withTxId(txBody);
    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(signedTx);

    const status = preScan.flagged ? CONTENT_STATUS.PENDING_REVIEW : CONTENT_STATUS.REGISTERED;
    log.info(`Content proposed: ${ctid} (origin: ${origin_code}, author: ${author_tip_id})`);

    return {
      ctid, origin_code, origin_label: ORIGIN_LABELS[origin_code],
      content_hash: contentHashFull, author_tip_id, tx_id: signedTx.tx_id,
      registered_at: registeredAt, status,
      confirmation: "proposed",
      prescan_flagged: preScan.flagged,
      prescan_note: preScan.flagged ? "Content flagged by AI pre-scan. You have 24 hours to change the origin code at zero penalty." : null,
      http_headers: {
        [HTTP_HEADERS.AUTHOR]: author_tip_id, [HTTP_HEADERS.CONTENT]: ctid,
        [HTTP_HEADERS.ORIGIN]: ORIGIN_LABELS[origin_code].toLowerCase().replace(/ /g, "-"),
        [HTTP_HEADERS.TRUST_SCORE]: scoring.getScore(author_tip_id).score.toString(),
        [HTTP_HEADERS.SIGNATURE]: signature,
      },
      meta_tags: {
        "tip:author": author_tip_id, "tip:content": ctid,
        "tip:origin": ORIGIN_LABELS[origin_code].toLowerCase().replace(/ /g, "-"),
        "tip:score": scoring.getScore(author_tip_id).score.toString(),
        "tip:status": preScan.flagged ? "PENDING" : "REGISTERED",
      },
    };
  }

  function resolve(ctid) {
    const rec = dag.getContent(ctid);
    if (!rec) throw { status: 404, error: "Content record not found" };

    const tx = rec.tx_id ? dag.getTx(rec.tx_id) : null;
    const txValid = tx ? verifyTxId(tx) : false;
    const prevValid = tx && tx.prev ? tx.prev.every(p => !!dag.getTx(p)) : false;
    const author = dag.getIdentity(rec.author_tip_id);
    const authorValid = !!author && author.status === "active" && !dag.isRevoked(rec.author_tip_id);

    const verifyCount = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_VERIFIED, ctid).length;
    const disputeCount = dag.getTxsByTypeAndCtid(TX_TYPES.CONTENT_DISPUTED, ctid).length;

    return {
      ...rec,
      origin_label: ORIGIN_LABELS[rec.origin_code] || rec.origin_code,
      author_score: scoring.getScore(rec.author_tip_id).score,
      author_tier: scoring.getScore(rec.author_tip_id).tier.name,
      verify_count: verifyCount,
      dispute_count: disputeCount,
      verification: {
        tx_exists: !!tx, tx_id_valid: txValid, prev_valid: prevValid,
        author_valid: authorValid, author_revoked: dag.isRevoked(rec.author_tip_id), on_dag: true,
      },
    };
  }

  function verify(ctid, body) {
    const rec = dag.getContent(ctid);
    if (!rec) throw { status: 404, error: "Content record not found" };

    validate(body, { verifier_tip_id: { required: true }, signature: { required: true } });
    const { verifier_tip_id, verdict, signature } = body;

    const verifier = dag.getIdentity(verifier_tip_id);
    if (!verifier) throw { status: 404, error: "Verifier TIP-ID not found" };
    if (dag.isRevoked(verifier_tip_id)) throw { status: 403, error: "Verifier TIP-ID is revoked" };
    if (verifier_tip_id === rec.author_tip_id) throw { status: 403, error: "Cannot verify your own content" };

    if (dag.isRevoked(rec.author_tip_id)) throw { status: 403, error: "Content author has been revoked — verification not allowed" };
    if (rec.status === CONTENT_STATUS.RETRACTED) throw { status: 403, error: "Content has been retracted by the author — verification not allowed" };
    if (rec.status === CONTENT_STATUS.DISPUTED) throw { status: 403, error: "Content is under dispute — verification blocked until resolved" };
    if (rec.status === CONTENT_STATUS.PENDING_REVIEW) throw { status: 403, error: "Content is pending review — verification blocked until 24-hour grace period ends" };

    const VERIFY_FIELDS = ["verifier_tip_id", "verdict"];
    if (!verifyBodySignature(body, signature, verifier.public_key, VERIFY_FIELDS)) {
      throw { status: 403, error: "Verifier signature verification failed" };
    }

    if (dag.hasVerification(ctid, verifier_tip_id)) throw { status: 409, error: "You have already verified this content" };

    // Caps
    const allVerifyTxs = dag.getTxsByType(TX_TYPES.CONTENT_VERIFIED);
    const authorTipId = rec.author_tip_id;
    const now = new Date();
    const dayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

    const contentDeltaSum = allVerifyTxs.filter(t => t.data?.ctid === ctid).reduce((s, t) => s + (t.data?.weighted_delta || 0), 0);
    const dailyDeltaSum = allVerifyTxs.filter(t => t.data?.author_tip_id === authorTipId && t.timestamp >= dayStart).reduce((s, t) => s + (t.data?.weighted_delta || 0), 0);
    const monthlyDeltaSum = allVerifyTxs.filter(t => t.data?.author_tip_id === authorTipId && t.timestamp >= monthStart).reduce((s, t) => s + (t.data?.weighted_delta || 0), 0);

    const verifierScore = scoring.getScore(verifier_tip_id).score;
    let weightedDelta = verifierScore >= VERIFY_CAPS.HIGH_TRUST_MIN ? VERIFY_CAPS.HIGH_TRUST_DELTA : VERIFY_CAPS.BASE_DELTA;
    weightedDelta = Math.min(weightedDelta,
      Math.max(0, VERIFY_CAPS.PER_CONTENT - contentDeltaSum),
      Math.max(0, VERIFY_CAPS.PER_DAY - dailyDeltaSum),
      Math.max(0, VERIFY_CAPS.PER_MONTH - monthlyDeltaSum));

    const verifyTxBody = {
      tx_type: TX_TYPES.CONTENT_VERIFIED, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(),
      data: { ctid, verifier_tip_id, verdict: verdict || "ORIGIN_CONFIRMED", weighted_delta: weightedDelta, author_tip_id: authorTipId, signature },
    };
    const signedTx = withTxId(verifyTxBody);
    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(signedTx);

    return {
      success: true, delta_applied: weightedDelta,
      confirmation: "proposed",
      caps: {
        content: { used: contentDeltaSum + weightedDelta, max: VERIFY_CAPS.PER_CONTENT },
        daily: { used: dailyDeltaSum + weightedDelta, max: VERIFY_CAPS.PER_DAY },
        monthly: { used: monthlyDeltaSum + weightedDelta, max: VERIFY_CAPS.PER_MONTH },
      },
    };
  }

  function updateOrigin(ctid, body) {
    const rec = dag.getContent(ctid);
    if (!rec) throw { status: 404, error: "Content record not found" };

    validate(body, { author_tip_id: { required: true }, new_origin_code: { required: true }, signature: { required: true } });
    const { author_tip_id, new_origin_code, signature } = body;

    if (author_tip_id !== rec.author_tip_id) throw { status: 403, error: "Only the content author can update the origin code" };
    if (rec.status !== CONTENT_STATUS.REGISTERED && rec.status !== CONTENT_STATUS.PENDING_REVIEW) throw { status: 403, error: `Cannot update origin — content status is '${rec.status}'` };

    // Only one origin update allowed
    const existingUpdates = dag.getTxsByTypeAndCtid(TX_TYPES.UPDATE_ORIGIN, ctid);
    if (existingUpdates.length > 0) throw { status: 409, error: "Origin has already been updated once — no further changes allowed" };

    const registeredAt = new Date(rec.registered_at).getTime();
    if (Date.now() - registeredAt > 24 * 60 * 60 * 1000) throw { status: 403, error: "24-hour grace period has expired." };
    if (!ORIGIN[new_origin_code]) throw { status: 400, error: `Invalid origin_code. Must be one of: ${Object.keys(ORIGIN).join(", ")}` };

    const author = dag.getIdentity(author_tip_id);
    if (!author) throw { status: 404, error: "Author identity not found" };

    const UPDATE_FIELDS = ["author_tip_id", "new_origin_code"];
    if (!verifyBodySignature(body, signature, author.public_key, UPDATE_FIELDS)) {
      throw { status: 403, error: "Author signature verification failed" };
    }

    const updateTx = withTxId({
      tx_type: TX_TYPES.UPDATE_ORIGIN, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(),
      data: { ctid, old_origin_code: rec.origin_code, new_origin_code, author_tip_id, signature },
    });
    submitTx(updateTx);

    log.info(`Origin update proposed: ${ctid} ${rec.origin_code} → ${new_origin_code} (by ${author_tip_id})`);
    return { success: true, ctid, old_origin_code: rec.origin_code, new_origin_code, tx_id: updateTx.tx_id, confirmation: "proposed" };
  }

  function retract(ctid, body) {
    const rec = dag.getContent(ctid);
    if (!rec) throw { status: 404, error: "Content record not found" };

    validate(body, { author_tip_id: { required: true }, signature: { required: true } });
    const { author_tip_id, signature } = body;

    if (author_tip_id !== rec.author_tip_id) throw { status: 403, error: "Only the content author can retract" };
    if (rec.status === CONTENT_STATUS.RETRACTED) throw { status: 409, error: "Content is already retracted" };
    if (rec.status === CONTENT_STATUS.DISPUTED) throw { status: 403, error: "Cannot retract content that is under dispute" };

    const author = dag.getIdentity(author_tip_id);
    if (!author) throw { status: 404, error: "Author identity not found" };
    if (dag.isRevoked(author_tip_id)) throw { status: 403, error: "Author TIP-ID is revoked" };

    if (!verifyBodySignature(body, signature, author.public_key, ["author_tip_id"])) {
      throw { status: 403, error: "Author signature verification failed" };
    }

    const retractTx = withTxId({
      tx_type: TX_TYPES.CONTENT_RETRACTED, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(),
      data: { ctid, author_tip_id, signature, origin_code: rec.origin_code, pre_retract_status: rec.status },
    });
    submitTx(retractTx);

    log.info(`Content retraction proposed: ${ctid} by ${author_tip_id}`);
    return { success: true, ctid, penalty: SCORE_EVENTS.CONTENT_RETRACTION.delta, tx_id: retractTx.tx_id, confirmation: "proposed" };
  }

  return { register, resolve, verify, updateOrigin, retract };
}

module.exports = { createContentService };
