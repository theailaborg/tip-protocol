"use strict";

const {
  shake256, hashContent, perceptualHashText, tipNormalize,
  generateCTID, verifyBodySignature, verifyTxId,
} = require("../../../shared/crypto");
const { TX_TYPES, ORIGIN, ORIGIN_LABELS, HTTP_HEADERS, CONTENT_STATUS, PRESCAN_TIERS, PRESCAN_NOTES } = require("../../../shared/constants");
const { VERIFY_CAPS, SCORE_EVENTS } = require("../../../shared/protocol-constants");
const contentRegisterSchema = require("../schemas/content-register");
const { schemaError } = require("../schemas/_common");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId } = require("./helpers");
// Imported via the module reference (not destructured) so tests can
// jest.spyOn(helpers, "preScanContent") to drive specific tier scenarios.
const helpers = require("./helpers");
const { validate } = require("../middleware/validate");
const { log } = require("../logger");

function createContentService({ dag, scoring, config, submitTx }) {

  function register(body) {
    contentRegisterSchema.validateRequest(body, { mediaLimits: config.mediaLimits, dag });

    const {
      signer_tip_id, origin_code, content, signature, media_canonical_hash,
    } = body;
    const identity = contentRegisterSchema.resolveSigner(signer_tip_id, dag);

    // CNA-MIX-1: when media hash is present, combine media + text hashes.
    // The client signs the combined hash, so the node must reproduce it.
    const textHashFull = content ? shake256(tipNormalize(content)) : shake256("");
    const contentHashFull = media_canonical_hash
      ? shake256(media_canonical_hash + textHashFull)
      : textHashFull;
    const contentHashShort = hashContent(content || media_canonical_hash || "");

    // ── Signature verification ─────────────────────────────────────────────
    const canonicalPayload = contentRegisterSchema.buildSigningPayload(body, contentHashFull);
    if (!contentRegisterSchema.verifySignature(canonicalPayload, signature, identity.public_key)) {
      throw schemaError(403, "Content signature verification failed", "signature_invalid");
    }

    const perceptHash = content ? perceptualHashText(content) : null;
    const contentHistory = { verified_oh_count: dag.getContentByAuthor(signer_tip_id).filter(c => c.origin_code === ORIGIN.OH && c.status === CONTENT_STATUS.VERIFIED).length };
    const preScan = helpers.preScanContent(content || "", origin_code, contentHistory);

    // Synchronous 409 + retry flow for HIGH/CRITICAL prescan. When the
    // calibrated tier says the content looks AI-generated and creator
    // declared OH, require an explicit override in the request body.
    // Clients render the spec's blocking modal and retry with
    // override=true. Without this gate, an unaware client could
    // silently land content as flagged with no creator confirmation.
    // AA gets the same treatment (same human-primary claim → same gate).
    const needsOverride =
      (preScan.tier === PRESCAN_TIERS.HIGH || preScan.tier === PRESCAN_TIERS.CRITICAL)
      && (origin_code === ORIGIN.OH || origin_code === ORIGIN.AA);
    if (needsOverride && body.override !== true) {
      throw {
        status: 409,
        error: `Content flagged at ${preScan.tier.toUpperCase()} confidence (${Math.round(preScan.probability * 100)}%). Retry with override=true to register as ${origin_code} anyway, or change origin_code to a more conservative label.`,
        code: "prescan_override_required",
        details: {
          tier: preScan.tier,
          raw_tier: preScan.raw_tier,
          probability: preScan.probability,
          // Future-proof slot for Pattern 2 (preflight + signed token).
          // v1 always null — server runs prescan fresh on retry. When we
          // add Pattern 2 the 409 response will carry a signed token here
          // and the retry will skip re-prescan via token validation.
          prescan_token: null,
        },
      };
    }

    const registeredAt = new Date().toISOString();
    const ctid = generateCTID(origin_code, contentHashShort, signer_tip_id);

    const { valid, error } = rules.canRegisterContent(dag, { signer_tip_id, ctid, origin_code });
    if (!valid) throw schemaError(error.status, error.message, error.code);

    const txBody = {
      tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: {
        // ── Server-derived / informational fields ─────────────────
        // origin_code + content_hash mirror the canonical signed values
        // (verifier needs them on tx.data to rebuild the payload).
        // origin_label is derived at response time from origin_code —
        // not stored on tx.data. author_tip_id is derived at persist
        // time from signer_tip_id — see commit-handler REGISTER_CONTENT.
        ctid, origin_code: canonicalPayload.origin_code,
        content_hash: contentHashFull, perceptual_hash: perceptHash,
        signature,
        prescan_flagged: preScan.flagged,
        prescan_probability: preScan.probability,
        prescan_tier: preScan.tier,
        // True only when the creator explicitly retried with override=true
        // after receiving the 409. needsOverride is the trigger; reaching
        // this line means body.override was true (above check passed).
        override: needsOverride,

        // ── CNA-2.2 signed canonical fields (mirror canonicalPayload
        //    so commit-handler can replay buildSigningPayload(d, d.content_hash))
        cna_version: canonicalPayload.cna_version,
        attribution_mode: canonicalPayload.attribution_mode,
        authors: canonicalPayload.authors,
        extras: canonicalPayload.extras,
        registered_urls: canonicalPayload.registered_urls,
        signer_tip_id: canonicalPayload.signer_tip_id,
      },
    };
    const signedTx = withTxId(txBody);
    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(signedTx);

    const status = preScan.flagged ? CONTENT_STATUS.PENDING_REVIEW : CONTENT_STATUS.REGISTERED;
    log.info(`Content proposed: ${ctid} (origin: ${origin_code}, signer: ${signer_tip_id})`);

    // Note: direct dag.saveContent happens in commit-handler when the tx
    // commits via consensus. API returns 202-style "proposed" so client
    // knows to expect async finalization.
    return {
      ctid, origin_code, origin_label: ORIGIN_LABELS[origin_code],
      content_hash: contentHashFull, signer_tip_id, tx_id: signedTx.tx_id,
      registered_at: registeredAt, status,
      confirmation: "proposed",
      author_name: identity?.creator_name || null,
      registered_urls: canonicalPayload.registered_urls,
      prescan_flagged: preScan.flagged,
      prescan_tier: preScan.tier,
      prescan_probability: preScan.probability,
      prescan_note: PRESCAN_NOTES[preScan.tier] || null,
      http_headers: {
        [HTTP_HEADERS.AUTHOR]: signer_tip_id, [HTTP_HEADERS.CONTENT]: ctid,
        [HTTP_HEADERS.ORIGIN]: ORIGIN_LABELS[origin_code].toLowerCase().replace(/ /g, "-"),
        [HTTP_HEADERS.TRUST_SCORE]: scoring.getScore(signer_tip_id).score.toString(),
        [HTTP_HEADERS.SIGNATURE]: signature,
      },
      meta_tags: {
        "tip:author": signer_tip_id, "tip:content": ctid,
        "tip:origin": ORIGIN_LABELS[origin_code].toLowerCase().replace(/ /g, "-"),
        "tip:score": scoring.getScore(signer_tip_id).score.toString(),
        "tip:status": preScan.flagged ? "PENDING" : "REGISTERED",
      },
    };
  }

  function resolve(ctid) {
    const rec = dag.getContent(ctid);
    if (!rec) throw schemaError(404, "Content record not found", "content_not_found");

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
      author_name: (author && author.creator_name) || null,
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
    validate(body, { verifier_tip_id: { required: true }, signature: { required: true } });
    const { verifier_tip_id, verdict, signature } = body;

    // Stateful pre-conditions — same predicate as commit-handler.
    const { valid, error } = rules.canVerify(dag, { ctid, verifier_tip_id });
    if (!valid) throw schemaError(error.status, error.message, error.code);
    const rec = dag.getContent(ctid);
    const verifier = dag.getIdentity(verifier_tip_id);

    const VERIFY_FIELDS = ["verifier_tip_id", "verdict"];
    if (!verifyBodySignature(body, signature, verifier.public_key, VERIFY_FIELDS)) {
      throw schemaError(403, "Verifier signature verification failed", "signature_invalid");
    }

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

    const verifyTxTimestamp = new Date().toISOString();
    const verifyTxBody = {
      tx_type: TX_TYPES.CONTENT_VERIFIED, timestamp: verifyTxTimestamp, prev: dag.getRecentPrev(),
      data: { ctid, verifier_tip_id, verdict: verdict || "ORIGIN_CONFIRMED", weighted_delta: weightedDelta, author_tip_id: authorTipId, signature },
    };
    const signedTx = withTxId(verifyTxBody);
    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(signedTx);

    // Paired score-effect (single-channel rule): the CONTENT_VERIFIED tx
    // owns the verification record; this SCORE_UPDATE owns the score
    // delta. Submitted right after so they land in the same anchor commit.
    if (weightedDelta > 0 && authorTipId) {
      const scoreTx = scoring.buildScoreUpdateTx({
        tipId: authorTipId, delta: weightedDelta,
        reason: `Content verified (${ctid})`,
        ctid, relatedTxId: signedTx.tx_id,
        timestamp: verifyTxTimestamp,
        getRecentPrev: () => dag.getRecentPrev(),
        config,
      });
      submitTx(scoreTx);
    }

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
    validate(body, { author_tip_id: { required: true }, new_origin_code: { required: true }, signature: { required: true } });
    const { author_tip_id, new_origin_code, signature } = body;

    // Stateful + time-window pre-conditions. Time-window uses Date.now()
    // at API call; commit-handler re-checks with cert.timestamp.
    const { valid, error } = rules.canUpdateOrigin(dag, { ctid, author_tip_id, new_origin_code }, { now: Date.now() });
    if (!valid) throw schemaError(error.status, error.message, error.code);
    const rec = dag.getContent(ctid);
    const author = dag.getIdentity(author_tip_id);

    const UPDATE_FIELDS = ["author_tip_id", "new_origin_code"];
    if (!verifyBodySignature(body, signature, author.public_key, UPDATE_FIELDS)) {
      throw schemaError(403, "Author signature verification failed", "signature_invalid");
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
    validate(body, { author_tip_id: { required: true }, signature: { required: true } });
    const { author_tip_id, signature } = body;

    const { valid, error } = rules.canRetract(dag, { ctid, author_tip_id });
    if (!valid) throw schemaError(error.status, error.message, error.code);
    const rec = dag.getContent(ctid);
    const author = dag.getIdentity(author_tip_id);

    if (!verifyBodySignature(body, signature, author.public_key, ["author_tip_id"])) {
      throw schemaError(403, "Author signature verification failed", "signature_invalid");
    }

    const retractTimestamp = new Date().toISOString();
    const retractTx = withTxId({
      tx_type: TX_TYPES.CONTENT_RETRACTED, timestamp: retractTimestamp, prev: dag.getRecentPrev(),
      data: { ctid, author_tip_id, signature, origin_code: rec.origin_code, pre_retract_status: rec.status },
    });
    submitTx(retractTx);

    // Paired score-effect (single-channel rule): retraction record on
    // CONTENT_RETRACTED, score delta on SCORE_UPDATE. Submitted together
    // so they land in the same anchor commit.
    const scoreTx = scoring.buildScoreUpdateTx({
      tipId: author_tip_id, delta: SCORE_EVENTS.CONTENT_RETRACTION.delta,
      reason: `Content retracted (${ctid})`,
      ctid, relatedTxId: retractTx.tx_id,
      timestamp: retractTimestamp,
      getRecentPrev: () => dag.getRecentPrev(),
      config,
    });
    submitTx(scoreTx);

    log.info(`Content retraction proposed: ${ctid} by ${author_tip_id}`);
    return { success: true, ctid, penalty: SCORE_EVENTS.CONTENT_RETRACTION.delta, tx_id: retractTx.tx_id, confirmation: "proposed" };
  }

  return { register, resolve, verify, updateOrigin, retract };
}

module.exports = { createContentService };
