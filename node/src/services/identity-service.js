"use strict";

const {
  shake256, generateTIPID, verifyBodySignature, verifyTxId, mldsaVerify,
} = require("../../../shared/crypto");
const { verifyDedupProof } = require("../../../shared/zk");
const { TX_TYPES } = require("../../../shared/constants");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId } = require("./helpers");
const { validate } = require("../middleware/validate");
const { log } = require("../logger");

function createIdentityService({ dag, scoring, config, submitTx }) {

  async function register(body) {
    validate(body, {
      public_key: { required: true },
      dedup_hash: { required: true },
      zk_proof: { required: true },
      vp_id: { required: true },
      vp_signature: { required: true },
    });

    const {
      region = "US", public_key, dedup_hash, zk_proof,
      verification_tier = "T1", vp_id, vp_signature, social_attested = false,
      creator_name,
    } = body;

    {
      const r = rules.canRegisterIdentity(dag, { dedup_hash, vp_id });
      if (!r.valid) {
        const err = { status: r.error.status, error: r.error.message };
        if (r.error.message.startsWith("Identity already")) err.code = "DUPLICATE_IDENTITY";
        throw err;
      }
    }
    const vp = dag.getVP(vp_id);

    // VP signs all required fields; creator_name is included in the signed
    // payload only when the VP attested a name for the identity.
    const BASE_FIELDS = ["region", "public_key", "dedup_hash", "zk_proof", "verification_tier", "vp_id", "social_attested"];
    const VP_IDENTITY_FIELDS = creator_name ? [...BASE_FIELDS, "creator_name"] : BASE_FIELDS;
    if (!verifyBodySignature(body, vp_signature, vp.public_key, VP_IDENTITY_FIELDS)) {
      throw { status: 403, error: "VP signature verification failed" };
    }

    const proofValid = await verifyDedupProof(dedup_hash, zk_proof);
    if (!proofValid) throw { status: 400, error: "ZK proof verification failed" };

    const tipId = generateTIPID(region, public_key);
    const registeredAt = new Date().toISOString();
    const founding = false;

    const txBody = {
      tx_type: TX_TYPES.REGISTER_IDENTITY, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: {
        tip_id: tipId, region: region.toUpperCase(), public_key, vp_id, vp_signature,
        verification_tier, social_attested, founding, dedup_hash, zk_proof,
        ...(creator_name ? { creator_name } : {}),
      },
    };
    const signedTx = withTxId(txBody);

    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(signedTx);
    log.info(`Identity proposed: ${tipId} (tier: ${verification_tier}, vp: ${vp_id})`);

    // Note: direct dag.saveIdentity / addDedupHash / setScore happen in
    // commit-handler when the tx commits via consensus. API returns 202-style
    // "proposed" so client knows to expect async finalization.
    return {
      tip_id: tipId, public_key, tx_id: signedTx.tx_id,
      score: social_attested ? 550 : 500, registered_at: registeredAt,
      confirmation: "proposed",
      ...(creator_name ? { creator_name } : {}),
    };
  }

  function resolve(tipId) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const scoreData = scoring.getScore(tipId);
    const content = dag.getContentByAuthor(tipId);
    const revoked = dag.isRevoked(tipId);
    const tx = rec.tx_id ? dag.getTx(rec.tx_id) : null;
    const txValid = tx ? verifyTxId(tx) : false;
    const prevValid = tx && tx.prev ? tx.prev.every(p => !!dag.getTx(p)) : false;

    return {
      tip_id: rec.tip_id, region: rec.region, public_key: rec.public_key,
      vp_id: rec.vp_id, verification_tier: rec.verification_tier, founding: rec.founding,
      status: revoked ? "revoked" : rec.status, score: scoreData.score,
      tier: scoreData.tier.name, tier_color: scoreData.tier.color,
      content_count: content.length, registered_at: rec.registered_at,
      creator_name: rec.creator_name || null,
      verification: { tx_exists: !!tx, tx_id_valid: txValid, prev_valid: prevValid, on_dag: true },
    };
  }

  function verifyOwnership(body) {
    validate(body, { tip_id: { required: true }, challenge: { required: true }, signature: { required: true } });
    const { tip_id, challenge, signature } = body;

    const identity = dag.getIdentity(tip_id);
    if (!identity) throw { status: 404, error: "TIP-ID not found" };
    if (dag.isRevoked(tip_id)) throw { status: 403, error: "TIP-ID is revoked" };

    const valid = mldsaVerify(challenge, signature, identity.public_key);
    if (!valid) throw { status: 403, error: "Signature verification failed — you do not own this TIP-ID" };

    const scoreData = scoring.getScore(tip_id);
    return {
      verified: true, tip_id,
      creator_name: identity.creator_name || null,
      score: scoreData.score, tier: scoreData.tier.name, status: identity.status,
    };
  }

  function getScore(tipId) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const { score, tier, offense_count } = scoring.getScore(tipId);
    const displayMode = rec.score_display_mode || "TIER_ONLY";

    return {
      tip_id: tipId, tier: tier.name, tier_label: tier.label, tier_color: tier.color,
      verified_since: rec.registered_at, content_count: dag.getContentByAuthor(tipId).length,
      status: dag.isRevoked(tipId) ? "revoked" : rec.status,
      creator_name: rec.creator_name || null,
      ...(displayMode === "FULL_PUBLIC" ? { score, offense_count } : {}),
    };
  }

  function getHistory(tipId) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const { score, tier, offense_count, history } = scoring.computeScore(tipId);
    return {
      tip_id: tipId, creator_name: rec.creator_name || null,
      score, tier: tier.name, offense_count, history,
    };
  }

  return { register, resolve, verifyOwnership, getScore, getHistory };
}

module.exports = { createIdentityService };
