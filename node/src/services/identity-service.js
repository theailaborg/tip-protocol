"use strict";

const {
  shake256, generateTIPID, verifyBodySignature, verifyTxId, mldsaVerify,
} = require("../../../shared/crypto");
const { verifyDedupProof } = require("../../../shared/zk");
const { TX_TYPES } = require("../../../shared/constants");
const { validateTransaction } = require("../validators/tx-validator");
const { withTxId } = require("./helpers");
const { validate } = require("../middleware/validate");
const { log } = require("../logger");

function createIdentityService({ dag, scoring, config, broadcast }) {

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
    } = body;

    const vp = dag.getVP(vp_id);
    if (!vp || vp.status !== "active") throw { status: 403, error: "Verification provider not found or suspended" };

    const VP_IDENTITY_FIELDS = ["region", "public_key", "dedup_hash", "zk_proof", "verification_tier", "vp_id", "social_attested"];
    if (!verifyBodySignature(body, vp_signature, vp.public_key, VP_IDENTITY_FIELDS)) {
      throw { status: 403, error: "VP signature verification failed" };
    }

    const proofValid = await verifyDedupProof(dedup_hash, zk_proof);
    if (!proofValid) throw { status: 400, error: "ZK proof verification failed" };

    if (dag.hasDedupHash(dedup_hash)) {
      throw { status: 409, error: "Identity already registered. Each human may hold exactly one TIP-ID.", code: "DUPLICATE_IDENTITY" };
    }

    const tipId = generateTIPID(region, public_key);
    const registeredAt = new Date().toISOString();
    const founding = false;

    const txBody = {
      tx_type: TX_TYPES.REGISTER_IDENTITY, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: { tip_id: tipId, region: region.toUpperCase(), public_key, vp_id, verification_tier, social_attested, founding, dedup_hash, zk_proof },
    };
    const signedTx = withTxId(txBody);

    const validation = validateTransaction(signedTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    const tx = dag.addTx(signedTx);
    broadcast(tx);

    dag.saveIdentity({
      tip_id: tipId, region: region.toUpperCase(), public_key, vp_id,
      verification_tier, founding, status: "active", registered_at: registeredAt, tx_id: tx.tx_id,
    });
    dag.addDedupHash(dedup_hash);
    dag.setScore(tipId, social_attested ? 550 : 500, 0);

    log.info(`Identity registered: ${tipId} (tier: ${verification_tier}, vp: ${vp_id})`);

    return { tip_id: tipId, public_key, tx_id: tx.tx_id, score: social_attested ? 550 : 500, registered_at: registeredAt };
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
    return { verified: true, tip_id, score: scoreData.score, tier: scoreData.tier.name, status: identity.status };
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
      ...(displayMode === "FULL_PUBLIC" ? { score, offense_count } : {}),
    };
  }

  function getHistory(tipId) {
    const rec = dag.getIdentity(tipId);
    if (!rec) throw { status: 404, error: "TIP-ID not found" };

    const { score, tier, offense_count, history } = scoring.computeScore(tipId);
    return { tip_id: tipId, score, tier: tier.name, offense_count, history };
  }

  return { register, resolve, verifyOwnership, getScore, getHistory };
}

module.exports = { createIdentityService };
