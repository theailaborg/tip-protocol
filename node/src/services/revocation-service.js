"use strict";

const { verifyBodySignature } = require("../../../shared/crypto");
const { TX_TYPES } = require("../../../shared/constants");
const { validateTransaction } = require("../validators/tx-validator");
const { withTxId, nodeSignedAuto } = require("./helpers");
const { validate } = require("../middleware/validate");
const { log } = require("../logger");

function createRevocationService({ dag, scoring, config, broadcast, submitTx, submitBatch }) {

  function list(since) {
    const revocations = dag.getRevocations(since || undefined);
    return { revocations, count: revocations.length, since: since || null };
  }

  function create(body) {
    validate(body, { tip_id: { required: true }, tx_type: { required: true }, issuing_vp_id: { required: true }, signature: { required: true } });
    const { tx_type, tip_id, reason_code, evidence_hash, issuing_vp_id, signature } = body;

    const validTypes = [TX_TYPES.REVOKE_VOLUNTARY, TX_TYPES.REVOKE_VP, TX_TYPES.REVOKE_DECEASED, TX_TYPES.REVOKE_DEVICE];
    if (!validTypes.includes(tx_type)) throw { status: 400, error: `Invalid tx_type. Must be one of: ${validTypes.join(", ")}` };

    const issuingVp = dag.getVP(issuing_vp_id);
    if (!issuingVp) throw { status: 403, error: `Issuing VP not found: ${issuing_vp_id}` };
    if (issuingVp.status !== "active") throw { status: 403, error: `Issuing VP is not active: ${issuing_vp_id}` };

    const REVOCATION_FIELDS = ["tx_type", "tip_id", "reason_code", "evidence_hash", "issuing_vp_id"];
    if (!verifyBodySignature(body, signature, issuingVp.public_key, REVOCATION_FIELDS)) {
      throw { status: 403, error: "VP signature verification failed" };
    }

    const identity = dag.getIdentity(tip_id);
    if (!identity) throw { status: 404, error: "TIP-ID not found" };

    const timestamp = new Date().toISOString();
    const revokeTx = withTxId({
      tx_type, timestamp, prev: dag.getRecentPrev(),
      data: { tx_type, tip_id, reason_code, evidence_hash, issuing_vp_id, signature },
    });

    const validation = validateTransaction(revokeTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    // Collect batch: revocation + cascade txs (if VP revocation)
    const batchTxs = [revokeTx];

    if (tx_type === TX_TYPES.REVOKE_VP) {
      const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
      const recentContent = dag.getContentByAuthor(tip_id).filter(c => c.registered_at > cutoff);
      for (const c of recentContent) {
        const cascadeTx = nodeSignedAuto({
          tx_type: TX_TYPES.CONTENT_DISPUTED, timestamp: new Date().toISOString(), prev: dag.getRecentPrev(),
          data: { ctid: c.ctid, reason: "issuer_revocation_cascade", auto: true },
        }, config);
        batchTxs.push(cascadeTx);
      }
    }

    if (batchTxs.length > 1) {
      submitBatch(batchTxs);
    } else {
      submitTx(revokeTx);
    }

    log.info(`Revocation proposed: ${tip_id} (type: ${tx_type}, by: ${issuing_vp_id}, ${batchTxs.length} txs)`);
    return { tx_id: revokeTx.tx_id, tip_id, tx_type, timestamp, confirmation: "proposed" };
  }

  return { list, create };
}

module.exports = { createRevocationService };
