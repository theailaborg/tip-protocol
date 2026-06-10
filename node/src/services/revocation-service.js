"use strict";

const { verifyBodySignature } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId } = require("./helpers");
const { validate } = require("../middleware/validate");
const { log } = require("../logger");

function createRevocationService({ dag, submitTx }) {

  function list(since) {
    const revocations = dag.getRevocations(since || undefined);
    return { revocations, count: revocations.length, since: since || null };
  }

  function create(body) {
    validate(body, { tip_id: { required: true }, tx_type: { required: true }, issuing_vp_id: { required: true }, signature: { required: true } });
    const { tx_type, tip_id, reason_code, evidence_hash, issuing_vp_id, signature } = body;

    const revokeCheck = rules.canRevoke(dag, { tx_type, tip_id, issuing_vp_id });
    if (!revokeCheck.valid) throw { status: revokeCheck.error.status, error: revokeCheck.error.message };

    const issuingVp = dag.getVP(issuing_vp_id);

    const REVOCATION_FIELDS = ["tx_type", "tip_id", "reason_code", "evidence_hash", "issuing_vp_id"];
    if (!verifyBodySignature(body, signature, issuingVp.public_key, REVOCATION_FIELDS)) {
      throw { status: 403, error: "VP signature verification failed" };
    }

    const timestamp = nowMs();
    const txData = { tx_type, tip_id, issuing_vp_id };
    if (reason_code !== undefined && reason_code !== null) txData.reason_code = reason_code;
    if (evidence_hash !== undefined && evidence_hash !== null) txData.evidence_hash = evidence_hash;
    const revokeTx = withTxId({
      tx_type, timestamp, prev: dag.getRecentPrev(),
      data: txData,
      signature,
    });

    const validation = validateTransaction(revokeTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(revokeTx);

    log.info(`Revocation proposed: ${tip_id} (type: ${tx_type}, by: ${issuing_vp_id})`);
    return { tx_id: revokeTx.tx_id, tip_id, tx_type, timestamp, confirmation: "proposed" };
  }

  return { list, create };
}

module.exports = { createRevocationService };
