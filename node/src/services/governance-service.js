"use strict";

const { generateTIPID, verifyBodySignature } = require("../../../shared/crypto");
const { TX_TYPES } = require("../../../shared/constants");
const { validateTransaction } = require("../validators/tx-validator");
const { withTxId } = require("./helpers");
const { validate } = require("../middleware/validate");
const { getFoundingVP } = require("../genesis");
const { log } = require("../logger");

function createGovernanceService({ dag, scoring, config, broadcast }) {

  function registerVP(body) {
    validate(body, { name: { required: true }, public_key: { required: true }, council_signature: { required: true }, approving_vp_id: { required: true } });
    const { name, jurisdiction_tier = "green", public_key, council_signature, approving_vp_id } = body;

    const foundingVpId = getFoundingVP().vp_id;
    if (approving_vp_id !== foundingVpId) throw { status: 403, error: `Only the founding VP (${foundingVpId}) can approve new VPs` };

    const approvingVp = dag.getVP(approving_vp_id);
    if (!approvingVp) throw { status: 403, error: `Approving VP not found` };
    if (approvingVp.status !== "active") throw { status: 403, error: `Approving VP is not active` };

    const VP_REGISTER_FIELDS = ["name", "jurisdiction_tier", "public_key", "approving_vp_id"];
    if (!verifyBodySignature(body, council_signature, approvingVp.public_key, VP_REGISTER_FIELDS)) {
      throw { status: 403, error: "Council signature verification failed" };
    }

    const vpId = generateTIPID("VP", public_key);
    const registeredAt = new Date().toISOString();

    const vpTx = withTxId({
      tx_type: TX_TYPES.VP_REGISTERED, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: { vp_id: vpId, name, jurisdiction_tier, public_key, council_signature, approving_vp_id },
    });

    const validation = validateTransaction(vpTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    dag.addTx(vpTx);
    broadcast(vpTx);
    dag.saveVP({ vp_id: vpId, name, jurisdiction_tier, public_key, status: "active", registered_at: registeredAt });

    return { vp_id: vpId, name, jurisdiction_tier, registered_at: registeredAt };
  }

  function resolveVP(vpId) {
    const vp = dag.getVP(vpId);
    if (!vp) throw { status: 404, error: "Verification Provider not found" };
    return vp;
  }

  function registerNode(body) {
    validate(body, { public_key: { required: true }, council_signature: { required: true }, approving_vp_id: { required: true } });
    const { name, public_key, council_signature, approving_vp_id } = body;

    const foundingVpId = getFoundingVP().vp_id;
    if (approving_vp_id !== foundingVpId) throw { status: 403, error: `Only the founding VP can approve nodes` };

    const approvingVp = dag.getVP(approving_vp_id);
    if (!approvingVp) throw { status: 403, error: `Approving VP not found` };
    if (approvingVp.status !== "active") throw { status: 403, error: `Approving VP is not active` };

    const NODE_REGISTER_FIELDS = ["name", "public_key", "approving_vp_id"];
    if (!verifyBodySignature(body, council_signature, approvingVp.public_key, NODE_REGISTER_FIELDS)) {
      throw { status: 403, error: "Council signature verification failed" };
    }

    const nodeId = require("../../../shared/crypto").shake256(public_key).slice(0, 16);
    const registeredAt = new Date().toISOString();

    const nodeTx = withTxId({
      tx_type: TX_TYPES.NODE_REGISTERED, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: { node_id: nodeId, name: name || `node-${nodeId.slice(0, 8)}`, public_key, council_signature, approving_vp_id },
    });

    const validation = validateTransaction(nodeTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    dag.addTx(nodeTx);
    broadcast(nodeTx);
    dag.saveNode({ node_id: nodeId, name: name || `node-${nodeId.slice(0, 8)}`, public_key, status: "active", registered_at: registeredAt });

    log.info(`Node registered: ${nodeId}`);
    return { node_id: nodeId, name: name || `node-${nodeId.slice(0, 8)}`, registered_at: registeredAt };
  }

  return { registerVP, resolveVP, registerNode };
}

module.exports = { createGovernanceService };
