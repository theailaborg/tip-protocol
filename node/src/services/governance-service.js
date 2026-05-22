"use strict";

const { generateVPId, verifyBodySignature } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { TX_TYPES } = require("../../../shared/constants");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId } = require("./helpers");
const { validate } = require("../middleware/validate");
const { getFoundingVP } = require("../genesis");
const { log } = require("../logger");

function createGovernanceService({ dag, scoring, config, submitTx }) {

  function registerVP(body) {
    // GH #51 — accept legacy `council_signature` or new top-level
    // `signature`; map onto the same internal field for the rest of
    // the function. Lets new clients opt into the unified wire format.
    const normalisedBody = (body && typeof body === "object")
      ? { ...body, council_signature: body.council_signature || body.signature }
      : body;
    validate(normalisedBody, { name: { required: true }, public_key: { required: true }, jurisdiction: { required: true }, council_signature: { required: true }, approving_vp_id: { required: true } });
    const { name, jurisdiction, jurisdiction_tier = "green", public_key, council_signature, approving_vp_id } = normalisedBody;

    const foundingVpId = getFoundingVP().vp_id;
    if (approving_vp_id !== foundingVpId) throw { status: 403, error: `Only the founding VP (${foundingVpId}) can approve new VPs` };

    const approvingVp = dag.getVP(approving_vp_id);
    if (!approvingVp) throw { status: 403, error: `Approving VP not found` };
    if (approvingVp.status !== "active") throw { status: 403, error: `Approving VP is not active` };

    const VP_REGISTER_FIELDS = ["name", "jurisdiction", "jurisdiction_tier", "public_key", "approving_vp_id"];
    if (!verifyBodySignature(normalisedBody, council_signature, approvingVp.public_key, VP_REGISTER_FIELDS)) {
      throw { status: 403, error: "Council signature verification failed" };
    }

    const vpId = generateVPId(jurisdiction, public_key);
    const vpCheck = rules.canRegisterVp(dag, { vp_id: vpId });
    if (!vpCheck.valid) throw { status: vpCheck.error.status, error: vpCheck.error.message };

    const registeredAt = nowMs();

    const vpTx = withTxId({
      tx_type: TX_TYPES.VP_REGISTERED, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: { vp_id: vpId, name, jurisdiction, jurisdiction_tier, public_key, approving_vp_id },
      // GH #51 — approving VP's council signature lives at tx.signature.
      signature: council_signature,
    });

    const validation = validateTransaction(vpTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(vpTx);

    return { vp_id: vpId, name, jurisdiction_tier, registered_at: registeredAt, confirmation: "proposed" };
  }

  function resolveVP(vpId) {
    const vp = dag.getVP(vpId);
    if (!vp) throw { status: 404, error: "Verification Provider not found" };
    return vp;
  }

  function registerNode(body) {
    // Same GH #51 alias as registerVP — clients can send `signature`
    // or the legacy `council_signature`.
    const normalisedBody = (body && typeof body === "object")
      ? { ...body, council_signature: body.council_signature || body.signature }
      : body;
    validate(normalisedBody, { public_key: { required: true }, council_signature: { required: true }, approving_vp_id: { required: true } });
    const { name, public_key, council_signature, approving_vp_id } = normalisedBody;

    const foundingVpId = getFoundingVP().vp_id;
    if (approving_vp_id !== foundingVpId) throw { status: 403, error: `Only the founding VP can approve nodes` };

    const approvingVp = dag.getVP(approving_vp_id);
    if (!approvingVp) throw { status: 403, error: `Approving VP not found` };
    if (approvingVp.status !== "active") throw { status: 403, error: `Approving VP is not active` };

    const NODE_REGISTER_FIELDS = ["name", "public_key", "approving_vp_id"];
    if (!verifyBodySignature(normalisedBody, council_signature, approvingVp.public_key, NODE_REGISTER_FIELDS)) {
      throw { status: 403, error: "Council signature verification failed" };
    }

    const nodeId = require("../../../shared/crypto").generateNodeId(public_key);
    const nodeCheck = rules.canRegisterNode(dag, { node_id: nodeId });
    if (!nodeCheck.valid) throw { status: nodeCheck.error.status, error: nodeCheck.error.message };

    const registeredAt = nowMs();

    const nodeTx = withTxId({
      tx_type: TX_TYPES.NODE_REGISTERED, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: { node_id: nodeId, name: name || `node-${nodeId.slice(0, 8)}`, public_key, approving_vp_id },
      // GH #51 — approving VP's council signature lives at tx.signature.
      signature: council_signature,
    });

    const validation = validateTransaction(nodeTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(nodeTx);

    log.info(`Node registration proposed: ${nodeId}`);
    return { node_id: nodeId, name: name || `node-${nodeId.slice(0, 8)}`, registered_at: registeredAt, confirmation: "proposed" };
  }

  return { registerVP, resolveVP, registerNode };
}

module.exports = { createGovernanceService };
