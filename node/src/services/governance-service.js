"use strict";

const { generateVPId, verifyBodySignature } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { TX_TYPES } = require("../../../shared/constants");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId } = require("./helpers");
const { validate } = require("../middleware/validate");
const { getFoundingVP } = require("../genesis");
const interestRegisteredSchema = require("../schemas/interest-registered");
const { log } = require("../logger");

function createGovernanceService({ dag, scoring, config, submitTx }) {

  function registerVP(body) {
    // GH #51 — accept legacy `council_signature` or new top-level
    // `signature`; map onto the same internal field for the rest of
    // the function. Lets new clients opt into the unified wire format.
    // GH #60 — also normalise algorithm (default ml-dsa-65) onto the
    // body so signed bytes + tx.data carry it without needing to
    // splat at every read site.
    const normalisedBody = (body && typeof body === "object")
      ? {
          ...body,
          council_signature: body.council_signature || body.signature,
          algorithm: body.algorithm || "ml-dsa-65",
        }
      : body;
    validate(normalisedBody, { name: { required: true }, public_key: { required: true }, jurisdiction: { required: true }, council_signature: { required: true }, approving_vp_id: { required: true } });
    const { name, jurisdiction, jurisdiction_tier = "green", public_key, algorithm, council_signature, approving_vp_id } = normalisedBody;

    const foundingVpId = getFoundingVP().vp_id;
    if (approving_vp_id !== foundingVpId) throw { status: 403, error: `Only the founding VP (${foundingVpId}) can approve new VPs` };

    const approvingVp = dag.getVP(approving_vp_id);
    if (!approvingVp) throw { status: 403, error: `Approving VP not found` };
    if (approvingVp.status !== "active") throw { status: 403, error: `Approving VP is not active` };

    // GH #60: algorithm is in the canonical signed bytes — VP attests
    // the (pubkey, algorithm) pair. Field list sorted alphabetically
    // so signer + verifier agree on canonical order.
    const VP_REGISTER_FIELDS = ["algorithm", "approving_vp_id", "jurisdiction", "jurisdiction_tier", "name", "public_key"];
    if (!verifyBodySignature(normalisedBody, council_signature, approvingVp.public_key, VP_REGISTER_FIELDS)) {
      throw { status: 403, error: "Council signature verification failed" };
    }

    const vpId = generateVPId(jurisdiction, public_key);
    const vpCheck = rules.canRegisterVp(dag, { vp_id: vpId });
    if (!vpCheck.valid) throw { status: vpCheck.error.status, error: vpCheck.error.message };

    const registeredAt = nowMs();

    const vpTx = withTxId({
      tx_type: TX_TYPES.VP_REGISTERED, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: { vp_id: vpId, name, jurisdiction, jurisdiction_tier, public_key, algorithm, approving_vp_id },
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
    // or the legacy `council_signature`. GH #60: also normalise
    // algorithm (default ml-dsa-65) onto the body.
    const normalisedBody = (body && typeof body === "object")
      ? {
          ...body,
          council_signature: body.council_signature || body.signature,
          algorithm: body.algorithm || "ml-dsa-65",
        }
      : body;
    validate(normalisedBody, { public_key: { required: true }, council_signature: { required: true }, approving_vp_id: { required: true } });
    const { name, public_key, algorithm, council_signature, approving_vp_id } = normalisedBody;

    const foundingVpId = getFoundingVP().vp_id;
    if (approving_vp_id !== foundingVpId) throw { status: 403, error: `Only the founding VP can approve nodes` };

    const approvingVp = dag.getVP(approving_vp_id);
    if (!approvingVp) throw { status: 403, error: `Approving VP not found` };
    if (approvingVp.status !== "active") throw { status: 403, error: `Approving VP is not active` };

    // GH #60: algorithm is in canonical signed bytes; alphabetical sort
    // keeps signer/verifier byte-aligned.
    const NODE_REGISTER_FIELDS = ["algorithm", "approving_vp_id", "name", "public_key"];
    if (!verifyBodySignature(normalisedBody, council_signature, approvingVp.public_key, NODE_REGISTER_FIELDS)) {
      throw { status: 403, error: "Council signature verification failed" };
    }

    const nodeId = require("../../../shared/crypto").generateNodeId(public_key);
    const nodeCheck = rules.canRegisterNode(dag, { node_id: nodeId });
    if (!nodeCheck.valid) throw { status: nodeCheck.error.status, error: nodeCheck.error.message };

    const registeredAt = nowMs();

    const nodeTx = withTxId({
      tx_type: TX_TYPES.NODE_REGISTERED, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: { node_id: nodeId, name: name || `node-${nodeId.slice(0, 8)}`, public_key, algorithm, approving_vp_id },
      // GH #51 — approving VP's council signature lives at tx.signature.
      signature: council_signature,
    });

    const validation = validateTransaction(nodeTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(nodeTx);

    log.info(`Node registration proposed: ${nodeId}`);
    return { node_id: nodeId, name: name || `node-${nodeId.slice(0, 8)}`, registered_at: registeredAt, confirmation: "proposed" };
  }

  /**
   * Register a new interest in the curated taxonomy. VP-attested:
   * caller must be a registered + active VP and have signed the
   * canonical payload (alphabetical: approving_vp_id, category, label,
   * slug). Slug uniqueness is enforced at commit time via the unified
   * dedup gate (canCommitteeRotation-style); a 409 here surfaces the
   * duplicate before the tx is even submitted.
   */
  function addInterest(body) {
    interestRegisteredSchema.validateRequest(body, { dag });
    const { slug, label, category, approving_vp_id, signature } = body;
    const canonicalPayload = interestRegisteredSchema.buildSigningPayload({
      slug, label, category, approving_vp_id,
    });
    const approvingVp = dag.getVP(approving_vp_id);
    if (!interestRegisteredSchema.verifySignature(canonicalPayload, signature, approvingVp.public_key)) {
      throw { status: 403, error: "VP signature verification failed" };
    }

    const registeredAt = nowMs();
    const tx = withTxId({
      tx_type:   TX_TYPES.INTEREST_REGISTERED,
      timestamp: registeredAt,
      prev:      dag.getRecentPrev(),
      data:      { slug, label, category, approving_vp_id },
      signature,
    });

    const validation = validateTransaction(tx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(tx);
    log.info(`Interest registration proposed: ${slug} (category=${category}, vp=${approving_vp_id})`);
    return { slug, label, category, registered_at: registeredAt, confirmation: "proposed" };
  }

  function listInterests() {
    return { interests: dag.getAllInterests() };
  }

  return { registerVP, resolveVP, registerNode, addInterest, listInterests };
}

module.exports = { createGovernanceService };
