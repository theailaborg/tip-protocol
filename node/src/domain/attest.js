"use strict";

// One node's BIND_DOMAIN: its signed observation that the owner's proof is in
// place. Shared by the verify / renew API and the co-attest job.

const { TX_TYPES, DOMAIN_BINDING_STATUS, SIGNED_BY_KIND } = require("../../../shared/constants");
const { nowMs } = require("../../../shared/time");
const bindDomainSchema = require("../schemas/bind-domain");
const { schemaError } = require("../schemas/_common");
const { validateTransaction } = require("../validators/tx-validator");
const { withTxId } = require("../services/helpers");

// `claim` = { tip_id, claimed_at, method (what the owner signed), signature }.
function buildAttestationTx({ dag, config, claim, domain, result }) {
  if (!config.nodePrivateKey) {
    throw schemaError(500, "Node missing private key, cannot sign binding attestation", "node_unconfigured");
  }
  const nodeId = config.nodeRegisteredId || config.nodeId;
  if (!nodeId) throw schemaError(500, "Node id not configured", "node_unconfigured");

  const verifiedAt = result.verified_at || nowMs();
  const canonical = bindDomainSchema.buildSigningPayload({
    binding_state: DOMAIN_BINDING_STATUS.VERIFIED,
    claimed_at: claim.claimed_at,
    claimed_method: claim.method,
    domain,
    method: result.method,
    node_id: nodeId,
    tip_id: claim.tip_id,
    verified_at: verifiedAt,
  });
  const tx = withTxId({
    tx_type: TX_TYPES.BIND_DOMAIN,
    timestamp: verifiedAt,
    data: {
      ...canonical,
      // The owner's REGISTER_DOMAIN claim signature rides as a cosignature.
      cosignatures: [{ signer_kind: SIGNED_BY_KIND.SUBJECT, signer_ref: claim.tip_id, signature: claim.signature }],
      evidence: result.evidence,
    },
    signature: bindDomainSchema.sign(canonical, config.nodePrivateKey),
  }, dag);

  const validation = validateTransaction(tx, dag, { skipState: true });
  if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");
  return tx;
}

module.exports = { buildAttestationTx };
