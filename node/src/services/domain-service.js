/**
 * @file @tip-protocol/node/src/services/domain-service.js
 * @description Domain binding service — three endpoints:
 *
 *   POST /v1/domain/register — record the user-signed claim locally
 *                              (pending_domain_claims). No DAG tx yet.
 *   POST /v1/domain/verify   — node fetches DNS / well-known, attests via
 *                              ML-DSA-65 over the canonical BIND_DOMAIN
 *                              payload, submits the tx to consensus.
 *   GET  /v1/domain/:domain  — public reverse lookup. Returns the
 *                              DAG-committed binding with the node's
 *                              binding_signature. Same answer on every
 *                              node in the federation.
 *
 * Trust model + the user/node-signed split is described in
 * schemas/bind-domain.js (header). Spec: my-notes/DOMAIN_VERIFICATION.md.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const {
  TX_TYPES, DOMAIN_BINDING_STATUS, DOMAIN_VERIFICATION_METHODS,
  DOMAIN_DNS_TXT_PREFIX, DOMAIN_WELL_KNOWN_PATH,
} = require("../../../shared/constants");
const registerDomainSchema = require("../schemas/register-domain");
const bindDomainSchema = require("../schemas/bind-domain");
const { schemaError } = require("../schemas/_common");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId } = require("./helpers");
const domainVerifier = require("../domain/verifier");
const { log } = require("../logger");

/**
 * Build the TXT-record instruction surfaced in POST /register's response.
 * Matches the format the WP plugin's self-verifier expects.
 */
function _txtInstruction(domain, tipId) {
  return `${DOMAIN_DNS_TXT_PREFIX}.${domain} TXT "tip-id=${tipId}"`;
}

function createDomainService({ dag, config, submitTx, verifier = domainVerifier }) {

  // ── POST /v1/domain/register ─────────────────────────────────────────
  // Records the user-signed claim locally. Idempotent on (domain, tip_id):
  // re-registering with the same pair overwrites the pending row's
  // claimed_at / signature; re-registering with a DIFFERENT tip_id while
  // a VERIFIED binding exists for the same domain rejects with 409.
  function register(body) {
    const { identity, domain, method } = registerDomainSchema.validateRequest(body, { dag });

    // Verify the user's signature over the canonical claim payload BEFORE
    // persisting — a bad signature should never write to the pending table.
    const canonical = registerDomainSchema.buildSigningPayload({
      claimed_at: body.claimed_at,
      domain,
      method,
      tip_id: body.tip_id,
    });
    if (!registerDomainSchema.verifySignature(canonical, body.signature, identity.public_key)) {
      throw schemaError(403, "Claim signature verification failed — you do not own this TIP-ID", "signature_invalid");
    }

    // State precondition: domain already bound to a DIFFERENT tip_id.
    // Same predicate runs at consensus time in commit-handler._statefulCheck
    // so a direct tx-submission bypassing this API still gets dropped.
    const r = rules.canBindDomain(dag, { tip_id: body.tip_id, domain });
    if (!r.valid) {
      throw schemaError(r.error.status, r.error.message, "domain_already_claimed");
    }

    dag.savePendingDomainClaim({
      domain,
      tip_id: body.tip_id,
      method,
      claimed_at: body.claimed_at,
      signature: body.signature,
      received_at: new Date().toISOString(),
    });

    log.info(`Domain claim received: ${domain} → ${body.tip_id} (method: ${method})`);

    // If this tip_id is RE-registering for the same domain (e.g. re-verify
    // after a key rotation), surface the already-verified state in the
    // response so the client doesn't show "pending" for an active binding.
    const sameTipBinding = dag.getDomainBinding(domain);
    return {
      tip_id: body.tip_id,
      domain,
      method,
      status: sameTipBinding && sameTipBinding.tip_id === body.tip_id
        ? sameTipBinding.binding_state
        : DOMAIN_BINDING_STATUS.PENDING,
      verification_url: `https://${domain}${DOMAIN_WELL_KNOWN_PATH}`,
      expected_dns: _txtInstruction(domain, body.tip_id),
      node_seen_at: new Date().toISOString(),
    };
  }

  // ── POST /v1/domain/verify ───────────────────────────────────────────
  // Mirrors register()'s structure:
  //   1. validateVerifyRequest  (schema) — shape, pending-claim lookup,
  //                                        expiry, tip_id pin, claimant +
  //                                        org gate
  //   2. canBindDomain          (rules)  — race protection (same predicate
  //                                        commit-handler enforces)
  //   3. verifier.verify        (network) — DNS / HTTP proof of control
  //   4. bindDomainSchema.sign  (schema) — node's ML-DSA-65 attestation
  //   5. submit BIND_DOMAIN tx
  //
  // Replicating nodes re-verify both signatures at commit time but do NOT
  // re-perform DNS / HTTP (non-deterministic across the network).
  async function verify(body) {
    const { claim, identity, domain, method } =
      registerDomainSchema.validateVerifyRequest(body, { dag });

    // State precondition: domain not bound to a DIFFERENT tip_id. Same
    // predicate runs at consensus time so a direct tx submission bypassing
    // this API still gets dropped.
    const r = rules.canBindDomain(dag, { tip_id: claim.tip_id, domain });
    if (!r.valid) {
      throw schemaError(r.error.status, r.error.message, "domain_already_claimed");
    }

    // Node hits DNS / HTTP. Failure short-circuits with a structured code
    // straight from verifier.js — surfaced verbatim to the API caller.
    const result = await verifier.verify(method, domain, claim.tip_id, {
      expectedPublicKey: identity.public_key,
    });
    if (!result.verified) {
      const code = (result.error && result.error.code) || "verification_failed";
      const msg = (result.error && result.error.message) || "Node could not independently verify the binding";
      throw schemaError(422, msg, code);
    }

    if (!config.nodePrivateKey) {
      // Node misconfiguration — without a private key we can't attest.
      throw schemaError(500, "Node missing private key — cannot sign binding attestation", "node_unconfigured");
    }
    const nodeId = config.nodeRegisteredId || config.nodeId;
    if (!nodeId) {
      throw schemaError(500, "Node id not configured", "node_unconfigured");
    }

    const verifiedAt = result.verified_at || new Date().toISOString();
    const canonicalBinding = bindDomainSchema.buildSigningPayload({
      binding_state: DOMAIN_BINDING_STATUS.VERIFIED,
      claim_signature: claim.signature,
      claimed_at: claim.claimed_at,
      domain,
      method: result.method,
      node_id: nodeId,
      tip_id: claim.tip_id,
      verified_at: verifiedAt,
    });
    const bindingSignature = bindDomainSchema.sign(canonicalBinding, config.nodePrivateKey);

    const txBody = {
      tx_type: TX_TYPES.BIND_DOMAIN,
      timestamp: verifiedAt,
      prev: dag.getRecentPrev(),
      data: {
        // canonical fields mirrored onto tx.data so commit-handler can
        // replay buildSigningPayload(d) deterministically
        binding_state: canonicalBinding.binding_state,
        claim_signature: canonicalBinding.claim_signature,
        claimed_at: canonicalBinding.claimed_at,
        domain: canonicalBinding.domain,
        method: canonicalBinding.method,
        node_id: canonicalBinding.node_id,
        tip_id: canonicalBinding.tip_id,
        verified_at: canonicalBinding.verified_at,
        // tx-level fields
        binding_signature: bindingSignature,
        evidence: result.evidence,
      },
    };
    const signedTx = withTxId(txBody);

    const validation = validateTransaction(signedTx, dag, { skipState: true });
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(signedTx);
    log.info(`Domain binding proposed: ${domain} → ${claim.tip_id} (method: ${result.method}, tx: ${signedTx.tx_id.slice(0, 16)})`);

    return {
      tip_id: claim.tip_id,
      domain,
      verified: true,
      method: result.method,
      verified_at: verifiedAt,
      tx_id: signedTx.tx_id,
      evidence: result.evidence,
      confirmation: "proposed",
    };
  }

  // ── GET /v1/domain/:domain ───────────────────────────────────────────
  // Public reverse lookup. Returns the DAG-committed binding as the single
  // source of truth — the same answer on every node in the federation.
  //
  // Status derivation (read-time):
  //   - canonical binding_state === "revoked"     → "revoked"
  //   - now > expires_at                          → "expired"
  //   - otherwise                                 → canonical binding_state ("verified")
  //
  // `expires_at` + `days_until_expiry` are surfaced so consumers can apply
  // their own freshness policy (e.g. high-stakes citation flows may bound
  // staleness tighter than the protocol-wide expiry). When the v2 adaptive
  // renewal scheduler lands, the same fields drive automated re-probe;
  // the API surface is forward-compatible.
  function get(domain) {
    const normalized = registerDomainSchema.normalizeDomain(domain);
    const binding = dag.getDomainBinding(normalized);
    if (!binding) {
      // No committed binding. Is there a pending claim on this node?
      // Note: claims are per-node — peers won't surface a pending row
      // that arrived at a different node.
      const pending = dag.getPendingDomainClaim(normalized);
      if (pending) {
        return {
          domain: normalized,
          tip_id: pending.tip_id,
          status: DOMAIN_BINDING_STATUS.PENDING,
          method: pending.method,
          claimed_at: pending.claimed_at,
          verified_at: null,
          expires_at: null,
          days_until_expiry: null,
          consecutive_failures: 0,
          binding_signature: null,
          node_id: null,
          tx_id: null,
        };
      }
      throw schemaError(404, `No binding for domain ${normalized}`, "domain_not_found");
    }

    const expiresMs = binding.expires_at ? binding.expires_at : NaN;
    const nowMs = Date.now();
    const isExpired = Number.isFinite(expiresMs) && nowMs > expiresMs;
    const status = binding.binding_state === "revoked"
      ? "revoked"
      : isExpired
        ? DOMAIN_BINDING_STATUS.UNVERIFIED
        : binding.binding_state;
    const daysUntilExpiry = Number.isFinite(expiresMs)
      ? Math.ceil((expiresMs - nowMs) / (24 * 60 * 60 * 1000))
      : null;

    return {
      domain: binding.domain,
      tip_id: binding.tip_id,
      status,
      method: binding.method,
      claimed_at: binding.claimed_at,
      verified_at: binding.verified_at,
      expires_at: binding.expires_at || null,
      days_until_expiry: daysUntilExpiry,
      consecutive_failures: typeof binding.consecutive_failures === "number"
        ? binding.consecutive_failures
        : 0,
      binding_signature: binding.binding_signature,
      node_id: binding.node_id,
      tx_id: binding.tx_id,
    };
  }

  return {
    register,
    verify,
    get,
  };
}

module.exports = {
  createDomainService,
  // Re-export the well-known path + method enum for the WP plugin
  // coordination message and admin tooling.
  DOMAIN_WELL_KNOWN_PATH,
  DOMAIN_VERIFICATION_METHODS,
};
