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
  SIGNED_BY_KIND, DOMAIN_VERIFICATION_METHOD_VALUES,
} = require("../../../shared/constants");
const DOMAIN_VERIFICATION_METHOD_VALUES_LIST = [...DOMAIN_VERIFICATION_METHOD_VALUES];
const { nowMs } = require("../../../shared/time");
const registerDomainSchema = require("../schemas/register-domain");
const bindDomainSchema = require("../schemas/bind-domain");
const { schemaError } = require("../schemas/_common");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId } = require("./helpers");
const domainVerifier = require("../domain/verifier");
const { websiteProtectionOn } = require("../validators/website-gate");
const { log } = require("../logger");

/**
 * Build the TXT-record instruction surfaced in POST /register's response.
 * Matches the format the WP plugin's self-verifier expects.
 */
function _txtInstruction(domain, tipId) {
  return `${DOMAIN_DNS_TXT_PREFIX}.${domain} TXT "tip-id=${tipId}"`;
}

function createDomainService({ dag, config, submitTx, verifier = domainVerifier, websitePages = null }) {

  // A plan protects a number of websites (Free 1). Asked before the node
  // probes or attests, so a site past the plan is never verified or renewed.
  // `keep` = this site is already one of the owner's (renewal): it may stay
  // only while it is among the plan's oldest sites.
  async function _checkSitePlace(tipId, domain, now, keep) {
    if (!websitePages || !websitePages.enabled || !websiteProtectionOn(now)) return;
    const key = rules.siteKey(domain);
    const sites = rules.liveSitesOf(dag, tipId, now);
    const ans = await websitePages.sitesLimit({ tip_id: tipId });
    if (!ans) return;
    const limit = Math.max(0, ans.sites_limit);
    const ok = keep ? sites.indexOf(key) > -1 && sites.indexOf(key) < limit
      : sites.includes(key) || sites.length < limit;
    if (ok) return;
    throw schemaError(402,
      `Your plan protects ${limit} website${limit === 1 ? "" : "s"}. Choose a plan with more websites to protect ${domain}.`,
      "website_site_limit",
      { domain, sites_used: sites.length, sites_limit: limit, plan: ans.plan || null, upgrade_url: ans.upgrade_url || "/plans#websites" });
  }

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
    const r = rules.canBindDomain(dag, { tip_id: body.tip_id, domain, at_ms: nowMs() });
    if (!r.valid) {
      throw schemaError(r.error.status, r.error.message, "domain_already_claimed");
    }

    dag.savePendingDomainClaim({
      domain,
      tip_id: body.tip_id,
      method,
      claimed_at: body.claimed_at,
      signature: body.signature,
      received_at: nowMs(),
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
      node_seen_at: nowMs(),
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
    const r = rules.canBindDomain(dag, { tip_id: claim.tip_id, domain, at_ms: nowMs() });
    if (!r.valid) {
      throw schemaError(r.error.status, r.error.message, "domain_already_claimed");
    }

    await _checkSitePlace(claim.tip_id, domain, nowMs(), false);

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

    return _proposeBinding({ claim, domain, result });
  }

  // Node attestation + BIND_DOMAIN submission, shared by verify (a fresh
  // claim) and renew (the owner's original claim, re-proved today).
  // `claim` = { tip_id, claimed_at, method (what the user signed), signature }.
  function _proposeBinding({ claim, domain, result }) {
    if (!config.nodePrivateKey) {
      // Node misconfiguration — without a private key we can't attest.
      throw schemaError(500, "Node missing private key — cannot sign binding attestation", "node_unconfigured");
    }
    const nodeId = config.nodeRegisteredId || config.nodeId;
    if (!nodeId) {
      throw schemaError(500, "Node id not configured", "node_unconfigured");
    }

    const verifiedAt = result.verified_at || nowMs();
    const canonicalBinding = bindDomainSchema.buildSigningPayload({
      binding_state: DOMAIN_BINDING_STATUS.VERIFIED,
      claimed_at: claim.claimed_at,
      claimed_method: claim.method,
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
      data: {
        // canonical fields mirrored onto tx.data so commit-handler can
        // replay buildSigningPayload(d) deterministically
        binding_state: canonicalBinding.binding_state,
        claimed_at: canonicalBinding.claimed_at,
        claimed_method: canonicalBinding.claimed_method,
        domain: canonicalBinding.domain,
        method: canonicalBinding.method,
        node_id: canonicalBinding.node_id,
        tip_id: canonicalBinding.tip_id,
        verified_at: canonicalBinding.verified_at,
        // User's claim sig from REGISTER_DOMAIN, carried as a cosignature.
        // The cosigner (claimant tip_id) signed the register-domain
        // canonical body — verifyTx rebuilds that body and verifies via
        // the cosignatures dispatcher.
        cosignatures: [{
          signer_kind: SIGNED_BY_KIND.SUBJECT,
          signer_ref:  claim.tip_id,
          signature:   claim.signature,
        }],
        // tx-level fields
        evidence: result.evidence,
      },
      // Node's ML-DSA-65 attestation over the canonical binding payload.
      signature: bindingSignature,
    };
    const signedTx = withTxId(txBody, dag);

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
    const now = nowMs();
    const isExpired = Number.isFinite(expiresMs) && now > expiresMs;
    const status = binding.binding_state === "revoked"
      ? "revoked"
      : isExpired
        ? DOMAIN_BINDING_STATUS.UNVERIFIED
        : binding.binding_state;
    const daysUntilExpiry = Number.isFinite(expiresMs)
      ? Math.ceil((expiresMs - now) / (24 * 60 * 60 * 1000))
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

  // ── POST /v1/domain/renew ────────────────────────────────────────────
  // A binding lapses DOMAIN_HEALTHY_EXPIRY_MS after it was verified, and a
  // lapsed binding no longer protects the site or blocks a new owner. Renew
  // re-proves control TODAY and re-commits the owner's ORIGINAL signed claim
  // with a fresh verified_at, so an owner whose DNS record or well-known file
  // is still in place never has to sign again. Anyone may ask (it can only
  // confirm what the domain itself says); it does nothing before the renewal
  // window and at most once an hour per domain.
  const RENEW_WINDOW_MS = 10 * 24 * 60 * 60 * 1000;
  // Short, so a renewal tried during a brief outage cannot block retries for long.
  const RENEW_COOLDOWN_MS = 10 * 60 * 1000;
  const _renewTried = new Map();   // domain -> last attempt (bounded)

  async function renew(body) {
    const domain = registerDomainSchema.normalizeDomain(body && body.domain);
    const binding = dag.getDomainBinding(domain);
    if (!binding || binding.binding_state !== DOMAIN_BINDING_STATUS.VERIFIED) {
      throw schemaError(404, `No binding to renew for ${domain}`, "domain_not_found");
    }
    const now = nowMs();
    if (Number.isFinite(binding.expires_at) && binding.expires_at - now > RENEW_WINDOW_MS) {
      return { domain, tip_id: binding.tip_id, renewed: false, reason: "not_due", expires_at: binding.expires_at };
    }
    const last = _renewTried.get(domain);
    if (last && now - last < RENEW_COOLDOWN_MS) {
      throw schemaError(429, `Renewal for ${domain} was tried in the last 10 minutes`, "renew_too_soon");
    }
    if (_renewTried.size >= 10000) _renewTried.delete(_renewTried.keys().next().value);
    _renewTried.set(domain, now);

    const identity = registerDomainSchema.resolveClaimant(binding.tip_id, dag, now);
    // The binding keeps the claim signature but not which method the owner
    // signed; the signature itself says which one it covers.
    const claimedMethod = DOMAIN_VERIFICATION_METHOD_VALUES_LIST.find(m =>
      typeof binding.claim_signature === "string" && registerDomainSchema.verifySignature(
        registerDomainSchema.buildSigningPayload({
          claimed_at: binding.claimed_at, domain, method: m, tip_id: binding.tip_id,
        }),
        binding.claim_signature, identity.public_key,
      ));
    if (!claimedMethod) {
      throw schemaError(409, "The owner's key changed since this site was added. Add the site again to renew it.", "renewal_needs_new_claim");
    }
    const r = rules.canBindDomain(dag, { tip_id: binding.tip_id, domain, at_ms: now });
    if (!r.valid) throw schemaError(r.error.status, r.error.message, "domain_already_claimed");

    await _checkSitePlace(binding.tip_id, domain, now, true);

    const result = await verifier.verify(DOMAIN_VERIFICATION_METHODS.AUTO, domain, binding.tip_id, {
      expectedPublicKey: identity.public_key,
    });
    if (!result.verified) {
      const code = (result.error && result.error.code) || "verification_failed";
      const msg = (result.error && result.error.message) || "Node could not independently verify the binding";
      throw schemaError(422, msg, code);
    }
    const out = _proposeBinding({
      claim: { tip_id: binding.tip_id, claimed_at: binding.claimed_at, method: claimedMethod, signature: binding.claim_signature },
      domain, result,
    });
    log.info(`Domain binding renewed: ${domain} -> ${binding.tip_id}`);
    return { ...out, renewed: true };
  }

  // ── GET /v1/domains?tip_id= ──────────────────────────────────────────
  // Every site a TIP-ID has bound, in the same public shape as GET
  // /v1/domain/:domain. Bindings are public DAG state already.
  function listByTip(tipId) {
    if (typeof tipId !== "string" || !/^tip:\/\/id\/[A-Z]{2}-[0-9a-f]{16}$/.test(tipId)) {
      throw schemaError(400, "tip_id must look like tip://id/US-0123456789abcdef", "tip_id_invalid");
    }
    const rows = typeof dag.getDomainBindingsByTipId === "function" ? dag.getDomainBindingsByTipId(tipId) : [];
    return {
      tip_id: tipId,
      domains: rows
        .map(b => get(b.domain))
        .filter(b => b.tip_id === tipId)
        .map(({ binding_signature, ...rest }) => rest)   // eslint-disable-line no-unused-vars
        .sort((a, b) => String(a.domain).localeCompare(String(b.domain))),
    };
  }

  return {
    register,
    verify,
    renew,
    get,
    listByTip,
  };
}

module.exports = {
  createDomainService,
  // Re-export the well-known path + method enum for the WP plugin
  // coordination message and admin tooling.
  DOMAIN_WELL_KNOWN_PATH,
  DOMAIN_VERIFICATION_METHODS,
};
