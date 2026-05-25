/**
 * @file @tip-protocol/node/src/schemas/link-platform.js
 * @description Canonical schema for `LINK_PLATFORM` — NODE-ATTESTED social
 * account linking. The node verifies the user's social profile bio proof and
 * attests it on-chain. Each linked account earns +5 trust score (max 6 accounts,
 * +30 cap). The bonus arrives as a paired SCORE_UPDATE tx emitted by
 * identity-service.linkPlatform, not inline on this tx.
 *
 * Trust model:
 *   - The USER signs a claim {claimed_at, platform, profile_url, tip_id}
 *     (schemas/register-social.js) — proves they own the TIP-ID and intend
 *     to claim the social account.
 *   - The NODE independently verifies the social profile bio proof, then signs
 *     {claim_signature, claimed_at, handle, node_id, platform, profile_url,
 *      tip_id, verified_at} (this module) — proves a node observed proof at time T.
 *   - The LINK_PLATFORM tx carries BOTH signatures. Replicating nodes verify
 *     both at commit time.
 *
 * Signed canonical payload (8 fields, alphabetical):
 *   claim_signature  string,  required (user's ML-DSA hex over the register-social payload)
 *   claimed_at       number,  required (epoch ms — from the original claim)
 *   handle           string|null, required (platform username; null for LinkedIn/Facebook)
 *   node_id          string,  required (verifying node's TIP node_id)
 *   platform         string,  required (any non-empty string <= 50 chars)
 *   profile_url      string,  required (https:// URL)
 *   tip_id           string,  required (tip://id/... owner identity)
 *   verified_at      number,  required (epoch ms — when this node observed proof)
 *
 * Signer: the node (SIGNED_BY = NODE, SIGNATURE_SCOPE = BODY).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError, canonicalJson } = require("./_common");
const { TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND } = require("../../../shared/constants");
const { isValidMs } = require("../../../shared/time");
const registerSocialSchema = require("./register-social");

const TX_TYPE = TX_TYPES.LINK_PLATFORM;
const PLATFORM_MAX_LENGTH = 50;

/**
 * Build the canonical 8-field signed payload for a LINK_PLATFORM tx. All
 * fields always present; picks exactly these 8 keys in alphabetical order.
 */
function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (typeof input.tip_id !== "string" || !input.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required (tip://id/...)", "tip_id_required");
  }
  if (typeof input.platform !== "string" || input.platform.length === 0) {
    throw schemaError(400, "platform is required", "platform_required");
  }
  if (input.platform.length > PLATFORM_MAX_LENGTH) {
    throw schemaError(400, `platform must be <= ${PLATFORM_MAX_LENGTH} chars`, "platform_too_long");
  }
  if (typeof input.profile_url !== "string" || !input.profile_url.startsWith("https://")) {
    throw schemaError(400, "profile_url is required (https:// URL)", "profile_url_required");
  }
  if (input.handle !== null && input.handle !== undefined && typeof input.handle !== "string") {
    throw schemaError(400, "handle must be a string or null", "handle_invalid");
  }
  if (typeof input.node_id !== "string" || input.node_id.length === 0) {
    throw schemaError(400, "node_id is required", "node_id_required");
  }
  if (typeof input.claim_signature !== "string" || input.claim_signature.length === 0) {
    throw schemaError(400, "claim_signature is required", "claim_signature_required");
  }
  if (!isValidMs(input.claimed_at)) {
    throw schemaError(400, "claimed_at must be a valid epoch ms timestamp", "claimed_at_invalid");
  }
  if (!isValidMs(input.verified_at)) {
    throw schemaError(400, "verified_at must be a valid epoch ms timestamp", "verified_at_invalid");
  }

  return {
    claim_signature: input.claim_signature,
    claimed_at:      input.claimed_at,
    handle:          input.handle ?? null,
    node_id:         input.node_id,
    platform:        input.platform,
    profile_url:     input.profile_url,
    tip_id:          input.tip_id,
    verified_at:     input.verified_at,
  };
}

function sign(payload, nodePrivateKeyHex, opts) {
  return signPayload(payload, nodePrivateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * State-level verification at consensus replay. GH #51: the node's
 * attestation is verified by the unified dispatcher (tx.signature). This
 * function only enforces the state-machine invariants the dispatcher
 * doesn't know about:
 *
 *   1. Emitting node is registered + active
 *   2. Claimant TIP-ID is registered, not revoked
 *   3. User's claim_signature (attestation by the subject) verifies over
 *      the embedded register-social sub-payload
 *
 * Returns { ok: true } on success, or
 * { ok: false, status, error, code } on any failure.
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};

  if (!d.node_id) {
    return { ok: false, status: 400, error: "node_id missing", code: "node_id_missing" };
  }
  const node = dag.getNode(d.node_id);
  if (!node) {
    return { ok: false, status: 412, error: `Verifying node not registered: ${d.node_id}`, code: "node_not_registered" };
  }
  if (node.status !== "active") {
    return { ok: false, status: 403, error: `Verifying node not active: ${d.node_id}`, code: "node_inactive" };
  }

  const identity = dag.getIdentity(d.tip_id);
  if (!identity) {
    return { ok: false, status: 412, error: `TIP-ID not found: ${d.tip_id}`, code: "tip_id_not_found" };
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(d.tip_id)) {
    return { ok: false, status: 403, error: `TIP-ID is revoked: ${d.tip_id}`, code: "tip_id_revoked" };
  }

  // The original user-signed claim is bound into the LINK_PLATFORM tx so
  // replay-time verification re-establishes the full trust chain (user
  // → node) without needing the off-chain register call to still exist.
  let claimPayload;
  try {
    claimPayload = registerSocialSchema.buildSigningPayload({
      claimed_at:  d.claimed_at,
      platform:    d.platform,
      profile_url: d.profile_url,
      tip_id:      d.tip_id,
    });
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }

  if (!registerSocialSchema.verifySignature(claimPayload, d.claim_signature, identity.public_key)) {
    return { ok: false, status: 403, error: "User claim signature verification failed", code: "claim_signature_invalid" };
  }

  return { ok: true };
}

module.exports = {
  TX_TYPE,
  PLATFORM_MAX_LENGTH,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
  canonicalJson,
  // GH #51 — unified signature contract
  SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
  SIGNED_BY: SIGNED_BY_KIND.NODE,
};
