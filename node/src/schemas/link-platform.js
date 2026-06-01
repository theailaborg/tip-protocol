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
const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND,
  ALLOWED_PLATFORMS, OAUTH_REQUIRED_PLATFORMS, PLATFORM_MAX_LENGTH, CLAIM_MAX_AGE_MS,
} = require("../../../shared/constants");
const { isValidMs, nowMs } = require("../../../shared/time");
const registerSocialSchema = require("./register-social");
const registerIdentitySchema = require("./register-identity");

const TX_TYPE = TX_TYPES.LINK_PLATFORM;

/**
 * Request-envelope validator for POST /v1/identity/:tipId/link-platform.
 * Runs before any IO. Owns every request-time check so the service stays
 * thin (matches the update-profile / register-content pattern).
 *
 * Body shape (snake_case as received over HTTP):
 *   tip_id, platform, profile_url, claim_signature, claimed_at         required
 *   vp_id, vp_oauth_signature, vp_oauth_handle, vp_oauth_verified_at   optional
 *
 * deps:
 *   dag        — DAG store (identity / platform-link / mempool lookups)
 *   urlTipId   — when provided, body.tip_id must match
 *   now        — clock for the claim-age check (default nowMs())
 */
function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (deps && deps.urlTipId !== undefined && body.tip_id !== deps.urlTipId) {
    throw schemaError(400, "URL tip_id does not match body.tip_id", "tip_id_mismatch");
  }
  if (!body.tip_id || !body.platform || !body.profile_url || !body.claim_signature || !body.claimed_at) {
    throw schemaError(
      400,
      "tip_id, platform, profile_url, claim_signature, claimed_at are required",
      "missing_fields",
    );
  }
  if (typeof body.tip_id !== "string" || !body.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required (tip://id/...)", "tip_id_required");
  }
  if (typeof body.platform !== "string" || body.platform.length === 0) {
    throw schemaError(400, "platform is required", "platform_required");
  }
  if (body.platform.length > PLATFORM_MAX_LENGTH) {
    throw schemaError(400, `platform must be <= ${PLATFORM_MAX_LENGTH} chars`, "platform_too_long");
  }
  if (typeof body.profile_url !== "string" || !body.profile_url.startsWith("https://")) {
    throw schemaError(400, "profile_url is required (https:// URL)", "profile_url_required");
  }
  if (typeof body.claim_signature !== "string" || body.claim_signature.length === 0) {
    throw schemaError(400, "claim_signature is required", "claim_signature_required");
  }
  if (!isValidMs(body.claimed_at)) {
    throw schemaError(400, "claimed_at must be a valid epoch ms timestamp", "claimed_at_invalid");
  }

  const platformKey = body.platform.toLowerCase();
  const platformPatterns = ALLOWED_PLATFORMS[platformKey];
  if (!platformPatterns) {
    throw schemaError(400, `Unknown or unsupported platform: "${body.platform}"`, "unknown_platform");
  }
  if (!platformPatterns.some((re) => re.test(body.profile_url))) {
    throw schemaError(
      400,
      `profile_url does not match expected domain for platform "${body.platform}"`,
      "invalid_profile_url",
    );
  }

  const now = deps && typeof deps.now === "number" ? deps.now : nowMs();
  if (now - body.claimed_at > CLAIM_MAX_AGE_MS) {
    throw schemaError(400, "Claim has expired (max 15 minutes)", "claim_expired");
  }

  if (OAUTH_REQUIRED_PLATFORMS.has(platformKey) && !(body.vp_oauth_signature && body.vp_id)) {
    throw schemaError(
      403,
      `Platform "${body.platform}" requires VP OAuth verification`,
      "oauth_required",
    );
  }

  if (!deps || !deps.dag) return;
  const { dag } = deps;

  const identity = dag.getIdentity(body.tip_id);
  if (!identity) {
    throw schemaError(412, `TIP-ID not found: ${body.tip_id}`, "tip_id_not_found");
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(body.tip_id)) {
    throw schemaError(403, `TIP-ID is revoked: ${body.tip_id}`, "tip_id_revoked");
  }

  // First-wins guard against committed history. Relink after UNLINK is
  // allowed (existing row flips to "unlinked"); a second active link is
  // rejected so racing nodes / gossip-bypass txs can't double-write.
  const existingLink = typeof dag.getPlatformLink === "function"
    ? dag.getPlatformLink(body.tip_id, body.platform)
    : null;
  if (existingLink && existingLink.status === "active") {
    throw schemaError(
      409,
      `Platform "${body.platform}" already linked for ${body.tip_id}`,
      "platform_already_linked",
    );
  }

  // Mempool guard — block while another LINK_PLATFORM for the same
  // (tip_id, platform) is pending commit, otherwise the user gets two
  // committed txs that race on _applyDerivedState's upsert.
  if (typeof dag.getMempoolTxsByTipId === "function") {
    const pending = dag.getMempoolTxsByTipId(body.tip_id)
      .filter((t) => t.tx_type === TX_TYPE && t.data?.platform === body.platform);
    if (pending.length > 0) {
      throw schemaError(
        409,
        `Platform "${body.platform}" already linked for ${body.tip_id}`,
        "platform_already_linked",
      );
    }
  }

  // User's claim_signature — proves the subject TIP-ID attested to the
  // link before the node was asked to verify it.
  const claimPayload = registerSocialSchema.buildSigningPayload({
    tip_id: body.tip_id,
    platform: body.platform,
    profile_url: body.profile_url,
    claimed_at: body.claimed_at,
  });
  if (!registerSocialSchema.verifySignature(claimPayload, body.claim_signature, identity.public_key)) {
    throw schemaError(403, "User claim signature verification failed", "claim_signature_invalid");
  }

  // VP OAuth proof — alternative to bio-check for platforms that block
  // static scraping. Verified here so the service can skip the bio call.
  if (body.vp_oauth_signature && body.vp_id) {
    if (!isValidMs(body.vp_oauth_verified_at)) {
      throw schemaError(400, "vp_oauth_verified_at must be a valid epoch ms timestamp", "vp_oauth_verified_at_invalid");
    }
    const vp = registerIdentitySchema.resolveVP(body.vp_id, dag);
    const oauthProof = {
      claimed_at: body.claimed_at,
      handle: body.vp_oauth_handle ?? null,
      platform: body.platform,
      profile_url: body.profile_url,
      tip_id: body.tip_id,
      verified_at: body.vp_oauth_verified_at,
      vp_id: body.vp_id,
    };
    if (!verifyPayload(oauthProof, body.vp_oauth_signature, vp.public_key)) {
      throw schemaError(403, "VP OAuth signature verification failed", "vp_oauth_signature_invalid");
    }
  }
}

/**
 * Build the canonical signed payload for a LINK_PLATFORM tx. The 8 core
 * fields are always present; when the OAuth path was used, three more
 * fields (vp_id, vp_oauth_signature, vp_oauth_verified_at) are appended
 * so the node's body signature covers them and replay verification can
 * re-check the VP attestation. vp_oauth_handle is intentionally NOT in
 * the payload — tx.data.handle is the canonical handle for the OAuth
 * path too, asserted by an explicit invariant test.
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

  const payload = {
    claim_signature: input.claim_signature,
    claimed_at: input.claimed_at,
    handle: input.handle ?? null,
    node_id: input.node_id,
    platform: input.platform,
    profile_url: input.profile_url,
    tip_id: input.tip_id,
    verified_at: input.verified_at,
  };

  // OAuth bundle — included only when the link went through a VP OAuth
  // flow. All three fields move together; presence of any one without
  // the others would make the OAuth signature unverifiable at replay.
  const oauthPresent = input.vp_id || input.vp_oauth_signature || input.vp_oauth_verified_at;
  if (oauthPresent) {
    if (typeof input.vp_id !== "string" || input.vp_id.length === 0) {
      throw schemaError(400, "vp_id is required when OAuth proof is provided", "vp_id_required");
    }
    if (typeof input.vp_oauth_signature !== "string" || input.vp_oauth_signature.length === 0) {
      throw schemaError(400, "vp_oauth_signature is required when OAuth proof is provided", "vp_oauth_signature_required");
    }
    if (!isValidMs(input.vp_oauth_verified_at)) {
      throw schemaError(400, "vp_oauth_verified_at must be a valid epoch ms timestamp", "vp_oauth_verified_at_invalid");
    }
    payload.vp_id = input.vp_id;
    payload.vp_oauth_signature = input.vp_oauth_signature;
    payload.vp_oauth_verified_at = input.vp_oauth_verified_at;
  }

  return payload;
}

function sign(payload, nodePrivateKeyHex, opts) {
  return signPayload(payload, nodePrivateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * State-level verification at consensus replay. The node's attestation is
 * verified by the unified dispatcher (tx.signature). This function enforces
 * the state-machine invariants the dispatcher doesn't know about:
 *
 *   1. Emitting node is registered + active
 *   2. Claimant TIP-ID is registered, not revoked
 *   3. No existing active link for (tip_id, platform) — first-wins gate
 *      against gossip-bypass and racing nodes
 *   4. User's claim_signature (attestation by the subject) verifies over
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

  // First-wins guard. Relink after an UNLINK is allowed (existing row's
  // status flips to "unlinked"); a second LINK_PLATFORM while a link is
  // still active is rejected so racing nodes / gossip-bypass txs can't
  // overwrite the canonical row.
  if (typeof dag.getPlatformLink === "function") {
    const existing = dag.getPlatformLink(d.tip_id, d.platform);
    if (existing && existing.status === "active") {
      return {
        ok: false, status: 409,
        error: `Platform "${d.platform}" already linked for ${d.tip_id}`,
        code: "platform_already_linked",
      };
    }
  }

  // The original user-signed claim is bound into the LINK_PLATFORM tx so
  // replay-time verification re-establishes the full trust chain (user
  // → node) without needing the off-chain register call to still exist.
  let claimPayload;
  try {
    claimPayload = registerSocialSchema.buildSigningPayload({
      claimed_at: d.claimed_at,
      platform: d.platform,
      profile_url: d.profile_url,
      tip_id: d.tip_id,
    });
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }

  if (!registerSocialSchema.verifySignature(claimPayload, d.claim_signature, identity.public_key)) {
    return { ok: false, status: 403, error: "User claim signature verification failed", code: "claim_signature_invalid" };
  }

  // VP OAuth proof — for platforms that can't be bio-scraped, the VP's
  // off-chain OAuth attestation is the only proof of ownership. Replay
  // re-verifies the VP signature against the VP's on-chain public key
  // so a malicious node can't gossip a LINK_PLATFORM for an OAuth-only
  // platform without a real VP attestation.
  const platformKey = (d.platform || "").toLowerCase();
  const oauthRequired = OAUTH_REQUIRED_PLATFORMS.has(platformKey);
  const oauthPresent = d.vp_id && d.vp_oauth_signature && d.vp_oauth_verified_at;

  if (oauthRequired && !oauthPresent) {
    return {
      ok: false, status: 403,
      error: `Platform "${d.platform}" requires VP OAuth verification`,
      code: "oauth_required",
    };
  }

  if (oauthPresent) {
    let vp;
    try {
      vp = registerIdentitySchema.resolveVP(d.vp_id, dag);
    } catch (err) {
      if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
      throw err;
    }
    // tx.data.handle IS the OAuth-attested handle (enforced by the
    // service-layer invariant `handle = vpOauthHandle ?? null` on the
    // OAuth path, asserted by test). Reusing it here avoids an extra
    // tx.data field while keeping the OAuth signature reproducible.
    const oauthProof = {
      claimed_at: d.claimed_at,
      handle: d.handle ?? null,
      platform: d.platform,
      profile_url: d.profile_url,
      tip_id: d.tip_id,
      verified_at: d.vp_oauth_verified_at,
      vp_id: d.vp_id,
    };
    if (!verifyPayload(oauthProof, d.vp_oauth_signature, vp.public_key)) {
      return {
        ok: false, status: 403,
        error: "VP OAuth signature verification failed",
        code: "vp_oauth_signature_invalid",
      };
    }
  }

  return { ok: true };
}

module.exports = {
  TX_TYPE,
  PLATFORM_MAX_LENGTH,
  validateRequest,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
  canonicalJson,
  // Unified signature contract.
  SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
  SIGNED_BY: SIGNED_BY_KIND.NODE,
};
