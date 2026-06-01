/**
 * @file @tip-protocol/node/src/schemas/unlink-platform.js
 * @description Canonical schema for `UNLINK_PLATFORM` — user-initiated social
 * account unlinking. The user signs a 3-field claim; the node verifies and
 * attests the unlink on-chain. No score change on unlink.
 *
 * User-signed claim (3 fields, alphabetical):
 *   claimed_at  number   epoch ms
 *   platform    string   platform name
 *   tip_id      string   tip://id/... owner
 *
 * Node-signed body payload (6 fields, alphabetical):
 *   claim_signature  string   user's ML-DSA hex over the 3-field claim
 *   claimed_at       number   epoch ms
 *   node_id          string   verifying node
 *   platform         string   platform name
 *   tip_id           string   owner
 *   unlinked_at      number   epoch ms when processed
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError, canonicalJson } = require("./_common");
const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND,
  PLATFORM_MAX_LENGTH, CLAIM_MAX_AGE_MS,
} = require("../../../shared/constants");
const { isValidMs, nowMs } = require("../../../shared/time");

const TX_TYPE = TX_TYPES.UNLINK_PLATFORM;

/**
 * Request-envelope validator for POST /v1/identity/:tipId/unlink-platform.
 * Mirrors link-platform.validateRequest — owns every request-time check
 * (shape, claim age, identity exists, active link present, user
 * claim_signature verify) so the service stays thin.
 *
 * Body shape (snake_case):
 *   tip_id, platform, claim_signature, claimed_at  required
 *
 * deps: { dag, urlTipId?, now? }
 */
function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (deps && deps.urlTipId !== undefined && body.tip_id !== deps.urlTipId) {
    throw schemaError(400, "URL tip_id does not match body.tip_id", "tip_id_mismatch");
  }
  if (!body.tip_id || !body.platform || !body.claim_signature || !body.claimed_at) {
    throw schemaError(
      400,
      "tip_id, platform, claim_signature, claimed_at are required",
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
  if (typeof body.claim_signature !== "string" || body.claim_signature.length === 0) {
    throw schemaError(400, "claim_signature is required", "claim_signature_required");
  }
  if (!isValidMs(body.claimed_at)) {
    throw schemaError(400, "claimed_at must be a valid epoch ms timestamp", "claimed_at_invalid");
  }

  const now = deps && typeof deps.now === "number" ? deps.now : nowMs();
  if (now - body.claimed_at > CLAIM_MAX_AGE_MS) {
    throw schemaError(400, "Claim has expired (max 15 minutes)", "claim_expired");
  }

  if (!deps || !deps.dag) return;
  const { dag } = deps;

  const identity = dag.getIdentity(body.tip_id);
  if (!identity) {
    throw schemaError(412, `TIP-ID not found: ${body.tip_id}`, "tip_id_not_found");
  }

  const existingLink = typeof dag.getPlatformLink === "function"
    ? dag.getPlatformLink(body.tip_id, body.platform)
    : null;
  if (!existingLink || existingLink.status !== "active") {
    throw schemaError(
      409,
      `Platform "${body.platform}" is not actively linked for ${body.tip_id}`,
      "platform_not_linked",
    );
  }

  const claimPayload = buildUnlinkClaimPayload({
    claimed_at: body.claimed_at, platform: body.platform, tip_id: body.tip_id,
  });
  if (!verifyPayload(claimPayload, body.claim_signature, identity.public_key)) {
    throw schemaError(403, "User claim signature verification failed", "claim_signature_invalid");
  }
}

function buildUnlinkClaimPayload(input) {
  if (!input || typeof input !== "object") throw schemaError(400, "input must be an object", "input_invalid");
  if (typeof input.tip_id !== "string" || !input.tip_id.startsWith("tip://id/")) throw schemaError(400, "tip_id is required (tip://id/...)", "tip_id_required");
  if (typeof input.platform !== "string" || input.platform.length === 0) throw schemaError(400, "platform is required", "platform_required");
  if (input.platform.length > PLATFORM_MAX_LENGTH) throw schemaError(400, `platform must be <= ${PLATFORM_MAX_LENGTH} chars`, "platform_too_long");
  if (!isValidMs(input.claimed_at)) throw schemaError(400, "claimed_at must be a valid epoch ms timestamp", "claimed_at_invalid");
  return {
    claimed_at: input.claimed_at,
    platform: input.platform,
    tip_id: input.tip_id,
  };
}

function buildSigningPayload(input) {
  if (!input || typeof input !== "object") throw schemaError(400, "input must be an object", "input_invalid");
  if (typeof input.tip_id !== "string" || !input.tip_id.startsWith("tip://id/")) throw schemaError(400, "tip_id is required", "tip_id_required");
  if (typeof input.platform !== "string" || input.platform.length === 0) throw schemaError(400, "platform is required", "platform_required");
  if (typeof input.node_id !== "string" || input.node_id.length === 0) throw schemaError(400, "node_id is required", "node_id_required");
  if (typeof input.claim_signature !== "string" || input.claim_signature.length === 0) throw schemaError(400, "claim_signature is required", "claim_signature_required");
  if (!isValidMs(input.claimed_at)) throw schemaError(400, "claimed_at must be a valid epoch ms timestamp", "claimed_at_invalid");
  if (!isValidMs(input.unlinked_at)) throw schemaError(400, "unlinked_at must be a valid epoch ms timestamp", "unlinked_at_invalid");
  return {
    claim_signature: input.claim_signature,
    claimed_at: input.claimed_at,
    node_id: input.node_id,
    platform: input.platform,
    tip_id: input.tip_id,
    unlinked_at: input.unlinked_at,
  };
}

function sign(payload, nodePrivateKeyHex, opts) {
  return signPayload(payload, nodePrivateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

function verifyTx(tx, dag) {
  const d = tx.data || {};

  if (!d.node_id) return { ok: false, status: 400, error: "node_id missing", code: "node_id_missing" };
  const node = dag.getNode(d.node_id);
  if (!node) return { ok: false, status: 412, error: `Verifying node not registered: ${d.node_id}`, code: "node_not_registered" };
  if (node.status !== "active") return { ok: false, status: 403, error: `Verifying node not active: ${d.node_id}`, code: "node_inactive" };

  const identity = dag.getIdentity(d.tip_id);
  if (!identity) return { ok: false, status: 412, error: `TIP-ID not found: ${d.tip_id}`, code: "tip_id_not_found" };

  // Must have an active link to unlink. Catches gossip-bypass txs that
  // would otherwise flip a non-existent or already-unlinked row.
  if (typeof dag.getPlatformLink === "function") {
    const existing = dag.getPlatformLink(d.tip_id, d.platform);
    if (!existing || existing.status !== "active") {
      return {
        ok: false, status: 409,
        error: `No active link to unlink for (${d.tip_id}, ${d.platform})`,
        code: "platform_not_linked",
      };
    }
  }

  let claimPayload;
  try {
    claimPayload = buildUnlinkClaimPayload({ claimed_at: d.claimed_at, platform: d.platform, tip_id: d.tip_id });
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }

  if (!verifyPayload(claimPayload, d.claim_signature, identity.public_key)) {
    return { ok: false, status: 403, error: "User claim signature verification failed", code: "claim_signature_invalid" };
  }

  return { ok: true };
}

module.exports = {
  TX_TYPE,
  PLATFORM_MAX_LENGTH,
  validateRequest,
  buildUnlinkClaimPayload,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
  canonicalJson,
  SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
  SIGNED_BY: SIGNED_BY_KIND.NODE,
};
