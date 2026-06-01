/**
 * @file @tip-protocol/node/src/schemas/unlink-platform.js
 * @description Canonical schema for `UNLINK_PLATFORM` — user-initiated
 * revocation of a previously-linked social account.
 *
 * Trust model: SUBJECT-signed. There is no external verifier here (no
 * bio fetch, no OAuth, no DNS) — the user is revoking their own row.
 * Same shape as UPDATE_PROFILE: the user signs the canonical body
 * directly, no node attestation, no VP, no cosignatures.
 *
 * Replay protection — two layers:
 *   1. link_tx_id binds the signature to a specific LINK_PLATFORM tx.
 *      If the user re-links after unlinking, the new active link has a
 *      different tx_id; the old signature won't match → reject. Closes
 *      the toggle-within-window replay (unlink→relink→replay-old-unlink).
 *   2. claimed_at + CLAIM_MAX_AGE_MS freshness window. Leaked sigs
 *      older than the window are rejected even against the same
 *      still-active link.
 *
 * Signed canonical payload (4 fields, alphabetical):
 *   claimed_at   number  epoch ms — freshness window enforcer
 *   link_tx_id   string  tx_id of the LINK_PLATFORM being revoked
 *   platform     string  platform name (sanity / display)
 *   tip_id       string  tip://id/... owner of the link being revoked
 *
 * Signature scope: BODY. tx.timestamp on the envelope is the API-receipt
 * time and is what populates platform_links.unlinked_at on apply.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError, canonicalJson } = require("./_common");
const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS,
  PLATFORM_MAX_LENGTH, CLAIM_MAX_AGE_MS,
} = require("../../../shared/constants");
const { isValidMs, nowMs } = require("../../../shared/time");

const TX_TYPE = TX_TYPES.UNLINK_PLATFORM;
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.TIP_ID;

/**
 * Request-envelope validator for POST /v1/identity/:tipId/unlink-platform.
 *
 * Body shape (snake_case):
 *   tip_id, platform, link_tx_id, claimed_at, signature   required
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
  if (!body.tip_id || !body.platform || !body.link_tx_id || !body.signature || !body.claimed_at) {
    throw schemaError(
      400,
      "tip_id, platform, link_tx_id, signature, claimed_at are required",
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
  if (typeof body.link_tx_id !== "string" || body.link_tx_id.length === 0) {
    throw schemaError(400, "link_tx_id is required (tx_id of the LINK_PLATFORM being revoked)", "link_tx_id_required");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
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
  if (typeof dag.isRevoked === "function" && dag.isRevoked(body.tip_id)) {
    throw schemaError(403, `TIP-ID is revoked: ${body.tip_id}`, "tip_id_revoked");
  }

  // Active link must still exist at submit time.
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
  // Instance binding — the signed link_tx_id must match the CURRENT
  // active link's tx_id. A re-link after unlinking produces a new
  // tx_id, so an old signature won't match the new instance.
  if (existingLink.tx_id !== body.link_tx_id) {
    throw schemaError(
      409,
      `link_tx_id does not match active link instance for (${body.tip_id}, ${body.platform})`,
      "stale_unlink_signature",
    );
  }

  // User signs the canonical body directly (SUBJECT-signed). Verify
  // the sig against the subject's identity pubkey.
  const canonicalPayload = buildSigningPayload(body);
  if (!verifyPayload(canonicalPayload, body.signature, identity.public_key)) {
    throw schemaError(403, "Signature verification failed", "signature_invalid");
  }
}

/**
 * Build the canonical 4-field signed payload. User signs this and the
 * resulting hex sig becomes tx.signature on the envelope.
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
  if (typeof input.link_tx_id !== "string" || input.link_tx_id.length === 0) {
    throw schemaError(400, "link_tx_id is required", "link_tx_id_required");
  }
  if (!isValidMs(input.claimed_at)) {
    throw schemaError(400, "claimed_at must be a valid epoch ms timestamp", "claimed_at_invalid");
  }
  return {
    claimed_at: input.claimed_at,
    link_tx_id: input.link_tx_id,
    platform: input.platform,
    tip_id: input.tip_id,
  };
}

function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * State-level verification at consensus replay. The user's body
 * signature is verified by the unified dispatcher (SUBJECT-signed,
 * key resolved via SUBJECT_TIP_ID_FIELD). This function enforces the
 * state-machine invariants:
 *
 *   1. Subject TIP-ID is registered, not revoked
 *   2. An active link exists for (tip_id, platform)
 *   3. Signed link_tx_id matches the active link's tx_id (instance
 *      binding — defeats replay against a re-linked instance)
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};

  if (!d.tip_id) {
    return { ok: false, status: 400, error: "tip_id missing", code: "tip_id_missing" };
  }

  const identity = dag.getIdentity(d.tip_id);
  if (!identity) {
    return { ok: false, status: 412, error: `TIP-ID not found: ${d.tip_id}`, code: "tip_id_not_found" };
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(d.tip_id)) {
    return { ok: false, status: 403, error: `TIP-ID is revoked: ${d.tip_id}`, code: "tip_id_revoked" };
  }

  if (typeof dag.getPlatformLink === "function") {
    const existing = dag.getPlatformLink(d.tip_id, d.platform);
    if (!existing || existing.status !== "active") {
      return {
        ok: false, status: 409,
        error: `No active link to unlink for (${d.tip_id}, ${d.platform})`,
        code: "platform_not_linked",
      };
    }
    if (existing.tx_id !== d.link_tx_id) {
      return {
        ok: false, status: 409,
        error: `link_tx_id does not match active link instance for (${d.tip_id}, ${d.platform})`,
        code: "stale_unlink_signature",
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
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
};
