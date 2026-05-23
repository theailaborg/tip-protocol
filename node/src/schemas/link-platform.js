/**
 * @file @tip-protocol/node/src/schemas/link-platform.js
 * @description Canonical schema for `LINK_PLATFORM` — VP-attested social
 * account linking. Each linked account earns +5 trust score (max 6 accounts,
 * +30 cap). The bonus arrives as a paired SCORE_UPDATE tx emitted by
 * identity-service.linkPlatform, not inline on this tx.
 *
 * Signed canonical payload (4 fields, alphabetical):
 *   handle      string,  required (platform username / handle)
 *   linked_at   number,  required (epoch ms)
 *   platform    string,  required (any non-empty string ≤ 50 chars, e.g. "youtube", "x.com")
 *   tip_id      string,  required (tip://id/... owner identity)
 *
 * Signer: the VP that attested the identity signs the payload using its
 * ML-DSA-65 key, same as REGISTER_IDENTITY. This lets the VP server submit
 * social links on behalf of the user post-registration without requiring the
 * user's device private key to be re-involved.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError } = require("./_common");
const { TX_TYPES } = require("../../../shared/constants");

const TX_TYPE = TX_TYPES.LINK_PLATFORM;

const PLATFORM_MAX_LENGTH = 50;

function resolveVP(vpId, dag) {
  const vp = dag.getVP(vpId);
  if (!vp) throw schemaError(412, `VP not registered on DAG: ${vpId}`, "vp_not_registered");
  if (vp.status !== "active") throw schemaError(403, `VP is not active (status: ${vp.status}): ${vpId}`, "vp_inactive");
  return vp;
}

function resolveSubject(tipId, dag) {
  const identity = dag.getIdentity(tipId);
  if (!identity) throw schemaError(412, "TIP-ID not registered on DAG", "tip_id_not_registered");
  if (typeof dag.isRevoked === "function" && dag.isRevoked(tipId)) {
    throw schemaError(403, "TIP-ID is revoked", "tip_id_revoked");
  }
  return identity;
}

function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (typeof body.tip_id !== "string" || !body.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required (tip://id/...)", "tip_id_required");
  }
  if (deps && deps.urlTipId !== undefined && body.tip_id !== deps.urlTipId) {
    throw schemaError(400, "URL tip_id does not match body.tip_id", "tip_id_mismatch");
  }
  if (typeof body.platform !== "string" || body.platform.trim().length === 0) {
    throw schemaError(400, "platform is required (non-empty string)", "platform_required");
  }
  if (body.platform.trim().length > PLATFORM_MAX_LENGTH) {
    throw schemaError(400, `platform must be ${PLATFORM_MAX_LENGTH} characters or fewer`, "platform_too_long");
  }
  if (typeof body.handle !== "string" || body.handle.trim().length === 0) {
    throw schemaError(400, "handle is required (non-empty string)", "handle_required");
  }
  if (typeof body.vp_id !== "string" || !body.vp_id.startsWith("tip://vp/")) {
    throw schemaError(400, "vp_id is required (tip://vp/...)", "vp_id_required");
  }
  if (typeof body.vp_signature !== "string" || body.vp_signature.length === 0) {
    throw schemaError(400, "vp_signature is required", "vp_signature_required");
  }
  resolveSubject(body.tip_id, deps.dag);
  resolveVP(body.vp_id, deps.dag);
}

function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (typeof input.tip_id !== "string" || !input.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required", "tip_id_required");
  }
  if (typeof input.platform !== "string" || input.platform.trim().length === 0) {
    throw schemaError(400, "platform is required (non-empty string)", "platform_required");
  }
  if (input.platform.trim().length > PLATFORM_MAX_LENGTH) {
    throw schemaError(400, `platform must be ${PLATFORM_MAX_LENGTH} characters or fewer`, "platform_too_long");
  }
  if (typeof input.handle !== "string" || input.handle.trim().length === 0) {
    throw schemaError(400, "handle is required", "handle_required");
  }
  if (!Number.isFinite(input.linked_at) || input.linked_at <= 0) {
    throw schemaError(400, "linked_at is required (epoch ms)", "linked_at_required");
  }
  return {
    handle:    input.handle.trim(),
    linked_at: input.linked_at,
    platform:  input.platform,
    tip_id:    input.tip_id,
  };
}

function sign(payload, vpPrivateKeyHex, opts) {
  return signPayload(payload, vpPrivateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

function verifyTx(tx, dag) {
  const d = tx.data || {};
  if (typeof d.vp_signature !== "string") {
    return { ok: false, status: 400, error: "vp_signature missing on tx", code: "vp_signature_missing" };
  }
  if (!d.vp_id) {
    return { ok: false, status: 400, error: "vp_id missing", code: "vp_id_missing" };
  }
  let vp;
  let payload;
  try {
    vp = resolveVP(d.vp_id, dag);
    resolveSubject(d.tip_id, dag);
    payload = buildSigningPayload(d);
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }
  if (!verifySignature(payload, d.vp_signature, vp.public_key)) {
    return { ok: false, status: 403, error: "VP signature verification failed", code: "signature_invalid" };
  }
  return { ok: true };
}

module.exports = {
  TX_TYPE,
  PLATFORM_MAX_LENGTH,
  validateRequest,
  resolveVP,
  resolveSubject,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
};
