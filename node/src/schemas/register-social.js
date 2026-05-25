/**
 * @file @tip-protocol/node/src/schemas/register-social.js
 * @description User-side claim schema for social account registration.
 * A user signs a 4-field payload to prove they control their TIP-ID before
 * the node fetches their social profile to verify bio ownership.
 *
 * Signed canonical payload (4 fields, alphabetical):
 *   claimed_at    number,  required (epoch ms)
 *   platform      string,  required (e.g. "twitter", "github")
 *   profile_url   string,  required (https:// URL)
 *   tip_id        string,  required (tip://id/... owner identity)
 *
 * Signer: the user (subject) signs the payload using their ML-DSA-65 key,
 * proving they own the TIP-ID and intend to claim the social account.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError } = require("./_common");
const { isValidMs } = require("../../../shared/time");

const PLATFORM_MAX_LENGTH = 50;
const PROFILE_URL_MAX_LENGTH = 2048;

function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (typeof input.tip_id !== "string" || !input.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required (tip://id/...)", "tip_id_required");
  }
  if (typeof input.platform !== "string" || input.platform.length === 0) {
    throw schemaError(400, "platform is required (non-empty string)", "platform_required");
  }
  if (input.platform.length > PLATFORM_MAX_LENGTH) {
    throw schemaError(400, `platform must be <= ${PLATFORM_MAX_LENGTH} chars`, "platform_too_long");
  }
  if (typeof input.profile_url !== "string" || !input.profile_url.startsWith("https://")) {
    throw schemaError(400, "profile_url is required (https:// URL)", "profile_url_required");
  }
  if (input.profile_url.length > PROFILE_URL_MAX_LENGTH) {
    throw schemaError(400, `profile_url must be <= ${PROFILE_URL_MAX_LENGTH} chars`, "profile_url_too_long");
  }
  if (!isValidMs(input.claimed_at)) {
    throw schemaError(400, "claimed_at must be a valid epoch ms timestamp", "claimed_at_invalid");
  }
  return {
    claimed_at: input.claimed_at,
    platform: input.platform,
    profile_url: input.profile_url,
    tip_id: input.tip_id,
  };
}

function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

module.exports = {
  PLATFORM_MAX_LENGTH,
  buildSigningPayload,
  sign,
  verifySignature,
};
