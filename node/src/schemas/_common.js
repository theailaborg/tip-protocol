/**
 * @file @tip-protocol/node/src/schemas/_common.js
 * @description Shared helpers used by every per-tx_type schema module.
 *
 * Contract these helpers enforce:
 *   - canonical-JSON encoding rules from docs/CONTENT_SIGNING.md §3
 *     (sorted keys, no whitespace, slashes unescaped, UTF-8 passthrough,
 *     `{}` for empty objects, `[]` for empty arrays)
 *   - signing model: ML-DSA-65 over the ASCII bytes of the
 *     SHAKE-256(canonical_json(payload), 32) hex digest — NOT the raw
 *     32 hash bytes
 *   - reject-on-extra: schemas pick the exact fields they want; this
 *     module provides the helper that enforces the picked-fields
 *     discipline
 *
 * The actual canonicalJson + mldsaSign primitives live in
 * shared/crypto.js — those are byte-identical with what every TIP
 * client (browser extension, WordPress plugin, mobile app) implements.
 * This module is the protocol-side façade that schemas import.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { canonicalJson, shake256, mldsaSign, mldsaVerify } = require("../../../shared/crypto");

/**
 * Hash the canonical JSON of `payload`. Returns a 64-char lowercase
 * hex string (the message ML-DSA signs as ASCII bytes).
 */
function payloadHashHex(payload) {
  return shake256(canonicalJson(payload));   // shake256() returns hex
}

/**
 * Sign a canonical payload with ML-DSA-65. The signing message is the
 * ASCII bytes of the hex digest — i.e. mldsaSign treats the hex string
 * as a Buffer.from(string), which is UTF-8 (= ASCII for hex chars).
 *
 * Same primitive as `signBody` in shared/crypto.js — pulled out here
 * so the schema modules can import a single sign() helper without
 * also reaching into shared/crypto.
 */
function signPayload(payload, privateKeyHex, opts = {}) {
  return mldsaSign(payloadHashHex(payload), privateKeyHex, opts);
}

/**
 * Verify a signature against a canonical payload + public key.
 * Returns boolean; never throws (mldsaVerify swallows decode errors).
 */
function verifyPayload(payload, signatureHex, publicKeyHex) {
  if (!signatureHex || !publicKeyHex) return false;
  return mldsaVerify(payloadHashHex(payload), signatureHex, publicKeyHex);
}

/**
 * Pick the named fields from `input` and ignore everything else.
 * Used by schema modules to enforce reject-on-extra at canonicalisation
 * time — anything the client puts at the top level that isn't on the
 * picked list is silently stripped before hashing.
 *
 * Reject-on-extra is the right default for canonical signing payloads:
 * if a future client sends a field we don't recognise, our verifier
 * shouldn't fold it into the hash (we'd never agree on what value to
 * expect). The signed bytes commit only to the fields this module owns.
 */
function pickFields(input, fieldNames) {
  const out = {};
  for (const f of fieldNames) {
    if (input != null && Object.prototype.hasOwnProperty.call(input, f)) {
      out[f] = input[f];
    }
  }
  return out;
}

/**
 * Standard error shape thrown by buildSigningPayload / verifyTx when the
 * input fails schema validation. Caller (service or commit-handler)
 * surfaces { status, error } at the API or rejects the tx.
 */
function schemaError(status, message, code) {
  const e = { status, error: message };
  if (code) e.code = code;
  return e;
}

module.exports = {
  payloadHashHex,
  signPayload,
  verifyPayload,
  pickFields,
  schemaError,
  // Re-exports so schema modules don't need to also import shared/crypto.
  canonicalJson,
};
