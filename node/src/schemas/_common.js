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

const { canonicalJson, shake256, mldsaSign, mldsaVerify, canonicalTx, signTransaction, verifyTransaction } = require("../../../shared/crypto");
const { SIGNED_BY_KIND, SIGNED_BY_KIND_VALUES, SIGNATURE_SCOPE } = require("../../../shared/constants");

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

// ─── Unified-storage signature primitives (GH #51) ─────────────────────────
//
// Every tx has exactly one signature, stored at tx.signature. The schema
// module declares scope ("envelope" or "body") + the list of signed fields
// + who signed (SIGNED_BY = SIGNED_BY_KIND.{SUBJECT|NODE|VP|FOUNDING_VP},
// imported from shared/constants.js). Verification dispatches here so
// commit-handler + service code don't branch per tx_type. See
// my-notes/SIGNATURES.md for the full contract.

/**
 * Resolve the public key that should have signed tx.signature given the
 * schema's SIGNED_BY discriminator. Returns null when the relevant
 * identity isn't registered on the DAG — caller treats null as a
 * verification failure (don't throw here so the verifier can return a
 * clean boolean).
 */
function resolveSignerPubKey(tx, schema, dag) {
  if (!schema) return null;
  const kind = schema.SIGNED_BY;
  if (!SIGNED_BY_KIND_VALUES.has(kind)) return null;

  if (kind === SIGNED_BY_KIND.NODE) {
    const nodeId = tx?.data?.node_id;
    if (!nodeId) return null;
    const node = dag.getNode?.(nodeId);
    return node?.public_key || null;
  }
  if (kind === SIGNED_BY_KIND.VP || kind === SIGNED_BY_KIND.FOUNDING_VP) {
    const vpId = tx?.data?.vp_id || tx?.data?.founding_vp_id;
    if (!vpId) return null;
    const vp = dag.getVerificationProvider?.(vpId);
    return vp?.public_key || null;
  }
  // SIGNED_BY_KIND.SUBJECT — the entity whose action this tx represents. Each schema
  // exposes `resolveSubject(tx, dag)` to look up the right identity row
  // because the subject's tip_id lives at a tx-type-specific field
  // (signer_tip_id, tip_id, reviewer_tip_id, juror_tip_id, ...). Falls
  // back to a generic tip_id lookup when the schema doesn't override.
  if (typeof schema.resolveSubject === "function") {
    const subj = schema.resolveSubject(tx, dag);
    return subj?.public_key || null;
  }
  const tipId = tx?.data?.tip_id;
  if (!tipId) return null;
  const id = dag.getIdentity?.(tipId);
  return id?.public_key || null;
}

/**
 * Canonical signing payload for a "body"-scope tx. Picks the fields
 * declared by the schema (reject-on-extra), canonicalises, and hashes
 * with SHAKE-256. The signer signs the hex digest's ASCII bytes — same
 * primitive as `signPayload` above but specialised for body-scope.
 */
function bodyMessageHex(tx, schema) {
  const fields = schema?.SIGNATURE_FIELDS;
  if (!Array.isArray(fields) || fields.length === 0) {
    throw schemaError(500, `schema for ${tx?.tx_type} declares SCOPE=body but no SIGNATURE_FIELDS`, "schema_invalid");
  }
  return payloadHashHex(pickFields(tx.data || {}, fields));
}

/**
 * Uniform signature dispatch. Replaces per-schema `verifyTx` logic for
 * the signature-check step (schemas still own statefulness, registration
 * lookups, dedup rules; this helper covers only the actual cryptographic
 * verification).
 *
 * Returns { ok: true } on success, or
 *         { ok: false, error: string, code: string }
 *
 * @param {Object} tx     Full tx including tx.signature
 * @param {Object} schema The schema module (must export SIGNATURE_SCOPE,
 *                        SIGNATURE_FIELDS?, SIGNED_BY)
 * @param {Object} dag    DAG facade for identity / node / vp lookups
 */
function verifyTxSignature(tx, schema, dag) {
  if (!tx || typeof tx !== "object") {
    return { ok: false, error: "tx is required", code: "tx_missing" };
  }
  if (typeof tx.signature !== "string" || tx.signature.length === 0) {
    return { ok: false, error: "tx.signature is required", code: "signature_missing" };
  }
  if (!schema || !schema.SIGNATURE_SCOPE) {
    return { ok: false, error: "schema missing SIGNATURE_SCOPE", code: "schema_invalid" };
  }
  const pubKey = resolveSignerPubKey(tx, schema, dag);
  if (!pubKey) {
    return { ok: false, error: "signer not registered or not resolvable", code: "signer_unknown" };
  }
  let ok = false;
  if (schema.SIGNATURE_SCOPE === SIGNATURE_SCOPE.ENVELOPE) {
    // Outer signature: covers the canonical tx envelope (tx_type + data +
    // timestamp + prev). tx.signature is NOT part of canonicalTx so the
    // signature doesn't sign itself — same as today.
    ok = verifyTransaction(tx, pubKey);
  } else if (schema.SIGNATURE_SCOPE === SIGNATURE_SCOPE.BODY) {
    ok = mldsaVerify(bodyMessageHex(tx, schema), tx.signature, pubKey);
  } else {
    return { ok: false, error: `unknown SIGNATURE_SCOPE ${schema.SIGNATURE_SCOPE}`, code: "schema_invalid" };
  }
  if (!ok) {
    return { ok: false, error: "signature verification failed", code: "signature_invalid" };
  }
  return { ok: true };
}

/**
 * Sign a tx whose schema declares SCOPE=envelope. Sets tx.signature to
 * the ML-DSA-65 signature over canonicalTx(tx). Returns the tx (mutated)
 * for fluent chaining. tx.tx_id must already be set by the caller (use
 * `withTxId` from services/helpers.js).
 */
function signTxEnvelope(tx, privateKeyHex, opts = {}) {
  return signTransaction(tx, privateKeyHex, opts);  // signTransaction writes tx.signature
}

/**
 * Sign a tx whose schema declares SCOPE=body. Sets tx.signature to the
 * ML-DSA-65 signature over the canonical-JSON SHAKE-256 hex digest of
 * the picked-fields body. Schema decides WHICH fields; this helper just
 * picks + signs.
 */
function signTxBody(tx, schema, privateKeyHex, opts = {}) {
  tx.signature = mldsaSign(bodyMessageHex(tx, schema), privateKeyHex, opts);
  return tx;
}

module.exports = {
  payloadHashHex,
  signPayload,
  verifyPayload,
  pickFields,
  schemaError,
  // Re-exports so schema modules don't need to also import shared/crypto.
  canonicalJson,
  canonicalTx,
  // GH #51 — unified-storage signature helpers (constants in shared/constants.js)
  resolveSignerPubKey,
  bodyMessageHex,
  verifyTxSignature,
  signTxEnvelope,
  signTxBody,
};
