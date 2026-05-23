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

const { canonicalJson, shake256, mldsaSign, mldsaVerify, canonicalTx, signTransaction, verifyWithAlgorithm, signWithAlgorithm } = require("../../../shared/crypto");
const { SIGNED_BY_KIND, SIGNED_BY_KIND_VALUES, SIGNATURE_SCOPE, SIGNATURE_ALGORITHM_DEFAULT } = require("../../../shared/constants");

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
// Every tx has exactly one signature, stored at `tx.signature`. The
// contract for each tx_type lives in ONE of two places:
//
//   1. A schema module at `schemas/<tx-type>.js` for tx types with
//      non-trivial logic (validateRequest, resolveSubject, state-machine
//      gates). 11 schemas today: register-identity, update-profile,
//      register-domain, content-register, bind-domain, prescan-review-*.
//
//   2. The registry at `schemas/_registry.js` for tx types without a
//      full schema module. Mostly node-emitted envelopes plus
//      body-signed tx types whose buildSigningPayload is a thin
//      field-pick (SCORE_UPDATE, JURY_*, REVOKE_*, etc).
//
// Either source exports the same shape:
//
//     SIGNATURE_SCOPE      : SIGNATURE_SCOPE.ENVELOPE | SIGNATURE_SCOPE.BODY
//     SIGNED_BY            : SIGNED_BY_KIND.{SUBJECT,NODE,VP}
//     SUBJECT_TIP_ID_FIELD : TIP_ID_FIELDS.*  (only when SIGNED_BY=SUBJECT)
//     VP_ID_FIELD          : VP_ID_FIELDS.*   (only when SIGNED_BY=VP; default vp_id)
//     buildSigningPayload  : (data) -> canonical payload  (only when SCOPE=BODY)
//     getSignatureContract : (tx)   -> contract           (multi-mode tx types)
//
// `verifyTxSignature(tx, schema, dag)` is the entry point:
// `resolveSignatureContract` picks the contract; `resolveSignerRecord`
// looks up the public key + algorithm per `SIGNED_BY`;
// `verifyWithAlgorithm` dispatches to the right algorithm verifier
// (one branch today, ML-DSA-65, extensible to ML-DSA-87 / SLH-DSA /
// hybrid without per-signature overhead).
//
// See my-notes/SIGNATURES.md for the full contract.

/**
 * Resolve the signer's record (public_key + algorithm) for a tx.
 * `algorithm` defaults to SIGNATURE_ALGORITHM_DEFAULT (ML-DSA-65) for
 * any row that pre-dates the crypto-agility column. Returns null if
 * the contract can't be resolved or the relevant identity / node / VP
 * isn't registered on the DAG (caller treats null as a verification
 * failure; never throws so the verifier can return a clean boolean).
 */
/**
 * Resolve the per-tx signature contract. Source priority:
 *   1. `schema.getSignatureContract(tx)` for multi-mode tx types
 *      (prescan-review-recused, CONTENT_DISPUTED, APPEAL_FILED).
 *   2. Schema's static SIGNATURE_SCOPE + SIGNED_BY exports.
 *   3. TX_SIGNATURE_REGISTRY entry for tx types without a schema.
 * Returns null if no source produces a contract (caller treats as
 * verification failure).
 */
function resolveSignatureContract(tx, schema) {
  // Schema modules win: full per-tx-type logic lives there.
  if (schema) {
    if (typeof schema.getSignatureContract === "function") {
      return schema.getSignatureContract(tx) || null;
    }
    if (schema.SIGNATURE_SCOPE && schema.SIGNED_BY) {
      return {
        SIGNATURE_SCOPE: schema.SIGNATURE_SCOPE,
        SIGNED_BY: schema.SIGNED_BY,
        SUBJECT_TIP_ID_FIELD: schema.SUBJECT_TIP_ID_FIELD,
        VP_ID_FIELD: schema.VP_ID_FIELD,
        buildSigningPayload: schema.buildSigningPayload,
      };
    }
  }
  // Registry fallback for tx_types without a schema module.
  const { TX_SIGNATURE_REGISTRY } = require("./_registry");
  const entry = TX_SIGNATURE_REGISTRY[tx?.tx_type];
  if (!entry) return null;
  if (typeof entry.getSignatureContract === "function") {
    return entry.getSignatureContract(tx) || null;
  }
  if (!entry.SIGNATURE_SCOPE || !entry.SIGNED_BY) return null;
  return entry;
}

function resolveSignerRecord(tx, schema, dag) {
  const contract = resolveSignatureContract(tx, schema);
  if (!contract) return null;
  const kind = contract.SIGNED_BY;
  if (!SIGNED_BY_KIND_VALUES.has(kind)) return null;

  // GH #60: pick the entity_type discriminator + entity_id field. We
  // resolve the signer's key via dag.getKeyValidAt(entity_type,
  // entity_id, tx.timestamp) so historical signatures verify against
  // the key that was active at sign time (NOT today's active key
  // post-rotation). Pre-rotation identities have exactly one row in
  // entity_keys so the result is identical to the active-key lookup.
  let entityType;
  let entityId;
  if (kind === SIGNED_BY_KIND.NODE) {
    entityType = "node";
    entityId = tx?.data?.node_id;
  } else if (kind === SIGNED_BY_KIND.VP) {
    // VP-signed. Contract may declare a non-default VP_ID_FIELD
    // (REVOKE_* uses "issuing_vp_id"; VP_REGISTERED / NODE_REGISTERED
    // use "approving_vp_id"). Default "vp_id" covers REGISTER_IDENTITY
    // and any future VP-attestation tx that follows the canonical name.
    entityType = "vp";
    entityId = tx?.data?.[contract.VP_ID_FIELD || "vp_id"];
  } else {
    // SIGNED_BY_KIND.SUBJECT — the entity whose action this tx represents.
    // Contract declares WHICH field on tx.data carries the subject's
    // tip_id via `SUBJECT_TIP_ID_FIELD` (defaults to "tip_id").
    entityType = "identity";
    entityId = tx?.data?.[contract.SUBJECT_TIP_ID_FIELD || "tip_id"];
  }
  if (!entityId) return null;

  // Time-anchored lookup. Use tx.timestamp so a tx signed before a
  // rotation verifies against the OLD key (which is the row whose
  // [valid_from_ts, valid_to_ts) range contains tx.timestamp).
  // Fallback to active-key lookup if timestamp is missing (defensive
  // for API-time callers that haven't yet built a full tx envelope).
  const timestamp = Number(tx?.timestamp);
  const key = (typeof dag.getKeyValidAt === "function" && Number.isFinite(timestamp) && timestamp > 0)
    ? dag.getKeyValidAt(entityType, entityId, timestamp)
    : (typeof dag.getActiveKey === "function" ? dag.getActiveKey(entityType, entityId) : null);
  if (!key || typeof key.public_key !== "string") return null;
  return {
    public_key: key.public_key,
    algorithm: key.algorithm || SIGNATURE_ALGORITHM_DEFAULT,
  };
}

/**
 * Back-compat alias — older code may call `resolveSignerPubKey`; new
 * code should use `resolveSignerRecord` so the algorithm is available
 * for dispatch.
 */
function resolveSignerPubKey(tx, schema, dag) {
  return resolveSignerRecord(tx, schema, dag)?.public_key || null;
}

/**
 * Canonical signing-message hex for a "body"-scope tx. Delegates to the
 * schema's own `buildSigningPayload(data)` — the single source of truth
 * for which fields the signature covers. The verifier just hashes what
 * the signer hashed; no duplicate field-list to keep in sync.
 */
function bodyMessageHex(tx, contractOrSchema) {
  // Accept either a resolved contract (with buildSigningPayload baked in)
  // or a schema module (where buildSigningPayload lives at the top level).
  const build = contractOrSchema?.buildSigningPayload;
  if (typeof build !== "function") {
    throw schemaError(500, `contract for ${tx?.tx_type} declares SCOPE=body but exports no buildSigningPayload`, "schema_invalid");
  }
  return payloadHashHex(build(tx.data || {}));
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
  const contract = resolveSignatureContract(tx, schema);
  if (!contract) {
    return { ok: false, error: "schema missing signature contract (SIGNATURE_SCOPE/SIGNED_BY or getSignatureContract)", code: "schema_invalid" };
  }
  const signer = resolveSignerRecord(tx, schema, dag);
  if (!signer) {
    return { ok: false, error: "signer not registered or not resolvable", code: "signer_unknown" };
  }
  // Compute the message bytes this scope signs over, then dispatch via
  // the algorithm declared on the signer's record (today always
  // ML-DSA-65). The algorithm is bound to the key — not the signature —
  // for crypto agility without per-sig overhead. See GH #51.
  let message;
  if (contract.SIGNATURE_SCOPE === SIGNATURE_SCOPE.ENVELOPE) {
    // Outer signature: covers the canonical tx envelope. tx.signature is
    // NOT part of canonicalTx (signTransaction's contract), so the
    // signature doesn't sign itself. mldsaSign treats the input as raw
    // UTF-8 bytes — matches signTransaction's exact wire format.
    message = canonicalTx(tx);
  } else if (contract.SIGNATURE_SCOPE === SIGNATURE_SCOPE.BODY) {
    message = bodyMessageHex(tx, contract);
  } else {
    return { ok: false, error: `unknown SIGNATURE_SCOPE ${contract.SIGNATURE_SCOPE}`, code: "schema_invalid" };
  }
  let ok;
  try {
    ok = verifyWithAlgorithm(message, tx.signature, signer.public_key, signer.algorithm);
  } catch (e) {
    return { ok: false, error: `algorithm dispatch failed: ${e.message}`, code: "algorithm_unsupported" };
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
  resolveSignatureContract,
  resolveSignerRecord,
  resolveSignerPubKey,
  bodyMessageHex,
  verifyTxSignature,
  signTxEnvelope,
  signTxBody,
};
