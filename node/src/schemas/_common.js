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

// Cosignatures normalisation — see SIGNATURES.md "Cosignatures" section.
// Maps cosignature kind discriminator to entity_type used by
// dag.getKeyValidAt / dag.getActiveKey. The "pubkey" / future-self case
// (KEY_RECOVERY's new_key_signature) is intentionally NOT here — it's a
// proof-of-possession on the same identity's own future key, kept as a
// named field on its tx_type.
const COSIGNER_ENTITY_TYPE = Object.freeze({
  [SIGNED_BY_KIND.SUBJECT]: "identity",
  [SIGNED_BY_KIND.NODE]:    "node",
  [SIGNED_BY_KIND.VP]:      "vp",
});

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

// ─── Cosignatures (additional signers beyond tx.signature) ─────────────────
//
// Some tx_types carry signatures from a SECOND registered entity beyond
// the primary signer — e.g. a node-emitted BIND_DOMAIN carrying the
// user's prior REGISTER_DOMAIN attestation, an auto-escalated
// CONTENT_DISPUTED carrying the creator's escalation, a
// COMMITTEE_ROTATION carrying N previous-committee node signatures.
//
// Canonical shape, on every such tx:
//   tx.data.cosignatures = [
//     { signer_kind, signer_ref, signature },
//     ...
//   ]
//
// `signer_kind` is one of SIGNED_BY_KIND.{SUBJECT, NODE, VP}; key
// resolution is time-anchored at tx.timestamp exactly like the primary
// dispatcher. Builders MUST sort the array by (signer_kind, signer_ref)
// ASC before envelope-signing so canonicalTx(tx) bytes are deterministic.
//
// Schemas declare what each cosignature signs by passing a contract
// list to `verifyCosignatures(tx, contracts, dag)` from inside their
// own verifyTx. Each contract entry is:
//   { kind, ref, body }
// where `body` is the raw object the cosigner hashed (canonical-JSON +
// SHAKE-256). For cross-tx-type cosigs (BIND_DOMAIN's claim_signature
// signs the REGISTER_DOMAIN body, not the BIND_DOMAIN body), the
// schema constructs the correct body itself — the helper just verifies
// what the schema declares.

/**
 * Sort cosignatures into canonical wire order: (signer_kind, signer_ref)
 * ASC. Required before envelope-signing so canonicalTx bytes are
 * deterministic; safe to call on already-sorted arrays.
 */
function sortCosignatures(arr) {
  if (!Array.isArray(arr)) return [];
  return [...arr].sort((a, b) => {
    const ak = String(a?.signer_kind ?? "");
    const bk = String(b?.signer_kind ?? "");
    if (ak !== bk) return ak < bk ? -1 : 1;
    const ar = String(a?.signer_ref ?? "");
    const br = String(b?.signer_ref ?? "");
    if (ar !== br) return ar < br ? -1 : 1;
    return 0;
  });
}

/**
 * Build one cosignature entry: sign `body` with `privateKeyHex` and
 * label it with the signer's (kind, ref). Convenience for builders /
 * UATs / test fixtures; verification side has no equivalent (verifiers
 * read tx.data.cosignatures and compare against a schema-declared
 * contract list).
 */
function signCosignature(body, privateKeyHex, signerKind, signerRef, opts = {}) {
  return {
    signer_kind: signerKind,
    signer_ref:  signerRef,
    signature:   signPayload(body, privateKeyHex, opts),
  };
}

/**
 * Verify all cosignatures declared by a schema's contract list. Each
 * contract entry `{kind, ref, body}` is matched to a tx.data.cosignatures
 * entry by (signer_kind, signer_ref); the matched entry's signature is
 * verified against the body the schema declares the cosigner signed.
 *
 * Key resolution mirrors the primary dispatcher: time-anchored at
 * tx.timestamp via dag.getKeyValidAt(entityType, ref, timestamp), with
 * dag.getActiveKey as a defensive fallback when timestamp is missing.
 *
 * Returns { ok: true } on success, or { ok: false, error, code } on the
 * first failure. Empty contract list is a no-op (returns ok).
 */
function verifyCosignatures(tx, contracts, dag) {
  if (!Array.isArray(contracts) || contracts.length === 0) {
    return { ok: true };
  }
  const cosigs = tx?.data?.cosignatures;
  if (!Array.isArray(cosigs)) {
    return { ok: false, error: "tx.data.cosignatures missing or not an array", code: "cosignatures_missing" };
  }
  if (cosigs.length !== contracts.length) {
    return {
      ok: false,
      error: `expected ${contracts.length} cosignatures, got ${cosigs.length}`,
      code: "cosignatures_length_mismatch",
    };
  }
  const timestamp = Number(tx?.timestamp);
  for (const c of contracts) {
    const entityType = COSIGNER_ENTITY_TYPE[c.kind];
    if (!entityType) {
      return { ok: false, error: `unknown signer_kind: ${c.kind}`, code: "cosignature_kind_invalid" };
    }
    const entry = cosigs.find(e => e?.signer_kind === c.kind && e?.signer_ref === c.ref);
    if (!entry) {
      return { ok: false, error: `cosignature missing for ${c.kind}:${c.ref}`, code: "cosignature_missing" };
    }
    if (typeof entry.signature !== "string" || entry.signature.length === 0) {
      return { ok: false, error: `cosignature signature empty for ${c.kind}:${c.ref}`, code: "cosignature_invalid" };
    }
    // Time-anchored key lookup (same contract as the primary dispatcher
    // — a cosig signed before a rotation verifies against the OLD key).
    const key = (typeof dag.getKeyValidAt === "function" && Number.isFinite(timestamp) && timestamp > 0)
      ? dag.getKeyValidAt(entityType, c.ref, timestamp)
      : (typeof dag.getActiveKey === "function" ? dag.getActiveKey(entityType, c.ref) : null);
    if (!key || typeof key.public_key !== "string") {
      return { ok: false, error: `cosigner not resolvable: ${c.kind}:${c.ref}`, code: "cosigner_unknown" };
    }
    const algorithm = key.algorithm || SIGNATURE_ALGORITHM_DEFAULT;
    const message = payloadHashHex(c.body);
    let ok;
    try {
      ok = verifyWithAlgorithm(message, entry.signature, key.public_key, algorithm);
    } catch (e) {
      return { ok: false, error: `cosignature algorithm dispatch failed: ${e.message}`, code: "algorithm_unsupported" };
    }
    if (!ok) {
      return { ok: false, error: `cosignature verification failed for ${c.kind}:${c.ref}`, code: "cosignature_invalid" };
    }
  }
  return { ok: true };
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
  // Cosignatures
  sortCosignatures,
  signCosignature,
  verifyCosignatures,
};
