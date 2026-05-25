/**
 * @file @tip-protocol/node/src/schemas/register-identity.js
 * @description Canonical schema for `REGISTER_IDENTITY` — VP-attested
 * identity registration.
 *
 * Single source of truth for the canonical-payload shape the VP signs
 * over, the validateRequest envelope gate, and the verifyTx
 * consensus-replay verifier. Both identity-service.register (API time)
 * and commit-handler (consensus replay) import this module — the field
 * list, default-fill rules, and verifier all live here.
 *
 * Quick summary of the 9 signed fields (alphabetical):
 *
 *   creator_name      string|null,  default null (VP-attested display name)
 *   dedup_hash        string,       required (Poseidon field element from ZK proof)
 *   public_key        string,       required (raw ML-DSA-65 hex, 3904 chars)
 *   region            string,       default "US", uppercased
 *   social_attested   boolean,      default false
 *   tip_id_type       string,       default "personal" (enum: personal/organization)
 *   verification_tier string,       default "T1" (T1/T2/T3/T4)
 *   vp_id             string,       required (tip://vp/...)
 *   zk_proof          object,       required (Groth16 {pi_a, pi_b, pi_c, ...})
 *
 * Every field is always present in the canonical payload — defaults
 * fill in for omitted optionals. creator_name is emitted as `null`
 * (not omitted) when the VP didn't attest a name, so the canonical
 * payload shape is deterministic regardless of whether a name is set.
 *
 * NOTE: No `cna` field on this payload. CNA is the Canonical Content
 * Normalization Algorithm — it operates on raw content bytes for
 * REGISTER_CONTENT's `content_hash`. REGISTER_IDENTITY has no content
 * to normalize, so there is no CNA version to declare here.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const {
  signPayload, verifyPayload, schemaError, canonicalJson,
} = require("./_common");
const {
  TX_TYPES, TIP_ID_TYPES, TIP_ID_TYPE_VALUES,
  SIGNATURE_SCOPE, SIGNED_BY_KIND,
  SIGNATURE_ALGORITHM_VALUES, SIGNATURE_ALGORITHM_DEFAULT,
} = require("../../../shared/constants");

const TX_TYPE = TX_TYPES.REGISTER_IDENTITY;

// GH #51 — unified signature storage contract.
// VP signs the canonical payload produced by `buildSigningPayload`
// (defined below — single source of truth for which fields are signed).
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.VP;

const VERIFICATION_TIERS = Object.freeze(["T1", "T2", "T3", "T4"]);

/**
 * Verify the VP referenced by `vp_id` exists and is active on the DAG.
 * Throws structured error on missing / inactive. Returns the VP record
 * (carries `.public_key` for signature verification).
 */
function resolveVP(vpId, dag) {
  const vp = dag.getVP(vpId);
  if (!vp) {
    throw schemaError(412, `VP not registered on DAG: ${vpId}`, "vp_not_registered");
  }
  if (vp.status !== "active") {
    throw schemaError(403, `VP is not active: ${vpId} (status: ${vp.status})`, "vp_inactive");
  }
  return vp;
}

/**
 * Request-envelope validator for POST /v1/identity/register. Runs
 * before any crypto work. Covers:
 *
 *   1. Shape — public_key, dedup_hash, zk_proof, vp_id, vp_signature
 *      presence + basic types
 *   2. tip_id_type, verification_tier enums (if present)
 *   3. DAG presence — VP MUST exist and be active
 *
 * Throws `{ status, error, code }` shaped errors. Void return — the
 * caller fetches the VP record itself via `resolveVP` once validation
 * has passed.
 */
function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (typeof body.public_key !== "string" || body.public_key.length === 0) {
    throw schemaError(400, "public_key is required (hex-encoded ML-DSA-65)", "public_key_required");
  }
  if (typeof body.dedup_hash !== "string" || body.dedup_hash.length === 0) {
    throw schemaError(400, "dedup_hash is required", "dedup_hash_required");
  }
  if (!body.zk_proof || typeof body.zk_proof !== "object" || Array.isArray(body.zk_proof)) {
    throw schemaError(400, "zk_proof is required (Groth16 proof object)", "zk_proof_required");
  }
  if (typeof body.vp_id !== "string" || !body.vp_id.startsWith("tip://vp/")) {
    throw schemaError(400, "vp_id is required (tip://vp/...)", "vp_id_required");
  }
  if (typeof body.vp_signature !== "string" || body.vp_signature.length === 0) {
    throw schemaError(400, "vp_signature is required", "vp_signature_required");
  }
  if (body.tip_id_type !== undefined && !TIP_ID_TYPE_VALUES.includes(body.tip_id_type)) {
    throw schemaError(
      400,
      `tip_id_type must be one of ${TIP_ID_TYPE_VALUES.join(", ")}`,
      "tip_id_type_invalid",
    );
  }
  if (body.verification_tier !== undefined && !VERIFICATION_TIERS.includes(body.verification_tier)) {
    throw schemaError(
      400,
      `verification_tier must be one of ${VERIFICATION_TIERS.join(", ")}`,
      "verification_tier_invalid",
    );
  }
  // creator_name shape gate — must be either absent / null, or a
  // non-empty string. Empty string + non-string types are rejected so
  // the VP can't silently produce canonical bytes that disagree with
  // the server's reconstruction (signature would fail otherwise).
  if (body.creator_name !== undefined && body.creator_name !== null) {
    if (typeof body.creator_name !== "string" || body.creator_name.length === 0) {
      throw schemaError(
        400,
        "creator_name must be a non-empty string (omit or send null when not attested)",
        "creator_name_invalid",
      );
    }
  }
  // Organizations MUST attest a display name — orgs without a public
  // name aren't useful (can't claim domains, can't credibly publish).
  if (body.tip_id_type === TIP_ID_TYPES.ORGANIZATION
    && (typeof body.creator_name !== "string" || body.creator_name.length === 0)) {
    throw schemaError(
      400,
      "creator_name is required for tip_id_type='organization'",
      "creator_name_required",
    );
  }
  // DAG presence — VP must exist and be active.
  resolveVP(body.vp_id, deps.dag);
}

/**
 * Build the canonical 9-field signed payload. All fields always
 * present; defaults fill in for omitted optionals. Reject-on-extra:
 * picks exactly these 9 keys.
 */
function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  // Required-no-default fields (the canonical payload can't form without these).
  if (typeof input.public_key !== "string") {
    throw schemaError(400, "public_key is required", "public_key_required");
  }
  if (typeof input.dedup_hash !== "string") {
    throw schemaError(400, "dedup_hash is required", "dedup_hash_required");
  }
  if (!input.zk_proof || typeof input.zk_proof !== "object" || Array.isArray(input.zk_proof)) {
    throw schemaError(400, "zk_proof is required", "zk_proof_required");
  }
  if (typeof input.vp_id !== "string") {
    throw schemaError(400, "vp_id is required", "vp_id_required");
  }

  // tip_id_type default "personal"; enum-locked.
  const tipIdType = input.tip_id_type == null ? TIP_ID_TYPES.PERSONAL : input.tip_id_type;
  if (!TIP_ID_TYPE_VALUES.includes(tipIdType)) {
    throw schemaError(
      400,
      `tip_id_type must be one of ${TIP_ID_TYPE_VALUES.join(", ")}`,
      "tip_id_type_invalid",
    );
  }

  // verification_tier default T1; enum-locked.
  const verificationTier = input.verification_tier == null ? "T1" : input.verification_tier;
  if (!VERIFICATION_TIERS.includes(verificationTier)) {
    throw schemaError(
      400,
      `verification_tier must be one of ${VERIFICATION_TIERS.join(", ")}`,
      "verification_tier_invalid",
    );
  }

  // GH #60: algorithm bound to the public_key. Default ml-dsa-65;
  // enum-locked so unknown values reject before signing. Binding it
  // into the VP-signed canonical bytes means an attacker can't
  // post-hoc claim the same pubkey under a different algorithm — the
  // VP's attestation covers the (key, algorithm) pair. Required for
  // future hybrid schemes where pubkey byte-length is ambiguous.
  const algorithm = input.algorithm == null ? SIGNATURE_ALGORITHM_DEFAULT : input.algorithm;
  if (!SIGNATURE_ALGORITHM_VALUES.has(algorithm)) {
    throw schemaError(
      400,
      `algorithm must be one of ${[...SIGNATURE_ALGORITHM_VALUES].join(", ")}`,
      "algorithm_invalid",
    );
  }

  // creator_name pass-through: typeof check passes strings through
  // verbatim, null / undefined / non-strings emit `null`. Empty string
  // is REJECTED at validateRequest, so it never reaches here in normal
  // flow; the only callers that hit this with `""` are misbehaving
  // (and their canonical bytes won't match the server's anyway).
  return {
    algorithm,
    creator_name: typeof input.creator_name === "string" ? input.creator_name : null,
    dedup_hash: input.dedup_hash,
    public_key: input.public_key,
    region: typeof input.region === "string" ? input.region.toUpperCase() : "US",
    social_attested: !!input.social_attested,
    tip_id_type: tipIdType,
    verification_tier: verificationTier,
    vp_id: input.vp_id,
    zk_proof: input.zk_proof,
  };
}

/**
 * Sign helper — VP signs the canonical payload with their private key.
 */
function sign(payload, vpPrivateKeyHex, opts) {
  return signPayload(payload, vpPrivateKeyHex, opts);
}

/**
 * Pure signature verifier — given a canonical payload, signature, and
 * VP public key, returns boolean. Doesn't do any DAG lookup or
 * schema-shape validation; that's the caller's job (or use verifyTx
 * for the full server-side entry).
 */
function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * State-level verification at consensus replay. GH #51: the VP
 * signature is verified by the unified dispatcher
 * (`schemas/_common.verifyTxSignature`) against `tx.signature`. This
 * function only enforces the state-machine invariants the dispatcher
 * doesn't know about (VP existence + active on DAG, canonical payload
 * shape).
 *
 * Returns { ok: true } on success, or
 * { ok: false, status, error, code } on any failure.
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};

  if (!d.vp_id) {
    return { ok: false, status: 400, error: "vp_id missing", code: "vp_id_missing" };
  }

  try {
    resolveVP(d.vp_id, dag);
    // Rebuild + validate canonical payload shape — schemaError surfaces
    // any missing required field. The dispatcher does this implicitly
    // via bodyMessageHex when verifying, but doing it here keeps the
    // state-check error codes precise for the API path.
    buildSigningPayload(d);
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }

  return { ok: true };
}

module.exports = {
  TX_TYPE,
  TIP_ID_TYPES,
  TIP_ID_TYPE_VALUES,
  VERIFICATION_TIERS,
  validateRequest,
  resolveVP,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
  // GH #51 — unified signature contract (consumed by verifyTxSignature
  // in schemas/_common.js + commit-handler dispatch)
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  // Re-export for tests / debug:
  canonicalJson,
};
