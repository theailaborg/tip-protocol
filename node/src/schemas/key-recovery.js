/**
 * @file @tip-protocol/node/src/schemas/key-recovery.js
 * @description Canonical schema for `KEY_RECOVERY` (GH #60).
 *
 * Lost-key recovery: the user lost their CURRENT (OLD) private key
 * and goes back to a VP (the original, or any active VP under the
 * federation's recovery policy) for off-chain re-verification. The
 * VP signs a recovery tx attesting that the user has been re-verified
 * and supplies the user's NEW public key. commit-handler closes the
 * active entity_keys row (sets valid_to_ts = effective_at) and
 * appends a new active row owned by the new key.
 *
 * Trust model:
 *   - The VP signs the canonical body. The chain trusts the VP's
 *     attestation the same way it trusts REGISTER_IDENTITY (VPs are
 *     the network trust anchor for identity binding).
 *   - The signature is verified by the unified dispatcher resolving
 *     the signer to the VP via `dag.getKeyValidAt("vp", vp_id,
 *     tx.timestamp)`.
 *
 * Canonical signed payload (alphabetical, picked-fields):
 *
 *   algorithm               string,   new key's algorithm (default ml-dsa-65)
 *   effective_at            number,   epoch ms — boundary where OLD validity
 *                                     ends and NEW validity begins.
 *   new_public_key          string,   hex of the new public key
 *   recovery_evidence_hash  string,   shake256 of off-chain evidence body
 *                                     (passport scan, biometric match log,
 *                                     etc.) the VP attests they reviewed
 *   tip_id                  string,   the identity being recovered
 *   vp_id                   string,   the attesting VP
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError } = require("./_common");
const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND, VP_ID_FIELDS,
  SIGNATURE_ALGORITHM_VALUES, SIGNATURE_ALGORITHM_DEFAULT,
} = require("../../../shared/constants");

const TX_TYPE = TX_TYPES.KEY_RECOVERY;
// Body scope; the attesting VP signs.
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.VP;
const VP_ID_FIELD = VP_ID_FIELDS.VP_ID;

function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (typeof body.tip_id !== "string" || !body.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required (tip://id/...)", "tip_id_required");
  }
  if (typeof body.vp_id !== "string" || !body.vp_id.startsWith("tip://vp/")) {
    throw schemaError(400, "vp_id is required (tip://vp/...)", "vp_id_required");
  }
  if (typeof body.new_public_key !== "string" || body.new_public_key.length === 0) {
    throw schemaError(400, "new_public_key is required", "new_public_key_required");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }
  if (typeof body.recovery_evidence_hash !== "string" || body.recovery_evidence_hash.length === 0) {
    throw schemaError(400, "recovery_evidence_hash is required", "recovery_evidence_hash_required");
  }
  const algorithm = body.algorithm == null ? SIGNATURE_ALGORITHM_DEFAULT : body.algorithm;
  if (!SIGNATURE_ALGORITHM_VALUES.has(algorithm)) {
    throw schemaError(
      400,
      `algorithm must be one of ${[...SIGNATURE_ALGORITHM_VALUES].join(", ")}`,
      "algorithm_invalid",
    );
  }
  if (!Number.isFinite(body.effective_at) || body.effective_at <= 0) {
    throw schemaError(400, "effective_at must be a positive epoch ms", "effective_at_invalid");
  }
  // DAG presence.
  const identity = deps.dag.getIdentity(body.tip_id);
  if (!identity) {
    throw schemaError(412, "TIP-ID not registered on DAG", "tip_id_not_registered");
  }
  const vp = deps.dag.getVP(body.vp_id);
  if (!vp) {
    throw schemaError(412, `VP not registered: ${body.vp_id}`, "vp_not_registered");
  }
  if (vp.status !== "active") {
    throw schemaError(403, `VP not active (status=${vp.status})`, "vp_inactive");
  }
}

function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (typeof input.tip_id !== "string") {
    throw schemaError(400, "tip_id is required", "tip_id_required");
  }
  if (typeof input.vp_id !== "string") {
    throw schemaError(400, "vp_id is required", "vp_id_required");
  }
  if (typeof input.new_public_key !== "string") {
    throw schemaError(400, "new_public_key is required", "new_public_key_required");
  }
  if (typeof input.recovery_evidence_hash !== "string") {
    throw schemaError(400, "recovery_evidence_hash is required", "recovery_evidence_hash_required");
  }
  if (!Number.isFinite(input.effective_at)) {
    throw schemaError(400, "effective_at must be a number", "effective_at_invalid");
  }
  const algorithm = input.algorithm == null ? SIGNATURE_ALGORITHM_DEFAULT : input.algorithm;
  if (!SIGNATURE_ALGORITHM_VALUES.has(algorithm)) {
    throw schemaError(
      400,
      `algorithm must be one of ${[...SIGNATURE_ALGORITHM_VALUES].join(", ")}`,
      "algorithm_invalid",
    );
  }
  return {
    algorithm,
    effective_at: input.effective_at,
    new_public_key: input.new_public_key,
    recovery_evidence_hash: input.recovery_evidence_hash,
    tip_id: input.tip_id,
    vp_id: input.vp_id,
  };
}

function sign(payload, vpPrivateKeyHex, opts) {
  return signPayload(payload, vpPrivateKeyHex, opts);
}

function verifySignature(payload, signatureHex, vpPublicKeyHex) {
  return verifyPayload(payload, signatureHex, vpPublicKeyHex);
}

/**
 * State-level verification at consensus replay. GH #51: the VP
 * signature is verified by the unified dispatcher (against the VP's
 * key valid at tx.timestamp). This function enforces the state-machine
 * invariants:
 *
 *   1. Identity exists + active + not revoked.
 *   2. VP exists + active.
 *   3. effective_at >= tx.timestamp.
 *   4. NEW key is non-empty + algorithm is in the enum.
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};
  if (!d.tip_id) return { ok: false, status: 400, error: "tip_id missing", code: "tip_id_missing" };
  if (!d.vp_id) return { ok: false, status: 400, error: "vp_id missing", code: "vp_id_missing" };
  if (typeof d.new_public_key !== "string" || d.new_public_key.length === 0) {
    return { ok: false, status: 400, error: "new_public_key missing", code: "new_public_key_missing" };
  }
  const algorithm = d.algorithm || SIGNATURE_ALGORITHM_DEFAULT;
  if (!SIGNATURE_ALGORITHM_VALUES.has(algorithm)) {
    return { ok: false, status: 400, error: `algorithm invalid: ${algorithm}`, code: "algorithm_invalid" };
  }
  const identity = dag.getIdentity(d.tip_id);
  if (!identity) return { ok: false, status: 412, error: "TIP-ID not registered", code: "tip_id_not_registered" };
  if (typeof dag.isRevoked === "function" && dag.isRevoked(d.tip_id)) {
    return { ok: false, status: 403, error: "TIP-ID is revoked", code: "tip_id_revoked" };
  }
  if (identity.status && identity.status !== "active") {
    return { ok: false, status: 403, error: `TIP-ID is not active (status=${identity.status})`, code: "tip_id_inactive" };
  }
  const vp = dag.getVP(d.vp_id);
  if (!vp) return { ok: false, status: 412, error: `VP not registered: ${d.vp_id}`, code: "vp_not_registered" };
  if (vp.status !== "active") {
    return { ok: false, status: 403, error: `VP not active (status=${vp.status})`, code: "vp_inactive" };
  }
  if (!Number.isFinite(d.effective_at) || d.effective_at < tx.timestamp) {
    return { ok: false, status: 400, error: "effective_at must be >= tx.timestamp", code: "effective_at_invalid" };
  }
  return { ok: true };
}

module.exports = {
  TX_TYPE,
  validateRequest,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
  // GH #51 — unified signature contract
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  VP_ID_FIELD,
};
