/**
 * @file @tip-protocol/node/src/schemas/key-rotated.js
 * @description Canonical schema for `KEY_ROTATED` (GH #60).
 *
 * Healthy key rotation: the user generates a new keypair and proves
 * authorisation by signing the rotation tx with their CURRENT (OLD)
 * private key. commit-handler closes the active entity_keys row
 * (sets valid_to_ts = effective_at) and appends a new active row
 * (valid_from_ts = effective_at, valid_to_ts = NULL) — atomically.
 *
 * Trust model:
 *   - The OLD key signs the canonical body, proving possession.
 *   - The signature is verified by the unified dispatcher using
 *     `dag.getKeyValidAt("identity", tip_id, tx.timestamp)`. Since the
 *     tx timestamp is BEFORE effective_at, the dispatcher resolves the
 *     OLD key (which is still active at tx.timestamp), and the OLD key
 *     correctly verifies the signature.
 *   - effective_at must be >= tx.timestamp so the OLD key is still
 *     active at signing time and the NEW key takes over from a
 *     well-defined point.
 *
 * Canonical signed payload (alphabetical, picked-fields):
 *
 *   algorithm           string,   new key's algorithm (default ml-dsa-65)
 *   effective_at        number,   epoch ms — boundary where OLD validity ends
 *                                 and NEW validity begins. Must be >=
 *                                 tx.timestamp.
 *   new_public_key      string,   hex of the new public key (raw bytes)
 *   old_key_fingerprint string,   shake256 of current active public_key,
 *                                 first 32 hex chars — defends against
 *                                 race where two rotations target the
 *                                 same identity concurrently.
 *   tip_id              string,   the rotating identity
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError } = require("./_common");
const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS,
  SIGNATURE_ALGORITHM_VALUES, SIGNATURE_ALGORITHM_DEFAULT,
} = require("../../../shared/constants");

const TX_TYPE = TX_TYPES.KEY_ROTATED;
// Body scope; the OLD key (currently-active for the identity) signs.
// The dispatcher's time-aware lookup (`dag.getKeyValidAt`) picks the
// OLD key because tx.timestamp < effective_at — i.e. signature was
// produced while the OLD key was still active.
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.TIP_ID;

function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (typeof body.tip_id !== "string" || !body.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required (tip://id/...)", "tip_id_required");
  }
  if (typeof body.new_public_key !== "string" || body.new_public_key.length === 0) {
    throw schemaError(400, "new_public_key is required", "new_public_key_required");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
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
  if (typeof body.old_key_fingerprint !== "string" || body.old_key_fingerprint.length === 0) {
    throw schemaError(400, "old_key_fingerprint is required", "old_key_fingerprint_required");
  }
  // DAG presence: identity must exist + not revoked.
  const identity = deps.dag.getIdentity(body.tip_id);
  if (!identity) {
    throw schemaError(412, "TIP-ID not registered on DAG", "tip_id_not_registered");
  }
  if (typeof deps.dag.isRevoked === "function" && deps.dag.isRevoked(body.tip_id)) {
    throw schemaError(403, "TIP-ID is revoked", "tip_id_revoked");
  }
}

function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (typeof input.tip_id !== "string") {
    throw schemaError(400, "tip_id is required", "tip_id_required");
  }
  if (typeof input.new_public_key !== "string") {
    throw schemaError(400, "new_public_key is required", "new_public_key_required");
  }
  if (typeof input.old_key_fingerprint !== "string") {
    throw schemaError(400, "old_key_fingerprint is required", "old_key_fingerprint_required");
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
    old_key_fingerprint: input.old_key_fingerprint,
    tip_id: input.tip_id,
  };
}

function sign(payload, oldPrivateKeyHex, opts) {
  return signPayload(payload, oldPrivateKeyHex, opts);
}

function verifySignature(payload, signatureHex, oldPublicKeyHex) {
  return verifyPayload(payload, signatureHex, oldPublicKeyHex);
}

/**
 * State-level verification at consensus replay. GH #51: the signature
 * itself is verified by the unified dispatcher (against the OLD key
 * via dag.getKeyValidAt at tx.timestamp). This function only enforces
 * the state-machine invariants the dispatcher doesn't know about:
 *
 *   1. Identity exists + active + not revoked.
 *   2. effective_at >= tx.timestamp (NEW key takes over from a defined
 *      point in time, not retroactively).
 *   3. old_key_fingerprint matches the current active key.
 *   4. NEW key is non-empty + algorithm is in the enum.
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};
  if (!d.tip_id) return { ok: false, status: 400, error: "tip_id missing", code: "tip_id_missing" };
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
  SUBJECT_TIP_ID_FIELD,
};
