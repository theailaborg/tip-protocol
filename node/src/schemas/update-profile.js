/**
 * @file @tip-protocol/node/src/schemas/update-profile.js
 * @description Canonical schema for `UPDATE_PROFILE` — sparse update of
 * user-settable identity fields. The single tx type for any future
 * profile / participation preference; new fields are added to
 * KNOWN_FIELDS as the protocol grows (no new tx types per preference).
 *
 * Signed canonical payload:
 *
 *   tip_id            string,  required (subject identity)
 *   <known fields...> only present-in-input fields, sorted alphabetically
 *
 * Sparse-update semantics: only fields present in tx.data update the
 * identity row; missing fields preserve previous value. Strict schema —
 * unknown fields are rejected so a client can't sneak in unauthorized
 * mutations via a generic tx type.
 *
 * v1 known fields:
 *   reviewer_consent  boolean  — opt-in to be selected as adjudicator across
 *                                ALL protocol roles (Protocol Review reviewer,
 *                                Stage 2 jury, Stage 3 expert panel). Runtime
 *                                filters at selection time decide which role
 *                                a consenting user lands in for a given case.
 *
 * Signature scope: the user's own ML-DSA-65 key signs the canonical
 * payload. No VP attestation needed — this is purely the user mutating
 * their own preferences.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const {
  signPayload, verifyPayload, schemaError, canonicalJson,
} = require("./_common");
const { TX_TYPES, TIP_ID_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS } = require("../../../shared/constants");

const TX_TYPE = TX_TYPES.UPDATE_PROFILE;
// GH #51 — unified signature storage. Subject (data.tip_id) signs the
// canonical payload returned by buildSigningPayload.
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.TIP_ID;

// Fields the user may sparsely update via this tx. Adding a new field
// here makes it accepted without any other code change — sparse update +
// strict schema both consult this list. Keep alphabetized for canonical
// payload determinism (canonicalJson sorts keys anyway, but explicit
// ordering keeps reviewer + future-developer mental models aligned).
const KNOWN_FIELDS = Object.freeze({
  reviewer_consent: { type: "boolean" },
});

const KNOWN_FIELD_NAMES = Object.freeze(Object.keys(KNOWN_FIELDS));

/**
 * Resolve the subject identity and reject if missing / revoked. Same
 * shape as register-content's resolveSigner — single home for the
 * "is this user authorized to mutate their own row?" check.
 */
function resolveSubject(tipId, dag) {
  const identity = dag.getIdentity(tipId);
  if (!identity) {
    throw schemaError(412, "TIP-ID not registered on DAG", "tip_id_not_registered");
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(tipId)) {
    throw schemaError(403, "TIP-ID is revoked", "tip_id_revoked");
  }
  return identity;
}

/**
 * Request-envelope validator for POST /v1/identity/:tip_id/profile.
 * Runs before any crypto work. Covers:
 *
 *   1. Body shape — tip_id, signature presence + types
 *   2. URL ↔ body tip_id alignment (when deps.urlTipId is provided —
 *      prevents confused-deputy where the client signed one tip_id
 *      but submitted to a URL for another)
 *   3. At least one known preference field is present (no empty updates)
 *   4. Each present field has the declared type
 *   5. No unknown fields — strict schema prevents back-doors
 *   6. DAG presence — tip_id MUST exist and not be revoked
 */
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
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }

  // Strict schema — every non-reserved key on the body must be a known field.
  const reservedKeys = new Set(["tip_id", "signature"]);
  const presentFields = [];
  for (const key of Object.keys(body)) {
    if (reservedKeys.has(key)) continue;
    if (!KNOWN_FIELDS[key]) {
      throw schemaError(400, `Unknown field: "${key}". Allowed: ${KNOWN_FIELD_NAMES.join(", ")}`, "field_unknown");
    }
    const expectedType = KNOWN_FIELDS[key].type;
    if (typeof body[key] !== expectedType) {
      throw schemaError(400, `Field "${key}" must be ${expectedType}`, "field_type_invalid");
    }
    presentFields.push(key);
  }

  if (presentFields.length === 0) {
    throw schemaError(
      400,
      `at least one preference field is required (one of: ${KNOWN_FIELD_NAMES.join(", ")})`,
      "no_fields_to_update",
    );
  }

  const subject = resolveSubject(body.tip_id, deps.dag);

  // Organization identities cannot opt into adjudication roles. Reject
  // at the schema gate so the state can never end up with an org's
  // reviewer_consent=1 (matches the filter in selectJury / selectExperts /
  // reviewer-selection). Personal identities are the only legitimate
  // judgment-makers in the protocol.
  if (presentFields.includes("reviewer_consent") && body.reviewer_consent === true) {
    const subjectType = subject.tip_id_type || TIP_ID_TYPES.PERSONAL;
    if (subjectType !== TIP_ID_TYPES.PERSONAL) {
      throw schemaError(
        403,
        `Organization identities cannot opt into adjudication roles (tip_id_type: ${subjectType})`,
        "tip_id_type_not_personal",
      );
    }
  }
}

/**
 * Build the canonical signed payload from input. Includes tip_id plus
 * every present known field. Excludes unknown / reserved keys. Each
 * field's type is enforced — non-matching types throw so signing never
 * produces a payload the verifier can't reproduce.
 */
function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (typeof input.tip_id !== "string" || !input.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required", "tip_id_required");
  }

  const payload = { tip_id: input.tip_id };
  for (const field of KNOWN_FIELD_NAMES) {
    if (input[field] === undefined) continue;
    const expectedType = KNOWN_FIELDS[field].type;
    if (typeof input[field] !== expectedType) {
      throw schemaError(400, `Field "${field}" must be ${expectedType}`, "field_type_invalid");
    }
    payload[field] = input[field];
  }

  // canonicalJson() sorts keys, so the payload's serialized order is
  // deterministic regardless of insertion order. Returning the unsorted
  // object is fine — the sign/verify primitives canonicalize before
  // hashing.
  return payload;
}

function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * Server-side high-level entry. Used by profile-service (API time) and
 * commit-handler (consensus replay). Verifies the user's own ML-DSA-65
 * signature against their DAG identity public key.
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};

  if (typeof d.signature !== "string") {
    return { ok: false, status: 400, error: "signature missing on tx", code: "signature_missing" };
  }
  if (!d.tip_id) {
    return { ok: false, status: 400, error: "tip_id missing", code: "tip_id_missing" };
  }

  let identity;
  let payload;
  try {
    identity = resolveSubject(d.tip_id, dag);
    payload = buildSigningPayload(d);
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }

  if (!verifySignature(payload, d.signature, identity.public_key)) {
    return { ok: false, status: 403, error: "Signature verification failed", code: "signature_invalid" };
  }

  return { ok: true };
}

module.exports = {
  TX_TYPE,
  KNOWN_FIELDS,
  KNOWN_FIELD_NAMES,
  validateRequest,
  resolveSubject,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
  canonicalJson,
  // GH #51 — unified signature contract
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
};
