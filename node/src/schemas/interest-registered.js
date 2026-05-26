/**
 * @file @tip-protocol/node/src/schemas/interest-registered.js
 * @description Canonical schema for `INTEREST_REGISTERED` — VP-attested
 * registry entry that adds a new interest slug to the global taxonomy
 * users can pick from on their profile.
 *
 * Governance model — mirrors VP_REGISTERED / NODE_REGISTERED:
 *   - Only a registered + active VP can submit this tx (chain-side gate).
 *   - Slug is the primary key; commit-handler rejects duplicate slugs.
 *   - Category is from a closed enum (INTEREST_CATEGORIES); semantic-
 *     dupe prevention ("ai" vs "ai-ml" vs "machine-learning") is
 *     off-chain federation policy — the VP signing UI should fuzzy-
 *     match existing slugs and warn before signing.
 *   - Slug syntax (lowercase, hyphens, 3–40 chars) is enforced via
 *     INTEREST_SLUG_REGEX so the on-chain vocabulary stays canonical.
 *
 * Genesis bootstrap pre-populates the table from INITIAL_INTERESTS_SEED
 * at first boot; INTEREST_REGISTERED txs extend it at runtime.
 *
 * Canonical signed payload (alphabetical, picked-fields):
 *
 *   approving_vp_id   string,   the attesting VP
 *   category          string,   one of INTEREST_CATEGORY_VALUES
 *   label             string,   human-readable name, ≤ 80 chars
 *   slug              string,   matches INTEREST_SLUG_REGEX
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { signPayload, verifyPayload, schemaError } = require("./_common");
const {
  TX_TYPES,
  SIGNATURE_SCOPE, SIGNED_BY_KIND, VP_ID_FIELDS,
  INTEREST_SLUG_REGEX, INTEREST_LABEL_MAX_LEN, INTEREST_CATEGORY_VALUES,
} = require("../../../shared/constants");

const TX_TYPE = TX_TYPES.INTEREST_REGISTERED;
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.VP;
const VP_ID_FIELD = VP_ID_FIELDS.APPROVING_VP_ID;

function _validateSlug(slug) {
  if (typeof slug !== "string" || !INTEREST_SLUG_REGEX.test(slug)) {
    throw schemaError(400, `slug must match ${INTEREST_SLUG_REGEX} (3–40 chars, lowercase letters/digits/hyphens, starts with letter)`, "slug_invalid");
  }
}

function _validateLabel(label) {
  if (typeof label !== "string" || label.length === 0) {
    throw schemaError(400, "label is required", "label_required");
  }
  if (label.length > INTEREST_LABEL_MAX_LEN) {
    throw schemaError(400, `label must be ≤ ${INTEREST_LABEL_MAX_LEN} chars`, "label_too_long");
  }
}

function _validateCategory(category) {
  if (!INTEREST_CATEGORY_VALUES.has(category)) {
    throw schemaError(400, `category must be one of ${[...INTEREST_CATEGORY_VALUES].join(", ")}`, "category_invalid");
  }
}

function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  _validateSlug(body.slug);
  _validateLabel(body.label);
  _validateCategory(body.category);
  if (typeof body.approving_vp_id !== "string" || !body.approving_vp_id.startsWith("tip://vp/")) {
    throw schemaError(400, "approving_vp_id is required (tip://vp/...)", "approving_vp_id_required");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }
  // DAG presence — VP must exist + be active. Slug uniqueness checked
  // by the schema's verifyTx at commit, not here, so the API-time check
  // can stay tip-side stateless when needed.
  const vp = deps.dag.getVP(body.approving_vp_id);
  if (!vp) {
    throw schemaError(412, `VP not registered: ${body.approving_vp_id}`, "vp_not_registered");
  }
  if (vp.status !== "active") {
    throw schemaError(403, `VP not active (status=${vp.status})`, "vp_inactive");
  }
  const existing = deps.dag.getInterest(body.slug);
  if (existing) {
    throw schemaError(409, `slug already registered: ${body.slug}`, "slug_already_registered");
  }
}

function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  _validateSlug(input.slug);
  _validateLabel(input.label);
  _validateCategory(input.category);
  if (typeof input.approving_vp_id !== "string") {
    throw schemaError(400, "approving_vp_id is required", "approving_vp_id_required");
  }
  return {
    approving_vp_id: input.approving_vp_id,
    category: input.category,
    label: input.label,
    slug: input.slug,
  };
}

function sign(payload, vpPrivateKeyHex, opts) {
  return signPayload(payload, vpPrivateKeyHex, opts);
}

function verifySignature(payload, signatureHex, vpPublicKeyHex) {
  return verifyPayload(payload, signatureHex, vpPublicKeyHex);
}

/**
 * State-level verification at consensus replay. The VP signature is
 * verified by the unified dispatcher (against the VP's key valid at
 * tx.timestamp). This function enforces:
 *
 *   1. VP exists + active
 *   2. Slug not already registered (interests_registry PK uniqueness)
 *   3. Category is in the enum
 *   4. Slug + label syntax checks
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};
  if (typeof d.slug !== "string" || !INTEREST_SLUG_REGEX.test(d.slug)) {
    return { ok: false, status: 400, error: "slug invalid", code: "slug_invalid" };
  }
  if (typeof d.label !== "string" || d.label.length === 0 || d.label.length > INTEREST_LABEL_MAX_LEN) {
    return { ok: false, status: 400, error: "label invalid", code: "label_invalid" };
  }
  if (!INTEREST_CATEGORY_VALUES.has(d.category)) {
    return { ok: false, status: 400, error: `category invalid: ${d.category}`, code: "category_invalid" };
  }
  if (typeof d.approving_vp_id !== "string") {
    return { ok: false, status: 400, error: "approving_vp_id missing", code: "approving_vp_id_missing" };
  }
  const vp = dag.getVP(d.approving_vp_id);
  if (!vp) {
    return { ok: false, status: 412, error: `VP not registered: ${d.approving_vp_id}`, code: "vp_not_registered" };
  }
  if (vp.status !== "active") {
    return { ok: false, status: 403, error: `VP not active (status=${vp.status})`, code: "vp_inactive" };
  }
  const existing = dag.getInterest(d.slug);
  if (existing) {
    return { ok: false, status: 409, error: `slug already registered: ${d.slug}`, code: "slug_already_registered" };
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
  // Unified signature contract
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  VP_ID_FIELD,
};
