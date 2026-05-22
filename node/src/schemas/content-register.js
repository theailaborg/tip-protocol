/**
 * @file @tip-protocol/node/src/schemas/content-register.js
 * @description Canonical signing schema for `REGISTER_CONTENT` —
 * implements CNA-2.2 from docs/CONTENT_SIGNING.md.
 *
 * Single source of truth for what the canonical 9-field signed payload
 * looks like. Both content-service.register (API time) and
 * commit-handler (consensus replay) import this module — the field
 * list, default-fill rules, and verifier all live here.
 *
 * Spec: docs/CONTENT_SIGNING.md (full reference). Quick summary of the
 * 8 signed fields:
 *
 *   attribution_mode  string,  default "self" (enum: self/employed/hosted)
 *   authors[]         array,   ≥1 entry, each entry exactly 5 keys
 *   cna_version       string,  literal "CNA-2.2" (current); whitelisted versions accepted at verify
 *   content_hash      string,  required (no default)
 *   extras            object,  default {}
 *   origin_code       string,  required (no default), uppercased
 *   registered_urls   string[],default [], index 0 = canonical / primary URL
 *   signer_tip_id     string,  required (no default)
 *
 * NOTE: `signer_type` was previously signed but was dropped — the
 * signer's type is already on the identity record (DAG-resident),
 * not asserted per-message. See docs/CONTENT_SIGNING.md change log.
 *
 * Every field is always present in the canonical payload; default
 * values fill in for omitted optionals. Reject-on-extra: the builder
 * picks exactly these 8 fields and ignores any extras at the top level
 * (client junk doesn't get bound to the signature).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const {
  payloadHashHex, signPayload, verifyPayload, schemaError, canonicalJson,
} = require("./_common");
const {
  TX_TYPES, ORIGIN, CNA_VERSIONS, CNA22_AUTHOR_KEYS,
  ATTRIBUTION_MODES, ATTRIBUTION_MODE_VALUES,
  SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS,
} = require("../../../shared/constants");
const { validateContentSize } = require("../middleware/validate");

const TX_TYPE = TX_TYPES.REGISTER_CONTENT;
// GH #51 — unified signature storage. The signer (`signer_tip_id` —
// the author or attributed publisher under CNA-2.2) signs the
// canonical 8-field payload returned by buildSigningPayload.
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.BODY;
const SIGNED_BY = SIGNED_BY_KIND.SUBJECT;
const SUBJECT_TIP_ID_FIELD = TIP_ID_FIELDS.SIGNER_TIP_ID;
// `current` is the CNA version new submissions are signed under;
// `versions` is the full whitelist of historically-released CNA
// versions that verification must accept (replay correctness — old
// committed txs keep verifying forever).
const CURRENT_CNA_VERSION = CNA_VERSIONS.REGISTER_CONTENT.current;
const SUPPORTED_CNA_VERSIONS = CNA_VERSIONS.REGISTER_CONTENT.versions;
const ORIGIN_CODES = Object.keys(ORIGIN);
const AUTHOR_KEYS = CNA22_AUTHOR_KEYS;

/**
 * Walk authors[] and reject if any author's tip_id is not registered
 * on the DAG. Internal helper — used by both validateRequest (API
 * time) and verifyTx (consensus replay) so the predicate is identical
 * in both code paths.
 */
function _checkAuthorsRegistered(authors, dag) {
  for (const a of authors) {
    const identity = dag.getIdentity(a.tip_id);
    if (!identity) {
      throw schemaError(412, `Author TIP-ID not registered on DAG: ${a.tip_id}`, "author_not_registered");
    }
    // Strict cross-check: the per-author tip_id_type claim in the
    // signed payload MUST match the type on the DAG identity row.
    // Catches misattribution (e.g., claiming an org TIP-ID as a
    // personal byline). identity.tip_id_type defaults to "personal"
    // for any pre-tip_id_type-field identity (back-compat default
    // applied at DB level too).
    const claimedType = a.tip_id_type || "personal";
    const actualType = identity.tip_id_type || "personal";
    if (claimedType !== actualType) {
      throw schemaError(
        412,
        `Author tip_id_type mismatch for ${a.tip_id}: payload claims "${claimedType}", DAG identity is "${actualType}"`,
        "author_tip_id_type_mismatch",
      );
    }
  }
}

/**
 * Comprehensive request-envelope validator for POST /v1/content/register.
 * Single gate — runs before any crypto work and covers:
 *
 *   1. Shape — signer_tip_id, origin_code, signature presence,
 *      content/media XOR, content size, authors[] shape
 *   2. DAG presence — signer_tip_id MUST be on DAG and not revoked;
 *      every authors[].tip_id MUST also be on DAG (no off-DAG credit
 *      attribution)
 *
 * Throws `{ status, error, code }` shaped errors so callers can surface
 * them through the HTTP layer with structured codes. Void return —
 * the caller fetches the identity itself via `resolveSigner` once
 * validation has passed.
 *
 * @param {Object} body         req.body
 * @param {Object} deps         { mediaLimits, dag } — mediaLimits from
 *                              server config; dag for identity lookups
 */
function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (typeof body.signer_tip_id !== "string" || !body.signer_tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "signer_tip_id is required (tip://id/...)", "signer_tip_id_required");
  }
  const originCode = typeof body.origin_code === "string" ? body.origin_code.toUpperCase() : "";
  if (!ORIGIN_CODES.includes(originCode)) {
    throw schemaError(400, `origin_code must be one of ${ORIGIN_CODES.join(", ")}`, "origin_code_invalid");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }
  if (!body.content && !body.media_canonical_hash) {
    throw schemaError(400, "content or media_canonical_hash required", "content_required");
  }
  if (body.content) validateContentSize(body.content, body.content_type, deps.mediaLimits);

  // authors[] shape — ≥1 entry, each carrying a tip://id/... string —
  // checked here so we can confidently DAG-look-up every author below.
  if (!Array.isArray(body.authors) || body.authors.length === 0) {
    throw schemaError(400, "authors[] must have at least one entry", "authors_required");
  }
  for (const a of body.authors) {
    if (!a || typeof a !== "object" || typeof a.tip_id !== "string" || !a.tip_id.startsWith("tip://id/")) {
      throw schemaError(400, "authors[].tip_id must be a tip://id/... string", "authors_tip_id_invalid");
    }
  }

  // DAG presence — signer + every author. resolveSigner throws 412/403;
  // _checkAuthorsRegistered throws 412 on any off-DAG author.
  resolveSigner(body.signer_tip_id, deps.dag);
  _checkAuthorsRegistered(body.authors, deps.dag);
}

/**
 * Normalise a single author entry to exactly the 5 spec keys with
 * defaults for the optional ones. Strips any extra fields the client
 * tried to slip in.
 */
function _normalizeAuthor(a) {
  if (!a || typeof a !== "object") {
    throw schemaError(400, "authors[] entry must be an object", "authors_entry_invalid");
  }
  if (typeof a.tip_id !== "string" || !a.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "authors[].tip_id must be a tip://id/... string", "authors_tip_id_invalid");
  }
  return {
    key_mode: typeof a.key_mode === "string" ? a.key_mode : "attribution",
    role: typeof a.role === "string" ? a.role : "contributor",
    signed: !!a.signed,
    tip_id: a.tip_id,
    tip_id_type: typeof a.tip_id_type === "string" ? a.tip_id_type : "personal",
  };
}

/**
 * Coerce `registered_urls` input to the canonical array form.
 * Order is significant — index 0 is the canonical / primary URL where
 * the content was originally published. The signed canonical-JSON
 * preserves array order, so the canonical-URL-at-index-0 convention is
 * cryptographically enforceable, not just a docs-level rule.
 *
 * Accepts:
 *   - undefined / null  → []
 *   - string[]          → as-is, order preserved
 * Rejects anything else.
 */
function _normalizeRegisteredUrls(input) {
  if (input == null) return [];
  if (!Array.isArray(input)) {
    throw schemaError(400, "registered_urls must be an array of strings", "registered_urls_invalid");
  }
  for (const u of input) {
    if (typeof u !== "string") {
      throw schemaError(400, "registered_urls entries must be strings", "registered_urls_invalid");
    }
  }
  return input;
}

/**
 * Coerce `extras` input to a plain object. Spec rule: must be an object
 * (not null, not array). Empty maps to {} so the canonical payload
 * always has the field present.
 */
function _normalizeExtras(input) {
  if (input == null) return {};
  if (typeof input !== "object" || Array.isArray(input)) {
    throw schemaError(400, "extras must be an object (use {} for empty)", "extras_invalid");
  }
  return input;
}

/**
 * Build the canonical 9-field signed payload from a client-supplied
 * input. Default-fills the optional fields, normalises types, picks
 * exactly the 9 keys (reject-on-extra at the top level). Throws on
 * shape failures so the caller can surface the error before signing
 * or verifying.
 *
 * `contentHashFull` may be passed explicitly (sign-time at the
 * service layer: the SERVER recomputes content_hash from the actual
 * content bytes — never trusts the client's value) OR read from
 * `input.content_hash` (verify-time: the authoritative content_hash
 * was already mirrored onto tx.data at commit; the unified dispatcher
 * calls this with a single arg).
 *
 * @param {Object} input            client body or tx.data
 * @param {string} [contentHashFull]  authoritative content hash;
 *                                    defaults to input.content_hash
 * @returns {Object} the canonical 9-field payload
 */
function buildSigningPayload(input, contentHashFull) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  const ch = contentHashFull == null ? input.content_hash : contentHashFull;
  if (typeof ch !== "string" || !/^[0-9a-f]{64}$/.test(ch)) {
    throw schemaError(400, "content_hash must be a 64-char lowercase hex string", "content_hash_invalid");
  }

  // Required fields (no defaults). Reject early so signing never
  // produces a payload missing required-fields data.
  const signerTipId = input.signer_tip_id;
  if (typeof signerTipId !== "string" || !signerTipId.startsWith("tip://id/")) {
    throw schemaError(400, "signer_tip_id is required", "signer_tip_id_required");
  }
  const originCode = typeof input.origin_code === "string" ? input.origin_code.toUpperCase() : "";
  if (!ORIGIN_CODES.includes(originCode)) {
    throw schemaError(400, `origin_code must be one of ${ORIGIN_CODES.join(", ")}`, "origin_code_invalid");
  }

  // authors[] must have ≥1 entry per spec.
  if (!Array.isArray(input.authors) || input.authors.length === 0) {
    throw schemaError(400, "authors[] must have at least one entry", "authors_required");
  }
  const authors = input.authors.map(_normalizeAuthor);

  // attribution_mode defaults to SELF. Locked to the canonical enum
  // (SELF / EMPLOYED / HOSTED) — non-listed values reject so the
  // signed payload always carries a known mode.
  const attributionMode = input.attribution_mode == null
    ? ATTRIBUTION_MODES.SELF
    : input.attribution_mode;
  if (!ATTRIBUTION_MODE_VALUES.includes(attributionMode)) {
    throw schemaError(
      400,
      `attribution_mode must be one of ${ATTRIBUTION_MODE_VALUES.join(", ")}`,
      "attribution_mode_invalid",
    );
  }

  return {
    attribution_mode: attributionMode,
    authors,
    cna_version: CURRENT_CNA_VERSION,
    content_hash: ch,
    extras: _normalizeExtras(input.extras),
    origin_code: originCode,
    registered_urls: _normalizeRegisteredUrls(input.registered_urls),
    signer_tip_id: signerTipId,
  };
}

/**
 * Sign helper for clients (and tests). Same primitive as signBody —
 * pulled into the schema module so callers don't reach into
 * shared/crypto for it.
 */
function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

/**
 * Pure signature verifier — given a canonical payload, signature,
 * and public key, returns boolean. Doesn't do any DAG lookup or
 * schema-shape validation; that's the caller's job (or use verifyTx
 * for the full server-side entry).
 */
function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * Server-side high-level entry. Used by content-service (API time)
 * after content-hash recomputation and by commit-handler (consensus
 * replay) on every committed REGISTER_CONTENT tx.
 *
 *   1. Validate cna version matches
 *   2. Look up signer's identity on the DAG (no fallback per spec)
 *   3. Refuse if revoked
 *   4. Rebuild canonical payload from tx.data + the authoritative
 *      content_hash
 *   5. Verify ML-DSA-65 signature against DAG public key
 *
 * Returns { ok: true } on success, or
 * { ok: false, status, error, code } on any failure.
 */
/**
 * Resolve the signer's identity on the DAG and reject if missing or
 * revoked. Throws structured errors so the API layer can surface them
 * with the right HTTP status. Used by both API-time register and
 * consensus-replay verifyTx — single home for the "is this signer
 * authorised?" check.
 *
 * @param {string} signerTipId   the canonical signer TIP-ID
 * @param {Object} dag           dag adapter (getIdentity, isRevoked)
 * @returns {Object}             the identity record (has .public_key)
 */
function resolveSigner(signerTipId, dag) {
  const identity = dag.getIdentity(signerTipId);
  if (!identity) {
    throw schemaError(412, "Signer TIP-ID not registered on DAG", "signer_not_registered");
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(signerTipId)) {
    throw schemaError(403, "Signer TIP-ID is revoked", "signer_revoked");
  }
  return identity;
}

function verifyTx(tx, dag) {
  const d = tx.data || {};

  // Accept any whitelisted version — old committed txs (signed under
  // a previous version) must keep verifying forever for replay
  // correctness. New submissions are gated to CURRENT_CNA_VERSION at API time.
  if (d.cna_version && !SUPPORTED_CNA_VERSIONS.includes(d.cna_version)) {
    return { ok: false, status: 422, error: `Unsupported cna_version: ${d.cna_version}`, code: "cna_unsupported" };
  }
  if (typeof d.signature !== "string") {
    return { ok: false, status: 400, error: "signature missing on tx", code: "signature_missing" };
  }
  if (!d.signer_tip_id) {
    return { ok: false, status: 400, error: "signer_tip_id missing", code: "signer_tip_id_missing" };
  }

  let identity;
  let payload;
  try {
    identity = resolveSigner(d.signer_tip_id, dag);
    payload = buildSigningPayload(d, d.content_hash);
    _checkAuthorsRegistered(payload.authors, dag);
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }

  if (!verifySignature(payload, d.signature, identity.public_key)) {
    return { ok: false, status: 403, error: "Content signature verification failed", code: "signature_invalid" };
  }

  return { ok: true };
}

module.exports = {
  TX_TYPE,
  CURRENT_CNA_VERSION,
  SUPPORTED_CNA_VERSIONS,
  AUTHOR_KEYS,
  ORIGIN_CODES,
  validateRequest,
  resolveSigner,
  buildSigningPayload,
  sign,
  verifySignature,
  verifyTx,
  // GH #51 — unified signature contract
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
  SUBJECT_TIP_ID_FIELD,
  // Re-export for tests / debug:
  canonicalJson,
  payloadHashHex,
};
