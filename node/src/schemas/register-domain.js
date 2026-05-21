/**
 * @file @tip-protocol/node/src/schemas/register-domain.js
 * @description Canonical schema for the USER-SIGNED domain claim.
 *
 * Used by POST /v1/domain/register. The caller proves they own the
 * TIP-ID by signing { claimed_at, domain, method, tip_id } (alphabetical,
 * SHAKE-256 → ASCII-hex bytes → ML-DSA-65). Identical pipeline to
 * REGISTER_CONTENT / REGISTER_IDENTITY signing.
 *
 * Claims are stored locally on the receiving node only — they are NOT
 * committed to the DAG. Only the node's BIND_DOMAIN tx (after independent
 * verification, see schemas/bind-domain.js) lands on the chain.
 *
 * Quick summary of the 4 signed fields (alphabetical):
 *
 *   claimed_at  string,  required (ISO8601 timestamp — replay-resistant binding)
 *   domain      string,  required (lowercased, normalised)
 *   method      string,  required (enum: http / dns / auto)
 *   tip_id      string,  required (tip://id/...)
 *
 * Org-only: the resolved identity MUST have tip_id_type === "organization".
 * Personal TIP-IDs cannot bind a domain — see my-notes/DOMAIN_VERIFICATION.md §2.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const {
  signPayload, verifyPayload, schemaError, canonicalJson,
} = require("./_common");
const {
  TIP_ID_TYPES, DOMAIN_VERIFICATION_METHODS, DOMAIN_VERIFICATION_METHOD_VALUES,
  DOMAIN_PENDING_CLAIM_TTL_MS,
} = require("../../../shared/constants");

// Domain shape: 1-63 char labels separated by dots, 1-253 total chars, no
// trailing dot, no consecutive dots. Permissive enough for IDN xn--... and
// strict enough to reject obvious junk before any DNS / HTTP work.
const DOMAIN_REGEX = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

// Dev-mode shapes: `localhost`, `localhost:PORT`, `127.0.0.1`, `127.0.0.1:PORT`.
// Only accepted when the dev flag is set (see _devAllowLocalhost). Production
// always rejects these so a misconfigured node can't bind a real domain to a
// loopback claim.
const LOCALHOST_REGEX = /^(localhost|127\.0\.0\.1)(:\d{1,5})?$/;

// Single guarded entry-point: NEVER takes effect in production. Both
// NODE_ENV != "production" AND the explicit opt-in flag are required. Same
// pattern as TIP_DEV_BYPASS_VOTE_WINDOWS in business-rules.js — keeps the
// dev surface obvious in code review.
function _devAllowLocalhost() {
  return process.env.NODE_ENV !== "production"
      && process.env.TIP_DEV_ALLOW_LOCALHOST_DOMAINS === "1";
}

/**
 * Normalise a user-supplied domain string. Lowercases (DNS is case-insensitive)
 * and strips any trailing dot. Throws schemaError(400, ..., "domain_invalid")
 * for malformed input.
 *
 * Dev-mode (TIP_DEV_ALLOW_LOCALHOST_DOMAINS=1 + NODE_ENV != production): also
 * accepts `localhost`, `localhost:PORT`, `127.0.0.1`, `127.0.0.1:PORT` so the
 * full register/verify flow can be exercised against a local well-known
 * server. The canonical-payload bytes carry the input verbatim, so the
 * signature commits to "localhost" — clients running in prod against a
 * dev-mode node would still get a 400 here.
 */
function normalizeDomain(raw) {
  if (typeof raw !== "string" || raw.length === 0) {
    throw schemaError(400, "domain is required", "domain_required");
  }
  const d = raw.trim().toLowerCase().replace(/\.$/, "");
  if (DOMAIN_REGEX.test(d)) return d;
  if (_devAllowLocalhost() && LOCALHOST_REGEX.test(d)) return d;
  throw schemaError(400, `domain must be a valid hostname: ${raw}`, "domain_invalid");
}

/**
 * Non-throwing variant of normalizeDomain — returns true if the input
 * matches the production regex (or the loopback regex when dev-mode is on).
 * Used by tx-validator's L3 layer which accumulates errors instead of
 * throwing. Production regex stays the single source of truth.
 */
function isValidDomain(raw) {
  if (typeof raw !== "string" || raw.length === 0) return false;
  const d = raw.trim().toLowerCase().replace(/\.$/, "");
  if (DOMAIN_REGEX.test(d)) return true;
  if (_devAllowLocalhost() && LOCALHOST_REGEX.test(d)) return true;
  return false;
}

/**
 * Resolve the claiming identity on the DAG and reject if missing, revoked,
 * or non-organization. Throws structured errors so the route layer surfaces
 * them with the right HTTP status.
 */
function resolveClaimant(tipId, dag) {
  const identity = dag.getIdentity(tipId);
  if (!identity) {
    throw schemaError(412, `TIP-ID not registered on DAG: ${tipId}`, "signer_not_registered");
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(tipId)) {
    throw schemaError(403, `TIP-ID is revoked: ${tipId}`, "signer_revoked");
  }
  if ((identity.tip_id_type || TIP_ID_TYPES.PERSONAL) !== TIP_ID_TYPES.ORGANIZATION) {
    throw schemaError(
      403,
      "Domain binding requires an organization TIP-ID",
      "tip_id_not_authorised",
    );
  }
  return identity;
}

/**
 * Request-envelope validator for POST /v1/domain/register. Single gate —
 * runs before any crypto work. Covers shape, enum, DAG presence + org gate.
 * Returns the resolved identity record (carries .public_key) so the route
 * doesn't re-fetch.
 */
function validateRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (typeof body.tip_id !== "string" || !body.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required (tip://id/...)", "tip_id_required");
  }
  if (typeof body.signature !== "string" || body.signature.length === 0) {
    throw schemaError(400, "signature is required", "signature_required");
  }
  if (typeof body.claimed_at !== "string" || Number.isNaN(body.claimed_at)) {
    throw schemaError(400, "claimed_at must be an ISO8601 timestamp", "claimed_at_invalid");
  }
  const method = body.method == null ? DOMAIN_VERIFICATION_METHODS.AUTO : body.method;
  if (!DOMAIN_VERIFICATION_METHOD_VALUES.includes(method)) {
    throw schemaError(
      400,
      `method must be one of ${DOMAIN_VERIFICATION_METHOD_VALUES.join(", ")}`,
      "method_invalid",
    );
  }
  const domain = normalizeDomain(body.domain);

  const identity = resolveClaimant(body.tip_id, deps.dag);
  return { identity, domain, method };
}

/**
 * Request-envelope validator for POST /v1/domain/verify. Single gate —
 * covers everything the service used to do inline:
 *   1. Body shape — domain present + normalisable
 *   2. Local state — pending claim exists for this domain on this node
 *   3. Pending claim hasn't expired (TTL = DOMAIN_PENDING_CLAIM_TTL_MS)
 *   4. Optional caller-supplied tip_id pin matches the claim's tip_id
 *   5. DAG presence — claimant still registered + active + organization
 *
 * Side-effect-free: a stale pending claim is reported via the structured
 * `claim_expired` code; the service decides whether to GC the row. The
 * `method` returned is the resolved override (caller body.method wins,
 * falls back to the claim's method, falls back to "auto").
 */
function validateVerifyRequest(body, deps) {
  if (!body || typeof body !== "object") {
    throw schemaError(400, "request body is required", "body_invalid");
  }
  if (typeof body.domain !== "string") {
    throw schemaError(400, "domain is required", "domain_required");
  }
  const domain = normalizeDomain(body.domain);

  const claim = deps.dag.getPendingDomainClaim(domain);
  if (!claim) {
    throw schemaError(
      400,
      `No pending claim for ${domain}; POST /v1/domain/register first`,
      "not_registered",
    );
  }
  if (claim.received_at + DOMAIN_PENDING_CLAIM_TTL_MS < Date.now()) {
    throw schemaError(
      400,
      `Pending claim for ${domain} expired; please re-register`,
      "claim_expired",
    );
  }
  // Optional pin: caller can specify which tip_id they intended to verify
  // (defends against a stale pending claim from a different identity).
  if (typeof body.tip_id === "string" && body.tip_id !== claim.tip_id) {
    throw schemaError(
      409,
      `Pending claim is for a different TIP-ID (${claim.tip_id})`,
      "tip_id_mismatch",
    );
  }

  // Identity resolution + org gate. Throws structured 412 / 403 if the
  // claimant no longer qualifies (revoked or somehow flipped to personal
  // between /register and /verify).
  const identity = resolveClaimant(claim.tip_id, deps.dag);

  // Method resolution: caller-supplied override > claim's stored method >
  // canonical default. Validate against the enum so a bad value fails fast.
  const method = body.method == null ? claim.method : body.method;
  if (!DOMAIN_VERIFICATION_METHOD_VALUES.includes(method)) {
    throw schemaError(
      400,
      `method must be one of ${DOMAIN_VERIFICATION_METHOD_VALUES.join(", ")}`,
      "method_invalid",
    );
  }

  return { claim, identity, domain, method };
}

/**
 * Build the canonical 4-field signed payload. All fields always present;
 * reject-on-extra: picks exactly these 4 keys.
 */
function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (typeof input.tip_id !== "string" || !input.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required", "tip_id_required");
  }
  if (typeof input.claimed_at !== "string" || Number.isNaN(input.claimed_at)) {
    throw schemaError(400, "claimed_at is required", "claimed_at_invalid");
  }
  const method = input.method == null ? DOMAIN_VERIFICATION_METHODS.AUTO : input.method;
  if (!DOMAIN_VERIFICATION_METHOD_VALUES.includes(method)) {
    throw schemaError(
      400,
      `method must be one of ${DOMAIN_VERIFICATION_METHOD_VALUES.join(", ")}`,
      "method_invalid",
    );
  }
  const domain = normalizeDomain(input.domain);

  return {
    claimed_at: input.claimed_at,
    domain,
    method,
    tip_id: input.tip_id,
  };
}

function sign(payload, privateKeyHex, opts) {
  return signPayload(payload, privateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

module.exports = {
  DOMAIN_REGEX,
  normalizeDomain,
  isValidDomain,
  resolveClaimant,
  validateRequest,
  validateVerifyRequest,
  buildSigningPayload,
  sign,
  verifySignature,
  canonicalJson,
};
