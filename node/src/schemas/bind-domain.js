/**
 * @file @tip-protocol/node/src/schemas/bind-domain.js
 * @description Canonical schema for `BIND_DOMAIN` / `UNBIND_DOMAIN` — the
 * NODE-ATTESTED DAG tx that records a verified domain binding.
 *
 * Trust model:
 *   - The USER signs a claim {claimed_at, domain, method, tip_id}
 *     (schemas/register-domain.js) — proves they own the TIP-ID.
 *   - The NODE independently verifies DNS / well-known proof, then signs
 *     {binding_state, claim_signature, claimed_at, domain, method,
 *      node_id, tip_id, verified_at} (this module) — proves a node
 *     observed proof at time T.
 *   - The BIND_DOMAIN tx carries BOTH signatures. Replicating nodes
 *     verify both at commit time but do NOT re-perform DNS / HTTP
 *     (non-deterministic across nodes / time). Periodic re-verification
 *     lands as its own consensus-emitted tx in a follow-up.
 *
 * Quick summary of the 8 signed fields (alphabetical):
 *
 *   binding_state    string,  required (verified | revoked)
 *   claim_signature  string,  required (user's ML-DSA hex over the register-domain payload)
 *   claimed_at       string,  required (ISO8601 — from the original claim)
 *   domain           string,  required (lowercased)
 *   method           string,  required (http | dns | auto)
 *   node_id          string,  required (verifying node's TIP node_id)
 *   tip_id           string,  required (claimant)
 *   verified_at      string,  required (ISO8601 — when this node observed proof)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const {
  signPayload, verifyPayload, schemaError, canonicalJson,
} = require("./_common");
const {
  TX_TYPES, TIP_ID_TYPES,
  DOMAIN_BINDING_STATUS, DOMAIN_VERIFICATION_METHOD_VALUES,
  DOMAIN_UNBIND_REASON_VALUES,
} = require("../../../shared/constants");
const { isValidMs } = require("../../../shared/time");
const registerDomainSchema = require("./register-domain");

const TX_TYPE = TX_TYPES.BIND_DOMAIN;

// States that can appear on a committed binding tx. PENDING /
// VERIFICATION_FAILED / UNVERIFIED are statuses surfaced by the GET API and
// never themselves committed to the DAG.
const BIND_DOMAIN_STATES = Object.freeze([
  DOMAIN_BINDING_STATUS.VERIFIED,
  "revoked",
]);

/**
 * Build the canonical 8-field signed payload for a BIND_DOMAIN tx. All
 * fields always present, reject-on-extra: picks exactly these 8 keys.
 */
function buildSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (typeof input.tip_id !== "string" || !input.tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "tip_id is required", "tip_id_required");
  }
  if (typeof input.domain !== "string" || input.domain.length === 0) {
    throw schemaError(400, "domain is required", "domain_required");
  }
  if (typeof input.node_id !== "string" || input.node_id.length === 0) {
    throw schemaError(400, "node_id is required", "node_id_required");
  }
  if (!isValidMs(input.verified_at)) {
    throw schemaError(400, "verified_at must be a valid epoch ms timestamp", "verified_at_invalid");
  }
  if (!isValidMs(input.claimed_at)) {
    throw schemaError(400, "claimed_at must be a valid epoch ms timestamp", "claimed_at_invalid");
  }
  if (typeof input.claim_signature !== "string" || input.claim_signature.length === 0) {
    throw schemaError(400, "claim_signature is required", "claim_signature_required");
  }
  if (!DOMAIN_VERIFICATION_METHOD_VALUES.includes(input.method)) {
    throw schemaError(400, "method must be http | dns | auto", "method_invalid");
  }
  if (!BIND_DOMAIN_STATES.includes(input.binding_state)) {
    throw schemaError(
      400,
      `binding_state must be one of ${BIND_DOMAIN_STATES.join(", ")}`,
      "binding_state_invalid",
    );
  }

  return {
    binding_state: input.binding_state,
    claim_signature: input.claim_signature,
    claimed_at: input.claimed_at,
    domain: input.domain,
    method: input.method,
    node_id: input.node_id,
    tip_id: input.tip_id,
    verified_at: input.verified_at,
  };
}

function sign(payload, nodePrivateKeyHex, opts) {
  return signPayload(payload, nodePrivateKeyHex, opts);
}

function verifySignature(payload, signatureHex, publicKeyHex) {
  return verifyPayload(payload, signatureHex, publicKeyHex);
}

/**
 * Server-side high-level entry. Used by commit-handler on every committed
 * BIND_DOMAIN tx. Verifies:
 *
 *   1. Tx-level binding_signature is present
 *   2. Node that signed is registered + active on the DAG
 *   3. Canonical payload rebuilds deterministically
 *   4. Node's ML-DSA-65 signature verifies over the payload
 *   5. Claimant TIP-ID is registered, not revoked, and is an organization
 *   6. User's claim_signature verifies over the embedded register-domain
 *      sub-payload {claimed_at, domain, method, tip_id}
 *
 * Returns { ok: true } on success, or
 * { ok: false, status, error, code } on any failure.
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};

  if (typeof d.binding_signature !== "string") {
    return { ok: false, status: 400, error: "binding_signature missing on tx", code: "binding_signature_missing" };
  }
  if (!d.node_id) {
    return { ok: false, status: 400, error: "node_id missing", code: "node_id_missing" };
  }

  const node = dag.getNode(d.node_id);
  if (!node) {
    return { ok: false, status: 412, error: `Verifying node not registered: ${d.node_id}`, code: "node_not_registered" };
  }
  if (node.status !== "active") {
    return { ok: false, status: 403, error: `Verifying node not active: ${d.node_id}`, code: "node_inactive" };
  }

  let payload;
  try {
    payload = buildSigningPayload(d);
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }

  if (!verifySignature(payload, d.binding_signature, node.public_key)) {
    return { ok: false, status: 403, error: "Node binding signature verification failed", code: "binding_signature_invalid" };
  }

  // Claimant must still be an organization on the DAG at commit time —
  // revocation between submit and commit invalidates the binding.
  const identity = dag.getIdentity(d.tip_id);
  if (!identity) {
    return { ok: false, status: 412, error: `Claimant TIP-ID not registered: ${d.tip_id}`, code: "signer_not_registered" };
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(d.tip_id)) {
    return { ok: false, status: 403, error: `Claimant TIP-ID is revoked: ${d.tip_id}`, code: "signer_revoked" };
  }
  if ((identity.tip_id_type || TIP_ID_TYPES.PERSONAL) !== TIP_ID_TYPES.ORGANIZATION) {
    return { ok: false, status: 403, error: "Claimant TIP-ID is not an organization", code: "tip_id_not_authorised" };
  }

  // The original user-signed claim is bound into the BIND_DOMAIN tx so
  // replay-time verification re-establishes the full trust chain (user
  // → node) without needing the off-chain register call to still exist.
  const claimPayload = registerDomainSchema.buildSigningPayload({
    claimed_at: d.claimed_at,
    domain: d.domain,
    method: d.method,
    tip_id: d.tip_id,
  });
  if (!registerDomainSchema.verifySignature(claimPayload, d.claim_signature, identity.public_key)) {
    return { ok: false, status: 403, error: "User claim signature verification failed", code: "claim_signature_invalid" };
  }

  return { ok: true };
}

// ─── UNBIND_DOMAIN ──────────────────────────────────────────────────────────
// Sibling tx type. Emitted by node cascades today (revocation, lost
// verification, governance) — no user-facing endpoint in v1. Signed by the
// emitting node; replicating nodes verify the node sig and the canonical
// rebuild, same pattern as BIND_DOMAIN.
//
// Canonical 4-field signed payload (alphabetical):
//   domain     string,  required (lowercased)
//   node_id    string,  required (emitting node)
//   reason     string,  required (enum: see DOMAIN_UNBIND_REASONS)
//   revoked_at number,  required (epoch ms)
function buildUnbindSigningPayload(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "input must be an object", "input_invalid");
  }
  if (typeof input.domain !== "string" || input.domain.length === 0) {
    throw schemaError(400, "domain is required", "domain_required");
  }
  if (typeof input.node_id !== "string" || input.node_id.length === 0) {
    throw schemaError(400, "node_id is required", "node_id_required");
  }
  if (!isValidMs(input.revoked_at)) {
    throw schemaError(400, "revoked_at must be a valid epoch ms timestamp", "revoked_at_invalid");
  }
  if (!DOMAIN_UNBIND_REASON_VALUES.includes(input.reason)) {
    throw schemaError(
      400,
      `reason must be one of ${DOMAIN_UNBIND_REASON_VALUES.join(", ")}`,
      "reason_invalid",
    );
  }
  return {
    domain: input.domain,
    node_id: input.node_id,
    reason: input.reason,
    revoked_at: input.revoked_at,
  };
}

function signUnbind(payload, nodePrivateKeyHex, opts) {
  return signPayload(payload, nodePrivateKeyHex, opts);
}

/**
 * Server-side high-level entry for UNBIND_DOMAIN. Same shape as verifyTx:
 *   1. unbind_signature present
 *   2. Emitting node registered + active
 *   3. Canonical payload rebuilds deterministically
 *   4. Node's ML-DSA-65 signature verifies
 *   5. Domain has a current binding (otherwise unbind is a no-op / spurious)
 */
function verifyUnbindTx(tx, dag) {
  const d = tx.data || {};

  if (typeof d.unbind_signature !== "string") {
    return { ok: false, status: 400, error: "unbind_signature missing on tx", code: "unbind_signature_missing" };
  }
  if (!d.node_id) {
    return { ok: false, status: 400, error: "node_id missing", code: "node_id_missing" };
  }

  const node = dag.getNode(d.node_id);
  if (!node) {
    return { ok: false, status: 412, error: `Emitting node not registered: ${d.node_id}`, code: "node_not_registered" };
  }
  if (node.status !== "active") {
    return { ok: false, status: 403, error: `Emitting node not active: ${d.node_id}`, code: "node_inactive" };
  }

  let payload;
  try {
    payload = buildUnbindSigningPayload(d);
  } catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }

  if (!verifySignature(payload, d.unbind_signature, node.public_key)) {
    return { ok: false, status: 403, error: "Node unbind signature verification failed", code: "unbind_signature_invalid" };
  }

  const existing = dag.getDomainBinding(d.domain);
  if (!existing) {
    return { ok: false, status: 404, error: `No binding to unbind for ${d.domain}`, code: "domain_not_found" };
  }

  return { ok: true };
}

module.exports = {
  TX_TYPE,
  TX_TYPE_UNBIND: TX_TYPES.UNBIND_DOMAIN,
  BIND_DOMAIN_STATES,
  buildSigningPayload,
  buildUnbindSigningPayload,
  sign,
  signUnbind,
  verifySignature,
  verifyTx,
  verifyUnbindTx,
  canonicalJson,
};
