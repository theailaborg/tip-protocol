/**
 * @file @tip-protocol/node/src/schemas/_registry.js
 * @description Signature contract registry for tx types that don't (yet)
 * have a full schema module. Same shape the schemas export — the
 * unified-signature dispatcher (`schemas/_common.js verifyTxSignature`)
 * checks for a schema module first and falls back here for any tx type
 * whose contract lives in this map.
 *
 * Why a registry, not a schema file per tx_type:
 *
 *   - Most node-emitted tx types (SCORE_UPDATE, ADJUDICATION_RESULT,
 *     JURY_SUMMONS, APPEAL_RESULT, AI_CLASSIFIER_RESULT) carry no
 *     per-tx-type business logic — their contract is just
 *     `{ SCOPE: ENVELOPE, SIGNED_BY: NODE }`. A full schema module
 *     for each would be ~95% boilerplate.
 *
 *   - Some body-signed tx types (UPDATE_ORIGIN, CONTENT_RETRACTED,
 *     CONTENT_VERIFIED, JURY_VOTE_*, REVOKE_*) have non-trivial body
 *     payloads but no validateRequest / state-machine logic that
 *     would warrant a schema file. Their `buildSigningPayload`
 *     lives here as a thin function.
 *
 * Promotion path: when a tx_type accumulates real schema-side logic
 * (validateRequest, resolveSubject, state-machine gates), promote the
 * registry entry into a full `schemas/<tx-type>.js` module. The
 * registry entry deletes; the schema file takes over. Always one-way
 * — never split a tx_type's contract across both registry and schema.
 *
 * Contract shape (mirrors what schema modules export):
 *
 *   - SIGNATURE_SCOPE    : SIGNATURE_SCOPE.ENVELOPE | SIGNATURE_SCOPE.BODY
 *   - SIGNED_BY          : SIGNED_BY_KIND.SUBJECT | NODE | VP
 *   - SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.* (only when SIGNED_BY = SUBJECT)
 *   - VP_ID_FIELD        : VP_ID_FIELDS.*    (only when SIGNED_BY = VP; defaults to VP_ID)
 *   - buildSigningPayload: (data) → canonical payload   (only when SCOPE = BODY)
 *   - getSignatureContract: (tx) → contract             (multi-mode tx types)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const {
  TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND, TIP_ID_FIELDS, VP_ID_FIELDS,
} = require("../../../shared/constants");

// ─── Node-signed envelope (no per-tx-type config) ──────────────────────────
// Auto-emitted by a node; the node signs canonicalTx(tx) with its own
// ML-DSA-65 key. tx.data.node_id identifies the verifying public key.
const NODE_ENVELOPE = Object.freeze({
  SIGNATURE_SCOPE: SIGNATURE_SCOPE.ENVELOPE,
  SIGNED_BY: SIGNED_BY_KIND.NODE,
});

// ─── REVOKE_* — VP attests revocation with issuing_vp_id ───────────────────
// All four revocation tx types share the same canonical payload. tx_type
// is included in the signed payload so a captured signature for one
// revocation type can't be replayed as a different one. evidence_hash
// is conditional — only added to the canonical payload when present
// (matches verifyBodySignature's "ignore undefined" behaviour at the
// signer; including it as `undefined` would canonicalise to the literal
// string "undefined" and diverge from the signer's bytes).
const REVOKE_CONTRACT = Object.freeze({
  SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
  SIGNED_BY: SIGNED_BY_KIND.VP,
  VP_ID_FIELD: VP_ID_FIELDS.ISSUING_VP_ID,
  buildSigningPayload: (data) => {
    const out = {
      tx_type: data.tx_type,                  // distinguishes revoke types
      tip_id: data.tip_id,
      reason_code: data.reason_code,
      issuing_vp_id: data.issuing_vp_id,
    };
    if (data.evidence_hash !== undefined && data.evidence_hash !== null) {
      out.evidence_hash = data.evidence_hash;
    }
    return out;
  },
});

const TX_SIGNATURE_REGISTRY = Object.freeze({
  // ─── Pure node-signed envelopes ───────────────────────────────────────────
  [TX_TYPES.SCORE_UPDATE]: NODE_ENVELOPE,
  [TX_TYPES.ADJUDICATION_RESULT]: NODE_ENVELOPE,
  [TX_TYPES.APPEAL_RESULT]: NODE_ENVELOPE,
  [TX_TYPES.JURY_SUMMONS]: NODE_ENVELOPE,
  [TX_TYPES.AI_CLASSIFIER_RESULT]: NODE_ENVELOPE,

  // ─── Subject-signed body sigs (CTID-bound replay protection) ─────────────
  [TX_TYPES.CONTENT_VERIFIED]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
    SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.VERIFIER_TIP_ID,
    buildSigningPayload: (data) => ({
      verifier_tip_id: data.verifier_tip_id,
      ctid: data.ctid,
      verdict: data.verdict,
    }),
  },

  [TX_TYPES.UPDATE_ORIGIN]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
    SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.AUTHOR_TIP_ID,
    buildSigningPayload: (data) => ({
      author_tip_id: data.author_tip_id,
      ctid: data.ctid,
      new_origin_code: data.new_origin_code,
    }),
  },

  [TX_TYPES.CONTENT_RETRACTED]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
    SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.AUTHOR_TIP_ID,
    buildSigningPayload: (data) => ({
      author_tip_id: data.author_tip_id,
      ctid: data.ctid,
    }),
  },

  [TX_TYPES.JURY_VOTE_COMMIT]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
    SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.JUROR_TIP_ID,
    // Note: ctid is NOT in the signed payload by design — the commitment
    // is already cryptographically bound to (vote, salt) via shake256
    // and the JURY_SUMMONS that allocated this juror locks the ctid.
    // Matches today's commit-handler verifier at the byte level.
    buildSigningPayload: (data) => ({
      juror_tip_id: data.juror_tip_id,
      commitment: data.commitment,
    }),
  },

  [TX_TYPES.JURY_VOTE_REVEAL]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
    SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.JUROR_TIP_ID,
    // confirmed_origin is conditional — only present when the juror's
    // vote is MISMATCH + the suggested origin (matches the
    // commit-handler verifier today; both sides drop the field when
    // truthy=false to keep the canonical bytes aligned).
    buildSigningPayload: (data) => {
      const out = {
        juror_tip_id: data.juror_tip_id,
        vote: data.vote,
        salt: data.salt,
      };
      if (data.confirmed_origin) out.confirmed_origin = data.confirmed_origin;
      return out;
    },
  },

  // ─── DUAL-MODE: appeal can be user-filed or auto-escalated ────────────────
  [TX_TYPES.APPEAL_FILED]: {
    getSignatureContract: (tx) => {
      // Auto-escalation marks itself with appellant_tip_id="SYSTEM_AUTO_ESCALATION".
      // User appeals carry a real tip_id.
      if (tx?.data?.appellant_tip_id === "SYSTEM_AUTO_ESCALATION") {
        return NODE_ENVELOPE;
      }
      return {
        SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
        SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
        SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.APPELLANT_TIP_ID,
        buildSigningPayload: (data) => ({ appellant_tip_id: data.appellant_tip_id }),
      };
    },
  },

  // ─── DUAL-MODE: dispute can be user-filed or auto-cascade ─────────────────
  // The auto-mode case ALSO carries an inner escalation_signature when
  // the escalator is a real user (Option 2 from a CONFIRMED review).
  // That secondary attestation stays on `tx.data.escalation_signature`
  // — it's a separate signer (the creator) whose signature is carried
  // forward as evidence-on-data, not the tx's own signature.
  [TX_TYPES.CONTENT_DISPUTED]: {
    getSignatureContract: (tx) => {
      if (tx?.data?.auto) {
        return NODE_ENVELOPE;
      }
      return {
        SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
        SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
        SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.DISPUTER_TIP_ID,
        buildSigningPayload: (data) => {
          // claimed_origin + evidence_hash are conditional. Mirror the
          // dispute-service.fileDispute + UI canonicalisation: only
          // emit when truthy. Listing them unconditionally would diverge
          // from the signer's canonical bytes (drift class observed in
          // #54 / #55 / #56).
          const out = {
            disputer_tip_id: data.disputer_tip_id,
            reason: data.reason,
          };
          if (data.claimed_origin) out.claimed_origin = data.claimed_origin;
          if (data.evidence_hash) out.evidence_hash = data.evidence_hash;
          return out;
        },
      };
    },
  },

  // ─── VP-signed body sigs ──────────────────────────────────────────────────
  [TX_TYPES.REVOKE_VOLUNTARY]: REVOKE_CONTRACT,
  [TX_TYPES.REVOKE_VP]: REVOKE_CONTRACT,
  [TX_TYPES.REVOKE_DECEASED]: REVOKE_CONTRACT,
  [TX_TYPES.REVOKE_DEVICE]: REVOKE_CONTRACT,

  // VP_REGISTERED / NODE_REGISTERED — council-style attestation by an
  // approving VP. Signed payload binds the new entity's identity to
  // the approving VP. Today's storage uses `data.council_signature` —
  // post-refactor moves to `tx.signature` at write time, same canonical
  // bytes.
  [TX_TYPES.VP_REGISTERED]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.VP,
    VP_ID_FIELD: VP_ID_FIELDS.APPROVING_VP_ID,
    buildSigningPayload: (data) => ({
      name: data.name,
      jurisdiction: data.jurisdiction,
      jurisdiction_tier: data.jurisdiction_tier,
      public_key: data.public_key,
      approving_vp_id: data.approving_vp_id,
    }),
  },
  [TX_TYPES.NODE_REGISTERED]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.VP,
    VP_ID_FIELD: VP_ID_FIELDS.APPROVING_VP_ID,
    buildSigningPayload: (data) => ({
      name: data.name,
      public_key: data.public_key,
      approving_vp_id: data.approving_vp_id,
    }),
  },

  // ─── COMMITTEE_ROTATION ───────────────────────────────────────────────────
  // Aggregate-signed exception to the single-tx.signature model. The
  // 2f+1 prev-committee sigs over `data.payload_hash` live in
  // `data.signer_node_ids[]` + `data.signatures[]` and are verified by
  // `rules.canCommitteeRotation` from `_statefulCheck`. tx.signature
  // is NOT used: `tx_id` must be byte-identical across all honest
  // submitters (multi-aggregator submission, see #81), so the envelope
  // cannot carry a submitter-derived signature. The registry entry
  // shape stays here as a placeholder so the uniform-interface sweep
  // counts every TX_TYPES; the commit-handler dispatcher special-cases
  // this tx_type to gate on signature-array presence instead of
  // calling the unified dispatcher. See the docstring on
  // `_verifyTxSignature` in commit-handler.js for the full rationale.
  [TX_TYPES.COMMITTEE_ROTATION]: NODE_ENVELOPE,

  // UNBIND_DOMAIN — currently delegated to bind-domain.verifyUnbindTx
  // (subject-signed body, same identity that holds the binding). Same
  // SUBJECT_TIP_ID_FIELD as BIND_DOMAIN. Promote to a registry entry
  // here so the unified dispatcher can route to it without the
  // schemaForTxType wiring having to special-case bind-domain.
  [TX_TYPES.UNBIND_DOMAIN]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
    SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.TIP_ID,
    buildSigningPayload: (data) => ({
      tip_id: data.tip_id,
      domain: data.domain,
      reason: data.reason,
      claimed_at: data.claimed_at,
    }),
  },
});

module.exports = {
  TX_SIGNATURE_REGISTRY,
  NODE_ENVELOPE,
  REVOKE_CONTRACT,
};
