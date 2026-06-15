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
// GH #85: the single canonical strip rule (omit undefined+null; keep "", 0,
// false). Every buildSigningPayload routes through this so the rule can't drift.
const { buildSignedPayload } = require("../../../shared/crypto");

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
      issuing_vp_id: data.issuing_vp_id,
    };
    // reason_code and evidence_hash are conditional — only added when present.
    // canonicalJson renders undefined as the literal string "undefined", which
    // diverges from verifyBodySignature's "skip undefined" behaviour at the
    // signer and breaks consensus-level signature replay.
    if (data.reason_code !== undefined && data.reason_code !== null) {
      out.reason_code = data.reason_code;
    }
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
  // Async-prescan worker verdict — node-signed envelope; carries
  // probability + tier + per-modality breakdown.
  [TX_TYPES.PRESCAN_COMPLETED]: NODE_ENVELOPE,
  // Node updating its own public API base URL. data.node_id is both
  // subject and signer — the envelope only verifies under that node's
  // registered key, so self-update is enforced by the signature itself.
  [TX_TYPES.NODE_ENDPOINT_UPDATED]: NODE_ENVELOPE,

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
    // vote is MISMATCH + the suggested origin. GH #85: the strip rule lives
    // in buildSignedPayload (omit undefined+null; keep "", 0, false).
    buildSigningPayload: (data) => buildSignedPayload(data, {
      required: ["juror_tip_id", "vote", "salt"],
      optional: ["confirmed_origin"],
    }),
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
  // When auto=true AND a real creator escalated (Option 2 from a
  // CONFIRMED review), the creator's authorising signature rides as a
  // cosignature entry on tx.data.cosignatures (signer_kind=subject,
  // signer_ref=<escalator tip_id>). Pure system auto-escalations
  // (h=R+24) have no cosigner.
  [TX_TYPES.CONTENT_DISPUTED]: {
    getSignatureContract: (tx) => {
      if (tx?.data?.auto) {
        return NODE_ENVELOPE;
      }
      return {
        SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
        SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
        SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.DISPUTER_TIP_ID,
        // claimed_origin + evidence_hash are conditional. GH #85: the strip
        // rule lives in buildSignedPayload (omit undefined+null; keep "",0,false).
        buildSigningPayload: (data) => buildSignedPayload(data, {
          required: ["disputer_tip_id", "reason"],
          optional: ["claimed_origin", "evidence_hash"],
        }),
      };
    },
    // Cosignature contract — used by commit-handler to verify the
    // creator's authorisation on a manual auto-escalation. Returns []
    // for system auto-escalations and user-filed disputes (no
    // additional signer).
    getCosignatureContract: (tx) => {
      const d = tx?.data || {};
      if (!d.auto) return [];
      const escalator = d.escalated_by_tip_id;
      if (!escalator) return [];
      return [{
        kind: SIGNED_BY_KIND.SUBJECT,
        ref:  escalator,
        body: {
          author_tip_id: escalator,
          ctid:          d.ctid,
          review_id:     d.source_review_id,
        },
      }];
    },
  },

  // ─── VP-signed body sigs ──────────────────────────────────────────────────
  [TX_TYPES.REVOKE_VOLUNTARY]: REVOKE_CONTRACT,
  [TX_TYPES.REVOKE_VP]: REVOKE_CONTRACT,
  [TX_TYPES.REVOKE_DECEASED]: REVOKE_CONTRACT,
  [TX_TYPES.REVOKE_DEVICE]: REVOKE_CONTRACT,

  // VP_REGISTERED / NODE_REGISTERED — council-style attestation by an
  // approving VP. Signed payload binds the new entity's (key, algorithm)
  // pair to the approving VP. Signature lives at `tx.signature`
  // (GH #51). GH #60: `algorithm` is part of the canonical bytes so
  // the approving VP attests to the algorithm choice, not just the
  // pubkey. Default ml-dsa-65 when client omits.
  [TX_TYPES.VP_REGISTERED]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.VP,
    VP_ID_FIELD: VP_ID_FIELDS.APPROVING_VP_ID,
    buildSigningPayload: (data) => ({
      // GH #85: ?? instead of || so algorithm="" is not silently promoted
      // to the default; only null/undefined fall back to "ml-dsa-65".
      algorithm: data.algorithm ?? "ml-dsa-65",
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
      // GH #85: ?? instead of || so algorithm="" is not silently promoted
      // to the default; only null/undefined fall back to "ml-dsa-65".
      algorithm: data.algorithm ?? "ml-dsa-65",
      name: data.name,
      public_key: data.public_key,
      approving_vp_id: data.approving_vp_id,
      // Optional — the node's public API base URL. Peers use it for
      // cross-node media redirects (per-node S3 buckets mean bytes live
      // only on the upload-receiving node). Omitted on legacy txs;
      // included in canonical bytes only when present so old committed
      // txs keep verifying byte-for-byte.
      ...(data.api_endpoint ? { api_endpoint: data.api_endpoint } : {}),
    }),
  },

  // ─── COMMITTEE_ROTATION ───────────────────────────────────────────────────
  // Aggregate-signed exception to the single-tx.signature model. The
  // 2f+1 prev-committee sigs over `data.payload_hash` ride as cosignatures
  // on tx.data.cosignatures (signer_kind=node, signer_ref=node_id) and
  // are verified by `rules.canCommitteeRotation` from `_statefulCheck`
  // (NOT via the generic cosignatures dispatcher — rotation has
  // domain-specific quorum + prev-committee membership checks). tx.signature
  // is NOT used: `tx_id` must be byte-identical across all honest
  // submitters (multi-aggregator submission), so the envelope cannot
  // carry a submitter-derived signature. The registry entry stays here
  // as a placeholder so the uniform-interface sweep counts every TX_TYPES;
  // the commit-handler dispatcher special-cases this tx_type to gate on
  // cosignatures presence instead of calling the unified dispatcher.
  [TX_TYPES.COMMITTEE_ROTATION]: NODE_ENVELOPE,

  // UNBIND_DOMAIN — node-emitted on revocation / lost verification /
  // governance cascade. Signed by the emitting node over the canonical
  // 4-field unbind payload. Mirrors bind-domain.buildUnbindSigningPayload
  // exactly (same canonical bytes the schema sign helper produces).
  [TX_TYPES.UNBIND_DOMAIN]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.NODE,
    buildSigningPayload: (data) => ({
      domain: data.domain,
      node_id: data.node_id,
      reason: data.reason,
      revoked_at: data.revoked_at,
    }),
  },
});

module.exports = {
  TX_SIGNATURE_REGISTRY,
  NODE_ENVELOPE,
  REVOKE_CONTRACT,
};
