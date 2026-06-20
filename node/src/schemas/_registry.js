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
  // tx_type is in the signed payload so a captured signature for one revoke
  // type can't be replayed as another. reason_code + evidence_hash are
  // conditional. GH #85: the strip rule lives in buildSignedPayload (omit
  // undefined+null; keep "",0,false) so it can't drift from verifyBodySignature.
  buildSigningPayload: (data) => buildSignedPayload(data, {
    required: ["tx_type", "tip_id", "issuing_vp_id"],
    optional: ["reason_code", "evidence_hash"],
  }),
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
    // GH #85: route through the shared strip rule so a missing required field
    // throws at sign-time instead of silently signing a short payload.
    buildSigningPayload: (data) => buildSignedPayload(data, {
      required: ["verifier_tip_id", "ctid", "verdict"],
    }),
  },

  [TX_TYPES.UPDATE_ORIGIN]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
    SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.AUTHOR_TIP_ID,
    buildSigningPayload: (data) => buildSignedPayload(data, {
      required: ["author_tip_id", "ctid", "new_origin_code"],
    }),
  },

  [TX_TYPES.CONTENT_RETRACTED]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
    SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.AUTHOR_TIP_ID,
    buildSigningPayload: (data) => buildSignedPayload(data, {
      required: ["author_tip_id", "ctid"],
    }),
  },

  [TX_TYPES.JURY_VOTE_COMMIT]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.SUBJECT,
    SUBJECT_TIP_ID_FIELD: TIP_ID_FIELDS.JUROR_TIP_ID,
    buildSigningPayload: (data) => buildSignedPayload(data, {
      required: ["juror_tip_id", "commitment", "ctid", "is_appeal"],
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
      required: ["juror_tip_id", "vote", "salt", "ctid", "is_appeal"],
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
        // ctid is in the signed payload for replay protection: an
        // appellant_tip_id-only signature could be replayed against any
        // other ctid the same appellant has standing on (author or original
        // disputer), burning their stake on a case they never chose to
        // appeal. Mirrors prescan-review-dispute binding ctid + review_id.
        buildSigningPayload: (data) => buildSignedPayload(data, {
          required: ["appellant_tip_id", "ctid"],
        }),
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
          required: ["disputer_tip_id", "reason", "ctid"],
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
      // Reconstruct the cosigner body via the escalation endpoint's own
      // canonical builder (same {author_tip_id, ctid, review_id} the
      // creator signed) so the two definitions can't drift — same pattern
      // as BIND_DOMAIN / LINK_PLATFORM delegating to their register schemas.
      // Lazy require: prescan-review-dispute pulls in _common, which lazily
      // points back here; deferring the load avoids a load-order cycle.
      const prescanReviewDispute = require("./prescan-review-dispute");
      return [{
        kind: SIGNED_BY_KIND.SUBJECT,
        ref: escalator,
        body: prescanReviewDispute.buildSigningPayload({
          author_tip_id: escalator,
          ctid: d.ctid,
          review_id: d.source_review_id,
        }),
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
    buildSigningPayload: (data) => buildSignedPayload(
      { ...data, algorithm: data.algorithm ?? "ml-dsa-65" },
      { required: ["algorithm", "approving_vp_id", "jurisdiction", "jurisdiction_tier", "name", "public_key"] },
    ),
  },
  [TX_TYPES.NODE_REGISTERED]: {
    SIGNATURE_SCOPE: SIGNATURE_SCOPE.BODY,
    SIGNED_BY: SIGNED_BY_KIND.VP,
    VP_ID_FIELD: VP_ID_FIELDS.APPROVING_VP_ID,
    // api_endpoint is optional — omitted on legacy txs; included in
    // canonical bytes only when present so old committed txs keep
    // verifying byte-for-byte. GH #85: null/undefined is stripped by
    // buildSignedPayload, preserving the "omit on missing" behaviour.
    buildSigningPayload: (data) => buildSignedPayload(
      { ...data, algorithm: data.algorithm ?? "ml-dsa-65" },
      { required: ["algorithm", "approving_vp_id", "name", "public_key"], optional: ["api_endpoint"] },
    ),
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
    buildSigningPayload: (data) => buildSignedPayload(data, {
      required: ["domain", "node_id", "reason", "revoked_at"],
    }),
  },
});

module.exports = {
  TX_SIGNATURE_REGISTRY,
  NODE_ENVELOPE,
  REVOKE_CONTRACT,
};
