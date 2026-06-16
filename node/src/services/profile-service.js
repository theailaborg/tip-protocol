/**
 * @file @tip-protocol/node/src/services/profile-service.js
 * @description Sparse profile-preference update. Single tx type
 * (UPDATE_PROFILE) for any user-settable identity field — adding new
 * preferences later is a one-field-in-the-schema addition, never a new
 * tx type.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { TX_TYPES } = require("../../../shared/constants");
const { nowMs } = require("../../../shared/time");
const { validateTransaction } = require("../validators/tx-validator");
const updateProfileSchema = require("../schemas/update-profile");
const { schemaError } = require("../schemas/_common");
const { withTxId } = require("./helpers");
const { log } = require("../logger");

function createProfileService({ dag, config, submitTx }) {

  function updateProfile(tipId, body) {
    // URL tip_id is authoritative — passed to validateRequest which
    // rejects a mismatched body.tip_id. Service stays thin; all checks
    // live in the schema module.
    const safeBody = { ...(body || {}), tip_id: (body && body.tip_id) ?? tipId };
    updateProfileSchema.validateRequest(safeBody, { dag, urlTipId: tipId });

    const identity = updateProfileSchema.resolveSubject(tipId, dag);

    // Server-side signature verification — schema module owns this
    // single source of truth. Same module the commit-handler will use
    // on consensus replay, so API time + replay can't drift.
    const canonicalPayload = updateProfileSchema.buildSigningPayload(safeBody);
    if (!updateProfileSchema.verifySignature(canonicalPayload, safeBody.signature, identity.public_key)) {
      throw schemaError(403, "Signature verification failed", "signature_invalid");
    }

    const timestamp = nowMs();

    // tx.data carries tip_id + every present known field. Sparse: only
    // fields the client supplied land here. Commit-handler merges these
    // into the identity row. Signature lives at tx.signature (GH #51).
    const data = { tip_id: canonicalPayload.tip_id };
    for (const field of updateProfileSchema.KNOWN_FIELD_NAMES) {
      if (canonicalPayload[field] !== undefined) data[field] = canonicalPayload[field];
    }

    const tx = withTxId({
      tx_type: TX_TYPES.UPDATE_PROFILE,
      timestamp,
      prev: dag.getRecentPrev(),
      data,
      signature: safeBody.signature,
    });

    const validation = validateTransaction(tx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(tx);

    log.info(`Profile update proposed: ${tipId} fields=[${Object.keys(data).filter(k => k !== "tip_id").join(",")}]`);

    return {
      tip_id: tipId,
      tx_id: tx.tx_id,
      timestamp,
      confirmation: "proposed",
      // Echo the updated fields so the client can confirm what landed.
      updated: Object.fromEntries(
        Object.keys(data)
          .filter(k => k !== "tip_id")
          .map(k => [k, data[k]]),
      ),
    };
  }

  function getProfile(tipId) {
    const identity = dag.getIdentity(tipId);
    if (!identity) throw schemaError(404, "TIP-ID not registered", "tip_id_not_registered");
    // Project the user-settable preference fields only — internal fields
    // (founding, region, etc.) are exposed through other identity endpoints.
    // Type-aware projection so arrays/objects survive (interests is an
    // array; reviewer_consent is a boolean).
    const profile = { tip_id: tipId };
    for (const field of updateProfileSchema.KNOWN_FIELD_NAMES) {
      const spec = updateProfileSchema.KNOWN_FIELDS[field];
      const raw = identity[field];
      if (spec.type === "boolean") {
        profile[field] = !!raw;
      } else if (spec.type === "object") {
        profile[field] = Array.isArray(raw) ? [...raw] : (raw ? { ...raw } : []);
      } else {
        profile[field] = raw === undefined ? null : raw;
      }
    }
    return profile;
  }

  /**
   * Convenience helpers that pin a single consent field. Body shape:
   * { signature, tip_id? }. The client signs the canonical payload
   * assembled by buildSigningPayload (tip_id + the single consent field).
   */
  function becomeReviewer(tipId, body) {
    return updateProfile(tipId, {
      tip_id: (body && body.tip_id) ?? tipId,
      reviewer_consent: true,
      signature: body && body.signature,
    });
  }

  function stopReviewing(tipId, body) {
    return updateProfile(tipId, {
      tip_id: (body && body.tip_id) ?? tipId,
      reviewer_consent: false,
      signature: body && body.signature,
    });
  }

  function becomeJuror(tipId, body) {
    return updateProfile(tipId, {
      tip_id: (body && body.tip_id) ?? tipId,
      juror_consent: true,
      signature: body && body.signature,
    });
  }

  function stopJuror(tipId, body) {
    return updateProfile(tipId, {
      tip_id: (body && body.tip_id) ?? tipId,
      juror_consent: false,
      signature: body && body.signature,
    });
  }

  function becomeExpert(tipId, body) {
    return updateProfile(tipId, {
      tip_id: (body && body.tip_id) ?? tipId,
      expert_consent: true,
      signature: body && body.signature,
    });
  }

  function stopExpert(tipId, body) {
    return updateProfile(tipId, {
      tip_id: (body && body.tip_id) ?? tipId,
      expert_consent: false,
      signature: body && body.signature,
    });
  }

  return { updateProfile, getProfile, becomeReviewer, stopReviewing, becomeJuror, stopJuror, becomeExpert, stopExpert };
}

module.exports = { createProfileService };
