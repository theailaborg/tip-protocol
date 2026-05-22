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

    // tx.data carries tip_id + every present known field + the signature.
    // Sparse: only fields the client supplied land here. Commit-handler
    // merges these into the identity row.
    const data = { tip_id: canonicalPayload.tip_id, signature: safeBody.signature };
    for (const field of updateProfileSchema.KNOWN_FIELD_NAMES) {
      if (canonicalPayload[field] !== undefined) data[field] = canonicalPayload[field];
    }

    const tx = withTxId({
      tx_type: TX_TYPES.UPDATE_PROFILE,
      timestamp,
      prev: dag.getRecentPrev(),
      data,
    });

    const validation = validateTransaction(tx, dag, {});
    if (!validation.valid) throw schemaError(400, validation.errors, "tx_validation_failed");

    submitTx(tx);

    log.info(`Profile update proposed: ${tipId} fields=[${Object.keys(data).filter(k => k !== "tip_id" && k !== "signature").join(",")}]`);

    return {
      tip_id: tipId,
      tx_id: tx.tx_id,
      timestamp,
      confirmation: "proposed",
      // Echo the updated fields so the client can confirm what landed.
      updated: Object.fromEntries(
        Object.keys(data)
          .filter(k => k !== "tip_id" && k !== "signature")
          .map(k => [k, data[k]]),
      ),
    };
  }

  function getProfile(tipId) {
    const identity = dag.getIdentity(tipId);
    if (!identity) throw schemaError(404, "TIP-ID not registered", "tip_id_not_registered");
    // Project the user-settable preference fields only — internal fields
    // (founding, region, etc.) are exposed through other identity endpoints.
    const profile = { tip_id: tipId };
    for (const field of updateProfileSchema.KNOWN_FIELD_NAMES) {
      profile[field] = !!identity[field];
    }
    return profile;
  }

  /**
   * Convenience over updateProfile that pins reviewer_consent. Body
   * shape: { signature, tip_id? }. Signature must cover the canonical
   * payload that updateProfile assembles (tip_id + reviewer_consent),
   * so the client signs the exact bytes the schema validates.
   *
   * Separate from updateProfile so the API surface reads cleanly
   * ("become a reviewer") instead of forcing clients to know about
   * the UPDATE_PROFILE tx shape.
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

  return { updateProfile, getProfile, becomeReviewer, stopReviewing };
}

module.exports = { createProfileService };
