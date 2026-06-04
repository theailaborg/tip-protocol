/**
 * @file @tip-protocol/node/src/services/media-service.js
 * @description Node-side media upload + retrieval service. Sits between the
 * HTTP routes and the storage backend.
 *
 * Validation split (matches the project's per-endpoint validation rule):
 *   - SHAPE / format validation → `schemas/media-upload.js` validateRequest
 *   - Business-rule checks (identity active / signature verifies / size limit)
 *     stay here because they need DAG + crypto state.
 *
 * Returns the storage `media_id` (SHA3-256, content-addressed dedup key)
 * plus the protocol-level `content_hash` (SHAKE-256, used by CNA-MIX-1 to
 * combine with text at REGISTER_CONTENT time).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256, mldsaVerify } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { schemaError } = require("../schemas/_common");
const mediaUploadSchema = require("../schemas/media-upload");

function createMediaService({ storage, dag, log }) {
  if (!storage) throw new Error("media-service: storage required");
  if (!dag) throw new Error("media-service: dag required");
  const logger = log || console;

  async function upload(input) {
    // ALL request-level validation lives in the schema module (shape, mime
    // family, size limit, replay window). Service handles only the
    // business-rule checks that need DAG / crypto state.
    mediaUploadSchema.validateRequest(input);

    const { bytes, mime, signer_tip_id, signature, timestamp } = input;

    // Identity must exist, be active, and not be revoked.
    const identity = dag.getIdentity(signer_tip_id);
    if (!identity) throw schemaError(404, `Unknown signer: ${signer_tip_id}`, "signer_not_found");
    if (identity.status !== "active") throw schemaError(403, `Signer not active: ${signer_tip_id}`, "signer_inactive");
    if (dag.isRevoked(signer_tip_id)) throw schemaError(403, `Signer revoked: ${signer_tip_id}`, "signer_revoked");

    // Verify the author signed the upload challenge. content_hash is
    // shake256(bytes) — same value used as the storage media_id, so we
    // pass it down to storage to skip a rehash.
    const contentHash = shake256(bytes);
    const challenge = mediaUploadSchema.buildChallenge({
      content_hash: contentHash, mime, timestamp, signer_tip_id,
    });
    if (!mldsaVerify(challenge, signature, identity.public_key)) {
      throw schemaError(403, "Upload signature verification failed", "signature_invalid");
    }

    // Store. media_id == content_hash by construction (both shake256).
    const { media_id, size } = await storage.put(bytes, { mime, contentHash });
    const uploaded_at = nowMs();

    logger.info?.(`media-upload: ${signer_tip_id} → media_id=${media_id} mime=${mime} size=${size}`);
    // content_hash field kept for caller clarity even though it equals
    // media_id — REGISTER_CONTENT consumers think in terms of content_hash
    // (CNA-MIX-1 binding), and the duplication makes that contract explicit.
    return { media_id, content_hash: contentHash, mime, size, uploaded_at, signer_tip_id };
  }

  async function fetchBytes(mediaId) {
    return storage.get(mediaId);
  }

  async function presignedGet(mediaId, opts) {
    return storage.presignedGet(mediaId, opts);
  }

  async function head(mediaId) {
    return storage.head(mediaId);
  }

  async function deleteMedia(mediaId) {
    return storage.delete(mediaId);
  }

  return { upload, fetchBytes, presignedGet, head, delete: deleteMedia };
}

module.exports = { createMediaService };
