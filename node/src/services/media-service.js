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

const fsSync = require("fs");
const fs = require("fs/promises");
const path = require("path");
const { randomUUID } = require("crypto");
const { pipeline } = require("stream/promises");
const { Transform } = require("stream");
const { shake256, shake256Incremental, mldsaVerify } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { schemaError } = require("../schemas/_common");
const mediaUploadSchema = require("../schemas/media-upload");
const mediaAccessSchema = require("../schemas/media-access");
const { canAccessMedia } = require("./media-access-policy");

function createMediaService({ storage, dag, log, selfNodeId = null }) {
  if (!storage) throw new Error("media-service: storage required");
  // dag is optional: read-only callers (worker fetch path) don't need
  // identity / revocation lookups. upload() will assert dag itself.
  const logger = log || console;

  // Existence + mime-match validation for a media[] list referenced by
  // a REGISTER_CONTENT request. Dedupes on media_id (HEAD already cheap,
  // but skipping the re-check keeps the canonical list 1:1 with the
  // signed media_canonical_hash derivation). Returns the canonical
  // [{media_id, mime}] form callers persist to tx.data + queue payload.
  // Throws structured 404/400 so the HTTP layer surfaces clean codes.
  async function resolveRefs(media) {
    if (!Array.isArray(media) || media.length === 0) return [];
    const resolved = [];
    const seen = new Set();
    for (let i = 0; i < media.length; i++) {
      const m = media[i];
      if (seen.has(m.media_id)) continue;
      seen.add(m.media_id);
      const head = await storage.head(m.media_id);
      if (!head || !head.exists) {
        throw schemaError(404, `media[${i}] not found in storage: ${m.media_id}`, "media_not_found");
      }
      const claimed = String(m.mime).toLowerCase();
      const actual = String(head.mime).toLowerCase();
      if (claimed !== actual) {
        throw schemaError(
          400,
          `media[${i}] mime mismatch: client claims "${m.mime}" but stored object is "${head.mime}"`,
          "media_mime_mismatch",
        );
      }
      resolved.push({ media_id: m.media_id, mime: actual });
    }
    return resolved;
  }

  // Fetch bytes for each ref and return [{base64, mime}] — the shape the
  // classifier-client's `file` param expects. Order preserved so the
  // worker's text+media[0] convention still holds. Throws on the first
  // missing object — worker treats this as hard failure (retry/fail-open).
  async function fetchForClassifier(media) {
    if (!Array.isArray(media) || media.length === 0) return [];
    return Promise.all(media.map(async (m, i) => {
      const got = await storage.get(m.media_id);
      if (!got || !got.bytes) {
        throw new Error(`media-service: media[${i}] not found in storage: ${m.media_id}`);
      }
      return { base64: got.bytes.toString("base64"), mime: m.mime || got.mime };
    }));
  }

  async function upload(input) {
    if (!dag) throw new Error("media-service.upload: dag required");
    // Schema owns ALL request-level checks: shape, mime family, size
    // limit, replay window, DAG presence (signer exists / active / not
    // revoked). Service keeps only the signature verification.
    // Returns the mime DETECTED from the bytes' magic numbers — the
    // claimed mime stays in the signed challenge but never reaches
    // storage, caps, or the classifier. Bytes are the source of truth.
    const detectedMime = mediaUploadSchema.validateRequest(input, { dag });

    const { bytes, mime, signer_tip_id, signature, timestamp } = input;
    const identity = dag.getIdentity(signer_tip_id);  // guaranteed by schema

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

    if (detectedMime !== mime) {
      logger.warn?.(`media-upload: claimed mime ${mime} != detected ${detectedMime} — storing detected (signer ${signer_tip_id})`);
    }

    // Store. media_id == content_hash by construction (both shake256).
    const { media_id, size } = await storage.put(bytes, { mime: detectedMime, contentHash });
    const uploaded_at = nowMs();

    logger.info?.(`media-upload: ${signer_tip_id} → media_id=${media_id} mime=${detectedMime} size=${size}`);
    // content_hash field kept for caller clarity even though it equals
    // media_id — REGISTER_CONTENT consumers think in terms of content_hash
    // (CNA-MIX-1 binding), and the duplication makes that contract explicit.
    // mime is the DETECTED type — clients must use this value in media[].
    return { media_id, content_hash: contentHash, mime: detectedMime, size, uploaded_at, signer_tip_id };
  }

  // Streaming upload — flat memory regardless of file size. The request
  // body flows: stream → incremental shake256 + byte counter → tmp file
  // on disk → (hash verified against the signed challenge) → backend
  // promote (fs rename / single S3 PUT from disk). The per-mime size cap
  // aborts the stream the moment it's exceeded, so an oversized body
  // costs at most `limit` bytes of disk and zero RAM growth.
  //
  // Trust model is identical to upload(): the client signs
  // MEDIA_UPLOAD:{content_hash}:{mime}:{ts}:{tip_id} BEFORE sending. The
  // server recomputes the hash from the bytes it actually received and
  // verifies the signature against THAT — a client can't claim bytes it
  // didn't send, and a transport corruption fails closed.
  async function uploadStream(input) {
    if (!dag) throw new Error("media-service.uploadStream: dag required");
    const { stream, mime, signer_tip_id, signature, timestamp } = input;
    if (!stream || typeof stream.pipe !== "function") {
      throw new Error("media-service.uploadStream: readable stream required");
    }
    // Schema: everything except the bytes (not arrived yet). The claim's
    // cap is only a provisional ceiling; the authoritative gate + cap come
    // from the mime DETECTED off the first bytes below.
    mediaUploadSchema.validateStreamRequest(input, { dag });
    const identity = dag.getIdentity(signer_tip_id);  // guaranteed by schema

    const dir = await storage.stagingDir();
    const tmpPath = path.join(dir, `upl-${randomUUID()}.part`);

    const hasher = shake256Incremental(32);
    let size = 0;
    let detectedMime = null;
    let sizeLimit = null;
    let sniffBuf = Buffer.alloc(0);
    const gauge = new Transform({
      transform(chunk, _enc, cb) {
        // Sniff the real type off the first bytes (magic numbers live in
        // the first 16). The detected mime — never the claim — drives the
        // family gate and the size cap, so a mislabeled upload can't dodge
        // a cap or store a wrong label.
        if (detectedMime === null) {
          sniffBuf = Buffer.concat([sniffBuf, chunk]);
          if (sniffBuf.length >= 16) {
            detectedMime = mediaUploadSchema.detectMime(sniffBuf);
            try {
              sizeLimit = mediaUploadSchema.limitForDetectedMime(detectedMime);
            } catch (err) {
              cb(err);
              return;
            }
            sniffBuf = Buffer.alloc(0);
          }
        }
        size += chunk.length;
        if (sizeLimit !== null && size > sizeLimit) {
          cb(schemaError(413, `File too large: exceeded ${sizeLimit} bytes mid-stream`, "file_too_large"));
          return;
        }
        hasher.update(chunk);
        cb(null, chunk);
      },
    });

    try {
      await pipeline(stream, gauge, fsSync.createWriteStream(tmpPath));
      if (size === 0) {
        throw schemaError(400, "bytes is required (non-empty body)", "bytes_required");
      }
      // Bodies under 16 bytes never triggered the in-flight sniff; no real
      // media is that small, and limitForDetectedMime(null) rejects 415.
      if (detectedMime === null) {
        detectedMime = mediaUploadSchema.detectMime(sniffBuf);
        sizeLimit = mediaUploadSchema.limitForDetectedMime(detectedMime);
      }
      if (detectedMime !== mime) {
        logger.warn?.(`media-upload(stream): claimed mime ${mime} != detected ${detectedMime} — storing detected (signer ${signer_tip_id})`);
      }

      const contentHash = hasher.digest("hex");
      const challenge = mediaUploadSchema.buildChallenge({
        content_hash: contentHash, mime, timestamp, signer_tip_id,
      });
      if (!mldsaVerify(challenge, signature, identity.public_key)) {
        throw schemaError(403, "Upload signature verification failed", "signature_invalid");
      }

      const { media_id } = await storage.promoteTmpFile(tmpPath, { contentHash, mime: detectedMime, size });
      const uploaded_at = nowMs();
      logger.info?.(`media-upload(stream): ${signer_tip_id} → media_id=${media_id} mime=${detectedMime} size=${size}`);
      // mime is the DETECTED type — clients must use this value in media[].
      return { media_id, content_hash: contentHash, mime: detectedMime, size, uploaded_at, signer_tip_id };
    } catch (err) {
      await fs.unlink(tmpPath).catch(() => { });
      throw err;
    }
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

  // Reviewer / juror / disputer / author fetch path. Returns one of:
  //
  //   { transport: "redirect", origin_node_id, origin_endpoint }
  //     — this node does not hold the bytes. Storage is PER-NODE (each
  //       operator pays for and serves their own bucket), so remote
  //       media is the normal case, not a fallback. origin_endpoint is
  //       the on-chain api_endpoint of the node that received the
  //       upload (null when that node hasn't announced one); the route
  //       307s there so the requester re-presents the same signed
  //       request against the node that has the bytes.
  //
  //   { transport: "stream", media_id, mime, bytes }
  //     — fs backend (or s3 with presigning disabled). Caller streams.
  //
  //   { transport: "presigned", media_id, mime, presigned_url, expires_at }
  //     — s3 backend. Caller returns the URL; reviewer fetches direct.
  //
  // Throws schemaError on validation / auth / policy failure. dag is
  // required for this path (identity + revocation + content lookups).
  async function fetchForReviewer(input) {
    if (!dag) throw new Error("media-service.fetchForReviewer: dag required");
    // Schema owns ALL request-level checks: shape, replay window, and
    // DAG presence (identity exists / active / not revoked). Service
    // only does the things that genuinely need both — signature verify
    // (canonical challenge + public_key lookup) and the policy gate.
    mediaAccessSchema.validateRequest(input, { dag });

    const { ctid, idx, requester_tip_id, signature, timestamp } = input;
    const identity = dag.getIdentity(requester_tip_id);  // guaranteed by schema

    const challenge = mediaAccessSchema.buildChallenge({ ctid, idx, timestamp, requester_tip_id });
    if (!mldsaVerify(challenge, signature, identity.public_key)) {
      throw schemaError(403, "Access signature verification failed", "signature_invalid");
    }

    // Policy: only authorized roles get past this point. Returns the role
    // tag for logging / observability when ops enable storage-layer logs.
    const policy = canAccessMedia(dag, ctid, requester_tip_id);
    if (!policy.ok) {
      throw schemaError(policy.status || 403, "Not authorised to fetch this media", policy.code);
    }

    const content = dag.getContent(ctid);
    const media = Array.isArray(content.media) ? content.media : [];
    if (idx >= media.length) {
      throw schemaError(404, `media index ${idx} out of range (have ${media.length})`, "media_idx_out_of_range");
    }
    const ref = media[idx];

    // Local probe first. If this node holds the bytes, serve. If not,
    // redirect to the node that received the upload — per-node buckets
    // mean media lives only on the registering node's storage.
    // content.prescan_assigned_node_id is set on every REGISTER_CONTENT
    // and replicated through consensus, so every node computes the same
    // redirect target; its api_endpoint comes off the on-chain nodes row
    // (announced via NODE_ENDPOINT_UPDATED).
    const localHead = await storage.head(ref.media_id);
    if (!localHead || !localHead.exists) {
      const origin = content.prescan_assigned_node_id || null;
      // No origin recorded, OR THIS node IS the origin → the bytes are
      // genuinely gone (retention sweep / deletion), not "ask another
      // node". Redirecting to ourselves would loop. Return 410 Gone.
      if (!origin || origin === selfNodeId) {
        throw schemaError(410, "Media no longer available (retention-expired or deleted)", "media_unavailable");
      }
      const originNode = typeof dag.getNode === "function" ? dag.getNode(origin) : null;
      return {
        transport: "redirect",
        origin_node_id: origin,
        origin_endpoint: originNode?.api_endpoint || null,
        role: policy.role,
      };
    }

    // s3 backend serves bytes via short-TTL presigned URL — saves the
    // node's bandwidth and lets clients pull directly from object store.
    // fs backend has no presigning; presignedGet returns null, caller
    // falls through to streaming.
    const presigned = await storage.presignedGet(ref.media_id);
    if (presigned) {
      return {
        transport: "presigned",
        media_id: ref.media_id,
        mime: localHead.mime,
        presigned_url: presigned,
        expires_at: nowMs() + ((storage.presignTtlSec || 300) * 1000),
        role: policy.role,
      };
    }

    const got = await storage.get(ref.media_id);
    if (!got || !got.bytes) {
      // Race: object disappeared between HEAD and GET (retention sweep
      // mid-request, or fs corruption). Surface as 410 — the content row
      // referenced media that's no longer available.
      throw schemaError(410, "Media bytes not available", "media_unavailable");
    }
    return {
      transport: "stream",
      media_id: ref.media_id,
      mime: got.mime,
      bytes: got.bytes,
      role: policy.role,
    };
  }

  return { upload, uploadStream, fetchBytes, presignedGet, head, delete: deleteMedia, resolveRefs, fetchForClassifier, fetchForReviewer };
}

module.exports = { createMediaService };
