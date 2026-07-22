/**
 * @file @tip-protocol/node/src/services/chunked-upload-service.js
 * @description Chunked media upload service using S3 multipart uploads.
 *
 * Security model is identical to the single-shot upload:
 *   - Client signs MEDIA_UPLOAD:{content_hash}:{mime}:{timestamp}:{tip_id}
 *     where content_hash is the SHAKE-256 of the full file.
 *   - Server verifies the signature at session init.
 *   - Server hashes chunks incrementally as they arrive.
 *   - Server verifies the final hash matches the signed challenge before
 *     completing the S3 multipart upload.
 *
 * Design choices:
 *   - Chunks are processed sequentially in file order. This keeps the
 *     incremental hasher state simple and avoids temporary reassembly storage.
 *   - Each chunk is streamed directly to S3 as a multipart part; no local
 *     disk is used for staging or reassembly.
 *   - Signature verification is offloaded to the crypto worker pool when
 *     available, so uploads do not block consensus crypto.
 *
 * Trade-off: if the node process restarts, in-flight hasher state is lost.
 * The client can simply restart the upload (Resumable.js handles this).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256Incremental, mldsaVerify } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { schemaError } = require("../schemas/_common");
const mediaUploadSchema = require("../schemas/media-upload");

const DEFAULT_CHUNK_SIZE = 10 * 1024 * 1024; // 10 MB
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 h

function _resolveSessionTtlMs() {
  const raw = parseInt(process.env.TIP_CHUNKED_UPLOAD_SESSION_TTL_MS || "", 10);
  return Number.isInteger(raw) && raw > 0 ? raw : DEFAULT_SESSION_TTL_MS;
}

function createChunkedUploadService({
  storage,
  dag,
  cryptoPoolRef = { current: null },
  log = console,
  chunkSize = DEFAULT_CHUNK_SIZE,
  sessionTtlMs = _resolveSessionTtlMs(),
}) {
  if (!storage) throw new Error("chunked-upload-service: storage required");
  if (!dag) throw new Error("chunked-upload-service: dag required");

  // In-memory hasher state per session. Cannot be serialized to Postgres,
  // so a node restart aborts in-progress uploads. Clients retry via Resumable.js.
  const _hashers = new Map();

  function _objectKey(contentHash) {
    return `media/${contentHash.slice(0, 2)}/${contentHash.slice(2)}.bin`;
  }

  async function _verifySignature({ challenge, signature, publicKey }) {
    // Prefer crypto worker pool when available; fall back to sync verify.
    const pool = cryptoPoolRef && cryptoPoolRef.current ? cryptoPoolRef.current : null;
    if (pool && typeof pool.verifyRaw === "function") {
      const ok = await pool.verifyRaw([{
        message: challenge,
        signature,
        publicKey,
        algorithm: "ML-DSA-65",
      }]);
      if (ok) return true;
      // If worker returns false, fall through to sync verify to rule out
      // pool bugs. A bad signature will still return false.
    }
    return mldsaVerify(challenge, signature, publicKey);
  }

  async function init({
    mime,
    size,
    content_hash: contentHash,
    signer_tip_id: signerTipId,
    signature,
    timestamp,
  }) {
    if (!contentHash || !/^[0-9a-f]{64}$/.test(contentHash)) {
      throw schemaError(400, "content_hash must be 64-char lowercase hex", "content_hash_invalid");
    }
    if (!Number.isInteger(size) || size <= 0) {
      throw schemaError(400, "size must be a positive integer", "size_invalid");
    }

    // Schema validates mime family, signer shape, timestamp drift, identity.
    const sizeLimit = mediaUploadSchema.validateStreamRequest({
      mime, signer_tip_id: signerTipId, signature, timestamp,
    }, { dag });

    if (size > sizeLimit) {
      throw schemaError(413, `File size ${size} exceeds ${sizeLimit} bytes`, "file_too_large");
    }

    const identity = dag.getIdentity(signerTipId);
    const challenge = mediaUploadSchema.buildChallenge({
      content_hash: contentHash, mime, timestamp, signer_tip_id: signerTipId,
    });
    const ok = await _verifySignature({ challenge, signature, publicKey: identity.public_key });
    if (!ok) {
      throw schemaError(403, "Upload signature verification failed", "signature_invalid");
    }

    if (storage.backend !== "s3") {
      throw schemaError(400, "Chunked upload requires s3 media backend", "backend_not_supported");
    }

    const { upload_id: uploadId, key: s3Key } = await storage.createMultipartUpload(contentHash, mime);

    const sessionId = dag.generateUploadSessionId();
    const now = nowMs();
    const session = {
      session_id: sessionId,
      upload_id: uploadId,
      s3_key: s3Key,
      content_hash: contentHash,
      mime,
      size,
      signer_tip_id: signerTipId,
      timestamp,
      signature,
      parts: [],
      completed_size: 0,
      created_at: now,
      expires_at: now + sessionTtlMs,
    };

    await dag.createUploadSession(session);

    const hasher = shake256Incremental(32);
    let detectedMime = null;
    _hashers.set(sessionId, { hasher, detectedMime });

    const totalChunks = Math.ceil(size / chunkSize);
    log.info?.(`chunked-upload init: ${signerTipId} session=${sessionId} size=${size} chunks=${totalChunks} mime=${mime}`);

    return {
      session_id: sessionId,
      upload_id: uploadId,
      chunk_size: chunkSize,
      total_chunks: totalChunks,
      expires_at: session.expires_at,
    };
  }

  async function uploadChunk(sessionId, { chunkIndex, chunkBytes, totalChunks }) {
    const session = await dag.getUploadSession(sessionId);
    if (!session) {
      throw schemaError(404, "Upload session not found or expired", "session_not_found");
    }

    const state = _hashers.get(sessionId);
    if (!state) {
      // Session exists in DB but hasher was lost (node restart). Expire it.
      await dag.deleteUploadSession(sessionId);
      throw schemaError(410, "Upload session state lost; please restart upload", "session_state_lost");
    }

    const expectedIndex = session.parts.length;
    if (chunkIndex !== expectedIndex) {
      throw schemaError(409, `Expected chunk ${expectedIndex}, got ${chunkIndex}`, "chunk_out_of_order");
    }

    const newCompletedSize = session.completed_size + chunkBytes.length;
    if (newCompletedSize > session.size) {
      await _abort(session);
      throw schemaError(413, "Chunk exceeds declared file size", "size_exceeded");
    }

    // Detect MIME from first chunk if not already detected.
    if (state.detectedMime === null && chunkBytes.length >= 16) {
      state.detectedMime = mediaUploadSchema.detectMime(chunkBytes);
    }

    // Update incremental hash and size before S3 call so a stream error still
    // leaves consistent state (the client will retry the same chunk).
    state.hasher.update(chunkBytes);

    const partNumber = chunkIndex + 1; // S3 part numbers are 1-based.
    const { etag } = await storage.uploadPart(session.upload_id, session.s3_key, partNumber, chunkBytes);

    session.parts.push({ part_number: partNumber, etag });
    session.completed_size = newCompletedSize;
    await dag.updateUploadSession(sessionId, {
      parts: session.parts,
      completed_size: newCompletedSize,
    });

    log.debug?.(`chunked-upload chunk: session=${sessionId} idx=${chunkIndex} size=${chunkBytes.length}`);
    return { received: true, completed_size: newCompletedSize };
  }

  async function complete(sessionId) {
    const session = await dag.getUploadSession(sessionId);
    if (!session) {
      throw schemaError(404, "Upload session not found or expired", "session_not_found");
    }

    const state = _hashers.get(sessionId);
    if (!state) {
      await dag.deleteUploadSession(sessionId);
      throw schemaError(410, "Upload session state lost; please restart upload", "session_state_lost");
    }

    if (session.completed_size !== session.size) {
      throw schemaError(400, `Upload incomplete: ${session.completed_size}/${session.size}`, "upload_incomplete");
    }

    // Final MIME detection for very small files where the first chunk was < 16 bytes.
    if (state.detectedMime === null) {
      state.detectedMime = "application/octet-stream";
    }

    const contentHash = state.hasher.digest("hex");
    if (contentHash !== session.content_hash) {
      await _abort(session);
      throw schemaError(400, "Hash mismatch: received bytes do not match signed content_hash", "hash_mismatch");
    }

    // Signature was verified at init; re-checking the hash binding is enough.
    await storage.completeMultipartUpload(session.upload_id, session.s3_key, session.parts);

    await dag.deleteUploadSession(sessionId);
    _hashers.delete(sessionId);

    log.info?.(`chunked-upload complete: ${session.signer_tip_id} session=${sessionId} media_id=${contentHash} size=${session.size}`);

    return {
      media_id: contentHash,
      content_hash: contentHash,
      mime: state.detectedMime,
      size: session.size,
      uploaded_at: nowMs(),
      signer_tip_id: session.signer_tip_id,
    };
  }

  async function _abort(session) {
    try {
      await storage.abortMultipartUpload(session.upload_id, session.s3_key);
    } catch (err) {
      log.warn?.(`chunked-upload abort failed: ${err.message}`);
    }
    if (session && session.session_id) {
      await dag.deleteUploadSession(session.session_id);
      _hashers.delete(session.session_id);
    }
  }

  async function abort(sessionId) {
    const session = await dag.getUploadSession(sessionId);
    if (!session) return { aborted: false };
    await _abort(session);
    return { aborted: true };
  }

  async function cleanupExpired() {
    const before = nowMs();
    const removed = await dag.cleanupExpiredUploadSessions(before);
    // Also drop lost hasher state for sessions already gone from DB.
    for (const sessionId of _hashers.keys()) {
      const session = await dag.getUploadSession(sessionId);
      if (!session) {
        _hashers.delete(sessionId);
      }
    }
    return { removed };
  }

  return { init, uploadChunk, complete, abort, cleanupExpired };
}

module.exports = { createChunkedUploadService };
