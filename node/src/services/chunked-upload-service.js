/**
 * @file @tip-protocol/node/src/services/chunked-upload-service.js
 * @description Large media upload via presigned S3 multipart (Phase 1).
 *
 * Flow:
 *   1. init     — verify the signer's MEDIA_UPLOAD signature, open an S3 multipart
 *                 to a TMP key, and hand back presigned UploadPart URLs.
 *   2. (client)   PUTs parts DIRECTLY to S3 in parallel (bypasses Cloudflare + node).
 *   3. complete — verify a signed completion challenge, assemble the multipart,
 *                 re-read the assembled bytes from S3 and recompute SHAKE-256,
 *                 verify it matches the signed content_hash, enforce the real MIME,
 *                 then promote tmp -> the content-addressed key.
 *
 * Security equals single-shot upload: the node re-hashes the actual S3 bytes and
 * only promotes to the final key on a match; unverified bytes live only at the tmp
 * key. No server-side streaming hasher, so S3 handles retries/out-of-order parts.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256Incremental, mldsaVerify } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { schemaError } = require("../schemas/_common");
const mediaUploadSchema = require("../schemas/media-upload");

const DEFAULT_PART_SIZE = 10 * 1024 * 1024;   // status() fallback only
const MIN_PART_SIZE = 5 * 1024 * 1024;        // S3 hard minimum for every non-final part
const MAX_PART_SIZE = 5 * 1024 * 1024 * 1024; // S3 hard maximum per part (5 GB)
const ADAPTIVE_FLOOR = 8 * 1024 * 1024;       // adaptive lower bound (above the S3 min)
const ADAPTIVE_CAP = 128 * 1024 * 1024;       // adaptive upper bound (keeps a failed-part retry cheap)
const ADAPTIVE_TARGET_PARTS = 100;            // adaptive scales part size to ~this many parts
const MAX_PARTS = 10000;                      // S3 multipart hard limit
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const COMPLETE_DRIFT_MS = 5 * 60 * 1000;      // ±5min on the completion/abort timestamp

function _resolveSessionTtlMs() {
  const raw = parseInt(process.env.TIP_CHUNKED_UPLOAD_SESSION_TTL_MS || "", 10);
  return Number.isInteger(raw) && raw > 0 ? raw : DEFAULT_SESSION_TTL_MS;
}

function createChunkedUploadService({
  storage,
  dag,
  cryptoPoolRef = { current: null },
  log = console,
  partSize = null,      // optional fixed override; null => adaptive (default)
  sessionTtlMs = _resolveSessionTtlMs(),
}) {
  if (!storage) throw new Error("chunked-upload-service: storage required");
  if (!dag) throw new Error("chunked-upload-service: dag required");

  async function _verifySignature({ challenge, signature, publicKey }) {
    const pool = cryptoPoolRef && cryptoPoolRef.current ? cryptoPoolRef.current : null;
    if (pool && typeof pool.verifyRaw === "function") {
      const ok = await pool.verifyRaw([{ message: challenge, signature, publicKey, algorithm: "ML-DSA-65" }]);
      if (ok) return true;
      // Worker said false — fall through to a sync verify to rule out pool bugs.
    }
    return mldsaVerify(challenge, signature, publicKey);
  }

  // Scale part size so the part COUNT stays ~ADAPTIVE_TARGET_PARTS: bounds init
  // cost (one presigned URL per part) and keeps huge files under S3's 10k-part cap.
  // Client/config override wins, clamped to S3's [5MB, 5GB] per-part bounds.
  function _resolvePartSize(requested, size) {
    const override = (Number.isInteger(requested) && requested > 0) ? requested
      : (Number.isInteger(partSize) && partSize > 0) ? partSize : null;
    if (override != null) return Math.min(Math.max(override, MIN_PART_SIZE), MAX_PART_SIZE);
    const MB = 1024 * 1024;
    const raw = Math.ceil(size / ADAPTIVE_TARGET_PARTS);
    const clamped = Math.min(Math.max(raw, ADAPTIVE_FLOOR), ADAPTIVE_CAP);
    return Math.ceil(clamped / MB) * MB; // round up to a whole MB
  }

  // complete/abort require the session owner's fresh signature over
  // `${verb}:${sessionId}:${timestamp}:${signer_tip_id}` — the session_id alone is
  // not a bearer token for finalizing.
  async function _verifyOwnerAction(verb, sessionId, session, { signer_tip_id, signature, timestamp }) {
    if (signer_tip_id !== session.signer_tip_id) {
      throw schemaError(403, "Signer does not own this upload session", "signer_mismatch");
    }
    if (!Number.isInteger(timestamp) || Math.abs(nowMs() - timestamp) > COMPLETE_DRIFT_MS) {
      throw schemaError(400, "timestamp missing or out of range", "timestamp_invalid");
    }
    const identity = dag.getIdentity(signer_tip_id);
    if (!identity) throw schemaError(404, "Signer identity not found", "identity_not_found");
    const challenge = `${verb}:${sessionId}:${timestamp}:${signer_tip_id}`;
    const ok = await _verifySignature({ challenge, signature, publicKey: identity.public_key });
    if (!ok) throw schemaError(403, "Signature verification failed", "signature_invalid");
  }

  async function init({
    mime, size, content_hash: contentHash, signer_tip_id: signerTipId,
    signature, timestamp, part_size: reqPartSize,
  }) {
    if (!contentHash || !/^[0-9a-f]{64}$/.test(contentHash)) {
      throw schemaError(400, "content_hash must be 64-char lowercase hex", "content_hash_invalid");
    }
    if (!Number.isInteger(size) || size <= 0) {
      throw schemaError(400, "size must be a positive integer", "size_invalid");
    }

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
    if (!ok) throw schemaError(403, "Upload signature verification failed", "signature_invalid");

    if (storage.backend !== "s3") {
      throw schemaError(400, "Chunked upload requires s3 media backend", "backend_not_supported");
    }

    const resolvedPartSize = _resolvePartSize(reqPartSize, size);
    const partCount = Math.ceil(size / resolvedPartSize);
    if (partCount > MAX_PARTS) {
      throw schemaError(413, `Too many parts (${partCount}); use a larger part_size`, "too_many_parts");
    }

    const sessionId = dag.generateUploadSessionId();
    const { upload_id: uploadId, key: tmpKey } = await storage.createMultipartUpload(sessionId, mime, contentHash);
    const now = nowMs();
    const session = {
      session_id: sessionId,
      upload_id: uploadId,
      s3_key: tmpKey,
      content_hash: contentHash,
      mime,
      size,
      signer_tip_id: signerTipId,
      timestamp,
      signature,
      parts: [],
      completed_size: resolvedPartSize, // reuse: holds part_size (node-local, no schema change)
      created_at: now,
      expires_at: now + sessionTtlMs,
    };
    await dag.createUploadSession(session);

    const parts = [];
    for (let n = 1; n <= partCount; n++) {
      parts.push({ part_number: n, url: await storage.presignUploadPart(uploadId, tmpKey, n) });
    }

    log.info?.(`chunked-upload init: ${signerTipId} session=${sessionId} size=${size} parts=${partCount} mime=${mime}`);
    return {
      session_id: sessionId,
      part_size: resolvedPartSize,
      part_count: partCount,
      parts,
      expires_at: session.expires_at,
    };
  }

  async function status(sessionId) {
    const session = await dag.getUploadSession(sessionId);
    if (!session) throw schemaError(404, "Upload session not found or expired", "session_not_found");
    const psize = session.completed_size || DEFAULT_PART_SIZE;
    const partCount = Math.ceil(session.size / psize);
    const uploaded = await storage.listUploadedParts(session.upload_id, session.s3_key);
    const uploadedNums = uploaded.map(p => p.part_number).sort((a, b) => a - b);
    const have = new Set(uploadedNums);
    const missing = [];
    for (let n = 1; n <= partCount; n++) if (!have.has(n)) missing.push(n);
    const parts = [];
    for (const n of missing) {
      parts.push({ part_number: n, url: await storage.presignUploadPart(session.upload_id, session.s3_key, n) });
    }
    return {
      part_count: partCount,
      uploaded_parts: uploadedNums,
      missing_parts: missing,
      parts,
      expires_at: session.expires_at,
    };
  }

  async function complete(sessionId, { signer_tip_id, signature, timestamp, parts }) {
    const session = await dag.getUploadSession(sessionId);
    if (!session) throw schemaError(404, "Upload session not found or expired", "session_not_found");
    await _verifyOwnerAction("MEDIA_UPLOAD_COMPLETE", sessionId, session, { signer_tip_id, signature, timestamp });

    if (!Array.isArray(parts) || parts.length === 0) {
      throw schemaError(400, "parts (ETags) required to complete", "parts_required");
    }
    const normParts = parts
      .map(p => ({ part_number: Number(p.part_number), etag: p.etag }))
      .filter(p => Number.isInteger(p.part_number) && typeof p.etag === "string")
      .sort((a, b) => a.part_number - b.part_number);
    if (normParts.length === 0) throw schemaError(400, "parts malformed", "parts_invalid");

    // Assemble the multipart at the tmp key.
    await storage.completeMultipartUpload(session.upload_id, session.s3_key, normParts);

    // Re-read the assembled object from S3 and hash it ourselves — never trust the
    // client's claimed hash. Streamed, so memory stays flat for large files.
    let result;
    try {
      result = await _hashS3Object(session.s3_key);
    } catch (err) {
      await _dropAssembled(session);
      throw schemaError(400, `Failed to read assembled object: ${err.message}`, "assemble_failed");
    }
    const { hashHex, detectedMime, actualSize } = result;

    if (actualSize !== session.size) {
      await _dropAssembled(session);
      throw schemaError(400, `Assembled size ${actualSize} != declared ${session.size}`, "size_mismatch");
    }
    if (hashHex !== session.content_hash) {
      await _dropAssembled(session);
      throw schemaError(400, "Hash mismatch: uploaded bytes do not match signed content_hash", "hash_mismatch");
    }
    // Gate + label on the DETECTED type (like single-shot validateRequest): a
    // disabled/unrecognized type has cap 0 and is rejected; else it's stored under
    // its true mime, never the declared one, so a mislabel can't dodge a cap.
    const detected = detectedMime;
    const cap = mediaUploadSchema.limitForDetectedMime(detected);
    if (actualSize > cap) {
      await _dropAssembled(session);
      throw schemaError(415, `Detected type ${detected || "unknown"} is disabled or exceeds its cap`, "mime_disabled");
    }

    const { media_id } = await storage.copyToFinal(session.s3_key, session.content_hash, detected);
    await dag.deleteUploadSession(sessionId);

    log.info?.(`chunked-upload complete: ${session.signer_tip_id} session=${sessionId} media_id=${media_id} size=${actualSize} mime=${detected}`);
    return {
      media_id,
      content_hash: session.content_hash,
      mime: detected,
      size: actualSize,
      uploaded_at: nowMs(),
      signer_tip_id: session.signer_tip_id,
    };
  }

  // Stream the assembled tmp object from S3: SHAKE-256 over the whole thing plus
  // the first 64 bytes for MIME sniffing, without buffering the file in RAM.
  async function _hashS3Object(key) {
    const { stream } = await storage.getObjectStream(key);
    const hasher = shake256Incremental(32);
    let size = 0;
    let head = Buffer.alloc(0);
    for await (const chunk of stream) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      hasher.update(buf);
      size += buf.length;
      if (head.length < 64) head = Buffer.concat([head, buf.subarray(0, 64 - head.length)]);
    }
    const detectedMime = head.length >= 16 ? mediaUploadSchema.detectMime(head) : "application/octet-stream";
    return { hashHex: hasher.digest("hex"), detectedMime, actualSize: size };
  }

  // Assembled object exists at the tmp key but failed verification: delete it +
  // the session. (Multipart is already completed, so Abort no longer applies.)
  async function _dropAssembled(session) {
    try { await storage.deleteObjectByKey(session.s3_key); }
    catch (e) { log.warn?.(`chunked-upload drop-assembled failed: ${e.message}`); }
    await dag.deleteUploadSession(session.session_id);
  }

  // Still in-progress (not completed): abort the multipart (drops the parts), and
  // best-effort delete any object in case it was completed elsewhere.
  async function _abortSession(session) {
    try { await storage.abortMultipartUpload(session.upload_id, session.s3_key); }
    catch (e) { log.warn?.(`chunked-upload abort failed: ${e.message}`); }
    try { await storage.deleteObjectByKey(session.s3_key); } catch { /* best effort */ }
    await dag.deleteUploadSession(session.session_id);
  }

  async function abort(sessionId, auth = {}) {
    const session = await dag.getUploadSession(sessionId);
    if (!session) return { aborted: false };
    await _verifyOwnerAction("MEDIA_UPLOAD_ABORT", sessionId, session, auth);
    await _abortSession(session);
    return { aborted: true };
  }

  // Expiry sweep: for every expired session, ABORT the S3 multipart (releasing the
  // parts) BEFORE deleting the row — otherwise abandoned multipart parts orphan in
  // S3 and bill forever.
  async function cleanupExpired() {
    const before = nowMs();
    const expired = await dag.listExpiredUploadSessions(before);
    let removed = 0;
    for (const session of expired) {
      try { await storage.abortMultipartUpload(session.upload_id, session.s3_key); }
      catch (e) { log.warn?.(`chunked-upload cleanup abort failed session=${session.session_id}: ${e.message}`); }
      try { await storage.deleteObjectByKey(session.s3_key); } catch { /* best effort */ }
      await dag.deleteUploadSession(session.session_id);
      removed += 1;
    }
    return { removed };
  }

  return { init, status, complete, abort, cleanupExpired };
}

module.exports = { createChunkedUploadService };
