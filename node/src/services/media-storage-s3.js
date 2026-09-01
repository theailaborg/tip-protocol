/**
 * @file @tip-protocol/node/src/services/media-storage-s3.js
 * @description S3 backend for media-storage. Default for prod.
 *
 * Object layout in bucket:
 *   media/{media_id[0:2]}/{media_id[2:]}.bin  — the bytes
 *
 * MIME + content_hash live in S3 object metadata (`x-amz-meta-*`) so we don't
 * need a sidecar object. Saves one write per put.
 *
 * Encryption: SSE-KMS when `kmsKeyId` is configured (production posture).
 * Falls back to SSE-S3 if no key — never plaintext.
 *
 * Presigned GET URLs: short TTL (default 300s) so reviewers / disputers can
 * fetch directly without round-tripping bytes through the node. The node IS
 * the auth gate (it generates the URL only after auth); S3 enforces the URL
 * signature and TTL.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs/promises");
const fsSync = require("fs");
const os = require("os");
const path = require("path");
const { shake256 } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
  ListObjectsV2Command,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
  CopyObjectCommand,
  UploadPartCopyCommand,
  ListPartsCommand,
} = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { Upload } = require("@aws-sdk/lib-storage");
const { S3_SINGLE_COPY_MAX_BYTES, S3_COPY_PART_BYTES, S3_COPY_CONCURRENCY } = require("../../../shared/constants");

const DEFAULT_REGION = "us-west-2";
const DEFAULT_PRESIGN_TTL_SEC = 300;

function createS3Backend(config = {}) {
  const bucket = config.s3Bucket || process.env.TIP_MEDIA_S3_BUCKET;
  if (!bucket) {
    throw new Error("media-storage(s3): TIP_MEDIA_S3_BUCKET env / config.s3Bucket required");
  }
  const region = config.s3Region || process.env.TIP_MEDIA_S3_REGION || DEFAULT_REGION;
  const kmsKeyId = config.kmsKeyId || process.env.TIP_MEDIA_S3_KMS_KEY_ID || null;
  const presignTtlSec = config.presignTtlSec || parseInt(process.env.TIP_MEDIA_PRESIGN_TTL_SEC || "", 10) || DEFAULT_PRESIGN_TTL_SEC;

  // Credentials come from the ambient IAM role (IRSA in EKS, EC2 instance
  // role, or `aws sso` for local). No long-lived keys in config — that's a
  // hard rule. SDK's default credential chain picks the right source.
  const client = new S3Client({ region });

  function _objectKey(mediaId) {
    if (typeof mediaId !== "string" || !/^[0-9a-f]{64}$/.test(mediaId)) {
      throw new Error("media-storage(s3): media_id must be 64-char lowercase hex");
    }
    return `media/${mediaId.slice(0, 2)}/${mediaId.slice(2)}.bin`;
  }

  function _encryptionArgs() {
    if (kmsKeyId) {
      return { ServerSideEncryption: "aws:kms", SSEKMSKeyId: kmsKeyId };
    }
    // Always-on encryption even without a customer-managed key — never plaintext.
    return { ServerSideEncryption: "AES256" };
  }

  async function put(bytes, opts = {}) {
    if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
      throw new Error("media-storage(s3): put requires Buffer/Uint8Array bytes");
    }
    if (!opts.mime || typeof opts.mime !== "string") {
      throw new Error("media-storage(s3): put requires opts.mime");
    }
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    // media_id IS the content_hash (SHAKE-256). Caller may pass it via
    // opts.contentHash to skip rehashing; otherwise compute here. Same
    // contract as the fs backend so the factory is interchangeable.
    const mediaId = opts.contentHash || shake256(buf);
    const key = _objectKey(mediaId);

    // Content-addressed dedup: HEAD before PUT. Saves the cost of a redundant
    // upload + KMS encryption when the bytes already exist. Race is benign —
    // two concurrent identical puts both end with the same object.
    try {
      await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
      return { media_id: mediaId, size: buf.length };
    } catch (err) {
      if (err.$metadata?.httpStatusCode !== 404 && err.name !== "NotFound") {
        throw err;
      }
      // fallthrough: HEAD 404 → safe to PUT
    }

    await client.send(new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: buf,
      ContentType: opts.mime,
      Metadata: {
        mime: opts.mime,
        "created-at": String(nowMs()),
        ...(opts.contentHash ? { "content-hash": opts.contentHash } : {}),
      },
      ...(_encryptionArgs()),
    }));

    return { media_id: mediaId, size: buf.length };
  }

  async function get(mediaId) {
    const key = _objectKey(mediaId);
    try {
      const res = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
      // Body is a stream — buffer it. The caller can switch to streaming
      // later if media gets large; for image/audio (≤10MB) buffering is fine.
      const chunks = [];
      for await (const chunk of res.Body) chunks.push(chunk);
      const bytes = Buffer.concat(chunks);
      return {
        bytes,
        mime: res.ContentType || res.Metadata?.mime || "application/octet-stream",
        size: bytes.length,
        created_at: parseInt(res.Metadata?.["created-at"] || "0", 10) || null,
      };
    } catch (err) {
      if (err.$metadata?.httpStatusCode === 404 || err.name === "NoSuchKey") return null;
      throw err;
    }
  }

  async function head(mediaId) {
    const key = _objectKey(mediaId);
    try {
      const res = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
      return {
        exists: true,
        mime: res.ContentType || res.Metadata?.mime || "application/octet-stream",
        size: res.ContentLength || 0,
        created_at: parseInt(res.Metadata?.["created-at"] || "0", 10) || null,
      };
    } catch (err) {
      if (err.$metadata?.httpStatusCode === 404 || err.name === "NotFound") {
        return { exists: false };
      }
      throw err;
    }
  }

  async function presignedGet(mediaId, opts = {}) {
    const key = _objectKey(mediaId);
    const ttl = opts.ttlSec || presignTtlSec;
    const cmd = new GetObjectCommand({ Bucket: bucket, Key: key });
    return getSignedUrl(client, cmd, { expiresIn: ttl });
  }

  async function deleteMedia(mediaId) {
    const key = _objectKey(mediaId);
    try {
      await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
      return { deleted: true };
    } catch (err) {
      if (err.$metadata?.httpStatusCode === 404 || err.name === "NoSuchKey") {
        return { deleted: false };
      }
      throw err;
    }
  }

  // Async generator over every object under the `media/` prefix. Used by
  // the retention sweep to find orphans. Pages via ContinuationToken so a
  // bucket with millions of objects doesn't blow heap. created_at comes
  // from the object's LastModified — we don't HEAD each key (would cost
  // one HEAD per object); LastModified is set by S3 on put and is what
  // the lifecycle rules also key off, so it's the right source of truth
  // for age regardless of what's in our custom metadata.
  async function* list() {
    let continuationToken;
    while (true) {
      const res = await client.send(new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: "media/",
        ContinuationToken: continuationToken,
      }));
      for (const obj of res.Contents || []) {
        // key format: media/{shard}/{rest}.bin
        const m = obj.Key && obj.Key.match(/^media\/([0-9a-f]{2})\/([0-9a-f]{62})\.bin$/);
        if (!m) continue;
        const mediaId = m[1] + m[2];
        const createdAt = obj.LastModified instanceof Date ? obj.LastModified.getTime() : null;
        yield { media_id: mediaId, created_at: createdAt };
      }
      if (!res.IsTruncated) return;
      continuationToken = res.NextContinuationToken;
    }
  }

  // Scratch dir for in-flight streamed uploads. Node-local disk — the
  // bytes only hit S3 once the hash is verified at promote time.
  async function stagingDir() {
    const dir = path.join(os.tmpdir(), `tip-media-staging-${bucket}`);
    await fs.mkdir(dir, { recursive: true });
    return dir;
  }

  // Drop abandoned in-flight uploads — staging is node-local disk, so
  // this is identical to the fs backend's hygiene.
  async function cleanStaging(maxAgeMs) {
    const dir = await stagingDir();
    let removed = 0;
    for (const f of await fs.readdir(dir).catch(() => [])) {
      const p = path.join(dir, f);
      const st = await fs.stat(p).catch(() => null);
      if (st && nowMs() - st.mtimeMs > maxAgeMs) {
        await fs.unlink(p).catch(() => { });
        removed += 1;
      }
    }
    return { removed };
  }

  // Promote a fully-written tmp file (hash already verified by the
  // caller) to the bucket under the content-addressed key, then drop the
  // tmp. Streams from disk — flat memory regardless of file size; a
  // single PUT covers objects up to S3's 5GB non-multipart ceiling.
  async function promoteTmpFile(tmpPath, { contentHash, mime, size }) {
    const key = _objectKey(contentHash);
    try {
      await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
      await fs.unlink(tmpPath).catch(() => { });
      return { media_id: contentHash, size };
    } catch (err) {
      if (err.$metadata?.httpStatusCode !== 404 && err.name !== "NotFound") throw err;
    }

    // Managed multipart upload, NOT a single PutObject: a stream-bodied
    // PutObject is non-retryable in the SDK, so one network hiccup at any
    // point of a large transfer aborts the whole thing. Upload() splits
    // the file into parts, uploads 4 in parallel, and retries individual
    // failed parts. Small files (< partSize) collapse to one PUT
    // automatically. Failure hygiene: abort the multipart so no orphaned
    // parts accrue storage (the lifecycle rule also reaps them at 7d).
    const upload = new Upload({
      client,
      params: {
        Bucket: bucket,
        Key: key,
        Body: fsSync.createReadStream(tmpPath),
        ContentType: mime,
        Metadata: {
          mime,
          "created-at": String(nowMs()),
          "content-hash": contentHash,
        },
        ...(_encryptionArgs()),
      },
      partSize: 16 * 1024 * 1024,
      queueSize: 4,
    });
    await upload.done();
    await fs.unlink(tmpPath).catch(() => { });
    return { media_id: contentHash, size };
  }

  // Tmp key lives UNDER the media/<shard>/ prefix (the same IAM-allowed prefix as
  // the final object), so no extra S3 policy is needed. The "tmp-" + non-hex tail
  // means the retention sweep's media/<hex2>/<hex62>.bin regex skips it.
  const _tmpKey = (sessionId, contentHash) => `media/${contentHash.slice(0, 2)}/tmp-${sessionId}.bin`;

  // Opens the multipart at the tmp key: the final media/<hash> key gets the object
  // only after complete's re-hash passes, so it never holds unverified bytes.
  async function createMultipartUpload(sessionId, mime, contentHash) {
    const key = _tmpKey(sessionId, contentHash);
    const res = await client.send(new CreateMultipartUploadCommand({
      Bucket: bucket,
      Key: key,
      ContentType: mime,
      Metadata: { mime, "created-at": String(nowMs()) },
      ...(_encryptionArgs()),
    }));
    return { upload_id: res.UploadId, key };
  }

  // Presigned URL for one UploadPart — client PUTs the part bytes straight to S3.
  async function presignUploadPart(uploadId, key, partNumber, ttlSec) {
    const cmd = new UploadPartCommand({
      Bucket: bucket, Key: key, UploadId: uploadId, PartNumber: partNumber,
    });
    return getSignedUrl(client, cmd, { expiresIn: ttlSec || presignTtlSec });
  }

  // Parts S3 has received so far (resume support). Pages past 1000 parts.
  async function listUploadedParts(uploadId, key) {
    const parts = [];
    let marker;
    while (true) {
      const res = await client.send(new ListPartsCommand({
        Bucket: bucket, Key: key, UploadId: uploadId, PartNumberMarker: marker,
      }));
      for (const p of res.Parts || []) parts.push({ part_number: p.PartNumber, etag: p.ETag, size: p.Size });
      if (!res.IsTruncated) return parts;
      marker = res.NextPartNumberMarker;
    }
  }

  // Stream a raw object by key (used to re-hash the assembled tmp object without
  // buffering the whole file in RAM).
  async function getObjectStream(key) {
    const res = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    return { stream: res.Body, size: res.ContentLength || 0 };
  }

  async function deleteObjectByKey(key) {
    try {
      await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    } catch (err) {
      if (err.$metadata?.httpStatusCode !== 404 && err.name !== "NoSuchKey") throw err;
    }
    return { deleted: true };
  }

  // Copy a verified tmp object to its final content-addressed key, then drop the
  // tmp. Content-addressed dedup: if the final key already exists, skip the copy.
  async function copyToFinal(tmpKey, contentHash, mime) {
    const key = _objectKey(contentHash);
    try {
      await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
      await deleteObjectByKey(tmpKey);
      return { media_id: contentHash };
    } catch (err) {
      if (err.$metadata?.httpStatusCode !== 404 && err.name !== "NotFound") throw err;
    }
    const src = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: tmpKey }));
    const size = src.ContentLength || 0;
    const metadata = { mime, "created-at": String(nowMs()), "content-hash": contentHash };
    if (size > S3_SINGLE_COPY_MAX_BYTES) {
      await _multipartCopy(tmpKey, key, size, mime, metadata);
    } else {
      await client.send(new CopyObjectCommand({
        Bucket: bucket,
        Key: key,
        CopySource: `${bucket}/${tmpKey}`,
        ContentType: mime,
        MetadataDirective: "REPLACE",
        Metadata: metadata,
        ...(_encryptionArgs()),
      }));
    }
    const dst = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    if ((dst.ContentLength || 0) !== size) {
      await deleteObjectByKey(key);
      throw new Error(`media-storage(s3): promoted object size ${dst.ContentLength} != staged ${size}`);
    }
    await deleteObjectByKey(tmpKey);
    return { media_id: contentHash };
  }

  // S3 caps a single CopyObject at 5 GB; above that the object is copied
  // server-side in byte-range parts (no bytes transit the node).
  async function _multipartCopy(srcKey, key, size, mime, metadata) {
    const { UploadId } = await client.send(new CreateMultipartUploadCommand({
      Bucket: bucket, Key: key, ContentType: mime, Metadata: metadata, ...(_encryptionArgs()),
    }));
    const ranges = [];
    for (let start = 0; start < size; start += S3_COPY_PART_BYTES) {
      ranges.push({ n: ranges.length + 1, start, end: Math.min(start + S3_COPY_PART_BYTES, size) - 1 });
    }
    const parts = new Array(ranges.length);
    let next = 0;
    async function worker() {
      while (next < ranges.length) {
        const r = ranges[next++];
        const res = await client.send(new UploadPartCopyCommand({
          Bucket: bucket, Key: key, UploadId, PartNumber: r.n,
          CopySource: `${bucket}/${srcKey}`, CopySourceRange: `bytes=${r.start}-${r.end}`,
        }));
        parts[r.n - 1] = { PartNumber: r.n, ETag: res.CopyPartResult.ETag };
      }
    }
    try {
      await Promise.all(Array.from({ length: Math.min(S3_COPY_CONCURRENCY, ranges.length) }, worker));
      await client.send(new CompleteMultipartUploadCommand({
        Bucket: bucket, Key: key, UploadId, MultipartUpload: { Parts: parts },
      }));
    } catch (err) {
      await client.send(new AbortMultipartUploadCommand({ Bucket: bucket, Key: key, UploadId })).catch(() => { });
      throw err;
    }
  }

  async function uploadPart(uploadId, key, partNumber, body) {
    const res = await client.send(new UploadPartCommand({
      Bucket: bucket,
      Key: key,
      UploadId: uploadId,
      PartNumber: partNumber,
      Body: body,
    }));
    return { etag: res.ETag };
  }

  async function completeMultipartUpload(uploadId, key, parts) {
    await client.send(new CompleteMultipartUploadCommand({
      Bucket: bucket,
      Key: key,
      UploadId: uploadId,
      MultipartUpload: {
        Parts: parts.map(p => ({ PartNumber: p.part_number, ETag: p.etag })),
      },
    }));
    return { completed: true };
  }

  async function abortMultipartUpload(uploadId, key) {
    try {
      await client.send(new AbortMultipartUploadCommand({
        Bucket: bucket,
        Key: key,
        UploadId: uploadId,
      }));
    } catch (err) {
      if (err.name !== "NoSuchUpload") throw err;
    }
    return { aborted: true };
  }

  return {
    put, get, head, presignedGet, delete: deleteMedia, list, stagingDir,
    promoteTmpFile, cleanStaging, createMultipartUpload, uploadPart,
    completeMultipartUpload, abortMultipartUpload,
    presignUploadPart, listUploadedParts, getObjectStream, deleteObjectByKey, copyToFinal,
    backend: "s3",
  };
}

module.exports = { createS3Backend };
