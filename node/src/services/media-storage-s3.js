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

const crypto = require("crypto");
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
} = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

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

  function _computeMediaId(bytes) {
    // See notes in media-storage-local-fs.js — SHA3-256 fixed-output for
    // content-addressing at this layer. content_hash (shake256) is the
    // protocol-level hash and is stored separately on tx.data.
    return crypto.createHash("sha3-256").update(bytes).digest("hex");
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
    const mediaId = _computeMediaId(buf);
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
        "created-at": String(Date.now()),
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

  return { put, get, head, presignedGet, delete: deleteMedia, backend: "s3" };
}

module.exports = { createS3Backend };
