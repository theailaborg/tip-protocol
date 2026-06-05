/**
 * @file @tip-protocol/node/src/services/media-storage.js
 * @description Pluggable media-storage facade with two backends:
 *
 *   - `fs`  — local filesystem, default for dev/test. Writes `<prefix>/<rest>.bin`
 *             plus a `.meta.json` sidecar. No presigning (caller falls back to
 *             streaming via the API).
 *   - `s3`  — S3-compatible, default for prod. Uses SSE-KMS server-side
 *             encryption per object. presignedGet returns a short-TTL URL
 *             reviewers / disputers can fetch directly.
 *
 * Selection priority: explicit `config.backend` → `TIP_MEDIA_BACKEND` env →
 * `fs` (safe dev default).
 *
 * Object identity: `media_id = shake256(bytes, 32)` — a 64-char hex digest.
 * Content-addressed: identical bytes uploaded twice dedup to one stored
 * object (the second `put` is a no-op).
 *
 * Storage key layout: `{media_id[0:2]}/{media_id[2:]}.bin` — first-byte
 * sharding avoids cramming 100K+ files in one directory (or one S3 prefix's
 * partition).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { createLocalFsBackend } = require("./media-storage-local-fs");
const { createS3Backend } = require("./media-storage-s3");

/**
 * Build a media-storage instance. Returns the same interface regardless of
 * backend so callers don't branch on storage type.
 *
 * @param {Object} [config]
 * @param {"fs"|"s3"} [config.backend]   override env (used by tests)
 * @param {string}    [config.fsPath]    fs backend root (default: ./data/media)
 * @param {string}    [config.s3Bucket]  s3 backend bucket name
 * @param {string}    [config.s3Region]  s3 backend region (default us-west-2)
 * @param {string}    [config.kmsKeyId]  optional SSE-KMS key for server-side encryption
 * @param {number}    [config.presignTtlSec]  presigned-URL TTL (default 300)
 * @returns {{
 *   put: (bytes: Buffer, opts: {mime: string}) => Promise<{media_id: string, size: number}>,
 *   get: (media_id: string) => Promise<{bytes: Buffer, mime: string, size: number} | null>,
 *   head: (media_id: string) => Promise<{exists: boolean, mime: string, size: number, created_at: number} | null>,
 *   presignedGet: (media_id: string, opts?: {ttlSec?: number}) => Promise<string | null>,
 *   delete: (media_id: string) => Promise<{deleted: boolean}>,
 *   list: () => AsyncIterable<{media_id: string, created_at: number | null}>,
 *   backend: string,
 * }}
 */
function createMediaStorage(config = {}) {
  const backend = config.backend || process.env.TIP_MEDIA_BACKEND || "fs";
  if (backend === "fs") return createLocalFsBackend(config);
  if (backend === "s3") return createS3Backend(config);
  throw new Error(`media-storage: unknown backend "${backend}" (expected fs|s3)`);
}

module.exports = { createMediaStorage };
