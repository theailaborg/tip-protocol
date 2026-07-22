/**
 * @file tests/services/chunked-upload-service.test.js
 * @description Service-layer tests for chunked media uploads.
 *
 * Covers init, chunk upload, complete, abort, expiry cleanup, and
 * signature verification. Uses an in-memory DAG and a fake S3
 * multipart backend so no real credentials or network are needed.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");

const { initCrypto, shake256, mldsaSign, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createChunkedUploadService } = require(path.join(SRC, "services/chunked-upload-service"));
const mediaUploadSchema = require(path.join(SRC, "schemas/media-upload"));
const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

// Minimal ISO-BMFF `ftyp` box so detectMime sees "video/mp4".
function _mp4Bytes(text) {
  const ftyp = Buffer.concat([
    Buffer.from([0, 0, 0, 0x20]),
    Buffer.from("ftypisom"),
    Buffer.from([0, 0, 0, 0]),
    Buffer.from("isom"),
    Buffer.from("mp41"),
  ]);
  return Buffer.concat([ftyp, Buffer.from(text)]);
}

function _createFakeStorage() {
  const uploads = new Map();
  const parts = new Map();
  return {
    backend: "s3",
    async createMultipartUpload(contentHash, mime) {
      const uploadId = `fake-upload-${contentHash.slice(0, 16)}`;
      const key = `media/${contentHash.slice(0, 2)}/${contentHash.slice(2)}.bin`;
      uploads.set(uploadId, { key, mime, parts: [] });
      return { upload_id: uploadId, key };
    },
    async uploadPart(uploadId, key, partNumber, chunkBytes) {
      if (!uploads.has(uploadId)) throw new Error("multipart upload not found");
      parts.set(`${uploadId}:${partNumber}`, chunkBytes);
      uploads.get(uploadId).parts.push(partNumber);
      return { etag: `etag-${partNumber}` };
    },
    async completeMultipartUpload(uploadId, key, uploadParts) {
      if (!uploads.has(uploadId)) throw new Error("multipart upload not found");
      return { ok: true };
    },
    async abortMultipartUpload(uploadId, key) {
      uploads.delete(uploadId);
      return { ok: true };
    },
    _uploads: uploads,
    _parts: parts,
  };
}

function _seedIdentity(dag, tipId, publicKey) {
  dag.saveIdentity({
    tip_id: tipId,
    region: "US",
    public_key: publicKey,
    algorithm: "ml-dsa-65",
    vp_id: "tip://vp/US-0000000000000000",
    verification_tier: "T1",
    tip_id_type: "personal",
    founding: false,
    status: "active",
    reviewer_consent: 0,
    juror_consent: 0,
    expert_consent: 0,
    registered_at: 1,
    creator_name: null,
    tx_id: "tx-0",
  });
}

function _signInit({ contentHash, mime, timestamp, signerTipId }, privateKey) {
  const challenge = mediaUploadSchema.buildChallenge({ content_hash: contentHash, mime, timestamp, signer_tip_id: signerTipId });
  return mldsaSign(challenge, privateKey);
}

beforeAll(async () => {
  await initCrypto();
  try { PC._resetForTesting(); } catch { /* not yet initialised */ }
  PC.init(getGenesisPayload().protocol_constants);
});

describe("chunked-upload-service", () => {
  let dag, storage, service, kp, identity, timestamp;

  beforeEach(() => {
    dag = initDAG({ dbPath: ":memory-test:" });
    storage = _createFakeStorage();
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-aaaaaaaaaaaaaaaa", public_key: kp.publicKey, status: "active" };
    _seedIdentity(dag, identity.tip_id, identity.public_key);
    service = createChunkedUploadService({ storage, dag, log: { info: () => {}, debug: () => {}, warn: () => {} } });
    timestamp = nowMs();
  });

  describe("init", () => {
    test("creates a session and S3 multipart upload", async () => {
      const bytes = _mp4Bytes("hello");
      const contentHash = shake256(bytes);
      const signature = _signInit({ contentHash, mime: "video/mp4", timestamp, signerTipId: identity.tip_id }, kp.privateKey);

      const r = await service.init({
        mime: "video/mp4",
        size: bytes.length,
        content_hash: contentHash,
        signer_tip_id: identity.tip_id,
        signature,
        timestamp,
      });

      expect(r.session_id).toMatch(/^[0-9a-f]{32}$/);
      expect(r.upload_id).toMatch(/^fake-upload-/);
      expect(r.chunk_size).toBe(10 * 1024 * 1024);
      expect(r.total_chunks).toBe(1);
      expect(typeof r.expires_at).toBe("number");

      const session = await dag.getUploadSession(r.session_id);
      expect(session).not.toBeNull();
      expect(session.content_hash).toBe(contentHash);
      expect(session.size).toBe(bytes.length);
    });

    test("rejects bad content_hash format", async () => {
      await expect(service.init({
        mime: "video/mp4",
        size: 100,
        content_hash: "not-hex",
        signer_tip_id: identity.tip_id,
        signature: "00",
        timestamp,
      })).rejects.toMatchObject({ code: "content_hash_invalid" });
    });

    test("rejects invalid signature", async () => {
      const bytes = _mp4Bytes("hello");
      const contentHash = shake256(bytes);
      const otherKp = generateMLDSAKeypair();
      const badSignature = _signInit({ contentHash, mime: "video/mp4", timestamp, signerTipId: identity.tip_id }, otherKp.privateKey);

      await expect(service.init({
        mime: "video/mp4",
        size: bytes.length,
        content_hash: contentHash,
        signer_tip_id: identity.tip_id,
        signature: badSignature,
        timestamp,
      })).rejects.toMatchObject({ code: "signature_invalid" });
    });

    test("rejects unknown signer", async () => {
      const bytes = _mp4Bytes("hello");
      const contentHash = shake256(bytes);
      const unknownTipId = "tip://id/US-bbbbbbbbbbbbbbbb";

      await expect(service.init({
        mime: "video/mp4",
        size: bytes.length,
        content_hash: contentHash,
        signer_tip_id: unknownTipId,
        signature: "00",
        timestamp,
      })).rejects.toMatchObject({ code: "signer_not_found" });
    });
  });

  describe("uploadChunk", () => {
    test("accepts chunks in order and tracks completed_size", async () => {
      const bytes = _mp4Bytes("chunked-upload-test");
      const chunk1 = bytes.slice(0, 16);
      const chunk2 = bytes.slice(16);
      const contentHash = shake256(bytes);
      const signature = _signInit({ contentHash, mime: "video/mp4", timestamp, signerTipId: identity.tip_id }, kp.privateKey);

      const init = await service.init({
        mime: "video/mp4",
        size: bytes.length,
        content_hash: contentHash,
        signer_tip_id: identity.tip_id,
        signature,
        timestamp,
      });

      const r1 = await service.uploadChunk(init.session_id, { chunkIndex: 0, chunkBytes: chunk1, totalChunks: 2 });
      expect(r1.received).toBe(true);
      expect(r1.completed_size).toBe(chunk1.length);

      const r2 = await service.uploadChunk(init.session_id, { chunkIndex: 1, chunkBytes: chunk2, totalChunks: 2 });
      expect(r2.completed_size).toBe(bytes.length);
    });

    test("rejects out-of-order chunk", async () => {
      const bytes = _mp4Bytes("test");
      const contentHash = shake256(bytes);
      const signature = _signInit({ contentHash, mime: "video/mp4", timestamp, signerTipId: identity.tip_id }, kp.privateKey);
      const init = await service.init({ mime: "video/mp4", size: bytes.length, content_hash: contentHash, signer_tip_id: identity.tip_id, signature, timestamp });

      await expect(service.uploadChunk(init.session_id, { chunkIndex: 1, chunkBytes: bytes, totalChunks: 1 }))
        .rejects.toMatchObject({ code: "chunk_out_of_order" });
    });

    test("rejects chunk for expired/unknown session", async () => {
      await expect(service.uploadChunk("non-existent", { chunkIndex: 0, chunkBytes: _mp4Bytes("x"), totalChunks: 1 }))
        .rejects.toMatchObject({ code: "session_not_found" });
    });
  });

  describe("complete", () => {
    test("finalizes when hash matches", async () => {
      const bytes = _mp4Bytes("complete-me");
      const contentHash = shake256(bytes);
      const signature = _signInit({ contentHash, mime: "video/mp4", timestamp, signerTipId: identity.tip_id }, kp.privateKey);
      const init = await service.init({ mime: "video/mp4", size: bytes.length, content_hash: contentHash, signer_tip_id: identity.tip_id, signature, timestamp });
      await service.uploadChunk(init.session_id, { chunkIndex: 0, chunkBytes: bytes, totalChunks: 1 });

      const r = await service.complete(init.session_id);
      expect(r.media_id).toBe(contentHash);
      expect(r.content_hash).toBe(contentHash);
      expect(r.size).toBe(bytes.length);

      expect(await dag.getUploadSession(init.session_id)).toBeNull();
    });

    test("rejects when final hash mismatches", async () => {
      const bytes = _mp4Bytes("original");
      const wrongHash = shake256(Buffer.from("different"));
      const signature = _signInit({ contentHash: wrongHash, mime: "video/mp4", timestamp, signerTipId: identity.tip_id }, kp.privateKey);
      const init = await service.init({ mime: "video/mp4", size: bytes.length, content_hash: wrongHash, signer_tip_id: identity.tip_id, signature, timestamp });
      await service.uploadChunk(init.session_id, { chunkIndex: 0, chunkBytes: bytes, totalChunks: 1 });

      await expect(service.complete(init.session_id)).rejects.toMatchObject({ code: "hash_mismatch" });
    });

    test("rejects incomplete upload", async () => {
      const bytes = _mp4Bytes("too-short");
      const contentHash = shake256(bytes);
      const signature = _signInit({ contentHash, mime: "video/mp4", timestamp, signerTipId: identity.tip_id }, kp.privateKey);
      const init = await service.init({ mime: "video/mp4", size: bytes.length, content_hash: contentHash, signer_tip_id: identity.tip_id, signature, timestamp });

      await expect(service.complete(init.session_id)).rejects.toMatchObject({ code: "upload_incomplete" });
    });
  });

  describe("abort", () => {
    test("deletes session and aborts multipart upload", async () => {
      const bytes = _mp4Bytes("abort-me");
      const contentHash = shake256(bytes);
      const signature = _signInit({ contentHash, mime: "video/mp4", timestamp, signerTipId: identity.tip_id }, kp.privateKey);
      const init = await service.init({ mime: "video/mp4", size: bytes.length, content_hash: contentHash, signer_tip_id: identity.tip_id, signature, timestamp });

      const r = await service.abort(init.session_id);
      expect(r.aborted).toBe(true);
      expect(await dag.getUploadSession(init.session_id)).toBeNull();
      expect(storage._uploads.has(init.upload_id)).toBe(false);
    });

    test("returns aborted=false for unknown session", async () => {
      const r = await service.abort("non-existent");
      expect(r.aborted).toBe(false);
    });
  });

  describe("cleanupExpired", () => {
    test("removes expired sessions from the mirror", async () => {
      const bytes = _mp4Bytes("expire-me");
      const contentHash = shake256(bytes);
      const signature = _signInit({ contentHash, mime: "video/mp4", timestamp, signerTipId: identity.tip_id }, kp.privateKey);
      const init = await service.init({ mime: "video/mp4", size: bytes.length, content_hash: contentHash, signer_tip_id: identity.tip_id, signature, timestamp });

      expect(await dag.getUploadSession(init.session_id)).not.toBeNull();
      // Simulate expiry by mutating the in-memory row directly.
      dag._store._uploadSessions.get(init.session_id).expires_at = nowMs() - 1000;

      const r = await service.cleanupExpired();
      expect(r.removed).toBe(1);
      expect(await dag.getUploadSession(init.session_id)).toBeNull();
    });

    test("keeps non-expired sessions", async () => {
      const bytes = _mp4Bytes("keep-me");
      const contentHash = shake256(bytes);
      const signature = _signInit({ contentHash, mime: "video/mp4", timestamp, signerTipId: identity.tip_id }, kp.privateKey);
      const init = await service.init({ mime: "video/mp4", size: bytes.length, content_hash: contentHash, signer_tip_id: identity.tip_id, signature, timestamp });

      const r = await service.cleanupExpired();
      expect(r.removed).toBe(0);
      expect(await dag.getUploadSession(init.session_id)).not.toBeNull();
    });
  });
});
