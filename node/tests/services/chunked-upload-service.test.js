/**
 * @file tests/services/chunked-upload-service.test.js
 * @description Service-layer tests for Phase 1 presigned-multipart uploads.
 *
 * Covers init (presigned URLs), complete (assemble + re-hash + verify + promote),
 * hash-mismatch rejection, detected-MIME gate, complete/abort ownership auth, and
 * expiry cleanup aborting the S3 multipart. Uses an in-memory DAG and a fake S3
 * backend (no credentials / network).
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

beforeAll(async () => {
  await initCrypto();
  try { PC._resetForTesting(); } catch { /* fresh */ }
  PC.init(getGenesisPayload().protocol_constants);
});

// image/png (enabled) — detectMime reads the magic bytes.
function _png(len = 128) {
  const magic = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([magic, Buffer.alloc(Math.max(0, len - magic.length), 0x42)]);
}
// video/mp4 (disabled in genesis, cap 0) — ftyp box.
function _mp4(len = 128) {
  const ftyp = Buffer.concat([
    Buffer.from([0, 0, 0, 0x20]), Buffer.from("ftypisom"),
    Buffer.from([0, 0, 0, 0]), Buffer.from("isom"), Buffer.from("mp41"),
  ]);
  return Buffer.concat([ftyp, Buffer.alloc(Math.max(0, len - ftyp.length), 0x61)]);
}

function _seedIdentity(dag, tipId, publicKey) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: publicKey, algorithm: "ml-dsa-65",
    vp_id: "tip://vp/US-0000000000000000", verification_tier: "T1", tip_id_type: "personal",
    founding: false, status: "active", reviewer_consent: 0, juror_consent: 0, expert_consent: 0,
    registered_at: 1, creator_name: null, tx_id: "tx-0",
  });
}

const _signInit = ({ contentHash, mime, timestamp, signerTipId }, priv) =>
  mldsaSign(mediaUploadSchema.buildChallenge({ content_hash: contentHash, mime, timestamp, signer_tip_id: signerTipId }), priv);
const _signAction = (verb, sessionId, ts, tipId, priv) =>
  mldsaSign(`${verb}:${sessionId}:${ts}:${tipId}`, priv);

// Fake S3: presigned URLs are strings; the client "PUT" is simulated by _put();
// complete assembles parts in order; getObjectStream replays the assembled bytes.
function _fakeStorage() {
  const objects = new Map();     // key -> Buffer
  const multiparts = new Map();  // uploadId -> { key, parts: Map(n -> Buffer) }
  const aborted = [];
  let seq = 0;
  return {
    backend: "s3",
    async createMultipartUpload(sessionId) {
      const uploadId = `up-${++seq}`;
      const key = `media-tmp/${sessionId}.bin`;
      multiparts.set(uploadId, { key, parts: new Map() });
      return { upload_id: uploadId, key };
    },
    async presignUploadPart(uploadId, key, n) { return `https://s3.test/${key}?u=${uploadId}&p=${n}`; },
    async listUploadedParts(uploadId) {
      const mp = multiparts.get(uploadId);
      return mp ? [...mp.parts.entries()].map(([n, b]) => ({ part_number: n, etag: `"e${n}"`, size: b.length })) : [];
    },
    async completeMultipartUpload(uploadId, key, parts) {
      const mp = multiparts.get(uploadId);
      const ordered = [...parts].sort((a, b) => a.part_number - b.part_number);
      objects.set(key, Buffer.concat(ordered.map(p => mp.parts.get(p.part_number) || Buffer.alloc(0))));
      return { completed: true };
    },
    async getObjectStream(key) {
      const buf = objects.get(key);
      if (!buf) throw new Error(`no object at ${key}`);
      return { stream: (async function* () { yield buf; })(), size: buf.length };
    },
    async copyToFinal(tmpKey, contentHash) {
      objects.set(`media/${contentHash}`, objects.get(tmpKey));
      objects.delete(tmpKey);
      return { media_id: contentHash };
    },
    async deleteObjectByKey(key) { objects.delete(key); return { deleted: true }; },
    async abortMultipartUpload(uploadId, key) { aborted.push({ uploadId, key }); multiparts.delete(uploadId); return { aborted: true }; },
    _put(uploadId, n, bytes) { multiparts.get(uploadId).parts.set(n, Buffer.from(bytes)); return `"e${n}"`; },
    _objects: objects, _aborted: aborted, _multiparts: multiparts,
  };
}

const TIP = "tip://id/US-aaaaaaaaaaaaaaaa";

function _setup() {
  const dag = initDAG({ dbPath: ":memory-test:" });
  const kp = generateMLDSAKeypair();
  _seedIdentity(dag, TIP, kp.publicKey);
  const storage = _fakeStorage();
  const svc = createChunkedUploadService({ storage, dag, log: { info() {}, warn() {} } });
  return { dag, kp, storage, svc };
}

// Drive init -> put parts -> return everything needed to complete.
async function _upload(fx, fileBytes, mime, { declaredHash } = {}) {
  const contentHash = declaredHash || shake256(fileBytes);
  const ts = nowMs();
  const init = await fx.svc.init({
    mime, size: fileBytes.length, content_hash: contentHash,
    signer_tip_id: TIP, signature: _signInit({ contentHash, mime, timestamp: ts, signerTipId: TIP }, fx.kp.privateKey), timestamp: ts,
  });
  const session = fx.dag.getUploadSession(init.session_id);
  const parts = [];
  let off = 0;
  for (let n = 1; n <= init.part_count; n++) {
    const slice = fileBytes.subarray(off, off + init.part_size);
    off += init.part_size;
    parts.push({ part_number: n, etag: fx.storage._put(session.upload_id, n, slice) });
  }
  return { init, session, contentHash, parts };
}

describe("presigned chunked upload — init", () => {
  test("init returns one presigned URL per part", async () => {
    const fx = _setup();
    const file = _png(256);
    const contentHash = shake256(file);
    const ts = nowMs();
    const init = await fx.svc.init({
      mime: "image/png", size: file.length, content_hash: contentHash,
      signer_tip_id: TIP, signature: _signInit({ contentHash, mime: "image/png", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey), timestamp: ts,
    });
    expect(init.part_count).toBe(init.parts.length);
    expect(init.parts[0]).toEqual(expect.objectContaining({ part_number: 1, url: expect.stringContaining("https://s3.test/") }));
    expect(init.parts.every((p, i) => p.part_number === i + 1)).toBe(true);
    expect(fx.dag.getUploadSession(init.session_id)).not.toBeNull();
  });

  test("init rejects a bad signature", async () => {
    const fx = _setup();
    const file = _png();
    const ts = nowMs();
    await expect(fx.svc.init({
      mime: "image/png", size: file.length, content_hash: shake256(file),
      signer_tip_id: TIP, signature: "00", timestamp: ts,
    })).rejects.toMatchObject({ status: 403 });
  });
});

describe("presigned chunked upload — complete", () => {
  test("happy path: assembles, verifies, promotes to the content-addressed key", async () => {
    const fx = _setup();
    const file = _png(1024);
    const { init, contentHash, parts } = await _upload(fx, file, "image/png");
    const ts = nowMs();
    const out = await fx.svc.complete(init.session_id, {
      signer_tip_id: TIP, timestamp: ts, parts,
      signature: _signAction("MEDIA_UPLOAD_COMPLETE", init.session_id, ts, TIP, fx.kp.privateKey),
    });
    expect(out.media_id).toBe(contentHash);
    expect(out.mime).toBe("image/png");
    expect(out.size).toBe(file.length);
    // Real bytes ended up at the final key; session gone.
    expect(fx.storage._objects.get(`media/${contentHash}`).equals(file)).toBe(true);
    expect(fx.dag.getUploadSession(init.session_id)).toBeNull();
  });

  test("rejects when uploaded bytes do not match the signed content_hash, and drops the tmp object", async () => {
    const fx = _setup();
    const declared = _png(1024);
    const declaredHash = shake256(declared);
    const { init } = await _upload(fx, declared, "image/png", { declaredHash });
    // overwrite the part with SAME-SIZE but different bytes (so we hit the hash
    // check, not the size check)
    const session = fx.dag.getUploadSession(init.session_id);
    const wrong = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(1024 - 8, 0x99)]);
    const parts = [{ part_number: 1, etag: fx.storage._put(session.upload_id, 1, wrong) }];
    const ts = nowMs();
    await expect(fx.svc.complete(init.session_id, {
      signer_tip_id: TIP, timestamp: ts, parts,
      signature: _signAction("MEDIA_UPLOAD_COMPLETE", init.session_id, ts, TIP, fx.kp.privateKey),
    })).rejects.toMatchObject({ status: 400, code: "hash_mismatch" });
    expect(fx.storage._objects.has(`media/${declaredHash}`)).toBe(false); // never promoted
    expect(fx.storage._objects.has(session.s3_key)).toBe(false);          // tmp dropped
    expect(fx.dag.getUploadSession(init.session_id)).toBeNull();
  });

  test("stores the DETECTED mime, not the declared one — mislabel corrected (H4)", async () => {
    const fx = _setup();
    const video = _mp4(4096);
    const declaredHash = shake256(video); // hash matches the bytes so we reach the mime step
    const { init, parts } = await _upload(fx, video, "image/png", { declaredHash });
    const ts = nowMs();
    const out = await fx.svc.complete(init.session_id, {
      signer_tip_id: TIP, timestamp: ts, parts,
      signature: _signAction("MEDIA_UPLOAD_COMPLETE", init.session_id, ts, TIP, fx.kp.privateKey),
    });
    expect(out.mime).toBe("video/mp4"); // declared image/png, stored under the TRUE type
    expect(fx.storage._objects.has(`media/${declaredHash}`)).toBe(true);
  });

  test("rejects bytes whose type is unrecognized (cap 0)", async () => {
    const fx = _setup();
    const junk = Buffer.alloc(1024, 0x00); // detectMime -> null -> cap 0
    const declaredHash = shake256(junk);
    const { init, parts } = await _upload(fx, junk, "image/png", { declaredHash });
    const ts = nowMs();
    await expect(fx.svc.complete(init.session_id, {
      signer_tip_id: TIP, timestamp: ts, parts,
      signature: _signAction("MEDIA_UPLOAD_COMPLETE", init.session_id, ts, TIP, fx.kp.privateKey),
    })).rejects.toMatchObject({ status: 415 });
    expect(fx.storage._objects.has(`media/${declaredHash}`)).toBe(false);
  });

  test("complete requires the session owner's signature (H3)", async () => {
    const fx = _setup();
    const file = _png(1024);
    const { init, parts } = await _upload(fx, file, "image/png");
    const ts = nowMs();
    // wrong-key signature
    const other = generateMLDSAKeypair();
    await expect(fx.svc.complete(init.session_id, {
      signer_tip_id: TIP, timestamp: ts, parts,
      signature: _signAction("MEDIA_UPLOAD_COMPLETE", init.session_id, ts, TIP, other.privateKey),
    })).rejects.toMatchObject({ status: 403 });
    // different signer id
    await expect(fx.svc.complete(init.session_id, {
      signer_tip_id: "tip://id/US-bbbbbbbbbbbbbbbb", timestamp: ts, parts,
      signature: _signAction("MEDIA_UPLOAD_COMPLETE", init.session_id, ts, "tip://id/US-bbbbbbbbbbbbbbbb", fx.kp.privateKey),
    })).rejects.toMatchObject({ status: 403 });
  });
});

describe("presigned chunked upload — abort + cleanup", () => {
  test("abort (signed) aborts the S3 multipart", async () => {
    const fx = _setup();
    const { init, session } = await _upload(fx, _png(1024), "image/png");
    const ts = nowMs();
    await fx.svc.abort(init.session_id, {
      signer_tip_id: TIP, timestamp: ts,
      signature: _signAction("MEDIA_UPLOAD_ABORT", init.session_id, ts, TIP, fx.kp.privateKey),
    });
    expect(fx.storage._aborted.some(a => a.uploadId === session.upload_id)).toBe(true);
    expect(fx.dag.getUploadSession(init.session_id)).toBeNull();
  });

  test("cleanupExpired ABORTS the S3 multipart, not just the DB row (C1)", async () => {
    const fx = _setup();
    const { init, session } = await _upload(fx, _png(1024), "image/png");
    // force expiry (re-save the row with a past expires_at; MemoryStore upserts)
    const row = fx.dag.getUploadSession(init.session_id);
    row.expires_at = nowMs() - 1000;
    fx.dag.createUploadSession(row);
    const res = await fx.svc.cleanupExpired();
    expect(res.removed).toBeGreaterThanOrEqual(1);
    expect(fx.storage._aborted.some(a => a.uploadId === session.upload_id)).toBe(true);
    expect(fx.dag.getUploadSession(init.session_id)).toBeNull();
  });
});

describe("presigned chunked upload — status/resume", () => {
  test("status reports uploaded + missing parts with fresh URLs", async () => {
    const fx = _setup();
    const file = _png(1024);
    const contentHash = shake256(file);
    const ts = nowMs();
    const init = await fx.svc.init({
      mime: "image/png", size: file.length, content_hash: contentHash,
      signer_tip_id: TIP, signature: _signInit({ contentHash, mime: "image/png", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey), timestamp: ts,
    });
    // upload nothing yet
    const st = await fx.svc.status(init.session_id);
    expect(st.part_count).toBe(init.part_count);
    expect(st.uploaded_parts).toEqual([]);
    expect(st.missing_parts.length).toBe(init.part_count);
    expect(st.parts.length).toBe(init.part_count); // fresh URLs for the missing
  });
});
