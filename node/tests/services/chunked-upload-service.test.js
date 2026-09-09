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
const crypto = require("crypto");
const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");

const { initCrypto, shake256, mldsaSign, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createChunkedUploadService } = require(path.join(SRC, "services/chunked-upload-service"));
const mediaUploadSchema = require(path.join(SRC, "schemas/media-upload"));
const { MEDIA_LIMITS, UPLOAD_SESSION_STATE } = require(path.join(SHARED, "constants"));
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
  let gate = null;               // when set, getObjectStream waits on it (slow re-hash)
  let assembled = 0;
  let failReads = 0;             // getObjectStream throws this many times first (transient S3 error)
  let assembleError = null;      // completeMultipartUpload throws this once (bad ETags)
  let etagMode = "md5";          // md5 | opaque (SSE-KMS style) | throw
  const probes = [];             // node-side uploadPart calls (the etag probe)
  return {
    backend: "s3",
    partUrlTtlSec: 7200,
    async uploadPart(uploadId, key, n, body, opts = {}) {
      if (etagMode === "throw") throw new Error("AccessDenied");
      probes.push({ uploadId, key, n, body: Buffer.from(body), checksum: opts.checksum || null });
      multiparts.get(uploadId).parts.set(n, Buffer.from(body));
      const md5 = crypto.createHash("md5").update(body).digest("hex");
      return { etag: etagMode === "md5" ? `"${md5}"` : `"opaque-${n}-x"` };
    },
    _setEtagMode(m) { etagMode = m; },
    _probes: probes,
    // opts.checksum mirrors S3: a checksum-typed upload refuses to complete
    // without every part's checksum.
    async createMultipartUpload(sessionId, mime, contentHash, opts = {}) {
      const uploadId = `up-${++seq}`;
      const key = `media-tmp/${sessionId}.bin`;
      multiparts.set(uploadId, { key, parts: new Map(), checksum: opts.checksum || null, completedWith: null });
      return { upload_id: uploadId, key };
    },
    async presignUploadPart(uploadId, key, n, ttl, opts = {}) {
      return `https://s3.test/${key}?u=${uploadId}&p=${n}${opts.checksumCrc32 ? `&crc=${encodeURIComponent(opts.checksumCrc32)}` : ""}`;
    },
    async listUploadedParts(uploadId) {
      const mp = multiparts.get(uploadId);
      return mp ? [...mp.parts.entries()].map(([n, b]) => ({ part_number: n, etag: `"e${n}"`, size: b.length })) : [];
    },
    async completeMultipartUpload(uploadId, key, parts) {
      if (assembleError) { const e = assembleError; assembleError = null; throw e; }
      const mp = multiparts.get(uploadId);
      if (mp.checksum && parts.some(p => !p.checksum_crc32)) {
        throw new Error("InvalidRequest: The upload was created using a crc32 checksum. The complete request must include the checksum for each part.");
      }
      mp.completedWith = parts.map(p => ({ part_number: p.part_number, checksum_crc32: p.checksum_crc32 || null }));
      assembled += 1;
      const ordered = [...parts].sort((a, b) => a.part_number - b.part_number);
      objects.set(key, Buffer.concat(ordered.map(p => mp.parts.get(p.part_number) || Buffer.alloc(0))));
      return { completed: true };
    },
    async getObjectStream(key) {
      if (gate) await gate;
      if (failReads > 0) { failReads -= 1; throw new Error("socket hang up"); }
      const buf = objects.get(key);
      if (!buf) throw new Error(`no object at ${key}`);
      return { stream: (async function* () { yield buf; })(), size: buf.length };
    },
    _setGate(p) { gate = p; },
    _assembledCount() { return assembled; },
    _failReads(n) { failReads = n; },
    _failAssemble(err) { assembleError = err; },
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

function _setup(opts = {}) {
  const dag = initDAG({ dbPath: ":memory-test:" });
  const kp = generateMLDSAKeypair();
  _seedIdentity(dag, TIP, kp.publicKey);
  const storage = _fakeStorage();
  const svc = createChunkedUploadService({ storage, dag, log: { info() {}, warn() {} }, ...opts });
  return { dag, kp, storage, svc };
}

function _deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}

async function _pollUntil(fx, sessionId, states, timeoutMs = 3000) {
  const deadline = nowMs() + timeoutMs;
  while (true) {
    const st = await fx.svc.status(sessionId);
    if (states.includes(st.state)) return st;
    if (nowMs() > deadline) throw new Error(`session ${sessionId} stuck in ${st.state}`);
    await new Promise(r => setTimeout(r, 10));
  }
}

function _completeArgs(fx, sessionId, parts) {
  const ts = nowMs();
  return {
    signer_tip_id: TIP, timestamp: ts, parts,
    signature: _signAction("MEDIA_UPLOAD_COMPLETE", sessionId, ts, TIP, fx.kp.privateKey),
  };
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

  test("init rejects a file over the family size cap (413)", async () => {
    const fx = _setup();
    const contentHash = "a".repeat(64);
    const size = mediaUploadSchema.limitForDetectedMime("image/png", MEDIA_LIMITS) + 1;
    const ts = nowMs();
    await expect(fx.svc.init({
      mime: "image/png", size, content_hash: contentHash,
      signer_tip_id: TIP, signature: _signInit({ contentHash, mime: "image/png", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey), timestamp: ts,
    })).rejects.toMatchObject({ status: 413 });
  });

  test("part size scales adaptively for large files (bounded part count)", async () => {
    const fx = _setup();
    const contentHash = "a".repeat(64);
    const size = 1024 * 1024 * 1024; // 1 GB video
    const ts = nowMs();
    const init = await fx.svc.init({
      mime: "video/mp4", size, content_hash: contentHash, signer_tip_id: TIP,
      signature: _signInit({ contentHash, mime: "video/mp4", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey), timestamp: ts,
    });
    expect(init.part_size).toBeGreaterThan(10 * 1024 * 1024); // bigger than the old fixed 10MB
    expect(init.part_count).toBeLessThanOrEqual(128);          // ~100, not hundreds
    expect(init.parts.length).toBe(init.part_count);
    // a tiny file stays at the adaptive floor -> 1 part
    const small = await fx.svc.init({
      mime: "image/png", size: 100000, content_hash: "b".repeat(64), signer_tip_id: TIP,
      signature: _signInit({ contentHash: "b".repeat(64), mime: "image/png", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey), timestamp: ts,
    });
    expect(small.part_count).toBe(1);
  });

  test("client part_size override wins (clamped to S3's 5MB min)", async () => {
    const fx = _setup();
    const contentHash = "c".repeat(64);
    const ts = nowMs();
    const init = await fx.svc.init({
      mime: "video/mp4", size: 200 * 1024 * 1024, content_hash: contentHash, signer_tip_id: TIP, part_size: 50 * 1024 * 1024,
      signature: _signInit({ contentHash, mime: "video/mp4", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey), timestamp: ts,
    });
    expect(init.part_size).toBe(50 * 1024 * 1024);
  });
});

describe("presigned chunked upload — complete", () => {
  test("rejects a short/incomplete assembly (size mismatch) and drops the tmp", async () => {
    const fx = _setup();
    const file = _png(2048);
    const contentHash = shake256(file);
    const ts = nowMs();
    const init = await fx.svc.init({
      mime: "image/png", size: file.length, content_hash: contentHash,
      signer_tip_id: TIP, signature: _signInit({ contentHash, mime: "image/png", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey), timestamp: ts,
    });
    const session = fx.dag.getUploadSession(init.session_id);
    // upload only half the declared bytes
    const parts = [{ part_number: 1, etag: fx.storage._put(session.upload_id, 1, file.subarray(0, 1024)) }];
    const cts = nowMs();
    await expect(fx.svc.complete(init.session_id, {
      signer_tip_id: TIP, timestamp: cts, parts,
      signature: _signAction("MEDIA_UPLOAD_COMPLETE", init.session_id, cts, TIP, fx.kp.privateKey),
    })).rejects.toMatchObject({ status: 400, code: "size_mismatch" });
    expect(fx.storage._objects.has(session.s3_key)).toBe(false);
  });

  test("complete rejects a stale timestamp (replay window)", async () => {
    const fx = _setup();
    const { init, parts } = await _upload(fx, _png(1024), "image/png");
    const stale = nowMs() - 10 * 60 * 1000; // 10min ago, past ±5min
    await expect(fx.svc.complete(init.session_id, {
      signer_tip_id: TIP, timestamp: stale, parts,
      signature: _signAction("MEDIA_UPLOAD_COMPLETE", init.session_id, stale, TIP, fx.kp.privateKey),
    })).rejects.toMatchObject({ status: 400, code: "timestamp_invalid" });
  });

  test("complete on an unknown session -> 404", async () => {
    const fx = _setup();
    const ts = nowMs();
    await expect(fx.svc.complete("deadbeefdeadbeef", {
      signer_tip_id: TIP, timestamp: ts, parts: [{ part_number: 1, etag: "x" }],
      signature: _signAction("MEDIA_UPLOAD_COMPLETE", "deadbeefdeadbeef", ts, TIP, fx.kp.privateKey),
    })).rejects.toMatchObject({ status: 404 });
  });

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
    // Real bytes ended up at the final key; the outcome stays on the session for pickup.
    expect(fx.storage._objects.get(`media/${contentHash}`).equals(file)).toBe(true);
    const done = fx.dag.getUploadSession(init.session_id);
    expect(done.state).toBe(UPLOAD_SESSION_STATE.COMPLETE);
    expect(done.result.media_id).toBe(contentHash);
    expect(done.result.computed_hash).toBe(contentHash); // the node's own hash of the stored object, not an echo
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
    })).rejects.toMatchObject({
      status: 400, code: "hash_mismatch",
      details: { expected: declaredHash, computed: shake256(wrong), size: 1024 },
    });
    expect(fx.storage._objects.has(`media/${declaredHash}`)).toBe(false); // never promoted
    expect(fx.storage._objects.has(session.s3_key)).toBe(false);          // tmp dropped
    const failed = fx.dag.getUploadSession(init.session_id);
    expect(failed.state).toBe(UPLOAD_SESSION_STATE.FAILED);
    expect(failed.result.code).toBe("hash_mismatch");
    expect(failed.result.details).toEqual({ expected: declaredHash, computed: shake256(wrong), size: 1024 });
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
    expect(st.state).toBe(UPLOAD_SESSION_STATE.UPLOADING);
    expect(st.part_count).toBe(init.part_count);
    expect(st.uploaded_parts).toEqual([]);
    expect(st.missing_parts.length).toBe(init.part_count);
    expect(st.parts.length).toBe(init.part_count); // fresh URLs for the missing
  });
});

describe("presigned chunked upload: node-local caps", () => {
  test("a service built with a smaller image cap rejects init at 413", async () => {
    const fx = _setup({ mediaLimits: { ...MEDIA_LIMITS, max_image_bytes: 1024 } });
    const contentHash = "a".repeat(64);
    const ts = nowMs();
    await expect(fx.svc.init({
      mime: "image/png", size: 2048, content_hash: contentHash,
      signer_tip_id: TIP, signature: _signInit({ contentHash, mime: "image/png", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey), timestamp: ts,
    })).rejects.toMatchObject({ status: 413, code: "file_too_large" });
  });

  test("a video cap of 0 disables the family at init (415)", async () => {
    const fx = _setup({ mediaLimits: { ...MEDIA_LIMITS, max_video_bytes: 0 } });
    const contentHash = "b".repeat(64);
    const ts = nowMs();
    await expect(fx.svc.init({
      mime: "video/mp4", size: 2048, content_hash: contentHash,
      signer_tip_id: TIP, signature: _signInit({ contentHash, mime: "video/mp4", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey), timestamp: ts,
    })).rejects.toMatchObject({ status: 415, code: "mime_disabled" });
  });
});

describe("presigned chunked upload: async finalize", () => {
  test("complete answers 202 finalizing when verification outlives the sync window; status then carries the result", async () => {
    const fx = _setup({ completeSyncWaitMs: 20 });
    const file = _png(1024);
    const { init, contentHash, parts } = await _upload(fx, file, "image/png");
    const gate = _deferred();
    fx.storage._setGate(gate.promise);

    const pending = await fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts));
    expect(pending).toMatchObject({ state: UPLOAD_SESSION_STATE.FINALIZING, session_id: init.session_id });
    expect(pending.poll_after_ms).toBeGreaterThan(0);
    expect(fx.dag.getUploadSession(init.session_id).state).toBe(UPLOAD_SESSION_STATE.FINALIZING);
    expect(await fx.svc.status(init.session_id)).toMatchObject({ state: UPLOAD_SESSION_STATE.FINALIZING });
    // a repeat complete while finalizing is idempotent: same 202 shape, no second assemble
    expect(await fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts)))
      .toMatchObject({ state: UPLOAD_SESSION_STATE.FINALIZING });

    gate.resolve();
    const st = await _pollUntil(fx, init.session_id, [UPLOAD_SESSION_STATE.COMPLETE, UPLOAD_SESSION_STATE.FAILED]);
    expect(st.state).toBe(UPLOAD_SESSION_STATE.COMPLETE);
    expect(st.result.media_id).toBe(contentHash);
    expect(st.result.mime).toBe("image/png");
    expect(fx.storage._objects.get(`media/${contentHash}`).equals(file)).toBe(true);
    // complete on a finished session returns the stored descriptor (201 path)
    const again = await fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts));
    expect(again.media_id).toBe(contentHash);
  });

  test("a verification failure after 202 is reported by status as failed, with the code", async () => {
    const fx = _setup({ completeSyncWaitMs: 20 });
    const declared = _png(1024);
    const declaredHash = shake256(declared);
    const { init } = await _upload(fx, declared, "image/png", { declaredHash });
    const session = fx.dag.getUploadSession(init.session_id);
    const wrong = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(1024 - 8, 0x99)]);
    const parts = [{ part_number: 1, etag: fx.storage._put(session.upload_id, 1, wrong) }];
    const gate = _deferred();
    fx.storage._setGate(gate.promise);

    const pending = await fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts));
    expect(pending.state).toBe(UPLOAD_SESSION_STATE.FINALIZING);
    gate.resolve();
    const st = await _pollUntil(fx, init.session_id, [UPLOAD_SESSION_STATE.COMPLETE, UPLOAD_SESSION_STATE.FAILED]);
    expect(st.state).toBe(UPLOAD_SESSION_STATE.FAILED);
    expect(st.error).toMatchObject({
      code: "hash_mismatch", status: 400,
      details: { expected: declaredHash, computed: shake256(wrong), size: 1024 },
    });
    expect(fx.storage._objects.has(session.s3_key)).toBe(false);          // tmp dropped
    expect(fx.storage._objects.has(`media/${declaredHash}`)).toBe(false); // never promoted
    // a later complete surfaces the stored failure as the same error, details included
    await expect(fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts)))
      .rejects.toMatchObject({ status: 400, code: "hash_mismatch", details: { computed: shake256(wrong) } });
  });

  test("concurrent completes on an uploading session share one assemble + finalize", async () => {
    const fx = _setup({ completeSyncWaitMs: 20 });
    const file = _png(1024);
    const { init, contentHash, parts } = await _upload(fx, file, "image/png");
    const gate = _deferred();
    fx.storage._setGate(gate.promise);
    const [a, b] = await Promise.all([
      fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts)),
      fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts)),
    ]);
    expect(a.state).toBe(UPLOAD_SESSION_STATE.FINALIZING);
    expect(b.state).toBe(UPLOAD_SESSION_STATE.FINALIZING);
    expect(fx.storage._assembledCount()).toBe(1);
    gate.resolve();
    const st = await _pollUntil(fx, init.session_id, [UPLOAD_SESSION_STATE.COMPLETE, UPLOAD_SESSION_STATE.FAILED]);
    expect(st.state).toBe(UPLOAD_SESSION_STATE.COMPLETE);
    expect(st.result.media_id).toBe(contentHash);
    expect(fx.storage._assembledCount()).toBe(1);
  });

  test("a transient S3 read error during the re-hash is retried, not recorded as failed", async () => {
    const fx = _setup({ rehashRetryMs: 1 });
    const file = _png(1024);
    const { init, contentHash, parts } = await _upload(fx, file, "image/png");
    fx.storage._failReads(2);   // two drops, third read succeeds (3 attempts allowed)
    const out = await fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts));
    expect(out.media_id).toBe(contentHash);
    expect(fx.dag.getUploadSession(init.session_id).state).toBe(UPLOAD_SESSION_STATE.COMPLETE);
  });

  test("a persistent S3 read error is recorded as failed after the retries", async () => {
    const fx = _setup({ rehashRetryMs: 1 });
    const { init, parts, session } = await _upload(fx, _png(1024), "image/png");
    fx.storage._failReads(3);
    await expect(fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts)))
      .rejects.toMatchObject({ status: 400, code: "assemble_failed" });
    expect(fx.dag.getUploadSession(init.session_id).state).toBe(UPLOAD_SESSION_STATE.FAILED);
    expect(fx.storage._objects.has(session.s3_key)).toBe(false);
  });

  test("an S3 assemble error is a 400 assemble_failed and leaves the session uploading (retryable)", async () => {
    const fx = _setup();
    const { init, parts } = await _upload(fx, _png(1024), "image/png");
    fx.storage._failAssemble(new Error("InvalidPart: One or more of the specified parts could not be found"));
    await expect(fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts)))
      .rejects.toMatchObject({ status: 400, code: "assemble_failed" });
    expect(fx.dag.getUploadSession(init.session_id).state).toBe(UPLOAD_SESSION_STATE.UPLOADING);
    // the retry with correct parts then succeeds
    const out = await fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts));
    expect(out.media_id).toBeDefined();
  });

  test("entering finalizing refreshes the session TTL so the row outlives the re-hash", async () => {
    const fx = _setup({ completeSyncWaitMs: 20 });
    const { init, parts } = await _upload(fx, _png(1024), "image/png");
    const before = fx.dag.getUploadSession(init.session_id).expires_at;
    // age the row so it is about to expire, then complete
    fx.dag.updateUploadSession(init.session_id, { expires_at: nowMs() + 1000 });
    const gate = _deferred();
    fx.storage._setGate(gate.promise);
    await fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts));
    expect(fx.dag.getUploadSession(init.session_id).expires_at).toBeGreaterThanOrEqual(before - 1000);
    gate.resolve();
    await _pollUntil(fx, init.session_id, [UPLOAD_SESSION_STATE.COMPLETE, UPLOAD_SESSION_STATE.FAILED]);
  });

  test("abort is refused while finalizing (409)", async () => {
    const fx = _setup({ completeSyncWaitMs: 20 });
    const { init, parts } = await _upload(fx, _png(1024), "image/png");
    const gate = _deferred();
    fx.storage._setGate(gate.promise);
    await fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts));
    const ts = nowMs();
    await expect(fx.svc.abort(init.session_id, {
      signer_tip_id: TIP, timestamp: ts,
      signature: _signAction("MEDIA_UPLOAD_ABORT", init.session_id, ts, TIP, fx.kp.privateKey),
    })).rejects.toMatchObject({ status: 409, code: "finalizing" });
    gate.resolve();
    await _pollUntil(fx, init.session_id, [UPLOAD_SESSION_STATE.COMPLETE, UPLOAD_SESSION_STATE.FAILED]);
  });

  test("sessions left finalizing by a restart are resumed by a fresh service instance", async () => {
    const fx = _setup();
    const file = _png(1024);
    const { init, contentHash, parts, session } = await _upload(fx, file, "image/png");
    // simulate: multipart assembled + state persisted, then the process died before finalize ran
    await fx.storage.completeMultipartUpload(session.upload_id, session.s3_key, parts);
    fx.dag.updateUploadSession(init.session_id, { state: UPLOAD_SESSION_STATE.FINALIZING, parts });

    const restarted = createChunkedUploadService({ storage: fx.storage, dag: fx.dag, log: { info() {}, warn() {} } });
    expect(await restarted.resumeFinalizing()).toEqual({ resumed: 1 });
    const st = await _pollUntil({ svc: restarted }, init.session_id, [UPLOAD_SESSION_STATE.COMPLETE, UPLOAD_SESSION_STATE.FAILED]);
    expect(st.state).toBe(UPLOAD_SESSION_STATE.COMPLETE);
    expect(st.result.media_id).toBe(contentHash);
    expect(fx.storage._objects.get(`media/${contentHash}`).equals(file)).toBe(true);
    // nothing else to resume
    expect(await restarted.resumeFinalizing()).toEqual({ resumed: 0 });
  });

  test("cleanupExpired does not abort a finished session's multipart (already assembled)", async () => {
    const fx = _setup();
    const { init, parts, session } = await _upload(fx, _png(1024), "image/png");
    const out = await fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, parts));
    expect(out.media_id).toBeDefined();
    const row = fx.dag.getUploadSession(init.session_id);
    row.expires_at = nowMs() - 1000;
    fx.dag.createUploadSession(row);
    const res = await fx.svc.cleanupExpired();
    expect(res.removed).toBeGreaterThanOrEqual(1);
    expect(fx.storage._aborted.some(a => a.uploadId === session.upload_id)).toBe(false);
    expect(fx.dag.getUploadSession(init.session_id)).toBeNull();
  });
});

describe("presigned chunked upload: part sizing, etag probe, url ttl", () => {
  const GIB = 1024 ** 3;
  const MIB = 1024 ** 2;
  const bigLimits = { ...MEDIA_LIMITS, max_image_bytes: 64 * GIB };

  async function _init(fx, size, extra = {}) {
    const ts = nowMs();
    const contentHash = "ab".repeat(32);
    return fx.svc.init({
      mime: "image/png", size, content_hash: contentHash, signer_tip_id: TIP, timestamp: ts,
      signature: _signInit({ contentHash, mime: "image/png", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey),
      ...extra,
    });
  }

  test("large files get 32 MiB parts by default, with part url expiry", async () => {
    const fx = _setup({ mediaLimits: bigLimits });
    const before = nowMs();
    const init = await _init(fx, 15 * GIB);
    expect(init.part_size).toBe(32 * MIB);
    expect(init.part_count).toBe(480);
    expect(init.parts).toHaveLength(480);
    for (const p of init.parts.slice(0, 3)) {
      expect(p.url_expires_at).toBeGreaterThanOrEqual(before + 7200 * 1000);
      expect(p.url_expires_at).toBeLessThanOrEqual(nowMs() + 7200 * 1000);
    }
    const st = await fx.svc.status(init.session_id);
    expect(st.missing_parts).toHaveLength(480);
    expect(st.parts[0].url_expires_at).toBeGreaterThanOrEqual(before + 7200 * 1000);
  });

  test("more than 9,999 parts is rejected", async () => {
    const fx = _setup({ mediaLimits: bigLimits });
    await expect(_init(fx, 60 * GIB, { part_size: 5 * MIB }))
      .rejects.toMatchObject({ status: 413, code: "too_many_parts" });
  });

  test("etag probe uploads the reserved part and reports md5 etags", async () => {
    const fx = _setup();
    const init = await _init(fx, 1024);
    expect(init.part_etag_is_md5).toBe(true);
    expect(fx.storage._probes).toHaveLength(1);
    expect(fx.storage._probes[0].n).toBe(10000);
    expect(fx.storage._probes[0].body.toString("utf8")).toBe("tip-etag-probe-1");
  });

  test("etag probe reports false on opaque etags and null when it fails, without blocking init", async () => {
    const fx = _setup();
    fx.storage._setEtagMode("opaque");
    expect((await _init(fx, 1024)).part_etag_is_md5).toBe(false);
    fx.storage._setEtagMode("throw");
    const init = await _init(fx, 2048);
    expect(init.part_etag_is_md5).toBeNull();
    expect(init.part_count).toBe(1);
    expect(fx.dag.getUploadSession(init.session_id)).toBeTruthy();
  });

  test("status hides the probe part and complete ignores it if a client echoes it", async () => {
    const fx = _setup();
    const file = _png(4096);
    const up = await _upload(fx, file, "image/png");
    expect(fx.storage._multiparts.get(up.session.upload_id).parts.has(10000)).toBe(true);
    const st = await fx.svc.status(up.init.session_id);
    expect(st.uploaded_parts).not.toContain(10000);
    expect(st.missing_parts).toEqual([]);
    const echoed = [...up.parts, { part_number: 10000, etag: '"whatever"' }];
    const res = await fx.svc.complete(up.init.session_id, _completeArgs(fx, up.init.session_id, echoed));
    expect(res.media_id).toBe(up.contentHash);
    expect(res.size).toBe(file.length);
  });
});

describe("presigned chunked upload: per-part crc32 checksums (opt-in)", () => {
  const CRC = "SORArw=="; // any well-formed value: base64 of 4 bytes
  function _crc32(buf) {
    let crc = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
      let c = (crc ^ buf[i]) & 0xff;
      for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
      crc = (crc >>> 8) ^ c;
    }
    const b = Buffer.alloc(4); b.writeUInt32BE((crc ^ 0xffffffff) >>> 0); return b.toString("base64");
  }
  async function _init(fx, size, extra = {}) {
    const ts = nowMs();
    const contentHash = extra.contentHash || "ab".repeat(32);
    return fx.svc.init({
      mime: "image/png", size, content_hash: contentHash, signer_tip_id: TIP, timestamp: ts,
      signature: _signInit({ contentHash, mime: "image/png", timestamp: ts, signerTipId: TIP }, fx.kp.privateKey),
      checksum: "crc32", ...extra,
    });
  }

  test("init opts in: checksum-typed upload, no URLs up front, probe still runs with the checksum", async () => {
    const fx = _setup();
    const init = await _init(fx, 100 * 1024 * 1024);
    expect(init.checksum).toBe("crc32");
    expect(init.parts).toEqual([]);
    expect(init.part_count).toBeGreaterThan(1);
    const session = fx.dag.getUploadSession(init.session_id);
    expect(session.checksum_algorithm).toBe("crc32");
    expect(fx.storage._multiparts.get(session.upload_id).checksum).toBe("crc32");
    expect(fx.storage._probes[0].checksum).toBe("crc32");
    expect(init.part_etag_is_md5).toBe(true);
  });

  test("an unknown checksum algorithm is refused; omitting it keeps today's behaviour", async () => {
    const fx = _setup();
    await expect(_init(fx, 1024, { checksum: "md5" })).rejects.toMatchObject({ status: 400, code: "checksum_unsupported" });
    const plain = await _init(fx, 1024, { checksum: undefined });
    expect(plain.checksum).toBeNull();
    expect(plain.parts).toHaveLength(1);
    expect(fx.dag.getUploadSession(plain.session_id).checksum_algorithm).toBeNull();
  });

  test("mintPartUrls signs each URL with the part's crc32 and validates the batch", async () => {
    const fx = _setup();
    const init = await _init(fx, 100 * 1024 * 1024);
    const out = await fx.svc.mintPartUrls(init.session_id, [
      { part_number: 1, checksum_crc32: CRC }, { part_number: 5, checksum_crc32: "AAAAAA==" },
    ]);
    expect(out.checksum).toBe("crc32");
    expect(out.parts.map(p => p.part_number)).toEqual([1, 5]);
    expect(out.parts[0].url).toContain(`&crc=${encodeURIComponent(CRC)}`);
    expect(out.parts[0].checksum_crc32).toBe(CRC);
    expect(out.parts[0].url_expires_at).toBeGreaterThan(nowMs());
    await expect(fx.svc.mintPartUrls(init.session_id, [{ part_number: 2 }]))
      .rejects.toMatchObject({ status: 400, code: "checksum_required" });
    await expect(fx.svc.mintPartUrls(init.session_id, [{ part_number: 2, checksum_crc32: "not-base64" }]))
      .rejects.toMatchObject({ status: 400, code: "checksum_required" });
    await expect(fx.svc.mintPartUrls(init.session_id, [{ part_number: init.part_count + 1, checksum_crc32: CRC }]))
      .rejects.toMatchObject({ status: 400, code: "part_number_invalid" });
    const tooMany = Array.from({ length: 65 }, (_, i) => ({ part_number: i + 1, checksum_crc32: CRC }));
    await expect(fx.svc.mintPartUrls(init.session_id, tooMany)).rejects.toMatchObject({ status: 400, code: "parts_too_many" });
    await expect(fx.svc.mintPartUrls(init.session_id, [])).rejects.toMatchObject({ status: 400, code: "parts_required" });
    // GET-style status on a checksum session lists what is missing but mints nothing
    const st = await fx.svc.status(init.session_id);
    expect(st.checksum).toBe("crc32");
    expect(st.missing_parts).toHaveLength(init.part_count);
    expect(st.parts).toEqual([]);
  });

  test("a session without checksum mode refuses checksums but still mints plain URLs on demand", async () => {
    const fx = _setup();
    const init = await _init(fx, 100 * 1024 * 1024, { checksum: undefined });
    await expect(fx.svc.mintPartUrls(init.session_id, [{ part_number: 1, checksum_crc32: CRC }]))
      .rejects.toMatchObject({ status: 400, code: "checksum_not_enabled" });
    const out = await fx.svc.mintPartUrls(init.session_id, [{ part_number: 1 }, { part_number: 2 }]);
    expect(out.checksum).toBeNull();
    expect(out.parts.map(p => p.url)).toEqual([expect.not.stringContaining("crc="), expect.not.stringContaining("crc=")]);
  });

  test("complete on a checksum session requires every part's crc32 and passes them to S3", async () => {
    const fx = _setup();
    const file = _png(4096);
    const contentHash = shake256(file);
    const init = await _init(fx, file.length, { contentHash });
    const session = fx.dag.getUploadSession(init.session_id);
    const crc = _crc32(file);
    await fx.svc.mintPartUrls(init.session_id, [{ part_number: 1, checksum_crc32: crc }]);
    const etag = fx.storage._put(session.upload_id, 1, file);
    await expect(fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, [{ part_number: 1, etag }])))
      .rejects.toMatchObject({ status: 400, code: "checksum_required" });
    const res = await fx.svc.complete(init.session_id, _completeArgs(fx, init.session_id, [{ part_number: 1, etag, checksum_crc32: crc }]));
    expect(res.media_id).toBe(contentHash);
    expect(fx.storage._multiparts.get(session.upload_id).completedWith).toEqual([{ part_number: 1, checksum_crc32: crc }]);
  });

  test("mintPartUrls refuses a session that is no longer uploading", async () => {
    const fx = _setup();
    const file = _png(2048);
    const up = await _upload(fx, file, "image/png");
    await fx.svc.complete(up.init.session_id, _completeArgs(fx, up.init.session_id, up.parts));
    await expect(fx.svc.mintPartUrls(up.init.session_id, [{ part_number: 1 }]))
      .rejects.toMatchObject({ status: 409, code: "session_not_uploading" });
  });
});
