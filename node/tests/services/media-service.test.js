/**
 * @file tests/services/media-service.test.js
 * @description Service-layer tests for media uploads — shape validation,
 * size limits, identity gates, signature verification, replay defense,
 * round-trip success.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs/promises");
const os = require("os");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, mldsaSign, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { createMediaStorage } = require(path.join(SRC, "services/media-storage"));
const { createMediaService } = require(path.join(SRC, "services/media-service"));
const mediaUploadSchema = require(path.join(SRC, "schemas/media-upload"));

// Initialise protocol constants so CONTENT_LIMITS getters return real values.
const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

beforeAll(async () => {
  await initCrypto();
  try { PC._resetForTesting(); } catch { /* not yet initialised */ }
  PC.init(getGenesisPayload().protocol_constants);
});

function _fakeDag(identity, isRevoked = false) {
  return {
    getIdentity: (tipId) => tipId === identity.tip_id ? identity : null,
    isRevoked: () => isRevoked,
  };
}

async function _scratch() {
  return fs.mkdtemp(path.join(os.tmpdir(), "tip-media-service-"));
}

function _signedUpload(bytes, mime, signerTipId, kp, timestamp = nowMs()) {
  const content_hash = shake256(bytes);
  const challenge = mediaUploadSchema.buildChallenge({ content_hash, mime, timestamp, signer_tip_id: signerTipId });
  const signature = mldsaSign(challenge, kp.privateKey);
  return { bytes, mime, signer_tip_id: signerTipId, signature, timestamp };
}

describe("media-service.upload — happy path", () => {
  let storage, service, root, kp, identity;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = {
      tip_id: "tip://id/US-aaaaaaaaaaaaaaaa", public_key: kp.publicKey,
      status: "active",
    };
    service = createMediaService({ storage, dag: _fakeDag(identity) });
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  test("uploads valid image; returns media_id + content_hash + size", async () => {
    const bytes = Buffer.from("png-bytes-here");
    const input = _signedUpload(bytes, "image/png", identity.tip_id, kp);
    const r = await service.upload(input);

    expect(r.media_id).toMatch(/^[0-9a-f]{64}$/);
    expect(r.content_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(r.mime).toBe("image/png");
    expect(r.size).toBe(bytes.length);
    expect(r.signer_tip_id).toBe(identity.tip_id);
    expect(typeof r.uploaded_at).toBe("number");
  });

  test("media_id equals shake256(bytes) — single hash across storage + protocol", async () => {
    const bytes = Buffer.from("equivalence proof");
    const r = await service.upload(_signedUpload(bytes, "image/png", identity.tip_id, kp));
    expect(r.media_id).toBe(shake256(bytes));
    expect(r.media_id).toBe(r.content_hash);
  });

  test("upload then fetchBytes round-trips", async () => {
    const bytes = Buffer.from("round trip me");
    const r = await service.upload(_signedUpload(bytes, "image/png", identity.tip_id, kp));
    const got = await service.fetchBytes(r.media_id);
    expect(got.bytes.equals(bytes)).toBe(true);
    expect(got.mime).toBe("image/png");
  });
});

describe("media-service.upload — validation", () => {
  let storage, service, root, kp, identity;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-bbbbbbbbbbbbbbbb", public_key: kp.publicKey, status: "active" };
    service = createMediaService({ storage, dag: _fakeDag(identity) });
  });

  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("rejects empty bytes", async () => {
    const input = _signedUpload(Buffer.alloc(0), "image/png", identity.tip_id, kp);
    await expect(service.upload(input)).rejects.toMatchObject({ code: "bytes_required" });
  });

  test("rejects unsupported mime family", async () => {
    const input = _signedUpload(Buffer.from("x"), "application/pdf", identity.tip_id, kp);
    await expect(service.upload(input)).rejects.toMatchObject({ code: "mime_invalid" });
  });

  test("rejects video (gated by VIDEO_MAX_BYTES=0)", async () => {
    const input = _signedUpload(Buffer.from("x"), "video/mp4", identity.tip_id, kp);
    await expect(service.upload(input)).rejects.toMatchObject({ code: "mime_disabled" });
  });

  test("rejects malformed signer_tip_id", async () => {
    const input = _signedUpload(Buffer.from("x"), "image/png", "not-a-tip-id", kp);
    await expect(service.upload(input)).rejects.toMatchObject({ code: "signer_tip_id_required" });
  });

  test("rejects non-hex signature", async () => {
    const input = _signedUpload(Buffer.from("x"), "image/png", identity.tip_id, kp);
    input.signature = "NOT-HEX!";
    await expect(service.upload(input)).rejects.toMatchObject({ code: "signature_required" });
  });

  test("rejects non-integer timestamp", async () => {
    const input = _signedUpload(Buffer.from("x"), "image/png", identity.tip_id, kp);
    input.timestamp = "not-a-number";
    await expect(service.upload(input)).rejects.toMatchObject({ code: "timestamp_required" });
  });

  test("rejects file exceeding size limit", async () => {
    // image limit = 5MB; send 6MB. Sign over the actual bytes.
    const big = Buffer.alloc(6 * 1024 * 1024, 0x42);
    const input = _signedUpload(big, "image/png", identity.tip_id, kp);
    await expect(service.upload(input)).rejects.toMatchObject({ code: "file_too_large" });
  });

  test("rejects timestamp outside replay window", async () => {
    const stale = nowMs() - (10 * 60 * 1000); // 10 min ago
    const input = _signedUpload(Buffer.from("x"), "image/png", identity.tip_id, kp, stale);
    await expect(service.upload(input)).rejects.toMatchObject({ code: "timestamp_drift" });
  });
});

describe("media-service.upload — identity + signature checks", () => {
  let storage, service, root, kp, identity;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-cccccccccccccccc", public_key: kp.publicKey, status: "active" };
  });

  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("rejects unknown signer", async () => {
    service = createMediaService({ storage, dag: _fakeDag(identity) });
    const otherKp = generateMLDSAKeypair();
    const otherTip = "tip://id/US-ffffffffffffffff";
    const input = _signedUpload(Buffer.from("x"), "image/png", otherTip, otherKp);
    await expect(service.upload(input)).rejects.toMatchObject({ code: "signer_not_found" });
  });

  test("rejects inactive signer", async () => {
    service = createMediaService({ storage, dag: _fakeDag({ ...identity, status: "suspended" }) });
    const input = _signedUpload(Buffer.from("x"), "image/png", identity.tip_id, kp);
    await expect(service.upload(input)).rejects.toMatchObject({ code: "signer_inactive" });
  });

  test("rejects revoked signer", async () => {
    service = createMediaService({ storage, dag: _fakeDag(identity, /* isRevoked */ true) });
    const input = _signedUpload(Buffer.from("x"), "image/png", identity.tip_id, kp);
    await expect(service.upload(input)).rejects.toMatchObject({ code: "signer_revoked" });
  });

  test("rejects wrong signature (signed by different key)", async () => {
    service = createMediaService({ storage, dag: _fakeDag(identity) });
    const decoyKp = generateMLDSAKeypair();
    const input = _signedUpload(Buffer.from("x"), "image/png", identity.tip_id, decoyKp);
    await expect(service.upload(input)).rejects.toMatchObject({ code: "signature_invalid" });
  });
});

describe("media-service — content-addressed dedup", () => {
  test("identical bytes from the same signer produce the same media_id", async () => {
    const root = await _scratch();
    try {
      const storage = createMediaStorage({ backend: "fs", fsPath: root });
      const kp = generateMLDSAKeypair();
      const identity = { tip_id: "tip://id/US-dddddddddddddddd", public_key: kp.publicKey, status: "active" };
      const service = createMediaService({ storage, dag: _fakeDag(identity) });

      const bytes = Buffer.from("dedup");
      const r1 = await service.upload(_signedUpload(bytes, "image/png", identity.tip_id, kp));
      const r2 = await service.upload(_signedUpload(bytes, "image/png", identity.tip_id, kp));
      expect(r1.media_id).toBe(r2.media_id);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
