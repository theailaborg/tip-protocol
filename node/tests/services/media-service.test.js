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
const mediaAccessSchema = require(path.join(SRC, "schemas/media-access"));
const { PRESCAN_REVIEW_STATES } = require(path.join(SHARED, "constants"));

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

// ─── M3: resolveRefs (used by content-service to validate REGISTER refs) ────

describe("media-service.resolveRefs", () => {
  let storage, service, root, kp, identity;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-eeeeeeeeeeeeeeee", public_key: kp.publicKey, status: "active" };
    service = createMediaService({ storage, dag: _fakeDag(identity) });
  });

  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("empty / missing media → []", async () => {
    expect(await service.resolveRefs([])).toEqual([]);
    expect(await service.resolveRefs(undefined)).toEqual([]);
    expect(await service.resolveRefs(null)).toEqual([]);
  });

  test("missing ref → 404 media_not_found", async () => {
    const ghost = "0".repeat(64);
    await expect(service.resolveRefs([{ media_id: ghost, mime: "image/png" }]))
      .rejects.toMatchObject({ status: 404, code: "media_not_found" });
  });

  test("mime mismatch → 400 media_mime_mismatch", async () => {
    const r = await service.upload(_signedUpload(Buffer.from("png-bytes"), "image/png", identity.tip_id, kp));
    await expect(service.resolveRefs([{ media_id: r.media_id, mime: "image/jpeg" }]))
      .rejects.toMatchObject({ status: 400, code: "media_mime_mismatch" });
  });

  test("happy path: returns canonical [{media_id, mime}], mime lowercased", async () => {
    const r = await service.upload(_signedUpload(Buffer.from("png-1"), "image/png", identity.tip_id, kp));
    const out = await service.resolveRefs([{ media_id: r.media_id, mime: "IMAGE/PNG" }]);
    expect(out).toEqual([{ media_id: r.media_id, mime: "image/png" }]);
  });

  test("dedups on media_id — duplicate refs collapse to one entry", async () => {
    const r = await service.upload(_signedUpload(Buffer.from("dup-bytes"), "image/png", identity.tip_id, kp));
    const out = await service.resolveRefs([
      { media_id: r.media_id, mime: "image/png" },
      { media_id: r.media_id, mime: "image/png" },
    ]);
    expect(out).toHaveLength(1);
  });
});

// ─── M3: fetchForClassifier (used by the prescan worker fan-out) ────────────

describe("media-service.fetchForClassifier", () => {
  let storage, service, root, kp, identity;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-ffffffffffffffff", public_key: kp.publicKey, status: "active" };
    service = createMediaService({ storage, dag: _fakeDag(identity) });
  });

  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("empty media → []", async () => {
    expect(await service.fetchForClassifier([])).toEqual([]);
  });

  test("returns {base64, mime} per ref, preserving order", async () => {
    const a = await service.upload(_signedUpload(Buffer.from("alpha"), "image/png", identity.tip_id, kp));
    const b = await service.upload(_signedUpload(Buffer.from("beta"),  "image/jpeg", identity.tip_id, kp));
    const out = await service.fetchForClassifier([
      { media_id: a.media_id, mime: "image/png" },
      { media_id: b.media_id, mime: "image/jpeg" },
    ]);
    expect(out).toHaveLength(2);
    expect(Buffer.from(out[0].base64, "base64").toString()).toBe("alpha");
    expect(out[0].mime).toBe("image/png");
    expect(Buffer.from(out[1].base64, "base64").toString()).toBe("beta");
    expect(out[1].mime).toBe("image/jpeg");
  });

  test("missing media_id in storage → throws (worker treats as hard failure)", async () => {
    const ghost = "0".repeat(64);
    await expect(service.fetchForClassifier([{ media_id: ghost, mime: "image/png" }]))
      .rejects.toThrow(/not found in storage/);
  });
});

// ─── M4: fetchForReviewer ────────────────────────────────────────────────

const CTID = "tip://c/OH-aabbccddeeff11-1234";
const ORIGIN_NODE = "tip://node/efbe3707224fb785";

function _accessDag({ identity, content, openReview = null, disputerSet = new Set(), isRevoked = false }) {
  return {
    getIdentity: (tipId) => (tipId === identity.tip_id ? identity : null),
    isRevoked: () => isRevoked,
    getContent: (ctid) => (content && content.ctid === ctid ? content : null),
    getOpenPrescanReviewByCtid: (ctid) => (openReview && openReview.ctid === ctid ? openReview : null),
    hasDispute: (ctid, tipId) => disputerSet.has(`${ctid}|${tipId}`),
  };
}

function _signedAccess(ctid, idx, requesterTipId, kp, timestamp = nowMs()) {
  const challenge = mediaAccessSchema.buildChallenge({ ctid, idx, timestamp, requester_tip_id: requesterTipId });
  const signature = mldsaSign(challenge, kp.privateKey);
  return { ctid, idx, requester_tip_id: requesterTipId, signature, timestamp };
}

describe("media-service.fetchForReviewer — happy path", () => {
  let storage, service, root, kp, identity, mediaId;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-1111111111111111", public_key: kp.publicKey, status: "active" };

    // Pre-load a media object on the local backend so the route serves
    // bytes (not a redirect).
    const up = await storage.put(Buffer.from("png-bytes"), { mime: "image/png" });
    mediaId = up.media_id;

    const content = {
      ctid: CTID,
      signer_tip_id: identity.tip_id,
      media: [{ media_id: mediaId, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    service = createMediaService({ storage, dag: _accessDag({ identity, content }) });
  });

  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("author fetches own media → transport=stream, bytes returned", async () => {
    const out = await service.fetchForReviewer(_signedAccess(CTID, 0, identity.tip_id, kp));
    expect(out.transport).toBe("stream");
    expect(out.role).toBe("author");
    expect(out.bytes.toString()).toBe("png-bytes");
    expect(out.mime).toBe("image/png");
  });
});

describe("media-service.fetchForReviewer — validation + auth", () => {
  let storage, service, root, kp, identity, mediaId, content;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-2222222222222222", public_key: kp.publicKey, status: "active" };
    const up = await storage.put(Buffer.from("png-bytes"), { mime: "image/png" });
    mediaId = up.media_id;
    content = {
      ctid: CTID,
      signer_tip_id: identity.tip_id,
      media: [{ media_id: mediaId, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
  });

  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("schema validation fires before service work (e.g. malformed ctid)", async () => {
    // Sanity-check: the service forwards into schema.validateRequest. Full
    // shape + DAG-presence coverage lives in tests/schemas/media-access.test.js.
    service = createMediaService({ storage, dag: _accessDag({ identity, content }) });
    const input = _signedAccess(CTID, 0, identity.tip_id, kp);
    input.ctid = "not-a-ctid";
    await expect(service.fetchForReviewer(input)).rejects.toMatchObject({ code: "ctid_invalid" });
  });

  test("wrong signature → 403 signature_invalid", async () => {
    service = createMediaService({ storage, dag: _accessDag({ identity, content }) });
    const decoyKp = generateMLDSAKeypair();
    const input = _signedAccess(CTID, 0, identity.tip_id, decoyKp);  // signed by wrong key
    await expect(service.fetchForReviewer(input)).rejects.toMatchObject({ code: "signature_invalid" });
  });
});

describe("media-service.fetchForReviewer — policy gate", () => {
  let storage, service, root, kp, identity, mediaId;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-3333333333333333", public_key: kp.publicKey, status: "active" };
    const up = await storage.put(Buffer.from("png-bytes"), { mime: "image/png" });
    mediaId = up.media_id;
  });

  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("outsider (no role) → 403 forbidden", async () => {
    const author = { tip_id: "tip://id/US-aaaaaaaaaaaaaaaa", public_key: "ff".repeat(32), status: "active" };
    const content = {
      ctid: CTID, signer_tip_id: author.tip_id,
      media: [{ media_id: mediaId, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    service = createMediaService({ storage, dag: _accessDag({ identity, content }) });

    const input = _signedAccess(CTID, 0, identity.tip_id, kp);
    await expect(service.fetchForReviewer(input)).rejects.toMatchObject({ status: 403, code: "forbidden" });
  });

  test("assigned reviewer with open TRIGGERED review → allowed, role=assigned_reviewer", async () => {
    const author = { tip_id: "tip://id/US-bbbbbbbbbbbbbbbb", public_key: "ff".repeat(32), status: "active" };
    const content = {
      ctid: CTID, signer_tip_id: author.tip_id,
      media: [{ media_id: mediaId, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    const openReview = { ctid: CTID, assigned_reviewer: identity.tip_id, state: PRESCAN_REVIEW_STATES.TRIGGERED };
    service = createMediaService({ storage, dag: _accessDag({ identity, content, openReview }) });

    const out = await service.fetchForReviewer(_signedAccess(CTID, 0, identity.tip_id, kp));
    expect(out.role).toBe("assigned_reviewer");
    expect(out.transport).toBe("stream");
  });

  test("disputer (hasDispute true) → allowed, role=disputer", async () => {
    const author = { tip_id: "tip://id/US-cccccccccccccccc", public_key: "ff".repeat(32), status: "active" };
    const content = {
      ctid: CTID, signer_tip_id: author.tip_id,
      media: [{ media_id: mediaId, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    const disputerSet = new Set([`${CTID}|${identity.tip_id}`]);
    service = createMediaService({ storage, dag: _accessDag({ identity, content, disputerSet }) });

    const out = await service.fetchForReviewer(_signedAccess(CTID, 0, identity.tip_id, kp));
    expect(out.role).toBe("disputer");
  });
});

describe("media-service.fetchForReviewer — idx + cross-node", () => {
  let storage, service, root, kp, identity;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-4444444444444444", public_key: kp.publicKey, status: "active" };
  });

  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("idx out of range → 404 media_idx_out_of_range", async () => {
    const up = await storage.put(Buffer.from("png-bytes"), { mime: "image/png" });
    const content = {
      ctid: CTID, signer_tip_id: identity.tip_id,
      media: [{ media_id: up.media_id, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    service = createMediaService({ storage, dag: _accessDag({ identity, content }) });

    await expect(service.fetchForReviewer(_signedAccess(CTID, 5, identity.tip_id, kp)))
      .rejects.toMatchObject({ status: 404, code: "media_idx_out_of_range" });
  });

  test("bytes not held locally → redirect with origin_node_id", async () => {
    // Content references a media_id that storage does NOT have. Simulates
    // a juror hitting a node that wasn't the upload-receiver, in a federation
    // without shared S3.
    const ghostMediaId = "9".repeat(64);
    const content = {
      ctid: CTID, signer_tip_id: identity.tip_id,
      media: [{ media_id: ghostMediaId, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    service = createMediaService({ storage, dag: _accessDag({ identity, content }) });

    const out = await service.fetchForReviewer(_signedAccess(CTID, 0, identity.tip_id, kp));
    expect(out.transport).toBe("redirect");
    expect(out.origin_node_id).toBe(ORIGIN_NODE);
  });

  test("bytes not held locally AND origin unknown → 410 media_unavailable", async () => {
    const ghostMediaId = "9".repeat(64);
    const content = {
      ctid: CTID, signer_tip_id: identity.tip_id,
      media: [{ media_id: ghostMediaId, mime: "image/png" }],
      prescan_assigned_node_id: null,  // unknown — can't redirect
    };
    service = createMediaService({ storage, dag: _accessDag({ identity, content }) });

    await expect(service.fetchForReviewer(_signedAccess(CTID, 0, identity.tip_id, kp)))
      .rejects.toMatchObject({ status: 410, code: "media_unavailable" });
  });
});
