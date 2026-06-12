/**
 * @file tests/routes/media-access-route.test.js
 * @description M4 route integration test — GET /v1/content/:ctid/media/:idx.
 *
 * Unit tests for the underlying pieces (schema, policy, fetchForReviewer)
 * live in:
 *   - tests/schemas/media-access.test.js
 *   - tests/services/media-access-policy.test.js
 *   - tests/services/media-service.test.js
 *
 * This file exists to catch wiring bugs at the express layer — missing
 * router mount, wrong header names, response-shape regressions across
 * stream / presigned / redirect transports, and errorHandler payload
 * shape on 4xx.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const express = require("express");
const fs = require("fs/promises");
const os = require("os");
const request = require("supertest");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, mldsaSign, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { createMediaStorage } = require(path.join(SRC, "services/media-storage"));
const { createMediaService } = require(path.join(SRC, "services/media-service"));
const mediaAccessSchema = require(path.join(SRC, "schemas/media-access"));
const mediaRoutes = require(path.join(SRC, "routes/media"));
const { errorHandler } = require(path.join(SRC, "middleware/error-handler"));

const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

beforeAll(async () => {
  await initCrypto();
  try { PC._resetForTesting(); } catch { /* not yet initialised */ }
  PC.init(getGenesisPayload().protocol_constants);
});

const CTID = "tip://c/OH-aabbccddeeff11-1234";
const ORIGIN_NODE = "tip://node/efbe3707224fb785";

function _scratch() {
  return fs.mkdtemp(path.join(os.tmpdir(), "tip-media-route-"));
}

function _accessDag({ identity, content, isRevoked = false, nodes = {} }) {
  return {
    getIdentity: (tipId) => (tipId === identity.tip_id ? identity : null),
    isRevoked: () => isRevoked,
    getContent: (ctid) => (content && content.ctid === ctid ? content : null),
    getOpenPrescanReviewByCtid: () => null,
    hasDispute: () => false,
    getTxsByTypeAndCtid: () => [],
    getNode: (nodeId) => nodes[nodeId] || null,
  };
}

function _signedAccess(ctid, idx, requesterTipId, kp, timestamp = nowMs()) {
  const challenge = mediaAccessSchema.buildChallenge({ ctid, idx, timestamp, requester_tip_id: requesterTipId });
  return {
    requester_tip_id: requesterTipId,
    signature: mldsaSign(challenge, kp.privateKey),
    timestamp,
  };
}

function _makeApp({ mediaService }) {
  const app = express();
  // Match the production wrapper in api.js — gives us the same JSON envelope
  // on success and the structured error payload on failures.
  app.use((req, res, next) => {
    const _json = res.json.bind(res);
    res.json = (body) => {
      if (body && body.ok !== undefined) return _json(body);
      return _json({ ok: true, status: res.statusCode, data: body });
    };
    next();
  });
  app.use("/v1", mediaRoutes.createRouter({ mediaService }));
  app.use(errorHandler);
  return app;
}

describe("GET /v1/content/:ctid/media/:idx — stream transport (fs backend)", () => {
  let storage, service, app, root, kp, identity, mediaId;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-1111111111111111", public_key: kp.publicKey, status: "active" };
    const up = await storage.put(Buffer.from("png-bytes-here"), { mime: "image/png" });
    mediaId = up.media_id;

    const content = {
      ctid: CTID,
      signer_tip_id: identity.tip_id,
      media: [{ media_id: mediaId, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    service = createMediaService({ storage, dag: _accessDag({ identity, content }) });
    app = _makeApp({ mediaService: service });
  });

  afterEach(async () => { await fs.rm(root, { recursive: true, force: true }); });

  test("author fetches own media → 200 with image bytes + correct Content-Type", async () => {
    const sig = _signedAccess(CTID, 0, identity.tip_id, kp);
    const res = await request(app)
      .get(`/v1/content/${encodeURIComponent(CTID)}/media/0`)
      .set("X-Requester-TipId", sig.requester_tip_id)
      .set("X-Signature", sig.signature)
      .set("X-Timestamp", String(sig.timestamp))
      .buffer(true)
      .parse((res, cb) => {
        const chunks = [];
        res.on("data", c => chunks.push(c));
        res.on("end", () => cb(null, Buffer.concat(chunks)));
      });

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/^image\/png/);
    expect(res.body.equals(Buffer.from("png-bytes-here"))).toBe(true);
  });
});

describe("GET /v1/content/:ctid/media/:idx — presigned transport (s3 stub)", () => {
  let app, kp, identity;

  beforeEach(() => {
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-2222222222222222", public_key: kp.publicKey, status: "active" };

    // Stub storage that pretends to be the s3 backend — head() reports the
    // object exists, presignedGet() returns a real-looking URL with a TTL.
    // No actual S3 round-trip; we're testing the route's handling of the
    // presigned transport, not the AWS SDK.
    const stubStorage = {
      backend: "s3",
      presignTtlSec: 300,
      head: async () => ({ exists: true, mime: "image/jpeg", size: 1024, created_at: nowMs() }),
      presignedGet: async () => "https://stub-bucket.s3.amazonaws.com/media/aa/bb.bin?X-Amz-Signature=stub",
      get: async () => { throw new Error("presigned path shouldn't call get()"); },
    };
    const content = {
      ctid: CTID,
      signer_tip_id: identity.tip_id,
      media: [{ media_id: "aa".repeat(32), mime: "image/jpeg" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    const service = createMediaService({ storage: stubStorage, dag: _accessDag({ identity, content }) });
    app = _makeApp({ mediaService: service });
  });

  test("returns 200 with { media_id, mime, presigned_url, expires_at }", async () => {
    const sig = _signedAccess(CTID, 0, identity.tip_id, kp);
    const res = await request(app)
      .get(`/v1/content/${encodeURIComponent(CTID)}/media/0`)
      .set("X-Requester-TipId", sig.requester_tip_id)
      .set("X-Signature", sig.signature)
      .set("X-Timestamp", String(sig.timestamp));

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.data.presigned_url).toMatch(/^https:\/\/stub-bucket\.s3/);
    expect(res.body.data.mime).toBe("image/jpeg");
    expect(res.body.data.expires_at).toBeGreaterThan(nowMs());
  });
});

describe("GET /v1/content/:ctid/media/:idx — cross-node redirect", () => {
  let app, kp, identity;

  beforeEach(async () => {
    const root = await _scratch();
    const storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-3333333333333333", public_key: kp.publicKey, status: "active" };

    // Content references a media_id that storage does NOT have — simulates
    // a juror hitting a node that wasn't the upload-receiver.
    const ghostMediaId = "9".repeat(64);
    const content = {
      ctid: CTID,
      signer_tip_id: identity.tip_id,
      media: [{ media_id: ghostMediaId, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    const service = createMediaService({ storage, dag: _accessDag({ identity, content }) });
    app = _makeApp({ mediaService: service });
  });

  test("303 with available_at_node_id when origin node has no api_endpoint", async () => {
    const sig = _signedAccess(CTID, 0, identity.tip_id, kp);
    const res = await request(app)
      .get(`/v1/content/${encodeURIComponent(CTID)}/media/0`)
      .set("X-Requester-TipId", sig.requester_tip_id)
      .set("X-Signature", sig.signature)
      .set("X-Timestamp", String(sig.timestamp));

    expect(res.status).toBe(303);
    expect(res.body.ok).toBe(true);
    expect(res.body.data.available_at_node_id).toBe(ORIGIN_NODE);
    expect(res.body.data.code).toBe("media_remote");
  });

  test("real 307 to the origin node's announced api_endpoint", async () => {
    const root = await _scratch();
    const storage = createMediaStorage({ backend: "fs", fsPath: root });
    const ghostMediaId = "9".repeat(64);
    const content = {
      ctid: CTID,
      signer_tip_id: identity.tip_id,
      media: [{ media_id: ghostMediaId, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    const dag = _accessDag({
      identity, content,
      nodes: { [ORIGIN_NODE]: { node_id: ORIGIN_NODE, api_endpoint: "https://node-a.example.com" } },
    });
    const service = createMediaService({ storage, dag });
    const redirectApp = _makeApp({ mediaService: service });

    const sig = _signedAccess(CTID, 0, identity.tip_id, kp);
    const res = await request(redirectApp)
      .get(`/v1/content/${encodeURIComponent(CTID)}/media/0`)
      .set("X-Requester-TipId", sig.requester_tip_id)
      .set("X-Signature", sig.signature)
      .set("X-Timestamp", String(sig.timestamp))
      .redirects(0);

    expect(res.status).toBe(307);
    expect(res.headers.location).toBe(
      `https://node-a.example.com/v1/content/${encodeURIComponent(CTID)}/media/0`,
    );

    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("POST /v1/media/upload — body-parser size cap", () => {
  test("body above REQUEST_BODY_MAX_BYTES → 413 file_too_large (not 500)", async () => {
    const kp = generateMLDSAKeypair();
    const identity = { tip_id: "tip://id/US-5555555555555555", public_key: kp.publicKey, status: "active" };
    const root = await _scratch();
    const storage = createMediaStorage({ backend: "fs", fsPath: root });
    const service = createMediaService({ storage, dag: _accessDag({ identity, content: null }) });
    const app = _makeApp({ mediaService: service });

    // Real PNG magic + just over the genesis image cap: the streaming
    // route's mid-flight gauge must abort with 413 once the cap is crossed.
    const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const big = Buffer.concat([PNG_MAGIC, Buffer.alloc(PC.CONTENT_LIMITS.IMAGE_MAX_BYTES, 1)]);
    const res = await request(app)
      .post("/v1/media/upload")
      .set("Content-Type", "application/octet-stream")
      .set("X-Media-Mime", "image/png")
      .set("X-Signer-TipId", identity.tip_id)
      .set("X-Signer-Signature", "deadbeef")
      .set("X-Timestamp", String(nowMs()))
      .send(big);

    expect(res.status).toBe(413);
    expect(res.body.error?.code).toBe("file_too_large");
    // Mid-body rejection leaves unread bytes on the wire — the server
    // must tell the client not to reuse the connection.
    expect(res.headers.connection).toBe("close");

    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("GET /v1/content/:ctid/media/:idx — error envelopes", () => {
  let app, kp, identity, otherKp, otherTip;

  beforeEach(async () => {
    const root = await _scratch();
    const storage = createMediaStorage({ backend: "fs", fsPath: root });
    kp = generateMLDSAKeypair();
    identity = { tip_id: "tip://id/US-4444444444444444", public_key: kp.publicKey, status: "active" };
    const up = await storage.put(Buffer.from("img"), { mime: "image/png" });
    const content = {
      ctid: CTID, signer_tip_id: identity.tip_id,
      media: [{ media_id: up.media_id, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    const service = createMediaService({ storage, dag: _accessDag({ identity, content }) });
    app = _makeApp({ mediaService: service });

    otherKp = generateMLDSAKeypair();
    otherTip = "tip://id/US-9999999999999999";
  });

  test("missing headers → 400 with structured shape error", async () => {
    const res = await request(app)
      .get(`/v1/content/${encodeURIComponent(CTID)}/media/0`);
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test("unknown requester → 404 requester_not_found", async () => {
    const sig = _signedAccess(CTID, 0, otherTip, otherKp);
    const res = await request(app)
      .get(`/v1/content/${encodeURIComponent(CTID)}/media/0`)
      .set("X-Requester-TipId", sig.requester_tip_id)
      .set("X-Signature", sig.signature)
      .set("X-Timestamp", String(sig.timestamp));

    expect(res.status).toBe(404);
    expect(res.body.ok).toBe(false);
    expect(res.body.error?.code || res.body.code).toBe("requester_not_found");
  });

  test("outsider (no role) → 403 forbidden", async () => {
    // Make the requester an active DAG identity but with no role on this ctid.
    const outsiderKp = generateMLDSAKeypair();
    const outsiderTip = "tip://id/US-8888888888888888";
    const outsiderIdentity = { tip_id: outsiderTip, public_key: outsiderKp.publicKey, status: "active" };

    const root = await _scratch();
    const storage = createMediaStorage({ backend: "fs", fsPath: root });
    const up = await storage.put(Buffer.from("img"), { mime: "image/png" });
    const author = { tip_id: "tip://id/US-7777777777777777", public_key: "ff".repeat(32), status: "active" };
    const content = {
      ctid: CTID, signer_tip_id: author.tip_id,
      media: [{ media_id: up.media_id, mime: "image/png" }],
      prescan_assigned_node_id: ORIGIN_NODE,
    };
    // dag returns the outsider identity but the content signer is someone else.
    const dag = _accessDag({ identity: outsiderIdentity, content });
    const service = createMediaService({ storage, dag });
    const outsiderApp = _makeApp({ mediaService: service });

    const sig = _signedAccess(CTID, 0, outsiderTip, outsiderKp);
    const res = await request(outsiderApp)
      .get(`/v1/content/${encodeURIComponent(CTID)}/media/0`)
      .set("X-Requester-TipId", sig.requester_tip_id)
      .set("X-Signature", sig.signature)
      .set("X-Timestamp", String(sig.timestamp));

    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.error?.code || res.body.code).toBe("forbidden");

    await fs.rm(root, { recursive: true, force: true });
  });
});
