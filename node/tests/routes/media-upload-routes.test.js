/**
 * @file tests/routes/media-upload-routes.test.js
 * @description Wiring test for the presigned multipart upload routes. The
 * service is unit-tested elsewhere; this catches a request field the route
 * forgets to forward (the checksum opt-in was missed exactly this way), the
 * POST/GET split on upload-status, and error-envelope shape.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const express = require("express");
const request = require("supertest");

const SRC = path.resolve(__dirname, "../../src");
const mediaRoutes = require(path.join(SRC, "routes/media"));
const { errorHandler } = require(path.join(SRC, "middleware/error-handler"));
const { schemaError } = require(path.join(SRC, "schemas/_common"));

function _app() {
  const calls = [];
  const chunkedUploadService = {
    async init(args) { calls.push(["init", args]); return { session_id: "s1", checksum: args.checksum || null, parts: [] }; },
    async status(id) { calls.push(["status", id]); return { state: "uploading", parts: [] }; },
    async mintPartUrls(id, parts) {
      calls.push(["mintPartUrls", id, parts]);
      if (!Array.isArray(parts) || parts.length === 0) throw schemaError(400, "parts required", "parts_required");
      return { state: "uploading", checksum: "crc32", parts: parts.map(p => ({ ...p, url: `u${p.part_number}` })) };
    },
    async complete(id, args) { calls.push(["complete", id, args]); return { state: "finalizing", session_id: id, poll_after_ms: 5000 }; },
    async abort(id) { calls.push(["abort", id]); return { aborted: true }; },
  };
  const app = express();
  app.use("/v1", mediaRoutes.createRouter({ mediaService: {}, chunkedUploadService }));
  app.use(errorHandler);
  return { app, calls };
}

describe("media upload routes forward every request field", () => {
  test("upload-init passes checksum and part_size through to the service", async () => {
    const { app, calls } = _app();
    const res = await request(app).post("/v1/media/upload-init").send({
      mime: "video/mp4", size: 10, content_hash: "ab".repeat(32), signer_tip_id: "tip://id/US-1",
      timestamp: 1, signature: "sig", part_size: 5242880, checksum: "crc32",
    });
    expect(res.status).toBe(201);
    expect(calls[0][0]).toBe("init");
    expect(calls[0][1]).toMatchObject({ mime: "video/mp4", size: 10, part_size: 5242880, checksum: "crc32" });
    expect((res.body.data || res.body).checksum).toBe("crc32");
  });

  test("GET upload-status resumes, POST upload-status mints checksum-bound urls", async () => {
    const { app, calls } = _app();
    expect((await request(app).get("/v1/media/upload-status/s1")).status).toBe(200);
    expect(calls[0]).toEqual(["status", "s1"]);
    const parts = [{ part_number: 1, checksum_crc32: "SORArw==" }];
    const res = await request(app).post("/v1/media/upload-status/s1").send({ parts });
    expect(res.status).toBe(200);
    expect(calls[1]).toEqual(["mintPartUrls", "s1", parts]);
    expect((res.body.data || res.body).parts[0].url).toBe("u1");
  });

  test("a service schemaError surfaces as the envelope with its code", async () => {
    const { app } = _app();
    const res = await request(app).post("/v1/media/upload-status/s1").send({ parts: [] });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("parts_required");
  });

  test("upload-complete forwards the checksum on each part and maps finalizing to 202", async () => {
    const { app, calls } = _app();
    const parts = [{ part_number: 1, etag: "\"e1\"", checksum_crc32: "SORArw==" }];
    const res = await request(app).post("/v1/media/upload-complete/s1").send({ signer_tip_id: "tip://id/US-1", timestamp: 1, signature: "sig", parts });
    expect(res.status).toBe(202);
    expect(calls[0][2].parts).toEqual(parts);
  });
});
