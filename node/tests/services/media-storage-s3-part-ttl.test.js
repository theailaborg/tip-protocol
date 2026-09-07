/**
 * @file tests/services/media-storage-s3-part-ttl.test.js
 * @description Presigned part URLs get their own, longer TTL: a multi-hour
 * upload must not have its URLs expire mid-flight, while GET presigns handed
 * to the classifier keep the short default. Signing is local (no network).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const { createS3Backend } = require(path.resolve(__dirname, "../../src/services/media-storage-s3"));
const { UPLOAD_PART_PRESIGN_TTL_SEC } = require(path.resolve(__dirname, "../../../shared/constants"));

const HASH = "cd".repeat(32);
const saved = {};

function _expires(url) {
  return Number(new URL(url).searchParams.get("X-Amz-Expires"));
}

beforeAll(() => {
  for (const k of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "TIP_MEDIA_PART_PRESIGN_TTL_SEC", "TIP_MEDIA_PRESIGN_TTL_SEC"]) {
    saved[k] = process.env[k];
  }
  process.env.AWS_ACCESS_KEY_ID = "AKIATESTONLY";
  process.env.AWS_SECRET_ACCESS_KEY = "test-only-secret";
  delete process.env.TIP_MEDIA_PART_PRESIGN_TTL_SEC;
  delete process.env.TIP_MEDIA_PRESIGN_TTL_SEC;
});

afterAll(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

describe("media-storage(s3) presign TTLs", () => {
  test("part URLs default to the long part TTL, GET presigns keep the short default", async () => {
    const s3 = createS3Backend({ s3Bucket: "bucket-test", s3Region: "us-east-1" });
    const part = await s3.presignUploadPart("mpu-1", `media/cd/tmp-sess.bin`, 7);
    expect(_expires(part)).toBe(UPLOAD_PART_PRESIGN_TTL_SEC);
    expect(s3.partUrlTtlSec).toBe(UPLOAD_PART_PRESIGN_TTL_SEC);
    const get = await s3.presignedGet(HASH);
    expect(_expires(get)).toBe(300);
  });

  test("TIP_MEDIA_PART_PRESIGN_TTL_SEC overrides the part TTL only", async () => {
    process.env.TIP_MEDIA_PART_PRESIGN_TTL_SEC = "900";
    try {
      const s3 = createS3Backend({ s3Bucket: "bucket-test", s3Region: "us-east-1" });
      expect(_expires(await s3.presignUploadPart("mpu-1", `media/cd/tmp-sess.bin`, 1))).toBe(900);
      expect(s3.partUrlTtlSec).toBe(900);
      expect(_expires(await s3.presignedGet(HASH))).toBe(300);
    } finally {
      delete process.env.TIP_MEDIA_PART_PRESIGN_TTL_SEC;
    }
  });

  test("an explicit per-call ttl still wins", async () => {
    const s3 = createS3Backend({ s3Bucket: "bucket-test", s3Region: "us-east-1" });
    expect(_expires(await s3.presignUploadPart("mpu-1", `media/cd/tmp-sess.bin`, 1, 60))).toBe(60);
  });
});
