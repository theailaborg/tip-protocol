/**
 * @file tests/services/media-storage-s3-copy.test.js
 * @description copyToFinal promotes a verified staged object to its
 * content-addressed key. S3 caps a single CopyObject at 5 GB, so larger
 * objects must go through a server-side multipart copy; the S3Client is
 * stubbed at send() so no credentials or network are involved.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const {
  S3Client, HeadObjectCommand, CopyObjectCommand, CreateMultipartUploadCommand,
  UploadPartCopyCommand, CompleteMultipartUploadCommand, AbortMultipartUploadCommand, DeleteObjectCommand,
} = require("@aws-sdk/client-s3");
const { createS3Backend } = require(path.resolve(__dirname, "../../src/services/media-storage-s3"));
const { S3_SINGLE_COPY_MAX_BYTES, S3_COPY_PART_BYTES } = require(path.resolve(__dirname, "../../../shared/constants"));

const HASH = "ab".repeat(32);
const FINAL_KEY = `media/${HASH.slice(0, 2)}/${HASH.slice(2)}.bin`;
const TMP_KEY = `media/${HASH.slice(0, 2)}/tmp-sess.bin`;
const GIB = 1024 ** 3;

function _notFound() {
  const e = new Error("NotFound");
  e.name = "NotFound";
  e.$metadata = { httpStatusCode: 404 };
  return e;
}

// Fake S3: HEAD final -> 404 until a copy lands; HEAD tmp -> staged size.
function _stubS3(size, opts = {}) {
  const sent = [];
  let finalSize = opts.finalExists ? size : null;
  jest.spyOn(S3Client.prototype, "send").mockImplementation(async (cmd) => {
    sent.push(cmd);
    if (cmd instanceof HeadObjectCommand) {
      if (cmd.input.Key === FINAL_KEY) {
        if (finalSize == null) throw _notFound();
        return { ContentLength: finalSize };
      }
      if (cmd.input.Key === TMP_KEY) return { ContentLength: size };
      throw _notFound();
    }
    if (cmd instanceof CopyObjectCommand) { finalSize = opts.promotedSize ?? size; return {}; }
    if (cmd instanceof CreateMultipartUploadCommand) return { UploadId: "mpu-1" };
    if (cmd instanceof UploadPartCopyCommand) {
      if (opts.failPart === cmd.input.PartNumber) throw new Error("part copy failed");
      return { CopyPartResult: { ETag: `"etag-${cmd.input.PartNumber}"` } };
    }
    if (cmd instanceof CompleteMultipartUploadCommand) { finalSize = opts.promotedSize ?? size; return {}; }
    if (cmd instanceof AbortMultipartUploadCommand) return {};
    if (cmd instanceof DeleteObjectCommand) return {};
    throw new Error(`unexpected command ${cmd.constructor.name}`);
  });
  return sent;
}

const _of = (sent, Cls) => sent.filter(c => c instanceof Cls);

describe("media-storage(s3).copyToFinal", () => {
  let storage;
  beforeEach(() => { storage = createS3Backend({ s3Bucket: "test-bucket", s3Region: "us-east-1" }); });
  afterEach(() => jest.restoreAllMocks());

  test("objects up to S3's 5 GB single-copy ceiling promote with one CopyObject", async () => {
    const sent = _stubS3(S3_SINGLE_COPY_MAX_BYTES);
    const out = await storage.copyToFinal(TMP_KEY, HASH, "video/mp4");
    expect(out).toEqual({ media_id: HASH });
    expect(_of(sent, CopyObjectCommand)).toHaveLength(1);
    expect(_of(sent, CopyObjectCommand)[0].input).toMatchObject({ Key: FINAL_KEY, CopySource: `test-bucket/${TMP_KEY}`, ContentType: "video/mp4" });
    expect(_of(sent, CreateMultipartUploadCommand)).toHaveLength(0);
    expect(_of(sent, DeleteObjectCommand).map(c => c.input.Key)).toEqual([TMP_KEY]);
  });

  test("objects over 5 GB promote with a server-side multipart copy in contiguous ranges", async () => {
    const size = 15 * GIB;
    const sent = _stubS3(size);
    const out = await storage.copyToFinal(TMP_KEY, HASH, "video/mp4");
    expect(out).toEqual({ media_id: HASH });
    expect(_of(sent, CopyObjectCommand)).toHaveLength(0);
    expect(_of(sent, CreateMultipartUploadCommand)).toHaveLength(1);
    expect(_of(sent, CreateMultipartUploadCommand)[0].input).toMatchObject({ Key: FINAL_KEY, ContentType: "video/mp4" });

    const copies = _of(sent, UploadPartCopyCommand).sort((a, b) => a.input.PartNumber - b.input.PartNumber);
    expect(copies).toHaveLength(Math.ceil(size / S3_COPY_PART_BYTES));
    let expectStart = 0;
    for (const c of copies) {
      const m = /^bytes=(\d+)-(\d+)$/.exec(c.input.CopySourceRange);
      expect(Number(m[1])).toBe(expectStart);
      expectStart = Number(m[2]) + 1;
      expect(c.input).toMatchObject({ Key: FINAL_KEY, UploadId: "mpu-1", CopySource: `test-bucket/${TMP_KEY}` });
    }
    expect(expectStart).toBe(size);

    const done = _of(sent, CompleteMultipartUploadCommand);
    expect(done).toHaveLength(1);
    expect(done[0].input.MultipartUpload.Parts.map(p => p.PartNumber)).toEqual(copies.map((_, i) => i + 1));
    expect(done[0].input.MultipartUpload.Parts.map(p => p.ETag)).toEqual(copies.map(c => `"etag-${c.input.PartNumber}"`));
    expect(_of(sent, AbortMultipartUploadCommand)).toHaveLength(0);
    expect(_of(sent, DeleteObjectCommand).map(c => c.input.Key)).toEqual([TMP_KEY]);
  });

  test("a failed range copy aborts the multipart, keeps the staged object, and rethrows", async () => {
    const sent = _stubS3(7 * GIB, { failPart: 3 });
    await expect(storage.copyToFinal(TMP_KEY, HASH, "video/mp4")).rejects.toThrow("part copy failed");
    expect(_of(sent, AbortMultipartUploadCommand)).toHaveLength(1);
    expect(_of(sent, AbortMultipartUploadCommand)[0].input).toMatchObject({ Key: FINAL_KEY, UploadId: "mpu-1" });
    expect(_of(sent, CompleteMultipartUploadCommand)).toHaveLength(0);
    expect(_of(sent, DeleteObjectCommand)).toHaveLength(0);
  });

  test("a promoted object whose size differs from the staged one is deleted, not kept", async () => {
    const sent = _stubS3(6 * GIB, { promotedSize: 6 * GIB - 1 });
    await expect(storage.copyToFinal(TMP_KEY, HASH, "video/mp4")).rejects.toThrow(/promoted object size/);
    expect(_of(sent, DeleteObjectCommand).map(c => c.input.Key)).toEqual([FINAL_KEY]);
  });

  test("dedup: an existing final object skips the copy and drops the staged one", async () => {
    const sent = _stubS3(2 * GIB, { finalExists: true });
    expect(await storage.copyToFinal(TMP_KEY, HASH, "image/png")).toEqual({ media_id: HASH });
    expect(_of(sent, CopyObjectCommand)).toHaveLength(0);
    expect(_of(sent, CreateMultipartUploadCommand)).toHaveLength(0);
    expect(_of(sent, DeleteObjectCommand).map(c => c.input.Key)).toEqual([TMP_KEY]);
  });
});
