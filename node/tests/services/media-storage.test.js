/**
 * @file tests/services/media-storage.test.js
 * @description Storage-layer contract tests for the local-fs backend.
 *
 * Covers the put / get / head / delete / presignedGet round-trip. The S3
 * backend is tested separately (or skipped here) because it requires real
 * AWS credentials — same pattern as the classifier-client tests that ride
 * past live network.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs   = require("fs/promises");
const os   = require("os");
const SRC  = path.resolve(__dirname, "../../src");
const { createMediaStorage } = require(path.join(SRC, "services/media-storage"));

async function _scratch() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "tip-media-test-"));
  return dir;
}

async function _cleanup(dir) {
  await fs.rm(dir, { recursive: true, force: true });
}

describe("media-storage — local fs backend", () => {
  let storage, root;

  beforeEach(async () => {
    root = await _scratch();
    storage = createMediaStorage({ backend: "fs", fsPath: root });
  });

  afterEach(async () => {
    await _cleanup(root);
  });

  test("put → get round-trips bytes + mime", async () => {
    const bytes = Buffer.from("hello world image bytes");
    const { media_id, size } = await storage.put(bytes, { mime: "image/png" });
    expect(media_id).toMatch(/^[0-9a-f]{64}$/);
    expect(size).toBe(bytes.length);

    const got = await storage.get(media_id);
    expect(got).not.toBeNull();
    expect(got.bytes.equals(bytes)).toBe(true);
    expect(got.mime).toBe("image/png");
    expect(got.size).toBe(bytes.length);
    expect(typeof got.created_at).toBe("number");
  });

  test("content-addressed dedup: same bytes → same media_id (idempotent put)", async () => {
    const bytes = Buffer.from("dedup me");
    const a = await storage.put(bytes, { mime: "image/png" });
    const b = await storage.put(bytes, { mime: "image/png" });
    expect(a.media_id).toBe(b.media_id);
  });

  test("different bytes → different media_id", async () => {
    const a = await storage.put(Buffer.from("alpha"), { mime: "image/png" });
    const b = await storage.put(Buffer.from("beta"),  { mime: "image/png" });
    expect(a.media_id).not.toBe(b.media_id);
  });

  test("head returns metadata without loading bytes", async () => {
    const bytes = Buffer.from("head me");
    const { media_id } = await storage.put(bytes, { mime: "audio/mp3" });
    const h = await storage.head(media_id);
    expect(h.exists).toBe(true);
    expect(h.mime).toBe("audio/mp3");
    expect(h.size).toBe(bytes.length);
  });

  test("head + get return null/exists=false for unknown media_id", async () => {
    const unknown = "0".repeat(64);
    expect(await storage.get(unknown)).toBeNull();
    expect(await storage.head(unknown)).toEqual({ exists: false });
  });

  test("delete removes the object; subsequent get returns null", async () => {
    const bytes = Buffer.from("delete me");
    const { media_id } = await storage.put(bytes, { mime: "image/png" });
    expect(await storage.get(media_id)).not.toBeNull();

    const r = await storage.delete(media_id);
    expect(r.deleted).toBe(true);
    expect(await storage.get(media_id)).toBeNull();

    // Idempotent: deleting again is a no-op, returns { deleted: false }
    expect(await storage.delete(media_id)).toEqual({ deleted: false });
  });

  test("presignedGet returns null on fs backend (callers stream via API)", async () => {
    const { media_id } = await storage.put(Buffer.from("x"), { mime: "image/png" });
    expect(await storage.presignedGet(media_id)).toBeNull();
  });

  test("put rejects non-buffer input", async () => {
    await expect(storage.put("not a buffer", { mime: "image/png" }))
      .rejects.toThrow(/Buffer\/Uint8Array/);
  });

  test("put requires opts.mime", async () => {
    await expect(storage.put(Buffer.from("x"), {}))
      .rejects.toThrow(/opts\.mime/);
  });

  test("malformed media_id is rejected (defensive)", async () => {
    await expect(storage.get("not-a-hash")).rejects.toThrow(/64-char/);
    await expect(storage.head("00ff"))     .rejects.toThrow(/64-char/);
    await expect(storage.delete("ZZ".repeat(32))).rejects.toThrow(/64-char/);
  });

  test("crash safety: write-then-rename means no half-written .bin survives", async () => {
    // We can't simulate a real crash, but we CAN verify the rename strategy
    // by listing the directory after put — no .tmp files should remain.
    const bytes = Buffer.from("crash-safe");
    const { media_id } = await storage.put(bytes, { mime: "image/png" });
    const dir = path.join(root, media_id.slice(0, 2));
    const entries = await fs.readdir(dir);
    expect(entries.some(e => e.endsWith(".tmp"))).toBe(false);
    expect(entries.some(e => e.endsWith(".bin"))).toBe(true);
    expect(entries.some(e => e.endsWith(".meta.json"))).toBe(true);
  });

  test("backend label is fs", () => {
    expect(storage.backend).toBe("fs");
  });
});

describe("media-storage — factory selection", () => {
  test("createMediaStorage defaults to fs when TIP_MEDIA_BACKEND unset", () => {
    delete process.env.TIP_MEDIA_BACKEND;
    const s = createMediaStorage();
    expect(s.backend).toBe("fs");
  });

  test("createMediaStorage honors TIP_MEDIA_BACKEND=fs", () => {
    process.env.TIP_MEDIA_BACKEND = "fs";
    const s = createMediaStorage();
    expect(s.backend).toBe("fs");
    delete process.env.TIP_MEDIA_BACKEND;
  });

  test("createMediaStorage rejects unknown backend", () => {
    expect(() => createMediaStorage({ backend: "redis" })).toThrow(/unknown backend/);
  });

  test("createMediaStorage s3 throws without bucket configured", () => {
    delete process.env.TIP_MEDIA_S3_BUCKET;
    expect(() => createMediaStorage({ backend: "s3" })).toThrow(/TIP_MEDIA_S3_BUCKET/);
  });
});
