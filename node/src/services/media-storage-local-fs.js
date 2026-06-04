/**
 * @file @tip-protocol/node/src/services/media-storage-local-fs.js
 * @description Local filesystem backend for media-storage. Default for dev/test.
 *
 * Layout:
 *   {root}/{media_id[0:2]}/{media_id[2:]}.bin       — raw bytes
 *   {root}/{media_id[0:2]}/{media_id[2:]}.meta.json — { mime, size, created_at }
 *
 * Writes are atomic via write-to-`.tmp` then rename — a crash mid-put leaves
 * either a complete object or nothing (no half-written .bin to confuse readers).
 *
 * No presigning (presignedGet returns null). The API layer that serves media
 * is expected to stream bytes directly when the URL is null.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");

const DEFAULT_ROOT = path.join(process.cwd(), "data/media");

function createLocalFsBackend(config = {}) {
  const root = config.fsPath || process.env.TIP_MEDIA_FS_PATH || DEFAULT_ROOT;

  function _objectKeys(mediaId) {
    if (typeof mediaId !== "string" || !/^[0-9a-f]{64}$/.test(mediaId)) {
      throw new Error("media-storage(fs): media_id must be 64-char lowercase hex");
    }
    const dir = path.join(root, mediaId.slice(0, 2));
    const base = mediaId.slice(2);
    return { dir, bin: path.join(dir, `${base}.bin`), meta: path.join(dir, `${base}.meta.json`) };
  }

  async function _computeMediaId(bytes) {
    // SHAKE-256 isn't in Node's crypto, but SHA3-256 fixed-256-output is
    // functionally equivalent for content-addressing here. Both give 64-hex
    // content-deterministic ids. We use SHA3-256 to avoid a snarkjs dep at
    // this layer — content-hash (which IS shake256) is computed elsewhere
    // and stored in the sidecar / passed as opts.contentHash.
    const h = crypto.createHash("sha3-256").update(bytes).digest("hex");
    return h;
  }

  async function _exists(p) {
    try { await fs.access(p); return true; } catch { return false; }
  }

  async function put(bytes, opts = {}) {
    if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
      throw new Error("media-storage(fs): put requires Buffer/Uint8Array bytes");
    }
    if (!opts.mime || typeof opts.mime !== "string") {
      throw new Error("media-storage(fs): put requires opts.mime");
    }
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    const mediaId = await _computeMediaId(buf);
    const { dir, bin, meta } = _objectKeys(mediaId);

    // Content-addressed dedup: if the bin already exists with our id, the
    // bytes are byte-identical (otherwise the id would differ). Skip the
    // write. Sidecar may still need refreshing if it's missing — rare, but
    // keeps invariants tight.
    if (await _exists(bin)) {
      if (!(await _exists(meta))) {
        await fs.writeFile(meta, JSON.stringify({
          mime: opts.mime, size: buf.length, created_at: Date.now(),
        }));
      }
      return { media_id: mediaId, size: buf.length };
    }

    await fs.mkdir(dir, { recursive: true });

    // Write to .tmp first so a crash mid-write doesn't leave half a file.
    const tmpBin = `${bin}.tmp`;
    const tmpMeta = `${meta}.tmp`;
    await fs.writeFile(tmpBin, buf);
    await fs.writeFile(tmpMeta, JSON.stringify({
      mime: opts.mime, size: buf.length, created_at: Date.now(),
    }));
    await fs.rename(tmpBin, bin);
    await fs.rename(tmpMeta, meta);

    return { media_id: mediaId, size: buf.length };
  }

  async function get(mediaId) {
    const { bin, meta } = _objectKeys(mediaId);
    if (!(await _exists(bin))) return null;
    const [bytes, metaRaw] = await Promise.all([fs.readFile(bin), fs.readFile(meta, "utf8")]);
    const m = JSON.parse(metaRaw);
    return { bytes, mime: m.mime, size: m.size, created_at: m.created_at };
  }

  async function head(mediaId) {
    const { bin, meta } = _objectKeys(mediaId);
    if (!(await _exists(bin))) return { exists: false };
    const metaRaw = await fs.readFile(meta, "utf8");
    const m = JSON.parse(metaRaw);
    return { exists: true, mime: m.mime, size: m.size, created_at: m.created_at };
  }

  async function presignedGet() {
    // Local filesystem has no presigning concept — caller streams via API.
    return null;
  }

  async function deleteMedia(mediaId) {
    const { bin, meta } = _objectKeys(mediaId);
    const existed = await _exists(bin);
    if (!existed) return { deleted: false };
    await Promise.all([
      fs.unlink(bin).catch(() => { }),
      fs.unlink(meta).catch(() => { }),
    ]);
    return { deleted: true };
  }

  return { put, get, head, presignedGet, delete: deleteMedia, backend: "fs" };
}

module.exports = { createLocalFsBackend };
