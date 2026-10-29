/**
 * @file @tip-protocol/node/src/schemas/media-upload.js
 * @description Request validation for POST /v1/media/upload.
 *
 * Owns ALL request-level validation per the project rule (validateRequest
 * lives in schemas/, never inline in services). Matches media-access:
 *
 *   schema (here):                          service (media-service.js):
 *     - shape (bytes, mime, signer, sig)      - signature verifies against
 *     - mime format (image/audio/video or       identity's public_key
 *       a listed document type)
 *     - mime family enabled (video gate)      - storage.put
 *     - per-mime size limit (node-local deps.mediaLimits)
 *     - replay window (nowMs ± window)
 *     - DAG presence (signer exists,
 *       active, not revoked)
 *
 * Challenge format (signed by uploader's ML-DSA-65 key):
 *   MEDIA_UPLOAD:{content_hash_hex}:{mime}:{timestamp}:{signer_tip_id}
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError } = require("./_common");
const { isValidMs, nowMs } = require("../../../shared/time");
const { UPLOAD_CHECKSUM_CRC32, DOCUMENT_MIMES, DOCUMENT_MIME_VALUES } = require("../../../shared/constants");

const TIP_ID_RE = /^tip:\/\/id\/[A-Z]{2}-[0-9a-f]{16}$/;
const HEX_RE = /^[0-9a-f]+$/i;
const MIME_RE = /^(image|audio|video)\/[a-z0-9.+\-]+$/i;
const DOCUMENT_MIME_SET = new Set(DOCUMENT_MIME_VALUES);
// Browsers label RTF either way; the stored mime is the sniffed one anyway.
const DOCUMENT_MIME_ALIASES = new Set(["text/rtf"]);

function isDocumentMime(mime) {
  return typeof mime === "string" && DOCUMENT_MIME_SET.has(mime.toLowerCase());
}

function isAcceptedMime(mime) {
  if (typeof mime !== "string") return false;
  const m = mime.toLowerCase();
  return MIME_RE.test(m) || DOCUMENT_MIME_SET.has(m) || DOCUMENT_MIME_ALIASES.has(m);
}

const SUPPORTED_FORMATS = "png, jpeg, gif, webp, heic, heif, avif, mp3, wav, ogg, flac, m4a, mp4, webm, mkv, "
  + "pdf, rtf, docx, pptx, xlsx, odt, odp, ods, epub";

// ISO-BMFF `ftyp` brands that mark the mp4 container as carrying a still
// image, not audio/video. HEIC/AVIF/HEIF reuse the mp4 `ftyp` box, so a
// bare "ftyp -> video/mp4" sniff mislabels them as video.
const HEIC_BRANDS = new Set(["heic", "heix", "heim", "heis", "hevc", "hevx", "hevm", "hevs"]);
const AVIF_BRANDS = new Set(["avif", "avis"]);
const HEIF_BRANDS = new Set(["mif1", "msf1", "heif", "miaf"]);

// Replay window: signed timestamps from clients must fall within ±N ms of
// server clock. Tight enough to defeat replay; loose enough to forgive
// honest NTP-level clock skew.
const UPLOAD_TIMESTAMP_WINDOW_MS = 5 * 60 * 1000;

function _resolveSizeLimit(mime, limits) {
  if (!limits || typeof limits !== "object") {
    throw new Error("media-upload validate: deps.mediaLimits required");
  }
  if (mime.startsWith("image/")) return limits.max_image_bytes;
  if (mime.startsWith("audio/")) return limits.max_audio_bytes;
  if (mime.startsWith("video/")) return limits.max_video_bytes;
  if (isDocumentMime(mime) || DOCUMENT_MIME_ALIASES.has(mime.toLowerCase())) return limits.max_document_bytes;
  return null;
}

/**
 * Derive the mime from the file's magic bytes. The STORED mime is always
 * this value — the client's X-Media-Mime header is part of the signed
 * challenge but is never trusted for storage, size caps, or classifier
 * routing. A client cannot mislabel bytes (accidentally or maliciously),
 * and dedup can never produce conflicting labels because the stored mime
 * is a pure function of the bytes.
 *
 * Reads the first 16 bytes for the base magic numbers, and further into the
 * `ftyp` box when present to resolve the mp4-container brand. ZIP-based
 * documents are told apart by their member names: `tail` (the file's last
 * bytes) carries the central directory; without it the head is used. Returns
 * null for any format outside the supported set; callers reject those with 415.
 */
function detectMime(bytes, tail = null) {
  if (!bytes || bytes.length < 12) return null;
  const b = bytes;

  // documents
  if (_hasPdfHeader(b)) return DOCUMENT_MIMES.PDF;
  if (b.slice(0, 5).toString("latin1") === "{\\rtf") return DOCUMENT_MIMES.RTF;
  if (b.readUInt32LE(0) === ZIP_LOCAL_SIG) return _zipMime(b, tail || b);

  // image
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return "image/gif";

  // RIFF containers: WEBP (image) vs WAV (audio), split on bytes 8-11
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46) {
    const tag = b.slice(8, 12).toString("ascii");
    if (tag === "WEBP") return "image/webp";
    if (tag === "WAVE") return "audio/wav";
    return null;
  }

  // audio
  if (b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33) return "audio/mpeg";            // ID3-tagged MP3
  // Raw MPEG audio frame sync: 11 sync bits, plus a non-reserved version
  // (bits != 01) and layer (bits != 00). The reserved-bit checks reject
  // ADTS AAC (layer bits 00), which otherwise false-matches as mp3.
  if (b[0] === 0xff && (b[1] & 0xe0) === 0xe0 && (b[1] & 0x18) !== 0x08 && (b[1] & 0x06) !== 0x00) {
    return "audio/mpeg";
  }
  if (b[0] === 0x4f && b[1] === 0x67 && b[2] === 0x67 && b[3] === 0x53) return "audio/ogg";
  if (b[0] === 0x66 && b[1] === 0x4c && b[2] === 0x61 && b[3] === 0x43) return "audio/flac";

  // ISO-BMFF (`ftyp` at offset 4): the brand, not the bare box, decides
  // image (HEIC/AVIF/HEIF) vs audio (M4A) vs video (mp4/mov). HEIC/AVIF
  // stills share this container, so brand inspection is mandatory.
  if (b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70) {
    return _isobmffMime(b);
  }

  // Matroska / WebM (EBML). The DocType element separates matroska from
  // webm; audio-only EBML (.mka/.weba) still can't be split from video
  // without a Tracks parse, so both resolve to a video mime.
  if (b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3) return _ebmlMime(b);

  return null;
}

// The PDF spec lets a few bytes of junk precede the header, within 1024.
function _hasPdfHeader(b) {
  return b.slice(0, Math.min(b.length, 1024)).indexOf("%PDF-", 0, "latin1") !== -1;
}

const ZIP_LOCAL_SIG = 0x04034b50;
const ZIP_CENTRAL_SIG = 0x02014b50;
const ZIP_EOCD_SIG = 0x06054b50;
const ODF_MIMETYPES = Object.freeze({
  "application/vnd.oasis.opendocument.text": DOCUMENT_MIMES.ODT,
  "application/vnd.oasis.opendocument.presentation": DOCUMENT_MIMES.ODP,
  "application/vnd.oasis.opendocument.spreadsheet": DOCUMENT_MIMES.ODS,
  "application/epub+zip": DOCUMENT_MIMES.EPUB,
});
const OOXML_PARTS = Object.freeze([
  ["word/", DOCUMENT_MIMES.DOCX],
  ["ppt/", DOCUMENT_MIMES.PPTX],
  ["xl/", DOCUMENT_MIMES.XLSX],
]);

// A ZIP is only a document when its members say so. OpenDocument and EPUB
// store an uncompressed `mimetype` first entry naming the type; OOXML has
// `[Content_Types].xml` plus its main folder. Macro-carrying OOXML (any
// vbaProject.bin) is refused so a registration can never vouch for macros.
// Anything else (plain archives, APKs, JARs) is not a document.
function _zipMime(head, tail) {
  const odf = _odfMimetype(head);
  if (odf) return ODF_MIMETYPES[odf] || null;
  const names = _zipCentralNames(tail) || _zipLocalNames(head);
  if (!names.includes("[Content_Types].xml")) return null;
  if (names.some(n => /(^|\/)vbaProject\.bin$/i.test(n))) return null;
  for (const [prefix, mime] of OOXML_PARTS) {
    if (names.some(n => n.startsWith(prefix))) return mime;
  }
  return null;
}

function _odfMimetype(b) {
  if (b.length < 30 || b.readUInt32LE(0) !== ZIP_LOCAL_SIG) return null;
  const method = b.readUInt16LE(8);
  const size = b.readUInt32LE(18);
  const nameLen = b.readUInt16LE(26);
  const extraLen = b.readUInt16LE(28);
  if (method !== 0 || size === 0 || size > 128) return null;
  if (b.slice(30, 30 + nameLen).toString("latin1") !== "mimetype") return null;
  const start = 30 + nameLen + extraLen;
  if (start + size > b.length) return null;
  return b.slice(start, start + size).toString("latin1");
}

// Member names from the central directory, or null when the end-of-central-
// directory record (or the directory itself) is not inside `tail`.
function _zipCentralNames(t) {
  const minEocd = 22;
  if (!t || t.length < minEocd) return null;
  let eocd = -1;
  for (let i = t.length - minEocd; i >= 0 && i >= t.length - minEocd - 0xffff; i--) {
    if (t.readUInt32LE(i) === ZIP_EOCD_SIG) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  // ZIP64 directories (0xffffffff) are not parsed; the head fallback covers them.
  const cdSize = t.readUInt32LE(eocd + 12);
  const cdEnd = eocd;
  if (cdSize === 0xffffffff) return null;
  const cdStart = cdEnd - cdSize;
  if (cdStart < 0) return null;
  const names = [];
  for (let p = cdStart; p + 46 <= cdEnd;) {
    if (t.readUInt32LE(p) !== ZIP_CENTRAL_SIG) return null;
    const nameLen = t.readUInt16LE(p + 28);
    const extraLen = t.readUInt16LE(p + 30);
    const commentLen = t.readUInt16LE(p + 32);
    names.push(t.slice(p + 46, p + 46 + nameLen).toString("utf8"));
    p += 46 + nameLen + extraLen + commentLen;
  }
  return names;
}

// Fallback when only the head is known: local headers found by signature
// search, so entries written with data descriptors (sizes after the data,
// common in streamed exports) are still listed.
function _zipLocalNames(b) {
  const names = [];
  for (let i = b.indexOf("PK\x03\x04", 0, "latin1"); i !== -1 && i + 30 <= b.length;
    i = b.indexOf("PK\x03\x04", i + 4, "latin1")) {
    const nameLen = b.readUInt16LE(i + 26);
    if (nameLen === 0 || i + 30 + nameLen > b.length) continue;
    names.push(b.slice(i + 30, i + 30 + nameLen).toString("utf8"));
  }
  return names;
}

// Resolve an ISO-BMFF `ftyp` file to its mime by brand. Collects the major
// brand (bytes 8-11) plus every compatible brand in the box (4-byte slots
// from offset 16 to the box end, bounded by the sniff buffer so a bogus box
// size can't over-read). Image brands win first: a HEIC/AVIF that also lists
// `mp42`/`isom` must not fall through to video, while a real mp4 (no image
// brand) still resolves to video, so no mislabeled upload can dodge a cap.
function _isobmffMime(b) {
  const brands = [b.slice(8, 12).toString("latin1")];
  const boxSize = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  const end = Math.min(b.length, boxSize >= 16 ? boxSize : b.length);
  for (let o = 16; o + 4 <= end; o += 4) brands.push(b.slice(o, o + 4).toString("latin1"));

  if (brands.some((x) => HEIC_BRANDS.has(x))) return "image/heic";
  if (brands.some((x) => AVIF_BRANDS.has(x))) return "image/avif";
  if (brands.some((x) => HEIF_BRANDS.has(x))) return "image/heif";
  if (brands.some((x) => x.startsWith("M4A") || x.startsWith("M4B"))) return "audio/mp4";
  return "video/mp4";
}

// Resolve an EBML container (Matroska/WebM) by its DocType. The header
// carries a DocType element (id 0x4282) holding "webm" or "matroska"; scan
// the sniffed bytes for it. Audio-only EBML (.mka/.weba) is NOT split from
// video here (that needs a Tracks/TrackType parse deeper in the file), so
// both resolve to a video mime, the permissive and safe default.
function _ebmlMime(b) {
  const end = Math.min(b.length, 64);
  for (let i = 4; i + 2 < end; i++) {
    if (b[i] === 0x42 && b[i + 1] === 0x82) {
      const len = b[i + 2] & 0x7f; // EBML vint: strip the length-descriptor bit
      const start = i + 3;
      if (len > 0 && start + len <= b.length && b.slice(start, start + len).toString("latin1") === "matroska") {
        return "video/x-matroska";
      }
      break;
    }
  }
  return "video/webm";
}

/**
 * Gate + size cap for a SNIFFED mime. Throws the same 415/limit errors as
 * the claim-based path, but driven by what the bytes actually are.
 */
function limitForDetectedMime(mime, mediaLimits) {
  if (mime === null) {
    throw schemaError(415, `Unrecognized file format; supported: ${SUPPORTED_FORMATS}`, "format_unsupported");
  }
  const limit = _resolveSizeLimit(mime, mediaLimits);
  if (limit <= 0) {
    throw schemaError(415, `Mime family disabled on this node: ${mime} (detected from bytes)`, "mime_disabled");
  }
  return limit;
}

/**
 * Look up the signer's identity on the DAG and reject if missing,
 * inactive, or revoked. Mirrors media-access.resolveRequester so the
 * "is this caller a valid TIP-ID?" predicate is identical across
 * media endpoints.
 */
function resolveSigner(tipId, dag) {
  const identity = dag.getIdentity(tipId);
  if (!identity) {
    throw schemaError(404, `Unknown signer: ${tipId}`, "signer_not_found");
  }
  if (identity.status !== "active") {
    throw schemaError(403, `Signer not active: ${tipId}`, "signer_inactive");
  }
  if (typeof dag.isRevoked === "function" && dag.isRevoked(tipId)) {
    throw schemaError(403, `Signer revoked: ${tipId}`, "signer_revoked");
  }
  return identity;
}

/**
 * Validation shared by the buffered and streaming upload paths — every
 * check that doesn't need the bytes: mime family + gate, signer format,
 * signature format, timestamp + replay window, DAG presence.
 */
function _validateMeta(input, deps) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "request input is required", "input_invalid");
  }
  if (typeof input.mime !== "string" || input.mime.length === 0) {
    throw schemaError(400, "mime is required", "mime_required");
  }
  if (!isAcceptedMime(input.mime)) {
    throw schemaError(415, `mime must be image/*, audio/*, video/* or a supported document type (got ${input.mime})`, "mime_invalid");
  }

  const sizeLimit = _resolveSizeLimit(input.mime, deps?.mediaLimits);
  if (sizeLimit <= 0) {
    // Cap 0 disables the family on this node. Rejected at the schema layer
    // so callers see a 415 before any storage cost is paid.
    throw schemaError(415, `Mime family disabled on this node: ${input.mime}`, "mime_disabled");
  }

  if (typeof input.signer_tip_id !== "string" || !TIP_ID_RE.test(input.signer_tip_id)) {
    throw schemaError(400, "signer_tip_id is required (tip://id/<REGION>-<16hex>)", "signer_tip_id_required");
  }
  if (typeof input.signature !== "string" || !HEX_RE.test(input.signature) || input.signature.length === 0) {
    throw schemaError(400, "signature is required (hex-encoded ML-DSA)", "signature_required");
  }
  if (!Number.isInteger(input.timestamp) || !isValidMs(input.timestamp)) {
    throw schemaError(400, "timestamp is required (integer ms epoch)", "timestamp_required");
  }

  // Replay defense. Tight ±5min window; client must NTP-sync within
  // reason. Past failures here are usually a client clock skew bug.
  const drift = Math.abs(nowMs() - input.timestamp);
  if (drift > UPLOAD_TIMESTAMP_WINDOW_MS) {
    throw schemaError(
      400,
      `Timestamp drift ${drift}ms exceeds ${UPLOAD_TIMESTAMP_WINDOW_MS}ms window`,
      "timestamp_drift",
    );
  }

  if (!deps || !deps.dag) {
    throw new Error("media-upload validate: deps.dag required");
  }
  resolveSigner(input.signer_tip_id, deps.dag);

  return sizeLimit;
}

/**
 * Validate a buffered media upload request. Throws schemaError on the
 * first problem. Service keeps only the signature verification (needs
 * canonical challenge bytes + the identity's public key).
 *
 * @param {Object} input
 * @param {Buffer} input.bytes
 * @param {string} input.mime
 * @param {string} input.signer_tip_id
 * @param {string} input.signature
 * @param {number} input.timestamp
 * @param {Object} deps          { dag, mediaLimits }: identity lookups + node-local caps
 */
function validateRequest(input, deps) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "request input is required", "input_invalid");
  }
  if (!Buffer.isBuffer(input.bytes) || input.bytes.length === 0) {
    throw schemaError(400, "bytes is required (non-empty buffer)", "bytes_required");
  }
  _validateMeta(input, deps);
  // The bytes decide the mime — gate + cap run on the DETECTED type, so a
  // mislabeled claim can neither dodge a family cap nor poison storage.
  const detected = detectMime(input.bytes);
  const sizeLimit = limitForDetectedMime(detected, deps.mediaLimits);
  if (input.bytes.length > sizeLimit) {
    throw schemaError(413, `File too large: ${input.bytes.length} > ${sizeLimit}`, "file_too_large");
  }
  return detected;
}

/**
 * Validate a STREAMING upload request — everything except the bytes,
 * which haven't arrived yet. Returns the per-mime size limit so the
 * service can abort the stream the moment it's exceeded.
 *
 * @returns {number} max bytes allowed for this mime family
 */
function validateStreamRequest(input, deps) {
  return _validateMeta(input, deps);
}

/**
 * Build the canonical signed challenge for an upload. Single source of
 * truth so client and server compute identical bytes.
 *
 * @param {Object} input
 * @param {string} input.content_hash   shake256(bytes, 32) as 64-hex
 * @param {string} input.mime
 * @param {number} input.timestamp
 * @param {string} input.signer_tip_id
 * @returns {string} canonical challenge
 */
function buildChallenge({ content_hash, mime, timestamp, signer_tip_id }) {
  return `MEDIA_UPLOAD:${content_hash}:${mime}:${timestamp}:${signer_tip_id}`;
}

// S3's CRC32 wire form: base64 of the 4-byte big-endian CRC (always 8 chars, "==" tail).
const CHECKSUM_CRC32_RE = /^[A-Za-z0-9+/]{6}==$/;

// upload-init `checksum`: absent means no per-part integrity, "crc32" opts in.
function validateChecksumMode(value) {
  if (value === undefined || value === null) return null;
  if (value === UPLOAD_CHECKSUM_CRC32) return value;
  throw schemaError(400, `checksum must be "${UPLOAD_CHECKSUM_CRC32}" or omitted`, "checksum_unsupported");
}

// A batch of part entries for URL minting or completion. `required` (checksum
// mode) means every entry must carry a well-formed checksum_crc32; otherwise a
// checksum is refused, since S3 only honours it on a checksum-typed upload.
function validatePartChecksums(parts, { partCount, required, maxParts }) {
  if (!Array.isArray(parts) || parts.length === 0) {
    throw schemaError(400, "parts must be a non-empty array of { part_number, checksum_crc32 }", "parts_required");
  }
  if (maxParts && parts.length > maxParts) {
    throw schemaError(400, `At most ${maxParts} parts per request`, "parts_too_many");
  }
  const seen = new Set();
  return parts.map((p) => {
    const n = Number(p && p.part_number);
    if (!Number.isInteger(n) || n < 1 || n > partCount) {
      throw schemaError(400, `part_number must be an integer in 1..${partCount}`, "part_number_invalid");
    }
    if (seen.has(n)) throw schemaError(400, `part_number ${n} repeated`, "part_number_invalid");
    seen.add(n);
    const crc = p.checksum_crc32;
    if (required) {
      if (typeof crc !== "string" || !CHECKSUM_CRC32_RE.test(crc)) {
        throw schemaError(400, `checksum_crc32 required for part ${n} (base64 of the 4-byte CRC32)`, "checksum_required");
      }
      return { part_number: n, checksum_crc32: crc };
    }
    if (crc !== undefined && crc !== null) {
      throw schemaError(400, "checksum_crc32 given but the session was not opened with checksum: \"crc32\"", "checksum_not_enabled");
    }
    return { part_number: n };
  });
}

module.exports = {
  validateRequest,
  validateStreamRequest,
  validateChecksumMode,
  validatePartChecksums,
  detectMime,
  isDocumentMime,
  isAcceptedMime,
  limitForDetectedMime,
  resolveSigner,
  buildChallenge,
  CHECKSUM_CRC32_RE,
  TIP_ID_RE,
  MIME_RE,
  UPLOAD_TIMESTAMP_WINDOW_MS,
};
