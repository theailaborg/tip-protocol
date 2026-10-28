/**
 * @file tests/media-document-detect.test.js
 * @description Document uploads: type detection from the bytes (PDF, RTF and
 * ZIP-based OOXML / OpenDocument / EPUB) and the streaming head/tail sniffer.
 * Fixtures in fixtures/documents were made by real tools (macOS cupsfilter and
 * textutil) or Python zipfile for the formats and edge cases those can't
 * write: a data-descriptor ("streamed") DOCX and a DOCX whose OOXML names sit
 * only past the first 64 KiB.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const SHARED = path.resolve(__dirname, "../../shared");
const SRC = path.resolve(__dirname, "../src");

const mediaUpload = require(path.join(SRC, "schemas/media-upload"));
const { createMediaSniffer } = require(path.join(SRC, "services/media-sniff"));
const { DOCUMENT_MIMES, MEDIA_LIMITS, MEDIA_SNIFF_HEAD_BYTES } = require(path.join(SHARED, "constants"));

const FIX = path.join(__dirname, "fixtures/documents");
const read = (f) => fs.readFileSync(path.join(FIX, f));

const ACCEPTED = [
  ["fixture.pdf", DOCUMENT_MIMES.PDF],
  ["fixture.rtf", DOCUMENT_MIMES.RTF],
  ["fixture.docx", DOCUMENT_MIMES.DOCX],
  ["fixture.pptx", DOCUMENT_MIMES.PPTX],
  ["fixture.xlsx", DOCUMENT_MIMES.XLSX],
  ["fixture.odt", DOCUMENT_MIMES.ODT],
  ["fixture.odp", DOCUMENT_MIMES.ODP],
  ["fixture.ods", DOCUMENT_MIMES.ODS],
  ["fixture.epub", DOCUMENT_MIMES.EPUB],
  ["streamed.docx", DOCUMENT_MIMES.DOCX],
  ["names-at-end.docx", DOCUMENT_MIMES.DOCX],
];

const REFUSED = [
  ["archive.zip", "a plain archive"],
  ["fake-office.zip", "OOXML folder without [Content_Types].xml"],
  ["macro.docm", "macro-carrying OOXML"],
  ["template.ott", "OpenDocument type outside the list"],
  ["legacy.doc", "legacy Office compound file"],
];

function sniffChunks(bytes, chunkSize) {
  const s = createMediaSniffer();
  for (let i = 0; i < bytes.length; i += chunkSize) s.push(bytes.subarray(i, i + chunkSize));
  return s;
}

describe("detectMime: documents from their bytes", () => {
  test.each(ACCEPTED)("%s → %s", (file, mime) => {
    expect(mediaUpload.detectMime(read(file))).toBe(mime);
  });

  test.each(REFUSED)("%s is refused (%s)", (file) => {
    expect(mediaUpload.detectMime(read(file))).toBeNull();
  });

  test("a PDF header may follow up to 1024 bytes of leading junk, not more", () => {
    const pdf = read("fixture.pdf");
    expect(mediaUpload.detectMime(Buffer.concat([Buffer.alloc(900, 0x20), pdf]))).toBe(DOCUMENT_MIMES.PDF);
    expect(mediaUpload.detectMime(Buffer.concat([Buffer.alloc(1100, 0x20), pdf]))).toBeNull();
  });

  test("names-at-end.docx needs the tail: the first 64 KiB alone do not say Word", () => {
    const docx = read("names-at-end.docx");
    expect(docx.length).toBeGreaterThan(MEDIA_SNIFF_HEAD_BYTES);
    const head = docx.subarray(0, MEDIA_SNIFF_HEAD_BYTES);
    expect(mediaUpload.detectMime(head, head)).toBeNull();
    expect(mediaUpload.detectMime(head, docx.subarray(docx.length - 4096))).toBe(DOCUMENT_MIMES.DOCX);
  });

  test("streamed.docx (data descriptors) is read from the head alone too", () => {
    const docx = read("streamed.docx");
    expect(mediaUpload.detectMime(docx, docx.subarray(0, 0))).toBe(DOCUMENT_MIMES.DOCX);
  });

  test("existing media detection is unchanged", () => {
    const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(16)]);
    expect(mediaUpload.detectMime(png)).toBe("image/png");
    expect(mediaUpload.detectMime(Buffer.alloc(64, 0))).toBeNull();
  });
});

describe("claims, caps and errors", () => {
  test("document mimes are accepted claims; other application/* are not", () => {
    for (const m of Object.values(DOCUMENT_MIMES)) expect(mediaUpload.isAcceptedMime(m)).toBe(true);
    expect(mediaUpload.isAcceptedMime("text/rtf")).toBe(true);
    expect(mediaUpload.isAcceptedMime("application/zip")).toBe(false);
    expect(mediaUpload.isAcceptedMime("application/msword")).toBe(false);
    expect(mediaUpload.isAcceptedMime("application/x-msdownload")).toBe(false);
  });

  test("detected documents get the document cap; cap 0 disables them", () => {
    expect(mediaUpload.limitForDetectedMime(DOCUMENT_MIMES.PDF, MEDIA_LIMITS)).toBe(MEDIA_LIMITS.max_document_bytes);
    expect(() => mediaUpload.limitForDetectedMime(DOCUMENT_MIMES.DOCX, { ...MEDIA_LIMITS, max_document_bytes: 0 }))
      .toThrow(expect.objectContaining({ status: 415, code: "mime_disabled" }));
  });

  test("an unrecognized file names the supported formats", () => {
    expect(() => mediaUpload.limitForDetectedMime(null, MEDIA_LIMITS))
      .toThrow(expect.objectContaining({ status: 415, code: "format_unsupported", error: expect.stringContaining("docx") }));
  });
});

describe("createMediaSniffer", () => {
  test.each([1, 7, 4096, 64 * 1024])("chunks of %i bytes detect names-at-end.docx like the whole file", (size) => {
    const docx = read("names-at-end.docx");
    const s = sniffChunks(docx, size);
    expect(s.isZip()).toBe(true);
    expect(s.head().length).toBe(MEDIA_SNIFF_HEAD_BYTES);
    expect(mediaUpload.detectMime(s.head(), s.tail())).toBe(DOCUMENT_MIMES.DOCX);
  });

  test("the tail stays bounded and holds the file's last bytes", () => {
    const s = createMediaSniffer({ headBytes: 16, tailBytes: 1000 });
    const big = Buffer.concat([read("fixture.pptx").subarray(0, 4), Buffer.alloc(50000, 7), Buffer.from("THE-END")]);
    for (let i = 0; i < big.length; i += 333) s.push(big.subarray(i, i + 333));
    const tail = s.tail();
    expect(tail.length).toBe(1000);
    expect(tail.equals(big.subarray(big.length - 1000))).toBe(true);
  });

  test("non-ZIP uploads keep no tail", () => {
    const s = sniffChunks(read("fixture.pdf"), 512);
    expect(s.isZip()).toBe(false);
    expect(s.tail()).toBeNull();
    expect(mediaUpload.detectMime(s.head(), s.tail())).toBe(DOCUMENT_MIMES.PDF);
  });
});
