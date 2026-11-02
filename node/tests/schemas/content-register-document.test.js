/**
 * @file tests/schemas/content-register-document.test.js
 * @description cf-doc-1 document items in the register fingerprints envelope:
 * real library output passes; anything out of shape or past a bound is refused
 * before ingest derives index keys from it.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const zlib = require("zlib");
const schema = require("../../src/schemas/content-register");
const { DOCUMENT_FINGERPRINT, TEXT_LSH } = require("../../../shared/constants");
const LIB = require("tip-content-fingerprint/src/document/constants");
const TEXT_LIB = require("tip-content-fingerprint/src/text/constants");

const fixture = (name) => JSON.parse(JSON.stringify(require(`../fixtures/documents/${name}.json`)));

const pack = (items) => {
  const data = zlib.gzipSync(Buffer.from(JSON.stringify(items), "utf8")).toString("base64");
  return { profile: "cf-fingerprints-1", count: items.length, encoding: "gzip+base64", data };
};
const base = (extra) => ({ signer_tip_id: "tip://id/US-fp", origin_code: "OH", signature: "x", media: [], ...extra });
const deps = { mediaLimits: {}, dag: {} };

function codeFor(perceptual) {
  const env = pack([{ kind: "document", role: "document", perceptual }]);
  try {
    schema.validateRequest(base({ fingerprints: env, fingerprint_commit: schema.fingerprintsCommit(env) }), deps);
  } catch (e) {
    return e.code;
  }
  return null;
}

// Past the fingerprint gate, validateRequest trips a later, unrelated check (authors/DAG).
const passesGate = (perceptual) => !/^fingerprint/.test(String(codeFor(perceptual)));

describe("cf-doc-1 bounds match the vendored library", () => {
  test("node constants equal the library's for the profile", () => {
    expect(DOCUMENT_FINGERPRINT.PROFILE).toBe(LIB.PROFILE);
    for (const k of ["MAX_UNITS", "MAX_CHARS", "MAX_CHUNKS", "MAX_PICTURES", "PASSAGE_K", "PASSAGE_W", "PASSAGE_HASH_BYTES", "CHUNK_HASH_BYTES", "UNIT_HASH_BYTES"]) {
      expect([k, DOCUMENT_FINGERPRINT[k]]).toEqual([k, LIB[k]]);
    }
    expect(DOCUMENT_FINGERPRINT.TEXT_PROFILE).toBe(TEXT_LIB.PROFILE);
    expect(TEXT_LSH.MINHASH_K).toBe(TEXT_LIB.K);
  });
});

describe("validateRequest accepts real cf-doc-1 items", () => {
  test.each(["original", "exported", "chapter", "scan"])("%s", (name) => {
    expect(passesGate(fixture(name))).toBe(true);
  });

  test("a reject-tier document item passes (ingest skips it)", () => {
    expect(passesGate({ profile: "cf-doc-1", kind: "document", tier: "reject", reason: "encrypted" })).toBe(true);
  });
});

describe("validateRequest refuses document items out of shape", () => {
  const cases = {
    "unknown profile": [(d) => { d.profile = "cf-doc-2"; }, "fingerprint_document_profile_unsupported"],
    "text_hash not 64 hex": [(d) => { d.text_hash = "ABC"; }, "fingerprint_document_invalid"],
    "unknown format": [(d) => { d.format = "pages"; }, "fingerprint_document_invalid"],
    "text with another profile": [(d) => { d.text.profile = "cf-image-1"; }, "fingerprint_document_invalid"],
    "text MinHash of the wrong length": [(d) => { d.text.minhash = d.text.minhash.slice(1); }, "fingerprint_document_invalid"],
    "chunk hash too short": [(d) => { d.chunks[0].h = "abc"; }, "fingerprint_document_invalid"],
    "chunk on a unit past units_covered": [(d) => { d.chunks[0].at = d.units_covered + 1; }, "fingerprint_document_invalid"],
    "passage count disagrees with h": [(d) => { d.passages.count += 1; }, "fingerprint_document_invalid"],
    "passages with another window": [(d) => { d.passages.w = 100; }, "fingerprint_document_invalid"],
    "passages.at out of order": [(d) => { d.passages.at.reverse(); }, "fingerprint_document_invalid"],
    "one unit hash missing": [(d) => { d.unit_hashes = Buffer.from(d.unit_hashes, "base64").subarray(8).toString("base64"); }, "fingerprint_document_invalid"],
    "units_covered past the bound": [(d) => { d.units_covered = 2001; d.unit_count = 2001; }, "fingerprint_document_invalid"],
    "ocr filled": [(d) => { d.ocr = { lang: "eng" }; }, "fingerprint_document_invalid"],
  };
  test.each(Object.entries(cases))("%s", (_name, [mutate, code]) => {
    const d = fixture("original");
    mutate(d);
    expect(codeFor(d)).toBe(code);
  });

  test("a unitless document must not carry unit positions", () => {
    const d = fixture("exported");
    d.chunks[0].at = 1;
    expect(codeFor(d)).toBe("fingerprint_document_invalid");
  });

  test("more pictures than the bound", () => {
    const d = fixture("original");
    d.images = Array.from({ length: 201 }, () => ({ at: 1, pdq: "ab".repeat(32), quality: 90 }));
    expect(codeFor(d)).toBe("fingerprint_document_invalid");
  });

  test("a picture or page hash that is not a string, even one that prints as 64 hex", () => {
    const pic = fixture("original");
    pic.images = [{ at: 1, pdq: ["ab".repeat(32)], quality: 90 }];
    expect(codeFor(pic)).toBe("fingerprint_document_invalid");
    const scan = fixture("scan");
    scan.textless_pages[0].pdq = [scan.textless_pages[0].pdq];
    expect(codeFor(scan)).toBe("fingerprint_document_invalid");
  });

  test("more passages than the covered text can hold (one per 50-character window)", () => {
    const d = fixture("original");
    d.chars_covered = d.passages.count + 48;
    expect(codeFor(d)).toBe("fingerprint_document_invalid");
    d.chars_covered = d.passages.count + 49;
    expect(codeFor(d)).not.toBe("fingerprint_document_invalid");
  });

  test("a textless page with a hash but no quality", () => {
    const d = fixture("scan");
    d.textless_pages[0].quality = null;
    expect(codeFor(d)).toBe("fingerprint_document_invalid");
  });

  test("an item over 1.5 MB", () => {
    const d = fixture("original");
    d.padding = "x".repeat(DOCUMENT_FINGERPRINT.MAX_ITEM_BYTES);
    expect(codeFor(d)).toBe("fingerprint_document_too_large");
  });
});
