"use strict";

// Ingest consumes fingerprint objects; it does not compute them (the package's own
// tests cover computation). So we build synthetic fingerprints here and assert the
// ingest derives the right index rows. We deep-import the pure mih helper for the
// chunk assertion (the package root pulls compute-only ESM deps jest can't load).
const { indexChunks } = require("tip-content-fingerprint/src/image/mih");
const { buildIngestRows } = require("../../src/perceptual/ingest");

const minhash128 = Array.from({ length: 128 }, (_, i) => (i * 2654435761) % 100000);

describe("perceptual ingest row-building (step a: derive keys via the package)", () => {
  test("char-tier text -> 32 minhash_band rows + a fingerprint row, no codes", () => {
    const fp = { profile: "cf-text-2", kind: "text", tier: "char", shingle: "char-5", shingles: 120, minhash: minhash128 };
    const { fingerprint, bands, codes } = buildIngestRows(fp, { ctid: "OH-t", createdAt: 5 });
    expect(fingerprint).toMatchObject({ ctid: "OH-t", modality: "text", profile: "cf-text-2", created_at: 5 });
    expect(bands).toHaveLength(32); // LSH default b = 32
    expect(bands[0]).toMatchObject({ profile: "cf-text-2", band_idx: 0, ctid: "OH-t" });
    expect(typeof bands[0].band_hash).toBe("number");
    expect(codes).toHaveLength(0);
  });

  test("micro-tier text -> no bands, no codes (exact-match only)", () => {
    const fp = { profile: "cf-text-2", kind: "text", tier: "micro", exact: "deadbeef" };
    const { bands, codes } = buildIngestRows(fp, { ctid: "OH-m" });
    expect(bands).toHaveLength(0);
    expect(codes).toHaveLength(0);
  });

  test("image -> one phash_code row whose 16 chunks match indexChunks", () => {
    const pdq = "ab".repeat(32); // valid 64-hex PDQ
    const fp = { profile: "cf-image-1", kind: "image", pdq, quality: 95 };
    const { fingerprint, bands, codes } = buildIngestRows(fp, { ctid: "OH-i" });
    expect(fingerprint).toMatchObject({ ctid: "OH-i", modality: "image", quality: 95 });
    expect(bands).toHaveLength(0);
    expect(codes).toHaveLength(1);
    const expected = indexChunks(pdq);
    for (let i = 0; i < 16; i++) expect(codes[0]["c" + i]).toBe(expected[i]);
    expect(codes[0]).toMatchObject({ ctid: "OH-i", modality: "image", pdq, quality: 95 });
  });

  test("video -> one phash_code per frame, modality video, frame-level quality", () => {
    const frame = (h, i) => ({ frame: i, timestamp: i + 0.5, pdq: h, quality: 80 });
    const fp = { profile: "cf-video-1", kind: "video", features: [frame("aa".repeat(32), 0), frame("bb".repeat(32), 1)] };
    const { fingerprint, codes } = buildIngestRows(fp, { ctid: "OH-v" });
    expect(fingerprint.quality).toBeNull(); // per-frame quality lives on the codes
    expect(codes).toHaveLength(2);
    expect(codes[0]).toMatchObject({ ctid: "OH-v", modality: "video", frame: 0 });
    expect(codes[1].frame).toBe(1);
  });

  test("rejects a fingerprint with no ctid / no kind", () => {
    expect(() => buildIngestRows({ kind: "image", profile: "cf-image-1", pdq: "ab".repeat(32) }, {})).toThrow(/ctid/);
    expect(() => buildIngestRows({}, { ctid: "x" })).toThrow(/kind/);
  });
});
