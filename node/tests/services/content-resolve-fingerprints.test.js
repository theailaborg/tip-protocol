/**
 * @file tests/services/content-resolve-fingerprints.test.js
 * @description resolve() fingerprint serving — stored perceptual fingerprints
 * are returned only when explicitly requested, filtered by modality, video
 * frames thinned on demand. Default response stays byte-identical (the
 * browser-extension contract).
 */
"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { CONTENT_STATUS } = require(path.join(SHARED, "constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const AUTHOR = "tip://id/US-aaaaaaaaaaaaaaaa";
const CTID = "tip://c/OH-11111111111111-0001";

const TEXT_FP = { profile: "cf-text-3", kind: "text", tier: "char", shingle: "char-5", shingles: 1200, minhash: [1, 2, 3] };
const IMAGE_FP = { profile: "cf-image-1", kind: "image", pdq: "ab".repeat(32), quality: 92 };
const VIDEO_FP = {
  profile: "cf-video-1", kind: "video",
  features: Array.from({ length: 90 }, (_, i) => ({ frame: i, timestamp: i, pdq: "cd".repeat(32), quality: 80 })),
};

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  dag.saveIdentity({
    tip_id: AUTHOR, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: shake256("author"),
  });
  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
  dag.setScore(AUTHOR, 700, 0, nowMs());
  dag.saveContent({
    ctid: CTID, origin_code: "OH",
    content_hash: "ab".repeat(32),
    author_tip_id: AUTHOR, signer_tip_id: AUTHOR,
    authors: [{ tip_id: AUTHOR, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status: CONTENT_STATUS.VERIFIED,
    prescan_flagged: false, prescan_probability: 0.1, prescan_tier: "low", override: false,
    registered_at: 1775001600000,
    registered_urls: [], tx_id: shake256(`c:${CTID}`),
  });
  // Stored fingerprints, envelope stringified — exactly as perceptual/ingest writes them.
  const mk = (idx, modality, fp, quality) => dag.savePerceptualFingerprint({
    ctid: CTID, component_idx: idx, modality, profile: fp.profile,
    pipeline: JSON.stringify({ package: "test", profile: fp.profile }),
    quality: quality ?? null, fingerprint: JSON.stringify(fp), created_at: 1775001600000,
  });
  mk(0, "text", TEXT_FP, null);
  mk(1, "image", IMAGE_FP, 92);
  mk(2, "video", VIDEO_FP, 80);

  const service = createContentService({
    dag, scoring, config: { mediaLimits: {} }, submitTx: () => {},
  });
  return { dag, service };
}

describe("resolve() fingerprint serving", () => {

  test("default response carries NO fingerprints key (extension contract unchanged)", async () => {
    const { service } = _setup();
    const out = await service.resolve(CTID);
    expect(out).not.toHaveProperty("fingerprints");
  });

  test("include=fingerprints returns every component, envelope parsed, ordered by index", async () => {
    const { service } = _setup();
    const out = await service.resolve(CTID, { includeFingerprints: true, videoEvery: 1 });
    expect(out.fingerprints).toHaveLength(3);
    expect(out.fingerprints.map(f => f.modality)).toEqual(["text", "image", "video"]);
    expect(out.fingerprints[0].fingerprint).toEqual(TEXT_FP);      // parsed object, not string
    expect(out.fingerprints[1].quality).toBe(92);
  });

  test("modality filter returns only the requested kinds", async () => {
    const { service } = _setup();
    const out = await service.resolve(CTID, { includeFingerprints: true, modalities: ["text", "image"], videoEvery: 1 });
    expect(out.fingerprints.map(f => f.modality)).toEqual(["text", "image"]);
  });

  test("video_every thins the frame list", async () => {
    const { service } = _setup();
    const out = await service.resolve(CTID, { includeFingerprints: true, modalities: ["video"], videoEvery: 30 });
    const video = out.fingerprints[0].fingerprint;
    expect(video.features).toHaveLength(3);                        // 90 frames / 30
    expect(video.features.map(f => f.frame)).toEqual([0, 30, 60]);
    expect(video.thinned_every).toBe(30);
  });

  test("content with no stored fingerprints -> empty array (not an error)", async () => {
    const { dag, service } = _setup();
    const ctid2 = "tip://c/OH-22222222222222-0002";
    dag.saveContent({
      ctid: ctid2, origin_code: "OH", content_hash: "cd".repeat(32),
      author_tip_id: AUTHOR, signer_tip_id: AUTHOR,
      authors: [{ tip_id: AUTHOR, tip_id_type: "personal" }],
      attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
      status: CONTENT_STATUS.VERIFIED,
      prescan_flagged: false, prescan_probability: 0.1, prescan_tier: "low", override: false,
      registered_at: 1775001600000, registered_urls: [], tx_id: shake256(`c:${ctid2}`),
    });
    const out = await service.resolve(ctid2, { includeFingerprints: true, videoEvery: 1 });
    expect(out.fingerprints).toEqual([]);
  });

  test("corrupt stored envelope is skipped, not fatal", async () => {
    const { dag, service } = _setup();
    dag.savePerceptualFingerprint({
      ctid: CTID, component_idx: 3, modality: "audio", profile: "cf-audio-landmark-1",
      pipeline: "{}", quality: null, fingerprint: "{not json", created_at: 1775001600000,
    });
    const out = await service.resolve(CTID, { includeFingerprints: true, videoEvery: 1 });
    expect(out.fingerprints).toHaveLength(3);                      // audio row skipped
  });
});
