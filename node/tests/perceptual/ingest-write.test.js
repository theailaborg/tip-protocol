"use strict";
const { PROFILE: TEXT_PROFILE } = require("tip-content-fingerprint/src/text/constants"); // dynamic: text profile follows the lib

const { MemoryStore, SQLiteStore } = require("../../src/dag");
const { ingestFingerprint } = require("../../src/perceptual/ingest");

const minhash128 = Array.from({ length: 128 }, (_, i) => (i * 2654435761) % 100000);
const textFp = { profile: TEXT_PROFILE, kind: "text", tier: "char", shingle: "char-5", shingles: 120, minhash: minhash128 };
const imageFp = { profile: "cf-image-1", kind: "image", pdq: "ab".repeat(32), quality: 95 };
const videoFp = {
  profile: "cf-video-1", kind: "video",
  features: [
    { frame: 0, timestamp: 0, pdq: "cc".repeat(32), quality: 90 },
    { frame: 1, timestamp: 1, pdq: "dd".repeat(32), quality: 88 },
  ],
};
const audioFp = {
  profile: "cf-audio-landmark-1", kind: "audio", landmarkCount: 5,
  landmarks: [{ hash: 111, t: 1 }, { hash: 222, t: 1 }, { hash: 111, t: 5 }, { hash: 333, t: 2 }, { hash: 444, t: 3 }],
};

describe("perceptual ingest write path (step b: write via store methods)", () => {
  describe("MemoryStore", () => {
    test("text -> 32 bands; image -> 1 code; audio -> clip + 5 landmarks", async () => {
      const store = new MemoryStore();
      expect(await ingestFingerprint(store, textFp, { ctid: "OH-t", createdAt: 7 })).toMatchObject({ bands: 32, codes: 0 });
      expect(store._perceptualFingerprints.get("OH-t|0")).toMatchObject({ ctid: "OH-t", modality: "text", created_at: 7 });
      expect(store._minhashBands.filter((b) => b.ctid === "OH-t")).toHaveLength(32);

      expect(await ingestFingerprint(store, imageFp, { ctid: "OH-i" })).toMatchObject({ bands: 0, codes: 1 });
      expect(store._phashCodes.filter((c) => c.ctid === "OH-i")).toHaveLength(1);
      // Re-ingest is ignored: the image's single code row is not duplicated.
      await ingestFingerprint(store, imageFp, { ctid: "OH-i" });
      expect(store._phashCodes.filter((c) => c.ctid === "OH-i")).toHaveLength(1);

      expect(await ingestFingerprint(store, audioFp, { ctid: "OH-aud" })).toMatchObject({ landmarks: 5 });
      const clip = store._audioClips.get("OH-aud|0");
      expect(clip).toMatchObject({ ctid: "OH-aud", landmark_count: 5 });
      expect(store._audioLandmarks.filter((l) => l.clip_id === clip.clip_id)).toHaveLength(5);
    });
  });

  describe("SQLiteStore (real raw-SQL write path)", () => {
    let store;
    beforeAll(() => { store = new SQLiteStore(":memory:"); });
    afterAll(() => { if (store && store.db && store.db.close) store.db.close(); });

    test("text -> rows land in perceptual_fingerprint + minhash_band", async () => {
      await ingestFingerprint(store, textFp, { ctid: "OH-t", createdAt: 7 });
      const fp = store.db.prepare("SELECT * FROM perceptual_fingerprint WHERE tip_ctid=?").get("OH-t");
      expect(fp).toMatchObject({ tip_ctid: "OH-t", modality: "text", created_at: 7 });
      const bands = store.db.prepare("SELECT COUNT(*) AS n FROM minhash_band WHERE tip_ctid=?").get("OH-t");
      expect(bands.n).toBe(32);
    });

    test("image -> a phash_code row with all 16 chunks persisted", async () => {
      await ingestFingerprint(store, imageFp, { ctid: "OH-i" });
      const code = store.db.prepare("SELECT * FROM phash_code WHERE tip_ctid=?").get("OH-i");
      expect(code).toMatchObject({ tip_ctid: "OH-i", modality: "image", pdq: "ab".repeat(32), quality: 95 });
      for (let k = 0; k < 16; k++) expect(typeof code["c" + k]).toBe("number");
    });

    test("audio -> a clip row + 5 landmark rows referencing it", async () => {
      await ingestFingerprint(store, audioFp, { ctid: "OH-aud" });
      const clip = store.db.prepare("SELECT clip_id, landmark_count FROM audio_clip WHERE tip_ctid=? AND component_idx=0").get("OH-aud");
      expect(clip.landmark_count).toBe(5);
      const n = store.db.prepare("SELECT COUNT(*) AS n FROM audio_landmark WHERE clip_id=?").get(clip.clip_id);
      expect(n.n).toBe(5);
    });

    test("re-ingesting the same fingerprint is idempotent for the fingerprint row + bands", async () => {
      await ingestFingerprint(store, textFp, { ctid: "OH-t", createdAt: 9 }); // REPLACE + IGNORE
      const n = store.db.prepare("SELECT COUNT(*) AS n FROM perceptual_fingerprint WHERE tip_ctid=?").get("OH-t");
      expect(n.n).toBe(1);
      const bands = store.db.prepare("SELECT COUNT(*) AS n FROM minhash_band WHERE tip_ctid=?").get("OH-t");
      expect(bands.n).toBe(32);
    });

    test("re-ingesting phash codes is ignored, not duplicated (no duplicate frames)", async () => {
      const phashN = (ctid) => store.db.prepare("SELECT COUNT(*) AS n FROM phash_code WHERE tip_ctid=?").get(ctid).n;
      await ingestFingerprint(store, videoFp, { ctid: "OH-v" });
      expect(phashN("OH-v")).toBe(2);
      // Re-ingest the same video + the image (OH-i, ingested once earlier): counts
      // must not grow. Without ignore-on-conflict the video would double to 4
      // frames, inflating the matchVideo overlap denominator and degrading recall.
      await ingestFingerprint(store, videoFp, { ctid: "OH-v" });
      await ingestFingerprint(store, imageFp, { ctid: "OH-i" });
      expect(phashN("OH-v")).toBe(2);
      expect(phashN("OH-i")).toBe(1);
    });

    test("re-ingest of one component leaves a sibling component's rows intact", async () => {
      const phashN = (ctid) => store.db.prepare("SELECT COUNT(*) AS n FROM phash_code WHERE tip_ctid=?").get(ctid).n;
      await ingestFingerprint(store, imageFp, { ctid: "OH-multi", componentIdx: 0 });
      await ingestFingerprint(store, { ...imageFp, pdq: "cd".repeat(32) }, { ctid: "OH-multi", componentIdx: 1 });
      expect(phashN("OH-multi")).toBe(2);
      // Re-ingesting component 0 is ignored and must not touch component 1
      // (the natural key includes component_idx, so the two images stay distinct).
      await ingestFingerprint(store, imageFp, { ctid: "OH-multi", componentIdx: 0 });
      expect(phashN("OH-multi")).toBe(2);
      expect(store.db.prepare("SELECT COUNT(*) AS n FROM phash_code WHERE tip_ctid=? AND component_idx=1").get("OH-multi").n).toBe(1);
    });
  });
});
