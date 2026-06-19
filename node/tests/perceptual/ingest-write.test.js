"use strict";

const { MemoryStore, SQLiteStore } = require("../../src/dag");
const { ingestFingerprint } = require("../../src/perceptual/ingest");

const minhash128 = Array.from({ length: 128 }, (_, i) => (i * 2654435761) % 100000);
const textFp = { profile: "cf-text-2", kind: "text", tier: "char", shingle: "char-5", shingles: 120, minhash: minhash128 };
const imageFp = { profile: "cf-image-1", kind: "image", pdq: "ab".repeat(32), quality: 95 };

describe("perceptual ingest write path (step b: write via store methods)", () => {
  describe("MemoryStore", () => {
    test("text -> fingerprint row + 32 bands; image -> fingerprint row + 1 code", () => {
      const store = new MemoryStore();
      expect(ingestFingerprint(store, textFp, { ctid: "OH-t", createdAt: 7 })).toMatchObject({ bands: 32, codes: 0 });
      expect(store._perceptualFingerprints.get("OH-t|0")).toMatchObject({ ctid: "OH-t", modality: "text", created_at: 7 });
      expect(store._minhashBands.filter(b => b.ctid === "OH-t")).toHaveLength(32);

      expect(ingestFingerprint(store, imageFp, { ctid: "OH-i" })).toMatchObject({ bands: 0, codes: 1 });
      expect(store._phashCodes.filter(c => c.ctid === "OH-i")).toHaveLength(1);
    });
  });

  describe("SQLiteStore (real raw-SQL write path)", () => {
    let store;
    beforeAll(() => { store = new SQLiteStore(":memory:"); });
    afterAll(() => { if (store && store.db && store.db.close) store.db.close(); });

    test("text -> rows land in perceptual_fingerprint + minhash_band", () => {
      ingestFingerprint(store, textFp, { ctid: "OH-t", createdAt: 7 });
      const fp = store.db.prepare("SELECT * FROM perceptual_fingerprint WHERE ctid=?").get("OH-t");
      expect(fp).toMatchObject({ ctid: "OH-t", modality: "text", created_at: 7 });
      const bands = store.db.prepare("SELECT COUNT(*) AS n FROM minhash_band WHERE ctid=?").get("OH-t");
      expect(bands.n).toBe(32);
    });

    test("image -> a phash_code row with all 16 chunks persisted", () => {
      ingestFingerprint(store, imageFp, { ctid: "OH-i" });
      const code = store.db.prepare("SELECT * FROM phash_code WHERE ctid=?").get("OH-i");
      expect(code).toMatchObject({ ctid: "OH-i", modality: "image", pdq: "ab".repeat(32), quality: 95 });
      for (let k = 0; k < 16; k++) expect(typeof code["c" + k]).toBe("number");
    });

    test("re-ingesting the same fingerprint is idempotent for the fingerprint row + bands", () => {
      ingestFingerprint(store, textFp, { ctid: "OH-t", createdAt: 9 }); // REPLACE + IGNORE
      const n = store.db.prepare("SELECT COUNT(*) AS n FROM perceptual_fingerprint WHERE ctid=?").get("OH-t");
      expect(n.n).toBe(1); // one fingerprint row (replaced)
      const bands = store.db.prepare("SELECT COUNT(*) AS n FROM minhash_band WHERE ctid=?").get("OH-t");
      expect(bands.n).toBe(32); // bands IGNORE'd, not duplicated
    });
  });
});
