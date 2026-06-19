"use strict";

const { MemoryStore, SQLiteStore } = require("../../src/dag");
const { ingestFingerprint } = require("../../src/perceptual/ingest");
const { matchText } = require("../../src/perceptual/matcher");

const mk = (vals) => ({ profile: "cf-text-2", kind: "text", tier: "char", shingle: "char-5", shingles: 100, minhash: vals });

// A baseline signature, a near-duplicate (10/128 positions changed -> shares most
// bands, Jaccard ~0.92), and an unrelated one (every value offset -> shares no
// band, Jaccard 0).
const A = Array.from({ length: 128 }, (_, i) => (i * 7 + 13) % 100000);
const NEAR = A.map((v, i) => (i < 10 ? v + 1 : v));
const FAR = A.map((v) => v + 500000);

async function exercise(dag) {
  ingestFingerprint(dag, mk(A), { ctid: "OH-A" });

  const hits = await matchText(dag, mk(NEAR));
  expect(hits.map((h) => h.ctid)).toContain("OH-A");
  expect(hits.find((h) => h.ctid === "OH-A").similarity).toBeGreaterThan(0.8);

  const none = await matchText(dag, mk(FAR));
  expect(none.find((h) => h.ctid === "OH-A")).toBeUndefined();

  // a query identical to A still finds A (similarity 1), and excludeCtid drops self
  const self = await matchText(dag, mk(A), { excludeCtid: "OH-A" });
  expect(self.find((h) => h.ctid === "OH-A")).toBeUndefined();
}

describe("perceptual matcher: text near-duplicate (LSH candidate-gen + Jaccard verify)", () => {
  test("MemoryStore", async () => {
    await exercise(new MemoryStore());
  });
  test("SQLiteStore (real SQL candidate-gen)", async () => {
    const store = new SQLiteStore(":memory:");
    await exercise(store);
    store.db.close();
  });
});
