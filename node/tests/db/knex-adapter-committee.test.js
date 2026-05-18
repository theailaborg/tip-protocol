/**
 * @file tests/db/knex-adapter-committee.test.js
 * @description DB-persistence tests for all 11 committee_history +
 * rotation_participation methods in KnexAdapter.
 *
 * Tests the full write→DB→hydrate round-trip: write via adapter A,
 * create fresh adapter B, call migrate() (hydrates from DB), assert
 * reads on B match what A wrote.
 *
 * Requires env: DB_DRIVER, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
 * Skips automatically when DB_DRIVER is absent or "sqlite" (SQLite path
 * is covered by tests/dag/committee-history.test.js).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC    = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, canonicalJson } = require(path.join(SHARED, "crypto"));
const { KnexAdapter } = require(path.join(SRC, "db", "knex-adapter"));

const driver   = process.env.DB_DRIVER || "";
const shouldRun = !!driver && driver !== "sqlite";

beforeAll(async () => {
  await initCrypto();
});

function makeAdapter(dbName) {
  return new KnexAdapter(driver, {
    dbHost:     process.env.DB_HOST,
    dbPort:     process.env.DB_PORT ? Number(process.env.DB_PORT) : undefined,
    dbName:     dbName || process.env.DB_NAME,
    dbUser:     process.env.DB_USER,
    dbPassword: process.env.DB_PASSWORD,
  });
}

function rot(n, effectiveRound, committee, opts = {}) {
  const c = committee || [{ node_id: `test-node-${n}`, public_key: `pk-${n}` }];
  return {
    rotation_number:  n,
    effective_round:  effectiveRound,
    committee:        c,
    prev_rotation:    opts.prev_rotation === undefined ? n - 1 : opts.prev_rotation,
    signer_node_ids:  opts.signers || [],
    signatures:       opts.sigs    || [],
    payload_hash:     opts.hash    || shake256(canonicalJson({ rotation_number: n, effective_round: effectiveRound, committee: c })),
    committed_at:     opts.at      || "2026-05-05T00:00:00.000Z",
  };
}

async function cleanDB(adapter) {
  await adapter.knex("rotation_participation").delete();
  await adapter.knex("committee_history").delete();
}

// Give fire-and-forget DB writes time to settle before asserting DB state.
// 500 ms is conservative; Oracle round-trips (INSERT + catch + UPDATE) can
// take ~100-200 ms locally, Postgres/MariaDB/MSSQL typically <20 ms.
async function drain() {
  await new Promise(r => setTimeout(r, 500));
}

(shouldRun ? describe : describe.skip)(`KnexAdapter committee — ${driver || "skipped"}`, () => {
  jest.setTimeout(120_000);

  let a; // shared adapter, set up once per suite

  beforeAll(async () => {
    a = makeAdapter();
    await a.migrate();
    await cleanDB(a);
  });

  afterAll(async () => {
    await cleanDB(a).catch(() => {});
    await a.knex.destroy();
  });

  // ─── committee_history ───────────────────────────────────────────────────────

  describe("committee_history", () => {
    test("saveCommitteeRotation persists row to DB", async () => {
      const r1 = rot(1, 100, [{ node_id: "n1", public_key: "pk1" }], {
        prev_rotation: 0, signers: ["n0"], sigs: ["sig-1"],
      });
      a.saveCommitteeRotation(r1);
      await drain();

      const rows = await a.knex("committee_history").where("rotation_number", 1).select("*");
      expect(rows).toHaveLength(1);
      expect(Number(rows[0].effective_round)).toBe(100);
      expect(JSON.parse(rows[0].committee)).toEqual([{ node_id: "n1", public_key: "pk1" }]);
      expect(JSON.parse(rows[0].signer_node_ids)).toEqual(["n0"]);
      expect(JSON.parse(rows[0].signatures)).toEqual(["sig-1"]);
      expect(rows[0].payload_hash).toBe(r1.payload_hash);
    });

    test("saveCommitteeRotation is idempotent (INSERT OR IGNORE)", async () => {
      const r2 = rot(2, 200, [{ node_id: "n2", public_key: "pk2" }]);
      a.saveCommitteeRotation(r2);
      a.saveCommitteeRotation({ ...r2, payload_hash: "tampered" });
      await drain();

      const rows = await a.knex("committee_history").where("rotation_number", 2).select("*");
      expect(rows).toHaveLength(1);
      expect(rows[0].payload_hash).toBe(r2.payload_hash);
    });

    test("round-trip: fresh adapter hydrates committee_history from DB", async () => {
      const r3 = rot(3, 300, [
        { node_id: "n3a", public_key: "pk3a" },
        { node_id: "n3b", public_key: "pk3b" },
      ], {
        prev_rotation: 2,
        signers: ["n1", "n2"],
        sigs: ["sig-3a", "sig-3b"],
        at: "2026-05-01T12:00:00.000Z",
      });
      a.saveCommitteeRotation(r3);
      await drain();

      const b = makeAdapter();
      try {
        await b.migrate();

        const got = b.getCommitteeRotation(3);
        expect(got).not.toBeNull();
        expect(got.committee).toEqual(r3.committee);
        expect(got.signer_node_ids).toEqual(["n1", "n2"]);
        expect(got.signatures).toEqual(["sig-3a", "sig-3b"]);
        expect(got.payload_hash).toBe(r3.payload_hash);
        expect(got.committed_at).toBe("2026-05-01T12:00:00.000Z");

        expect(b.getLatestRotation().rotation_number).toBe(3);

        // rotation 2 (effective_round=200) is in effect at round 250
        expect(b.getCommitteeAtRound(250).rotation_number).toBe(2);

        // chain is ordered by rotation_number
        const chain = [...b.getRotationsFromGenesis()];
        expect(chain.map(r => r.rotation_number)).toEqual([1, 2, 3]);
      } finally {
        await b.knex.destroy();
      }
    });
  });

  // ─── rotation_participation ──────────────────────────────────────────────────

  describe("rotation_participation", () => {
    beforeEach(async () => {
      await a.knex("rotation_participation").delete();
      a.mirror._rotationParticipation = new Map();
    });

    test("incrementRotationParticipation persists incremented count to DB", async () => {
      // Drain between calls: Oracle's INSERT→catch→UPDATE is non-atomic, so
      // concurrent increments for the same key race. In production, increments
      // happen once per round (sequential). Test mirrors that by serializing.
      a.incrementRotationParticipation("nodeA", 1);
      await drain();
      a.incrementRotationParticipation("nodeA", 1);
      a.incrementRotationParticipation("nodeB", 1);
      await drain();

      const rows = await a.knex("rotation_participation").where("rotation_number", 1).select("*");
      const by = Object.fromEntries(rows.map(r => [r.node_id, Number(r.count)]));
      expect(by["nodeA"]).toBe(2);
      expect(by["nodeB"]).toBe(1);
    });

    test("setRotationParticipation persists exact count (merge/upsert)", async () => {
      a.setRotationParticipation("nodeX", 2, 50);
      await drain();  // serialize: first write must land before second upserts over it
      a.setRotationParticipation("nodeX", 2, 99);
      await drain();

      const rows = await a.knex("rotation_participation")
        .where({ node_id: "nodeX", rotation_number: 2 }).select("*");
      expect(rows).toHaveLength(1);
      expect(Number(rows[0].count)).toBe(99);
    });

    test("pruneRotationParticipationBefore removes rows with rotation_number < n", async () => {
      a.setRotationParticipation("nodeA", 1, 10);
      a.setRotationParticipation("nodeA", 2, 20);
      a.setRotationParticipation("nodeA", 3, 30);
      await drain();

      a.pruneRotationParticipationBefore(3);
      await drain();

      const rows = await a.knex("rotation_participation").select("rotation_number");
      const rots = rows.map(r => Number(r.rotation_number));
      expect(rots).not.toContain(1);
      expect(rots).not.toContain(2);
      expect(rots).toContain(3);
    });

    test("deleteRotationParticipationByRotation removes only that rotation", async () => {
      a.setRotationParticipation("nodeA", 4, 10);
      a.setRotationParticipation("nodeB", 4, 20);
      a.setRotationParticipation("nodeA", 5, 30);
      await drain();

      a.deleteRotationParticipationByRotation(4);
      await drain();

      const rows = await a.knex("rotation_participation").select("rotation_number");
      const rots = rows.map(r => Number(r.rotation_number));
      expect(rots).not.toContain(4);
      expect(rots).toContain(5);
    });

    test("iterateRotationParticipationForSnapshot yields all mirror rows", () => {
      a.setRotationParticipation("nodeA", 6, 100);
      a.setRotationParticipation("nodeB", 6, 200);
      a.setRotationParticipation("nodeA", 7, 300);

      const rows = [...a.iterateRotationParticipationForSnapshot()];
      const keys = rows.map(r => `${r.node_id}|${r.rotation_number}`).sort();
      expect(keys).toContain("nodeA|6");
      expect(keys).toContain("nodeB|6");
      expect(keys).toContain("nodeA|7");
    });

    test("round-trip: fresh adapter hydrates rotation_participation from DB", async () => {
      a.setRotationParticipation("nodeA", 8, 150);
      a.setRotationParticipation("nodeB", 8, 250);
      await drain();

      const b = makeAdapter();
      try {
        await b.migrate();

        const rp = b.getRotationParticipation(8);
        const by = Object.fromEntries(rp.map(r => [r.node_id, r.count]));
        expect(by["nodeA"]).toBe(150);
        expect(by["nodeB"]).toBe(250);

        const all = [...b.iterateRotationParticipationForSnapshot()];
        const for8 = all.filter(r => Number(r.rotation_number) === 8);
        expect(for8).toHaveLength(2);
      } finally {
        await b.knex.destroy();
      }
    });
  });
});
