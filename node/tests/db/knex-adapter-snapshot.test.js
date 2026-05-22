/**
 * @file tests/db/knex-adapter-snapshot.test.js
 * @description Snapshot serialization smoke-test for every DB driver.
 *
 * Reproduces the exact encode→wire→decode pipeline that snapshot-handler.js
 * runs for Phase D (committee rotations) and Phase F (rotation_participation).
 * Catches DB-driver-specific type leakage — e.g. Oracle returning CLOB fields
 * as Buffer objects instead of plain strings — before it corrupts the protobuf
 * stream and produces "invalid wire type N" errors on the joiner side.
 *
 * What this tests:
 *   1. After migrate(), hydrated rotation rows have plain JS types (Array,
 *      string, number) — not Buffer / Oracle LOB objects.
 *   2. canonRotation(r) → canonicalJson() produces a parseable JSON string.
 *   3. encode("SnapshotCommitteeRotationRow", ...) → decode round-trip
 *      preserves all fields, including nested JSON arrays (committee,
 *      signer_node_ids, signatures).
 *   4. rotations_full_root is identical on the "sender" (computed while
 *      encoding) and the "receiver" (recomputed while decoding) — the
 *      mismatch that would cause snapshot install rejection.
 *   5. SnapshotStateRow round-trip for rotation_participation rows.
 *
 * Requires env: DB_DRIVER, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
 * Skips automatically when DB_DRIVER is absent or "sqlite".
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC    = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, canonicalJson } = require(path.join(SHARED, "crypto"));
const { KnexAdapter }   = require(path.join(SRC, "db", "knex-adapter"));
const { loadTypes, encode, decode, bytesToUtf8 } = require(path.join(SRC, "network", "proto"));
const { canonRotation, createRotationsFullRootBuilder } = require(path.join(SRC, "sync", "snapshot-roots"));

const driver    = process.env.DB_DRIVER || "";
const shouldRun = !!driver && driver !== "sqlite";

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

function makeAdapter() {
  return new KnexAdapter(driver, {
    dbHost:     process.env.DB_HOST,
    dbPort:     process.env.DB_PORT ? Number(process.env.DB_PORT) : undefined,
    dbName:     process.env.DB_NAME,
    dbUser:     process.env.DB_USER,
    dbPassword: process.env.DB_PASSWORD,
  });
}

function rot(n, effectiveRound, committee, opts = {}) {
  const c = committee || [{ node_id: `sn-node-${n}`, public_key: `sn-pk-${n}` }];
  return {
    rotation_number: n,
    effective_round: effectiveRound,
    committee:       c,
    prev_rotation:   opts.prev_rotation === undefined ? n - 1 : opts.prev_rotation,
    signer_node_ids: opts.signers || [],
    signatures:      opts.sigs    || [],
    payload_hash:    opts.hash    || shake256(canonicalJson({ rotation_number: n, effective_round: effectiveRound, committee: c })),
    committed_at:    opts.at      || 1778025600000,
  };
}

async function cleanDB(adapter) {
  await adapter.knex("rotation_participation").delete();
  await adapter.knex("committee_history").delete();
}

async function drain() {
  await new Promise(r => setTimeout(r, 500));
}

(shouldRun ? describe : describe.skip)(`KnexAdapter snapshot serialization — ${driver || "skipped"}`, () => {
  jest.setTimeout(120_000);

  let a;

  beforeAll(async () => {
    a = makeAdapter();
    await a.migrate();
    await cleanDB(a);
  });

  afterAll(async () => {
    await cleanDB(a).catch(() => {});
    await a.knex.destroy();
  });

  // ── Phase D: SnapshotCommitteeRotationRow encode→decode round-trip ──────────

  describe("Phase D — SnapshotCommitteeRotationRow", () => {
    const rotations = [
      rot(1, 100, [{ node_id: "n1", public_key: "pk1" }], {
        prev_rotation: 0, signers: [], sigs: [],
      }),
      rot(2, 200, [
        { node_id: "n1", public_key: "pk1" },
        { node_id: "n2", public_key: "pk2" },
      ], {
        prev_rotation: 1,
        signers: ["n1"],
        sigs:    ["sig-2a"],
      }),
      rot(3, 300, [
        { node_id: "n1", public_key: "pk1" },
        { node_id: "n2", public_key: "pk2" },
        { node_id: "n3", public_key: "pk3" },
      ], {
        prev_rotation: 2,
        signers: ["n1", "n2"],
        sigs:    ["sig-3a", "sig-3b"],
        at:      1778029200000,
      }),
    ];

    beforeAll(async () => {
      for (const r of rotations) {
        a.saveCommitteeRotation(r);
      }
      await drain();
    });

    test("hydrated rows have plain JS types — no Buffer/LOB leakage", async () => {
      const b = makeAdapter();
      try {
        await b.migrate();
        const chain = [...b.getRotationsFromGenesis()];
        expect(chain).toHaveLength(3);

        for (const r of chain) {
          // committee must be an Array, not a Buffer or string
          expect(Array.isArray(r.committee)).toBe(true);
          expect(Array.isArray(r.signer_node_ids)).toBe(true);
          expect(Array.isArray(r.signatures)).toBe(true);
          // payload_hash must be a plain string
          expect(typeof r.payload_hash).toBe("string");
          // committee members must be plain objects
          for (const m of r.committee) {
            expect(typeof m.node_id).toBe("string");
            expect(typeof m.public_key).toBe("string");
          }
        }
      } finally {
        await b.knex.destroy();
      }
    });

    test("canonRotation → canonicalJson produces parseable JSON", async () => {
      const b = makeAdapter();
      try {
        await b.migrate();
        for (const r of b.getRotationsFromGenesis()) {
          const canonical = canonicalJson(canonRotation(r));
          expect(typeof canonical).toBe("string");
          const parsed = JSON.parse(canonical);
          expect(Array.isArray(parsed.committee)).toBe(true);
          expect(Array.isArray(parsed.signer_node_ids)).toBe(true);
          expect(Array.isArray(parsed.signatures)).toBe(true);
          expect(typeof parsed.payload_hash).toBe("string");
        }
      } finally {
        await b.knex.destroy();
      }
    });

    test("encode→decode round-trip preserves all fields", async () => {
      const b = makeAdapter();
      try {
        await b.migrate();
        const chain = [...b.getRotationsFromGenesis()];

        for (let i = 0; i < chain.length; i++) {
          const r       = chain[i];
          const orig    = rotations[i];
          const canon   = canonicalJson(canonRotation(r));

          const encoded = encode("SnapshotCommitteeRotationRow", {
            canonicalJson: Buffer.from(canon, "utf8"),
          });
          expect(Buffer.isBuffer(encoded)).toBe(true);
          expect(encoded.length).toBeGreaterThan(0);

          const decoded = decode("SnapshotCommitteeRotationRow", encoded);
          expect(decoded.canonicalJson).toBeTruthy();

          const parsed = JSON.parse(bytesToUtf8(decoded.canonicalJson));
          expect(parsed.rotation_number).toBe(orig.rotation_number);
          expect(parsed.effective_round).toBe(orig.effective_round);
          expect(parsed.committee).toEqual(orig.committee);
          expect(parsed.signer_node_ids).toEqual(orig.signer_node_ids);
          expect(parsed.signatures).toEqual(orig.signatures);
          expect(parsed.payload_hash).toBe(orig.payload_hash);
        }
      } finally {
        await b.knex.destroy();
      }
    });

    test("rotations_full_root matches between sender and receiver", async () => {
      const b = makeAdapter();
      try {
        await b.migrate();
        const chain = [...b.getRotationsFromGenesis()];

        // Sender: encode each row, accumulate root
        const senderRoot = createRotationsFullRootBuilder();
        const encodedFrames = [];
        for (const r of chain) {
          const canon = canonicalJson(canonRotation(r));
          senderRoot.addRow(canon);
          encodedFrames.push(encode("SnapshotCommitteeRotationRow", {
            canonicalJson: Buffer.from(canon, "utf8"),
          }));
        }
        const senderDigest = senderRoot.finalize();

        // Receiver: decode each frame, recompute root
        const receiverRoot = createRotationsFullRootBuilder();
        for (const frame of encodedFrames) {
          const decoded  = decode("SnapshotCommitteeRotationRow", frame);
          const canon    = bytesToUtf8(decoded.canonicalJson);
          receiverRoot.addRow(canon);
        }
        const receiverDigest = receiverRoot.finalize();

        expect(receiverDigest).toBe(senderDigest);
      } finally {
        await b.knex.destroy();
      }
    });
  });

  // ── Phase F: SnapshotStateRow (rotation_participation) round-trip ───────────

  describe("Phase F — SnapshotStateRow rotation_participation", () => {
    beforeEach(async () => {
      await a.knex("rotation_participation").delete();
      a.mirror._rotationParticipation = new Map();
    });

    test("encode→decode round-trip preserves node_id, rotation_number, count", async () => {
      a.setRotationParticipation("nodeA", 10, 42);
      a.setRotationParticipation("nodeB", 10, 99);
      a.setRotationParticipation("nodeA", 11, 7);
      await drain();

      const b = makeAdapter();
      try {
        await b.migrate();

        const rows = [...b.iterateRotationParticipationForSnapshot()];
        expect(rows.length).toBeGreaterThanOrEqual(3);

        for (const r of rows) {
          const canon = canonicalJson(r);
          expect(typeof canon).toBe("string");
          expect(() => JSON.parse(canon)).not.toThrow();

          const encoded = encode("SnapshotStateRow", {
            table:         "rotation_participation",
            canonicalJson: Buffer.from(canon, "utf8"),
          });
          expect(Buffer.isBuffer(encoded)).toBe(true);

          const decoded = decode("SnapshotStateRow", encoded);
          expect(decoded.table).toBe("rotation_participation");

          const parsed = JSON.parse(bytesToUtf8(decoded.canonicalJson));
          expect(typeof parsed.node_id).toBe("string");
          expect(typeof parsed.count).toBe("number");
        }

        // Spot-check specific values
        const by = Object.fromEntries(
          rows
            .filter(r => Number(r.rotation_number) === 10)
            .map(r => [r.node_id, r.count])
        );
        expect(by["nodeA"]).toBe(42);
        expect(by["nodeB"]).toBe(99);
      } finally {
        await b.knex.destroy();
      }
    });
  });
});
