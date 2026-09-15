/**
 * @file tests/sync/snapshot-biometric-commit-roundtrip.test.js
 * @description An identity's biometric_commit must survive a real snapshot
 * round trip: saved on the source, streamed over the wire, installed on a
 * fresh node. The state-root test proves the field is bound into the root
 * and the coverage test proves the table is installed; neither proves the
 * value itself crosses serialization and the receiver's hydrator. A dropped
 * value here shows up on the joiner as a root mismatch at its next check.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */
"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");
const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { initDAG } = require(path.join(SRC, "dag"));
const { computeStateMerkleRoot } = require(path.join(SRC, "consensus", "state-root"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));
const { buildCommittedDag } = require("../helpers/commit-builder");
const { attemptInstall } = require("../helpers/snapshot-install");

const COMMIT = "a1".repeat(32);
const WITH = "tip://id/US-biomroundtrip01";
const WITHOUT = "tip://id/US-biomroundtrip02";

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

function _identity(tipId, extra) {
  return {
    tip_id: tipId, region: "US", public_key: generateMLDSAKeypair().publicKey,
    algorithm: "ml-dsa-65", tip_id_type: "personal", verification_tier: "T1", status: "active",
    registered_at: 1779800000000, ...extra,
  };
}

function _identityRows(dag) {
  const rows = [];
  for (const { table, row } of dag.iterateCanonicalState()) {
    if (table === "identities" && row.tip_id.startsWith("tip://id/US-biomroundtrip")) rows.push(row);
  }
  return rows.sort((a, b) => a.tip_id.localeCompare(b.tip_id));
}

function _source() {
  return buildCommittedDag({
    committeeSize: 2,
    preCommitMutate: (d) => {
      d.saveIdentity(_identity(WITH, { biometric_commit: COMMIT }));
      d.saveIdentity(_identity(WITHOUT, {}));
    },
  });
}

async function _assertRoundTrip(fx, destDag) {
  const result = await attemptInstall(fx.sourceDag, destDag, { chunkSize: 7 });
  expect(result.state_merkle_root).toBe(fx.stateRoot);

  expect(destDag.getIdentity(WITH).biometric_commit).toBe(COMMIT);
  expect(destDag.getIdentity(WITHOUT).biometric_commit ?? null).toBeNull();

  // Canonical projection on the joiner must be byte-equal to the source's:
  // present value carried, absent value stripped (not "" or "null").
  expect(_identityRows(destDag)).toEqual(_identityRows(fx.sourceDag));
  expect(computeStateMerkleRoot(destDag)).toBe(fx.stateRoot);
}

describe("biometric_commit survives a snapshot round trip", () => {
  test("memory store joiner", async () => {
    const fx = _source();
    const sourceRows = _identityRows(fx.sourceDag);
    expect(sourceRows.find(r => r.tip_id === WITH).biometric_commit).toBe(COMMIT);
    expect(sourceRows.find(r => r.tip_id === WITHOUT).biometric_commit).toBeUndefined();

    await _assertRoundTrip(fx, initDAG({ dbPath: ":memory:" }));
  });

  test("sqlite store joiner", async () => {
    const dbPath = path.join(os.tmpdir(), `tip-biom-rt-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
    try {
      await _assertRoundTrip(_source(), initDAG({ dbPath }));
    } finally {
      for (const ext of ["", "-wal", "-shm"]) { try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ } }
    }
  });
});
