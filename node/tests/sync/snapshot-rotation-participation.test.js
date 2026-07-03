/**
 * @file tests/sync/snapshot-rotation-participation.test.js
 * @description #75 Phase F — rotation_participation rows ride the snapshot
 * wire format.
 *
 * Covers:
 *   - Source-streamed RP rows are byte-identically installed on dest
 *   - Pre-wipe: dest's stale row for a (node_id, rotation) absent from
 *     the snapshot's rotation set DOES get removed (so the snapshot is
 *     authoritative for the rotations it covers)
 *   - Rotations OUTSIDE the snapshot are NOT touched on dest (joiner
 *     keeps its own forward progress)
 *   - RP is intentionally OUTSIDE state_merkle_root — installing rows
 *     does not change state_merkle_root on either side
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createSnapshotHandler } = require(path.join(SRC, "sync", "snapshot-handler"));
const { computeStateMerkleRoot } = require(path.join(SRC, "consensus", "state-root"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));

const { createStreamPair } = require("../helpers/stream-pair");
const { buildCommittedDag } = require("../helpers/commit-builder");

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

function makeHandlers({ sourceDag, destDag }) {
  const { client, server } = createStreamPair();
  const sourceHandler = createSnapshotHandler({
    dag: sourceDag,
    network: { handle: () => { }, openStream: async () => client },
    config: { nodeId: "src" },
    isAuthorizedPeer: () => true,
  });
  const destHandler = createSnapshotHandler({
    dag: destDag,
    network: { handle: () => { }, openStream: async () => client },
    config: { nodeId: "dst" },
    isAuthorizedPeer: () => true,
  });
  return { client, server, sourceHandler, destHandler };
}

function _seedRP(dag, rows) {
  for (const { node_id, rotation_number, bucket = 0, count } of rows) {
    dag.setRotationParticipation(node_id, rotation_number, bucket, count);
  }
}

function _readRP(dag, rotation) {
  return dag.getRotationParticipation(rotation)
    .map(r => ({ node_id: r.node_id, count: r.count, buckets: r.buckets }))
    .sort((a, b) => a.node_id.localeCompare(b.node_id));
}

describe("#75 Phase F — rotation_participation snapshot sync", () => {
  test("rotation committed_at ships byte-identically; pre-genesis markers are clamped (spurious-rotation regression)", async () => {
    // Live incident 2026-07-03: install fabricated committed_at =
    // effective_round*1000 (epoch bucket 0), so the joiner proposed a
    // rotation at its first anchor commit, mid-epoch. committed_at is not
    // part of payload_hash or chain-of-trust, so rotation 0 (which needs no
    // sigs) exercises both wire-through and the clamp.
    const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));

    // Case 1: sane marker ships byte-identically.
    const goodTs = CONSENSUS.BFT_TIME_GENESIS_MS + 7 * 86400000;
    const fx1 = buildCommittedDag({ committeeSize: 1 });
    fx1.sourceDag.saveCommitteeRotation({ ...fx1.sourceDag.getCommitteeRotation(0), committed_at: goodTs });
    const dest1 = initDAG({ dbPath: ":memory:" });
    const h1 = makeHandlers({ sourceDag: fx1.sourceDag, destDag: dest1 });
    await Promise.all([
      h1.sourceHandler._handleIncomingSnapshot(h1.server, "test-client"),
      h1.destHandler.requestSnapshotFromPeer("test-server", {}),
    ]);
    expect(dest1.getCommitteeRotation(0).committed_at).toBe(goodTs);

    // Case 2: pre-genesis (poisoned) marker is clamped to >= BFT genesis so
    // the joiner can never see an ancient epoch bucket and fire a rotation.
    const fx2 = buildCommittedDag({ committeeSize: 1 });
    fx2.sourceDag.saveCommitteeRotation({ ...fx2.sourceDag.getCommitteeRotation(0), committed_at: 56000 });
    const dest2 = initDAG({ dbPath: ":memory:" });
    const h2 = makeHandlers({ sourceDag: fx2.sourceDag, destDag: dest2 });
    await Promise.all([
      h2.sourceHandler._handleIncomingSnapshot(h2.server, "test-client"),
      h2.destHandler.requestSnapshotFromPeer("test-server", {}),
    ]);
    const clamped = dest2.getCommitteeRotation(0).committed_at;
    expect(clamped).toBeGreaterThanOrEqual(CONSENSUS.BFT_TIME_GENESIS_MS);
    expect(clamped).not.toBe(56000);
  });

  test("source RP rows are installed byte-identically on dest", async () => {
    const fx = buildCommittedDag({ committeeSize: 1 });
    _seedRP(fx.sourceDag, [
      { node_id: "tip://node/A", rotation_number: 0, count: 50 },
      { node_id: "tip://node/B", rotation_number: 0, count: 75 },
      { node_id: "tip://node/A", rotation_number: 1, count: 100 },
      { node_id: "tip://node/B", rotation_number: 1, count: 200 },
    ]);

    const destDag = initDAG({ dbPath: ":memory:" });
    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    await Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ]);

    expect(_readRP(destDag, 0)).toEqual(_readRP(fx.sourceDag, 0));
    expect(_readRP(destDag, 1)).toEqual(_readRP(fx.sourceDag, 1));
  });

  test("pre-wipe: dest's stale (node_id, rotation) row is removed when source doesn't ship it", async () => {
    // Source has rotation 5 RP for node A only. Dest has stale rotation 5
    // RP for node B (left over from before — in real life, B was offline
    // for rotation 5 on source, so source's RP table has no row for B).
    // After install, dest's B-row for rotation 5 must be GONE.
    const fx = buildCommittedDag({ committeeSize: 1 });
    _seedRP(fx.sourceDag, [
      { node_id: "tip://node/A", rotation_number: 5, count: 200 },
    ]);

    const destDag = initDAG({ dbPath: ":memory:" });
    _seedRP(destDag, [
      { node_id: "tip://node/A", rotation_number: 5, count: 50 },   // stale, will be REPLACED
      { node_id: "tip://node/B", rotation_number: 5, count: 999 },  // stale, will be WIPED
    ]);

    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });
    await Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ]);

    const after = _readRP(destDag, 5);
    expect(after).toEqual([{ node_id: "tip://node/A", count: 200, buckets: 1 }]);
  });

  test("rotations OUTSIDE the snapshot are not touched on dest", async () => {
    // Source ships rotation 3 only. Dest has rotation 3 (will be wiped +
    // replaced) AND rotation 7 (forward state from after the snapshot
    // point — must NOT be touched, that's the joiner's own progress).
    const fx = buildCommittedDag({ committeeSize: 1 });
    _seedRP(fx.sourceDag, [
      { node_id: "tip://node/A", rotation_number: 3, count: 80 },
    ]);

    const destDag = initDAG({ dbPath: ":memory:" });
    _seedRP(destDag, [
      { node_id: "tip://node/A", rotation_number: 3, count: 1 },
      { node_id: "tip://node/A", rotation_number: 7, count: 555 },  // post-snapshot forward state
      { node_id: "tip://node/Z", rotation_number: 7, count: 777 },
    ]);

    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });
    await Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ]);

    expect(_readRP(destDag, 3)).toEqual([{ node_id: "tip://node/A", count: 80, buckets: 1 }]);
    // Forward-state rotation 7 is preserved verbatim.
    expect(_readRP(destDag, 7)).toEqual([
      { node_id: "tip://node/A", count: 555, buckets: 1 },
      { node_id: "tip://node/Z", count: 777, buckets: 1 },
    ]);
  });

  test("RP is excluded from state_merkle_root — installing RP doesn't change source's state root", () => {
    // Direct invariant check on iterateCanonicalState. RP rows must NOT
    // surface as `table === "rotation_participation"` here, because that
    // would put them in state_merkle_root and cause spurious DIVERGENCE
    // warnings between honest peers whose RP converges asynchronously.
    const dag = initDAG({ dbPath: ":memory:" });
    const beforeRoot = computeStateMerkleRoot(dag);

    dag.setRotationParticipation("tip://node/A", 0, 0, 100);
    dag.setRotationParticipation("tip://node/B", 0, 0, 200);

    const afterRoot = computeStateMerkleRoot(dag);
    expect(afterRoot).toBe(beforeRoot);

    // Defensive: nothing in iterateCanonicalState should have the RP table.
    for (const { table } of dag.iterateCanonicalState()) {
      expect(table).not.toBe("rotation_participation");
    }
  });
});
