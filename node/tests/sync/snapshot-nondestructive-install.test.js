/**
 * @file tests/sync/snapshot-nondestructive-install.test.js
 * @description Non-destructive streaming install (install-on-top + reconcile).
 *
 * The install must never leave a node with less state than it started with.
 * The previous design wiped canonical state at the HEADER frame, so a
 * mid-stream failure destroyed entity_keys/nodes and the node then rejected
 * every peer handshake as unauthorized, deadlocking the very resync it
 * needed (prod incident 2026-07-10). Rows now stream as upserts over the
 * existing state; local rows absent from the snapshot are pruned only after
 * the full state phase arrives, and the root check still gates go-live.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createSnapshotHandler } = require(path.join(SRC, "sync", "snapshot-handler"));
const { computeStateMerkleRoot } = require(path.join(SRC, "consensus", "state-root"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));
const { SNAPSHOT_INSTALL_MARKER_KEY } = require(path.join(SHARED, "constants"));

const { buildCommittedDag } = require("../helpers/commit-builder");
const { attemptInstall } = require("../helpers/snapshot-install");

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

const T0 = 1767225600000;

// A functioning node's pre-install state: the peer rows + key material it
// uses to authorize handshakes, plus rows the snapshot source doesn't have
// (fork artifacts a reconciling install must eventually prune).
function seedDestState(destDag) {
  destDag.saveNode({
    node_id: "PEER_NODE_A",
    name: "peer a",
    public_key: "ab".repeat(32),
    status: "active",
    registered_at: T0,
  });
  destDag.saveEntityKey({
    entity_type: "node",
    entity_id: "PEER_NODE_A",
    public_key: "ab".repeat(32),
    algorithm: "ml-dsa-65",
    valid_from_ts: T0,
    valid_to_ts: null,
    source_tx_id: "cafe01",
  });
  destDag.saveIdentity({
    tip_id: "tip://id/US-preexisting001",
    status: "active",
    created_at: T0,
  });
  destDag.saveIdentity({
    tip_id: "tip://id/US-stalefork0001",
    status: "active",
    created_at: T0 + 1,
  });
  destDag.addDedupHash(shake256("stale-fork-content"), T0 + 2, "tip://id/US-stalefork0001");
  destDag.setOwnerHead("id:tip://id/US-stalefork0001", shake256("stale-fork-tx"));
}

function expectDestStateIntact(destDag) {
  expect(destDag.getNode("PEER_NODE_A")).toBeTruthy();
  expect(destDag.getEntityKeyHistory("node", "PEER_NODE_A")).toHaveLength(1);
  expect(destDag.getIdentity("tip://id/US-preexisting001")).toBeTruthy();
  expect(destDag.getIdentity("tip://id/US-stalefork0001")).toBeTruthy();
}

describe("non-destructive install: mid-stream failure", () => {
  test("a truncated install keeps ALL pre-existing state (auth material survives)", async () => {
    const fx = buildCommittedDag({ committeeSize: 2, seedTxs: 3 });
    const destDag = initDAG({ dbPath: ":memory:" });
    seedDestState(destDag);

    await expect(
      attemptInstall(fx.sourceDag, destDag, { chunkSize: 8, truncateAfterFraction: 0.6 })
    ).rejects.toThrow();

    // The node it was before the attempt: peers stay authorized, resync can retry.
    expectDestStateIntact(destDag);

    // Nothing went live and the marker still guards the mixed state.
    const latest = fx.sourceDag.getLatestCommit();
    expect(destDag.getCommit(latest.round)).toBeNull();
    expect(String(destDag.getConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY))).toMatch(/^in_progress/);
  });

  test("crash → retry (no wipe in between) converges to the source's exact state", async () => {
    const fx = buildCommittedDag({ committeeSize: 2, seedTxs: 3 });
    const destDag = initDAG({ dbPath: ":memory:" });
    seedDestState(destDag);

    await expect(
      attemptInstall(fx.sourceDag, destDag, { chunkSize: 8, truncateAfterFraction: 0.6 })
    ).rejects.toThrow();
    expectDestStateIntact(destDag);

    const result = await attemptInstall(fx.sourceDag, destDag, { chunkSize: 16 });
    expect(computeStateMerkleRoot(destDag)).toBe(fx.stateRoot);
    expect(destDag.getCommit(result.round)).toBeTruthy();
    const marker = destDag.getConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY);
    expect(marker == null || marker === "").toBe(true);
  });
});

describe("non-destructive install: reconcile exactness", () => {
  test("a successful install prunes local rows absent from the snapshot and merges overlaps", async () => {
    const fx = buildCommittedDag({
      committeeSize: 2,
      seedTxs: 3,
      preCommitMutate: (d) => {
        d.saveIdentity({ tip_id: "tip://id/US-sharedrow001", status: "active", created_at: T0 });
      },
    });
    const destDag = initDAG({ dbPath: ":memory:" });
    seedDestState(destDag);
    // Overlapping PK with a stale local value: the peer's row must win.
    destDag.saveIdentity({ tip_id: "tip://id/US-sharedrow001", status: "revoked", created_at: T0 });

    await attemptInstall(fx.sourceDag, destDag, { chunkSize: 16 });

    expect(computeStateMerkleRoot(destDag)).toBe(fx.stateRoot);
    expect(destDag.getIdentity("tip://id/US-sharedrow001").status).toBe("active");
    // Every pre-existing row the source doesn't have is gone: exactness.
    expect(destDag.getIdentity("tip://id/US-stalefork0001")).toBeFalsy();
    expect(destDag.getIdentity("tip://id/US-preexisting001")).toBeFalsy();
    expect(destDag.getNode("PEER_NODE_A")).toBeFalsy();
    expect(destDag.getEntityKeyHistory("node", "PEER_NODE_A")).toHaveLength(0);
    expect(destDag.getOwnerHead("id:tip://id/US-stalefork0001")).toBeFalsy();
  });

  test("same-PK-different-value rows on first-write-wins tables converge to the peer's value", async () => {
    const H = shake256("colliding-dedup-content");
    const fx = buildCommittedDag({
      committeeSize: 2,
      preCommitMutate: (d) => {
        d.addDedupHash(H, T0 + 100, "tip://id/US-sourceowner1");
        d.saveProtocolParam({ param_key: "test_param", value: 42, effective_from_height: 5, update_tx_id: "aa01" });
      },
    });
    const destDag = initDAG({ dbPath: ":memory:" });
    // Same PKs, different bytes: addDedupHash / saveProtocolParam are
    // first-write-wins at runtime, so a plain re-apply would keep the stale
    // local value forever and the root check would fail on every retry.
    destDag.addDedupHash(H, T0 + 999, "tip://id/US-staleowner01");
    destDag.saveProtocolParam({ param_key: "test_param", value: 1, effective_from_height: 5, update_tx_id: "bb02" });

    await attemptInstall(fx.sourceDag, destDag, { chunkSize: 16 });
    expect(computeStateMerkleRoot(destDag)).toBe(fx.stateRoot);
  });
});

describe("non-destructive install: regression refusal", () => {
  test("a snapshot older than our attested head is refused when our state is consistent", async () => {
    const oldFx = buildCommittedDag({ committeeSize: 2, round: 2 });
    // Dest holds a NEWER attested commit (round 5) and reproduces its root.
    const newFx = buildCommittedDag({ committeeSize: 2, round: 5 });

    await expect(
      attemptInstall(oldFx.sourceDag, newFx.sourceDag, { chunkSize: 16 })
    ).rejects.toThrow(/refusing regression/);
  });

  test("a snapshot older than our attested head IS accepted when our state is broken (regress-then-replay)", async () => {
    const oldFx = buildCommittedDag({ committeeSize: 2, round: 2 });
    const newFx = buildCommittedDag({ committeeSize: 2, round: 5 });
    // Drift the dest's state away from its own attested head: mixed state,
    // exactly the shape a botched install leaves behind.
    newFx.sourceDag.saveIdentity({ tip_id: "tip://id/US-mixedblend001", status: "active", created_at: T0 });

    const result = await attemptInstall(oldFx.sourceDag, newFx.sourceDag, { chunkSize: 16 });
    expect(result.round).toBe(2);
    expect(computeStateMerkleRoot(newFx.sourceDag)).toBe(oldFx.stateRoot);
  });
});

describe("non-destructive install: stale marker resolution", () => {
  // A kept-state node that catches back up via the cert tail has no install
  // to clear its marker; resolveStaleInstallMarker must release it iff the
  // state root reproduces the latest commit's attested root.
  test("marker clears when state root matches the attested latest commit", async () => {
    const fx = buildCommittedDag({ committeeSize: 2 });
    const handler = createSnapshotHandler({
      dag: fx.sourceDag,
      network: { node: {}, openStream: async () => ({}) },
      isAuthorizedPeer: () => true,
    });
    fx.sourceDag.setConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY, "in_progress:2");

    expect(await handler.resolveStaleInstallMarker()).toBe("cleared");
    const marker = fx.sourceDag.getConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY);
    expect(marker == null || marker === "").toBe(true);
  });

  test("marker stays when state has drifted from the attested root (resync required)", async () => {
    const fx = buildCommittedDag({ committeeSize: 2 });
    const handler = createSnapshotHandler({
      dag: fx.sourceDag,
      network: { node: {}, openStream: async () => ({}) },
      isAuthorizedPeer: () => true,
    });
    fx.sourceDag.saveIdentity({ tip_id: "tip://id/US-driftedrow001", status: "active", created_at: T0 });
    fx.sourceDag.setConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY, "in_progress:2");

    expect(await handler.resolveStaleInstallMarker()).toBe("inconsistent");
    expect(String(fx.sourceDag.getConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY))).toMatch(/^in_progress/);
  });

  test("no-op without a marker", async () => {
    const fx = buildCommittedDag({ committeeSize: 2 });
    const handler = createSnapshotHandler({
      dag: fx.sourceDag,
      network: { node: {}, openStream: async () => ({}) },
      isAuthorizedPeer: () => true,
    });
    expect(await handler.resolveStaleInstallMarker()).toBe("none");
  });
});

describe("non-destructive install: boot recovery", () => {
  test("boot recovery after an interrupted install keeps state and re-signals resync", async () => {
    const destDag = initDAG({ dbPath: ":memory:" });
    seedDestState(destDag);
    destDag.setConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY, "in_progress:5");

    const bootHandler = createSnapshotHandler({
      dag: destDag,
      network: { node: {}, openStream: async () => ({}) },
      isAuthorizedPeer: () => true,
    });
    expect(await bootHandler.recoverInterruptedInstall()).toBe(true);

    // Mixed state stays: the node keeps authorizing peers so the resync it
    // just signalled can actually fetch a snapshot. The retry reconciles.
    expectDestStateIntact(destDag);
    expect(String(destDag.getConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY))).toMatch(/^in_progress/);
  });
});
