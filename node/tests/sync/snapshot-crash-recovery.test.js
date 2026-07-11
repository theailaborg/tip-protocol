/**
 * @file tests/sync/snapshot-crash-recovery.test.js
 * @description #132 streaming install crash-marker lifecycle + boot recovery.
 *
 * The streaming install writes canonical state in-place across many batches
 * (no single covering transaction), so it can't rely on transaction rollback
 * for crash-safety. Instead a persisted `snapshot_install_state` marker guards
 * the mixed state: set `in_progress` before the first row lands, cleared only
 * when the fully-verified install goes live. A node that boots and finds the
 * marker still `in_progress` keeps its state (entity_keys must stay live so
 * peers still authorize) and re-enters syncing rather than coming up `ready`
 * on unverified state (which would fork); the next install reconciles.
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
const { loadTypes } = require(path.join(SRC, "network", "proto"));
const { SNAPSHOT_INSTALL_MARKER_KEY } = require(path.join(SHARED, "constants"));

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
    network: { node: {}, handle: async () => { } },
    isAuthorizedPeer: () => true,
  });
  const destHandler = createSnapshotHandler({
    dag: destDag,
    network: { node: {}, openStream: async () => client },
    isAuthorizedPeer: () => true,
  });
  return { client, server, sourceHandler, destHandler };
}

describe("#132 streaming install crash marker", () => {
  test("a successful install clears the marker (node is a trusted checkpoint)", async () => {
    const fx = buildCommittedDag({ committeeSize: 1, seedTxs: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });
    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    await Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ]);

    // Cleared (empty string), NOT still in_progress.
    const marker = destDag.getConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY);
    expect(marker == null || marker === "" || !String(marker).startsWith("in_progress")).toBe(true);

    // And a boot check on a cleanly-installed node is a no-op.
    expect(await destHandler.recoverInterruptedInstall()).toBe(false);
  });

  test("boot recovery keeps state and the marker set for re-crash safety", async () => {
    const destDag = initDAG({ dbPath: ":memory:" });
    const destHandler = createSnapshotHandler({
      dag: destDag,
      network: { node: {}, openStream: async () => ({}) },
      isAuthorizedPeer: () => true,
    });

    // Simulate a crash mid-install: canonical row present + marker set.
    destDag.saveIdentity({
      tip_id: "tip://id/US-partialdeadbeef01",
      public_key: "ab".repeat(32),
      status: "active",
      created_at: 1783036800000,
    });
    destDag.setConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY, "in_progress:5");
    expect(destDag.getIdentity("tip://id/US-partialdeadbeef01")).toBeTruthy();

    const recovered = await destHandler.recoverInterruptedInstall();
    expect(recovered).toBe(true);

    // Mixed state kept: the retry's upsert+prune reconciles it; wiping here
    // destroyed entity_keys and deadlocked recovery (prod 2026-07-10).
    expect(destDag.getIdentity("tip://id/US-partialdeadbeef01")).toBeTruthy();

    // Marker LEFT set — a second crash during recovery must still resync, so
    // only a fully-verified install is allowed to clear it.
    expect(String(destDag.getConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY))).toMatch(/^in_progress/);
  });

  test("boot recovery is a no-op with no marker (fresh / cleanly-shut node)", async () => {
    const destDag = initDAG({ dbPath: ":memory:" });
    const destHandler = createSnapshotHandler({
      dag: destDag,
      network: { node: {}, openStream: async () => ({}) },
      isAuthorizedPeer: () => true,
    });
    expect(await destHandler.recoverInterruptedInstall()).toBe(false);
  });

  test("a marker left by a completed install (empty) is not treated as interrupted", async () => {
    const destDag = initDAG({ dbPath: ":memory:" });
    const destHandler = createSnapshotHandler({
      dag: destDag,
      network: { node: {}, openStream: async () => ({}) },
      isAuthorizedPeer: () => true,
    });
    destDag.setConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY, "");
    expect(await destHandler.recoverInterruptedInstall()).toBe(false);
  });
});
