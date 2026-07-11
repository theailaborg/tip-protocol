/**
 * @file tests/sync/snapshot-streaming-harness.test.js
 * @description #132 streaming install integration harness.
 *
 * The plain stream-pair delivers exactly one frame per chunk, so it never
 * forces the receiver's streamFrames() to reassemble a frame split across
 * chunk boundaries, nor to coalesce several frames arriving in one chunk , the
 * conditions a real TCP/libp2p stream produces and the ones a streaming parser
 * must survive. This harness re-fragments the server's byte stream into small
 * fixed-size chunks (spanning frame boundaries arbitrarily) and can truncate it
 * mid-flight to simulate a connection drop / crash. It proves:
 *   1. install is byte-correct under arbitrary fragmentation (down to 1 byte),
 *   2. a truncated stream is rejected, leaves the crash marker `in_progress`,
 *      and installs NO header commit (nothing goes live), and
 *   3. crash → boot-recover → re-install converges to the source's exact state
 *      and clears the marker.
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
const { SNAPSHOT_INSTALL_MARKER_KEY } = require(path.join(SHARED, "constants"));

const { buildCommittedDag } = require("../helpers/commit-builder");
const { attemptInstall } = require("../helpers/snapshot-install");

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

describe("#132 streaming install under fragmentation", () => {
  test.each([13, 7, 1])("fragmented delivery (%i-byte chunks) installs byte-identically to source", async (chunkSize) => {
    const fx = buildCommittedDag({ committeeSize: 2, seedTxs: 3 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const result = await attemptInstall(fx.sourceDag, destDag, { chunkSize });

    expect(result.state_merkle_root).toBe(fx.stateRoot);
    expect(computeStateMerkleRoot(destDag)).toBe(fx.stateRoot);
    expect(destDag.getCommit(result.round)).toBeTruthy();
    // Marker cleared → this is now a trusted checkpoint.
    const marker = destDag.getConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY);
    expect(marker == null || marker === "").toBe(true);
  });
});

describe("#132 streaming install crash mid-stream", () => {
  test("a stream truncated mid-download is rejected, marks in_progress, installs no header commit", async () => {
    const fx = buildCommittedDag({ committeeSize: 2, seedTxs: 3 });
    const destDag = initDAG({ dbPath: ":memory:" });

    // Truncate at a point past the header (so the install has begun)
    // but well before END.
    await expect(
      attemptInstall(fx.sourceDag, destDag, { chunkSize: 8, truncateAfterFraction: 0.6 })
    ).rejects.toThrow();

    // Nothing went live: the header commit is written last, only after full
    // verification, so it must be absent.
    const latest = fx.sourceDag.getLatestCommit();
    expect(destDag.getCommit(latest.round)).toBeNull();

    // Crash marker is still in_progress → a reboot stays in syncing + resyncs.
    expect(String(destDag.getConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY))).toMatch(/^in_progress/);
  });

  test("crash → boot-recover → re-install converges to the source's exact state", async () => {
    const fx = buildCommittedDag({ committeeSize: 2, seedTxs: 3 });
    const destDag = initDAG({ dbPath: ":memory:" });

    // First attempt crashes mid-stream.
    await expect(
      attemptInstall(fx.sourceDag, destDag, { chunkSize: 8, truncateAfterFraction: 0.6 })
    ).rejects.toThrow();

    // Simulate reboot: a fresh handler over the same DAG runs boot recovery.
    const bootHandler = createSnapshotHandler({
      dag: destDag,
      network: { node: {}, openStream: async () => ({}) },
      isAuthorizedPeer: () => true,
    });
    expect(await bootHandler.recoverInterruptedInstall()).toBe(true);

    // Re-install over a fresh (full) stream converges exactly.
    const result = await attemptInstall(fx.sourceDag, destDag, { chunkSize: 8 });
    expect(computeStateMerkleRoot(destDag)).toBe(fx.stateRoot);
    expect(destDag.getCommit(result.round)).toBeTruthy();
    const marker = destDag.getConsensusMeta(SNAPSHOT_INSTALL_MARKER_KEY);
    expect(marker == null || marker === "").toBe(true);
  });
});
