/**
 * @file tests/sync/snapshot-handler.test.js
 * @description §14 state-snapshot sync protocol tests.
 *
 * Exercises the full server ↔ client round-trip of
 * `/tip/state-snapshot/1.0.0` through an in-memory stream pair —
 * identical `{sink, source, close}` semantics to libp2p, so the
 * framing, decode, verify, and atomic-install paths all run for real.
 * The same test bodies will drive real libp2p dials once network
 * integration tests are set up — just swap `createStreamPair()` for
 * the real `network.openStream` / `network.handle` wiring.
 *
 * Covers:
 *   - happy path: server streams, client verifies + installs; dest DAG's
 *     state_merkle_root equals source's
 *   - tampered state row: root mismatch, install rolled back
 *   - insufficient acks: quorum rejection, install rolled back
 *   - peer has no qualifying commit: server replies with error header
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

/**
 * Wire up a source (server-role) handler and a destination (client-role)
 * handler connected by an in-memory stream pair. Both use `isAuthorizedPeer:
 * () => true` — authorization is tested separately and would otherwise add
 * noise here.
 */
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

describe("§14 snapshot round-trip", () => {
  test("server streams, client verifies + installs", async () => {
    const fx = buildCommittedDag({ committeeSize: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    const [, result] = await Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ]);

    expect(result.round).toBe(2);
    expect(result.state_merkle_root).toBe(fx.stateRoot);
    expect(result.txs_merkle_root).toBe(fx.txsRoot);
    expect(result.rows_installed).toBeGreaterThan(0);

    // Destination's derived state rehashes to the same root (end-to-end proof).
    expect(computeStateMerkleRoot(destDag)).toBe(fx.stateRoot);

    // Commit row landed atomically.
    const dc = destDag.getCommit(2);
    expect(dc).toBeTruthy();
    expect(dc.state_merkle_root).toBe(fx.stateRoot);
    expect(dc.txs_merkle_root).toBe(fx.txsRoot);
    expect(dc.committee).toEqual(fx.committee);
    expect(dc.consensus_index).toBe(fx.consensusIndex);
  });

  test("installs every committee node into destination's nodes table", async () => {
    const fx = buildCommittedDag({ committeeSize: 2 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });
    await Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ]);

    for (const { nodeId } of fx.committeeKeys) {
      const n = destDag.getNode(nodeId);
      expect(n).toBeTruthy();
      expect(n.node_id).toBe(nodeId);
    }
  });
});

describe("§14 snapshot rejection paths", () => {
  test("tampered state row → state_merkle_root mismatch, no commit installed", async () => {
    const fx = buildCommittedDag({ committeeSize: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    // MITM: intercept the server's outbound frames and flip a byte in the
    // first frame that looks like a state row (skip the header).
    const originalServerSink = server.sink;
    server.sink = async (src) => {
      await originalServerSink((async function* () {
        let headerSeen = false;
        let tampered = false;
        for await (const frame of src) {
          if (!headerSeen) {
            headerSeen = true;
            yield frame;
            continue;
          }
          if (!tampered && frame.length > 8) {
            const out = Buffer.from(frame);
            // Byte flip near the end — length prefix stays valid, but the
            // canonical_json content is corrupted so the client-side
            // rebuilt root differs from header's state_merkle_root.
            out[out.length - 2] ^= 0xff;
            tampered = true;
            yield out;
          } else {
            yield frame;
          }
        }
      })());
    };

    await expect(Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ])).rejects.toThrow(/mismatch|parse failed/i);

    // Atomicity: no commit row landed on rejection.
    expect(destDag.getCommit(2)).toBeNull();
  });

  test("insufficient ack quorum → rejected, no commit installed", async () => {
    // committee=2, drop 1 sig → quorum=2 needed, only 1 valid.
    const fx = buildCommittedDag({ committeeSize: 2, dropSigs: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    await expect(Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ])).rejects.toThrow(/insufficient ack quorum/i);

    expect(destDag.getCommit(2)).toBeNull();
  });

  test("peer with no qualifying commit replies with error header", async () => {
    const sourceDag = initDAG({ dbPath: ":memory:" });   // no saveCommit ever called
    const destDag = initDAG({ dbPath: ":memory:" });

    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag, destDag });

    await expect(Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", { minRound: 5 }),
    ])).rejects.toThrow(/peer declined snapshot/i);
  });
});
