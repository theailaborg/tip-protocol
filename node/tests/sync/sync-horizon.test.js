/**
 * @file tests/sync/sync-horizon.test.js
 * @description §2 cert GC interaction with the cert-sync protocol.
 *
 * When a joiner asks for `fromRound` that falls below the server's GC
 * horizon (i.e. the server has pruned all certs below some minimum),
 * cert-replay can't possibly succeed — the peer would hand back only
 * certs whose parent chain points into pruned territory. The server
 * detects this and responds with `snapshot_required: true`; the client
 * short-circuits cert-replay and returns the signal so the join-flow
 * can fall back to §14 state-snapshot sync.
 *
 * This file exercises both sides end-to-end via an in-memory stream pair.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");
const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createSyncHandler } = require(path.join(SRC, "sync", "sync-handler"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));
const { createStreamPair } = require("../helpers/stream-pair");

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

function fakeCert(round) {
  const hash = shake256(`cert:${round}`);
  return {
    hash,
    round,
    author_node_id: "tip://node/n1",
    batch: { round, author_node_id: "tip://node/n1", txs: [], signature: "00" },
    acknowledgments: [],
    parent_hashes: [],
    signature: "00",
  };
}

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  // Stub network — sync-handler only uses it for openStream, which we
  // override per-test via the stream pair.
  const network = {
    handle: () => { /* no-op — we call _handleIncomingSync directly */ },
    openStream: async () => { throw new Error("not used in this test"); },
  };
  return { dag, network };
}

describe("sync handler GC horizon signaling", () => {
  test("peer requesting from_round >= earliest available → normal reply, snapshot_required=false", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    // Server has certs at rounds 10-15 (simulating a state post-GC where
    // rounds < 10 have been pruned).
    for (let r = 10; r <= 15; r++) serverDag.saveCertificate(fakeCert(r));

    // Client asks from round 12 — inside horizon.
    const { loadTypes } = require(path.join(SRC, "network", "proto"));
    await loadTypes();
    const { encode, decode } = require(path.join(SRC, "network", "proto"));
    const { client, server } = createStreamPair();

    const serverPromise = serverSync.handleIncomingSync(server, "peer-x");

    // Write the client's SyncRequest.
    await client.sink((async function* () {
      yield encode("SyncRequest", { fromRound: 12, toRound: 0, merkleRoot: new Uint8Array(), batchSize: 100 });
    })());

    // Collect the server's response.
    const chunks = [];
    for await (const chunk of client.source) chunks.push(chunk);
    await serverPromise;

    const response = decode("SyncResponse", Buffer.concat(chunks));
    expect(response.snapshotRequired).toBe(false);
    expect(response.earliestAvailableRound).toBe(10);
    expect(response.certificates.length).toBeGreaterThan(0);
  });

  test("peer requesting from_round < earliest available → snapshot_required=true, no certs", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    // Server has certs only at rounds 100-105 (simulates post-GC horizon).
    for (let r = 100; r <= 105; r++) serverDag.saveCertificate(fakeCert(r));

    const { encode, decode } = require(path.join(SRC, "network", "proto"));
    const { client, server } = createStreamPair();

    const serverPromise = serverSync.handleIncomingSync(server, "peer-x");

    // Client asks from round 1 — below horizon (server's earliest is 100).
    await client.sink((async function* () {
      yield encode("SyncRequest", { fromRound: 1, toRound: 0, merkleRoot: new Uint8Array(), batchSize: 100 });
    })());

    const chunks = [];
    for await (const chunk of client.source) chunks.push(chunk);
    await serverPromise;

    const response = decode("SyncResponse", Buffer.concat(chunks));
    expect(response.snapshotRequired).toBe(true);
    expect(response.earliestAvailableRound).toBe(100);
    expect(response.certificates).toHaveLength(0);
    expect(response.latestRound).toBe(105);
  });

  test("empty DAG → earliest = 1 (fallback), fromRound=1 accepted as normal", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });
    // No certs seeded.

    const { encode, decode } = require(path.join(SRC, "network", "proto"));
    const { client, server } = createStreamPair();

    const serverPromise = serverSync.handleIncomingSync(server, "peer-x");

    await client.sink((async function* () {
      yield encode("SyncRequest", { fromRound: 1, toRound: 0, merkleRoot: new Uint8Array(), batchSize: 100 });
    })());

    const chunks = [];
    for await (const chunk of client.source) chunks.push(chunk);
    await serverPromise;

    const response = decode("SyncResponse", Buffer.concat(chunks));
    // On empty DAG, earliestRound stays at 1 (fallback), fromRound=1 is
    // NOT below horizon, so normal reply with no certs.
    expect(response.snapshotRequired).toBe(false);
    expect(response.certificates).toHaveLength(0);
  });

  test("client syncFromPeer surfaces snapshot_required signal to caller", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const { dag: clientDag } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    // Seed server with a post-GC horizon at round 100.
    for (let r = 100; r <= 105; r++) serverDag.saveCertificate(fakeCert(r));

    // Client sync handler — but override openStream to wire our pair.
    const { client, server } = createStreamPair();
    const clientNet = {
      handle: () => { },
      openStream: async () => client,
    };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    // Kick the server handler in parallel.
    const serverPromise = serverSync.handleIncomingSync(server, "peer-y");

    const result = await clientSync.syncFromPeer("peer-y", { fromRound: 1 });
    await serverPromise;

    expect(result.snapshotRequired).toBe(true);
    expect(result.earliestAvailableRound).toBe(100);
    expect(result.imported).toBe(0);
    expect(result.peerLatestRound).toBe(105);
  });
});
