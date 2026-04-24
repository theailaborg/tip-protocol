/**
 * @file tests/sync/sync-horizon.test.js
 * @description §2 cert GC interaction with the cert-sync protocol, now
 * reading the §19 framed wire format.
 *
 * When a joiner asks for `fromRound` that falls below the server's GC
 * horizon, the server responds with a SyncResponseHeader carrying
 * `snapshot_required: true` and zero Certificate frames between header
 * and footer. Client short-circuits and falls back to §14.
 *
 * Wire shape: [SyncResponseHeader][Certificate]*[SyncResponseFooter],
 * each length-prefixed per network/framing.js.
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
const { loadTypes, encode, decode } = require(path.join(SRC, "network", "proto"));
const { parseLengthPrefixedFrames } = require(path.join(SRC, "network", "framing"));
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
  const network = {
    handle: () => { },
    openStream: async () => { throw new Error("not used in this test"); },
  };
  return { dag, network };
}

/**
 * Read the full stream, parse frames, decode into structured
 * {header, certs[], footer}. Mirrors what the real client does but
 * returns the intermediate structure for test assertions.
 */
async function readFramedResponse(client) {
  const chunks = [];
  for await (const chunk of client.source) chunks.push(chunk.subarray ? chunk.subarray() : chunk);
  const frames = parseLengthPrefixedFrames(Buffer.concat(chunks));
  const header = decode("SyncResponseHeader", frames[0]);
  const footer = decode("SyncResponseFooter", frames[frames.length - 1]);
  const certs = frames.slice(1, -1).map(f => decode("Certificate", f));
  return { header, certs, footer, frameCount: frames.length };
}

describe("sync handler GC horizon signaling (framed wire)", () => {
  test("peer requesting from_round >= earliest available → normal reply, snapshot_required=false", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    // Server has certs at rounds 10-15 (simulating a state post-GC where
    // rounds < 10 have been pruned).
    for (let r = 10; r <= 15; r++) serverDag.saveCertificate(fakeCert(r));

    const { client, server } = createStreamPair();
    const serverPromise = serverSync.handleIncomingSync(server, "peer-x");

    // Send the request (unframed, single message).
    await client.sink((async function* () {
      yield encode("SyncRequest", { fromRound: 12, toRound: 0, merkleRoot: new Uint8Array(), batchSize: 100 });
    })());

    const { header, certs, footer } = await readFramedResponse(client);
    await serverPromise;

    expect(header.snapshotRequired).toBe(false);
    expect(Number(header.earliestAvailableRound)).toBe(10);
    expect(Number(header.latestRound)).toBe(15);
    expect(certs.length).toBeGreaterThan(0);
    expect(Number(footer.certCount)).toBe(certs.length);
  });

  test("peer requesting from_round < earliest available → snapshot_required=true, zero cert frames between header and footer", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    // Server has certs only at rounds 100-105 (simulates post-GC horizon).
    for (let r = 100; r <= 105; r++) serverDag.saveCertificate(fakeCert(r));

    const { client, server } = createStreamPair();
    const serverPromise = serverSync.handleIncomingSync(server, "peer-x");

    await client.sink((async function* () {
      yield encode("SyncRequest", { fromRound: 1, toRound: 0, merkleRoot: new Uint8Array(), batchSize: 100 });
    })());

    const { header, certs, footer } = await readFramedResponse(client);
    await serverPromise;

    expect(header.snapshotRequired).toBe(true);
    expect(Number(header.earliestAvailableRound)).toBe(100);
    expect(Number(header.latestRound)).toBe(105);
    expect(certs).toHaveLength(0);
    expect(Number(footer.certCount)).toBe(0);
  });

  test("empty DAG → earliest=1 (fallback), fromRound=1 accepted as normal (0 certs)", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });
    // No certs seeded.

    const { client, server } = createStreamPair();
    const serverPromise = serverSync.handleIncomingSync(server, "peer-x");

    await client.sink((async function* () {
      yield encode("SyncRequest", { fromRound: 1, toRound: 0, merkleRoot: new Uint8Array(), batchSize: 100 });
    })());

    const { header, certs } = await readFramedResponse(client);
    await serverPromise;

    expect(header.snapshotRequired).toBe(false);
    expect(certs).toHaveLength(0);
  });

  test("client syncFromPeer surfaces snapshot_required signal to caller", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const { dag: clientDag } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    for (let r = 100; r <= 105; r++) serverDag.saveCertificate(fakeCert(r));

    const { client, server } = createStreamPair();
    const clientNet = {
      handle: () => { },
      openStream: async () => client,
    };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const serverPromise = serverSync.handleIncomingSync(server, "peer-y");
    const result = await clientSync.syncFromPeer("peer-y", { fromRound: 1 });
    await serverPromise;

    expect(result.snapshotRequired).toBe(true);
    expect(result.earliestAvailableRound).toBe(100);
    expect(result.imported).toBe(0);
    expect(result.peerLatestRound).toBe(105);
  });
});
