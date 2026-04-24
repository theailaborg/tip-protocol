/**
 * @file tests/sync/sync-framing.test.js
 * @description §19 — tests specific to the length-prefixed framed sync
 * protocol. Complements sync-horizon.test.js (which covers the GC
 * horizon signaling) and the shared-framing tests in framing.test.js.
 *
 * Covers:
 *   - Many-cert stream (hundreds) round-trips end-to-end
 *   - Single-cert stream
 *   - Empty-cert stream (header + footer only, no body frames)
 *   - Client detects cert_count mismatch and rejects
 *   - Client detects truncated stream (no footer) and rejects
 *   - Client detects frame size exceeding max
 *   - Server and client agree on cert_count under normal flow
 *   - No-encode on snapshot-required path (footer has certCount=0)
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
const { loadTypes, encode, decode, hexToBytes } = require(path.join(SRC, "network", "proto"));
const { frame, parseLengthPrefixedFrames } = require(path.join(SRC, "network", "framing"));
const { createStreamPair } = require("../helpers/stream-pair");

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

function fakeCert(round, authorSuffix = "n1") {
  const author = `tip://node/${authorSuffix}`;
  const hash = shake256(`cert:${round}:${author}`);
  return {
    hash,
    round,
    author_node_id: author,
    batch: { round, author_node_id: author, txs: [], signature: "00" },
    acknowledgments: [],
    parent_hashes: [],
    signature: "00",
  };
}

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const network = {
    handle: () => { },
    openStream: async () => { throw new Error("not used"); },
  };
  return { dag, network };
}

/**
 * Richer fixture: a Certificate carrying actual Transaction entries
 * inside its batch. Exercises the full tx ser/deser path across the
 * framed wire — catches any regression in _serializeCertForSync or
 * _deserializeCertFromSync that fakeCert's empty-txs shape would miss.
 */
function certWithTxs(round, authorSuffix, txs) {
  const author = `tip://node/${authorSuffix}`;
  const hash = shake256(`cert:${round}:${author}:${JSON.stringify(txs)}`);
  return {
    hash,
    round,
    author_node_id: author,
    batch: {
      round,
      author_node_id: author,
      txs,
      signature: "00",
      hash: shake256(`batch:${round}:${author}`),
    },
    acknowledgments: [],
    parent_hashes: [],
    signature: "00",
  };
}

describe("§19 sync handler — framed wire format", () => {
  test("round-trip: 1 cert is wrapped in its own frame between header and footer", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });
    // Seed at round 1 so fromRound=1 is NOT below the GC horizon.
    serverDag.saveCertificate(fakeCert(1));

    const { client, server } = createStreamPair();
    const p = serverSync.handleIncomingSync(server, "peer");

    await client.sink((async function* () {
      yield encode("SyncRequest", { fromRound: 1, toRound: 0, merkleRoot: new Uint8Array(), batchSize: 100 });
    })());

    const chunks = [];
    for await (const c of client.source) chunks.push(c.subarray ? c.subarray() : c);
    await p;

    const frames = parseLengthPrefixedFrames(Buffer.concat(chunks));
    expect(frames).toHaveLength(3);  // header + 1 cert + footer

    const header = decode("SyncResponseHeader", frames[0]);
    const cert = decode("Certificate", frames[1]);
    const footer = decode("SyncResponseFooter", frames[2]);

    expect(header.snapshotRequired).toBe(false);
    expect(Number(cert.round)).toBe(1);
    expect(Number(footer.certCount)).toBe(1);
  });

  test("round-trip: many certs stream as individual frames (no aggregation)", async () => {
    // 200 certs across 50 rounds — stresses per-frame encoding and
    // verifies no single giant SyncResponse gets materialized.
    const { dag: serverDag, network: serverNet } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    let seeded = 0;
    for (let r = 1; r <= 50; r++) {
      for (let i = 0; i < 4; i++) {
        serverDag.saveCertificate(fakeCert(r, `n${i}`));
        seeded++;
      }
    }
    expect(seeded).toBe(200);

    const { client, server } = createStreamPair();
    const p = serverSync.handleIncomingSync(server, "peer");

    await client.sink((async function* () {
      yield encode("SyncRequest", { fromRound: 1, toRound: 0, merkleRoot: new Uint8Array(), batchSize: 1000 });
    })());

    const chunks = [];
    for await (const c of client.source) chunks.push(c.subarray ? c.subarray() : c);
    await p;

    const frames = parseLengthPrefixedFrames(Buffer.concat(chunks));
    // 1 header + 200 cert frames + 1 footer
    expect(frames).toHaveLength(202);

    const footer = decode("SyncResponseFooter", frames[frames.length - 1]);
    expect(Number(footer.certCount)).toBe(200);
  });

  test("round-trip: empty DAG yields exactly 2 frames (header + footer)", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    const { client, server } = createStreamPair();
    const p = serverSync.handleIncomingSync(server, "peer");

    await client.sink((async function* () {
      yield encode("SyncRequest", { fromRound: 1, toRound: 0, merkleRoot: new Uint8Array(), batchSize: 100 });
    })());

    const chunks = [];
    for await (const c of client.source) chunks.push(c.subarray ? c.subarray() : c);
    await p;

    const frames = parseLengthPrefixedFrames(Buffer.concat(chunks));
    expect(frames).toHaveLength(2);

    const footer = decode("SyncResponseFooter", frames[1]);
    expect(Number(footer.certCount)).toBe(0);
  });

  test("client imports every cert from a many-cert stream end-to-end", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const { dag: clientDag } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    for (let r = 10; r <= 30; r++) serverDag.saveCertificate(fakeCert(r));

    const { client, server } = createStreamPair();
    const clientNet = {
      handle: () => { },
      openStream: async () => client,
    };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const serverPromise = serverSync.handleIncomingSync(server, "peer");
    const result = await clientSync.syncFromPeer("peer", { fromRound: 10 });
    await serverPromise;

    expect(result.imported).toBe(21);  // rounds 10..30 inclusive
    expect(result.toRound).toBe(30);
    expect(result.snapshotRequired).toBeFalsy();
    // Client DAG now has every cert.
    for (let r = 10; r <= 30; r++) {
      expect(clientDag.getCertificatesByRound(r)).toHaveLength(1);
    }
  });

  test("client rejects response with cert_count mismatch (silent-truncation guard)", async () => {
    // Build a malicious response where the footer lies about the count.
    const header = encode("SyncResponseHeader", {
      fromRound: 1, toRound: 5, latestRound: 5,
      merkleRoot: new Uint8Array(), snapshotRequired: false,
      earliestAvailableRound: 1,
    });
    const certFrame = encode("Certificate", {
      round: 1, authorNodeId: "tip://node/x",
      batch: { round: 1, authorNodeId: "tip://node/x", txs: [], signature: hexToBytes("00"), hash: hexToBytes("00") },
      acknowledgments: [], parentHashes: [],
      signature: hexToBytes("00"), hash: hexToBytes(shake256("c1")),
    });
    // Footer claims 99 certs but we only sent 1.
    const footer = encode("SyncResponseFooter", { certCount: 99, merkleRoot: new Uint8Array() });

    const { dag: clientDag } = setup();
    const { client, server } = createStreamPair();

    // Custom server that writes the lying response.
    const serverPromise = (async () => {
      // Drain the request.
      for await (const _ of server.source) break;
      await server.sink((async function* () {
        yield frame(header);
        yield frame(certFrame);
        yield frame(footer);
      })());
    })();

    const clientNet = {
      handle: () => { },
      openStream: async () => client,
    };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const result = await clientSync.syncFromPeer("peer", { fromRound: 1 });
    await serverPromise;

    expect(result.imported).toBe(0);  // rejected due to mismatch
    expect(clientDag.certificateCount()).toBe(0);
  });

  test("client rejects response missing footer (truncated stream)", async () => {
    const header = encode("SyncResponseHeader", {
      fromRound: 1, toRound: 0, latestRound: 0,
      merkleRoot: new Uint8Array(), snapshotRequired: false,
      earliestAvailableRound: 1,
    });

    const { dag: clientDag } = setup();
    const { client, server } = createStreamPair();
    const serverPromise = (async () => {
      for await (const _ of server.source) break;
      await server.sink((async function* () {
        yield frame(header);  // header only — no footer
      })());
    })();

    const clientNet = { handle: () => { }, openStream: async () => client };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const result = await clientSync.syncFromPeer("peer", { fromRound: 1 });
    await serverPromise;

    expect(result.imported).toBe(0);
  });

  test("client rejects response with an oversized frame", async () => {
    // NETWORK.SNAPSHOT_MAX_FRAME_BYTES is 16MB. We construct a length
    // prefix declaring 17MB — parser throws, client logs + returns empty.
    const header = encode("SyncResponseHeader", {
      fromRound: 1, toRound: 0, latestRound: 0,
      merkleRoot: new Uint8Array(), snapshotRequired: false,
      earliestAvailableRound: 1,
    });
    const goodFramePrefix = Buffer.alloc(4);
    goodFramePrefix.writeUIntBE(header.length, 0, 4);

    // A length prefix that declares 17MB but only provides a few bytes.
    const badLen = Buffer.alloc(4);
    badLen.writeUIntBE(17 * 1024 * 1024, 0, 4);

    const { dag: clientDag } = setup();
    const { client, server } = createStreamPair();
    const serverPromise = (async () => {
      for await (const _ of server.source) break;
      await server.sink((async function* () {
        yield Buffer.concat([goodFramePrefix, header]);
        yield badLen;  // oversized claim — parser aborts
        yield Buffer.from([0, 0, 0]);  // not enough body anyway
      })());
    })();

    const clientNet = { handle: () => { }, openStream: async () => client };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const result = await clientSync.syncFromPeer("peer", { fromRound: 1 });
    await serverPromise;

    expect(result.imported).toBe(0);
  });

  test("client handles empty response stream (peer closed without writing)", async () => {
    const { dag: clientDag } = setup();
    const { client, server } = createStreamPair();
    const serverPromise = (async () => {
      for await (const _ of server.source) break;
      // Close without writing anything.
      await server.sink((async function* () { })());
    })();

    const clientNet = { handle: () => { }, openStream: async () => client };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const result = await clientSync.syncFromPeer("peer", { fromRound: 1 });
    await serverPromise;

    expect(result.imported).toBe(0);
  });

  test("real cert with txs: client imports transactions intact across framed wire", async () => {
    // End-to-end tx roundtrip: seed a cert carrying 3 Transactions, sync,
    // confirm the client's DAG has the cert + each tx's fields preserved.
    // Most of our other tests use empty-txs fakeCerts, which skip the
    // proto Transaction encode/decode path entirely. A regression in
    // _serializeCertForSync / _deserializeCertFromSync would not be
    // caught by them.
    const { dag: serverDag, network: serverNet } = setup();
    const { dag: clientDag } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    const txs = [
      {
        tx_id: "tx-001",
        tx_type: "REGISTER_IDENTITY",
        timestamp: "2026-04-24T10:00:00.000Z",
        prev: ["prev-1", "prev-2"],
        data: { region: "US", tier: "T1" },
        signature: "aabb",
      },
      {
        tx_id: "tx-002",
        tx_type: "REGISTER_CONTENT",
        timestamp: "2026-04-24T10:00:01.000Z",
        prev: ["tx-001"],
        data: { ctid: "tip://c/abc", origin: "OH" },
        signature: "ccdd",
      },
      {
        tx_id: "tx-003",
        tx_type: "VERIFY_CONTENT",
        timestamp: "2026-04-24T10:00:02.000Z",
        prev: [],
        data: {},
        signature: "eeff",
      },
    ];
    const cert = certWithTxs(1, "n1", txs);
    serverDag.saveCertificate(cert);

    const { client, server } = createStreamPair();
    const clientNet = { handle: () => { }, openStream: async () => client };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const serverPromise = serverSync.handleIncomingSync(server, "peer");
    const result = await clientSync.syncFromPeer("peer", { fromRound: 1 });
    await serverPromise;

    expect(result.imported).toBe(1);

    // Pull the imported cert back out of client DAG and verify txs.
    const imported = clientDag.getCertificatesByRound(1)[0];
    expect(imported).toBeTruthy();
    expect(imported.batch.txs).toHaveLength(3);
    expect(imported.batch.txs[0].tx_id).toBe("tx-001");
    expect(imported.batch.txs[0].tx_type).toBe("REGISTER_IDENTITY");
    expect(imported.batch.txs[0].prev).toEqual(["prev-1", "prev-2"]);
    expect(imported.batch.txs[0].data).toEqual({ region: "US", tier: "T1" });
    expect(imported.batch.txs[0].signature).toBe("aabb");
    expect(imported.batch.txs[1].tx_id).toBe("tx-002");
    expect(imported.batch.txs[1].data).toEqual({ ctid: "tip://c/abc", origin: "OH" });
    expect(imported.batch.txs[2].tx_id).toBe("tx-003");
    // Tx with empty data / prev / signature should still round-trip.
    expect(imported.batch.txs[2].prev).toEqual([]);
    expect(imported.batch.txs[2].data).toEqual({});
  });

  test("auth gate: unauthorized peer's request is rejected before handleIncomingSync runs", async () => {
    // registerProtocol wires isAuthorizedPeer as the first gate; our
    // framed handleIncomingSync runs only after the gate passes. A
    // peer that somehow opens the stream without authorization must
    // see a close, not a response.
    const { dag: serverDag } = setup();

    let registeredHandler = null;
    const serverNet = {
      handle: async (_protocol, handler) => { registeredHandler = handler; },
      openStream: async () => { throw new Error("unused"); },
      node: { /* present so handler is registered */ },
    };
    const serverSync = createSyncHandler({
      dag: serverDag,
      network: serverNet,
      isAuthorizedPeer: () => false,  // reject everyone
    });
    await serverSync.registerProtocol();
    expect(typeof registeredHandler).toBe("function");

    let streamClosed = false;
    const fakeStream = {
      sink: async () => { },
      source: (async function* () { /* never yields */ })(),
      close: () => { streamClosed = true; },
    };
    await registeredHandler({
      stream: fakeStream,
      connection: { remotePeer: { toString: () => "rogue-peer" } },
    });

    expect(streamClosed).toBe(true);
  });

  // Note on chunked reads: libp2p can split a stream at any byte boundary.
  // This is exercised at the framing-layer in tests/network/framing.test.js
  // ("stream.source and returns parsed frames") which feeds split chunks
  // into readAllFrames. The framed sync protocol uses the same framing, so
  // we don't duplicate the test at the sync layer.

  test("timeout: hanging peer triggers totalTimeoutMs and aborts with imported=0", async () => {
    // Peer accepts stream, writes nothing, hangs forever. Client must
    // bail after totalTimeoutMs with imported=0 — not hang. We override
    // the timeout via call options to keep the test fast (200ms).
    const { dag: clientDag } = setup();
    const hangingStream = {
      _closed: false,
      sink: async (src) => { for await (const _ of src) { /* drain request */ } },
      source: (async function* () {
        await new Promise((resolve) => {
          const check = setInterval(() => {
            if (hangingStream._closed) { clearInterval(check); resolve(); }
          }, 5);
        });
      })(),
      close: () => { hangingStream._closed = true; },
    };

    const clientNet = { handle: () => { }, openStream: async () => hangingStream };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const started = Date.now();
    const result = await clientSync.syncFromPeer("peer", { fromRound: 1, totalTimeoutMs: 200 });
    const elapsed = Date.now() - started;

    expect(result.imported).toBe(0);
    expect(elapsed).toBeGreaterThanOrEqual(180);
    expect(elapsed).toBeLessThan(600);
  });

  test("byte cap: response exceeding maxResponseBytes is aborted with imported=0", async () => {
    // Peer sends many valid-sized frames; cumulative bytes exceed the
    // per-call cap. Client's for-await loop detects the threshold and
    // throws internally; syncFromPeer catches + returns imported=0.
    // Override maxResponseBytes to 2 KB so a handful of frames trips it.
    const { dag: serverDag, network: serverNet } = setup();
    const { dag: clientDag } = setup();

    // Seed 50 certs → server streams ~52 frames. fakeCert encodes small
    // (~60-80 bytes including frame prefix), so at 50 certs total stream
    // is ~4 KB. Set cap below that and the client aborts.
    for (let r = 1; r <= 50; r++) serverDag.saveCertificate(fakeCert(r));
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    const { client, server } = createStreamPair();
    const clientNet = { handle: () => { }, openStream: async () => client };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const serverPromise = serverSync.handleIncomingSync(server, "peer");
    const result = await clientSync.syncFromPeer("peer", {
      fromRound: 1,
      maxResponseBytes: 500,  // well under the ~4 KB stream, must trip
    });
    await serverPromise;

    expect(result.imported).toBe(0);
    expect(clientDag.certificateCount()).toBe(0);
  });

  test("byte cap: response UNDER the cap imports normally (cap doesn't block legitimate sync)", async () => {
    // Positive control: give a generous cap and verify the same 20 certs
    // import. Rules out "cap fires no matter what" as a false-positive
    // on the previous test.
    const { dag: serverDag, network: serverNet } = setup();
    const { dag: clientDag } = setup();

    for (let r = 1; r <= 20; r++) serverDag.saveCertificate(fakeCert(r));
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });

    const { client, server } = createStreamPair();
    const clientNet = { handle: () => { }, openStream: async () => client };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const serverPromise = serverSync.handleIncomingSync(server, "peer");
    const result = await clientSync.syncFromPeer("peer", {
      fromRound: 1,
      maxResponseBytes: 1024 * 1024,  // 1 MB cap — well above what 20 fakeCerts need
    });
    await serverPromise;

    expect(result.imported).toBe(20);
  });

  test("malformed individual cert frame: decode-throw skipped, siblings still import", async () => {
    // Byzantine peer sends 3 cert frames: good, corrupt, good. Client
    // should log on the corrupt one, import the two valid certs, and
    // return imported=2 (not 0). Current policy is best-effort per
    // frame rather than reject-the-batch; this test nails down that
    // behavior so a future refactor is forced to think about it.
    const header = encode("SyncResponseHeader", {
      fromRound: 1, toRound: 2, latestRound: 2,
      merkleRoot: new Uint8Array(), snapshotRequired: false,
      earliestAvailableRound: 1,
    });

    const goodCertA = encode("Certificate", {
      round: 1, authorNodeId: "tip://node/a",
      batch: { round: 1, authorNodeId: "tip://node/a", txs: [], signature: hexToBytes("00"), hash: hexToBytes(shake256("bA")) },
      acknowledgments: [], parentHashes: [],
      signature: hexToBytes("00"), hash: hexToBytes(shake256("cA")),
    });
    const goodCertB = encode("Certificate", {
      round: 2, authorNodeId: "tip://node/b",
      batch: { round: 2, authorNodeId: "tip://node/b", txs: [], signature: hexToBytes("00"), hash: hexToBytes(shake256("bB")) },
      acknowledgments: [], parentHashes: [],
      signature: hexToBytes("00"), hash: hexToBytes(shake256("cB")),
    });
    // Corrupt cert frame: random bytes that don't parse as Certificate.
    const corruptCert = Buffer.from([0xff, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04]);

    const footer = encode("SyncResponseFooter", { certCount: 3, merkleRoot: new Uint8Array() });

    const { dag: clientDag } = setup();
    const { client, server } = createStreamPair();
    const serverPromise = (async () => {
      for await (const _ of server.source) break;
      await server.sink((async function* () {
        yield frame(header);
        yield frame(goodCertA);
        yield frame(corruptCert);
        yield frame(goodCertB);
        yield frame(footer);
      })());
    })();

    const clientNet = { handle: () => { }, openStream: async () => client };
    const clientSync = createSyncHandler({ dag: clientDag, network: clientNet });

    const result = await clientSync.syncFromPeer("peer", { fromRound: 1 });
    await serverPromise;

    // Corrupt cert is skipped, two valid certs import.
    expect(result.imported).toBe(2);
    expect(clientDag.certificateCount()).toBe(2);
  });

  // Note on server generator mid-stream throw:
  // If the server's generator throws (e.g. encoder bug, disk error on
  // cert read), the outer try/catch in _sendFramedResponse logs and
  // swallows — on the wire, client sees header + possibly some certs
  // with NO footer. This is exactly the "truncated stream" case
  // already covered by the "client rejects response missing footer"
  // test above; the silent-truncation guard rejects both paths with
  // imported=0. We don't duplicate the scenario at the sync layer.
  //
  // The server IS intentionally resilient to per-round DAG read
  // errors (see try/catch around getCertificatesByRound in
  // sync-handler.js) — a bad read for one round is skipped and the
  // sync continues with the remaining rounds. That's by design, not
  // a bug to catch in tests.

  test("server's footer merkle_root matches self.merkleRoot() at emit time", async () => {
    const { dag: serverDag, network: serverNet } = setup();
    const serverSync = createSyncHandler({ dag: serverDag, network: serverNet });
    for (let r = 1; r <= 3; r++) serverDag.saveCertificate(fakeCert(r));
    serverSync.onCertificateCommitted();  // rebuild merkle after seeding

    const expectedRoot = serverSync.merkleRoot();

    const { client, server } = createStreamPair();
    const p = serverSync.handleIncomingSync(server, "peer");

    await client.sink((async function* () {
      yield encode("SyncRequest", { fromRound: 1, toRound: 0, merkleRoot: new Uint8Array(), batchSize: 10 });
    })());

    const chunks = [];
    for await (const c of client.source) chunks.push(c.subarray ? c.subarray() : c);
    await p;

    const frames = parseLengthPrefixedFrames(Buffer.concat(chunks));
    const header = decode("SyncResponseHeader", frames[0]);
    const footer = decode("SyncResponseFooter", frames[frames.length - 1]);

    const headerRootHex = Buffer.from(header.merkleRoot).toString("hex");
    const footerRootHex = Buffer.from(footer.merkleRoot).toString("hex");
    expect(headerRootHex).toBe(expectedRoot);
    expect(footerRootHex).toBe(expectedRoot);  // same snapshot, same root
  });
});
