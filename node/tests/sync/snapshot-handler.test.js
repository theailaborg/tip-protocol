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

// ═══════════════════════════════════════════════════════════════════════════
// Security-critical ack verification edge cases.
//
// Each test crafts a specific ack-array malformation that a malicious peer
// might try — non-committee signer, duplicate signers, garbage sig bytes —
// and asserts the client rejects or refuses to count it toward quorum.
// These paths exist in snapshot-handler.js (Set-dedupe of `seen`, committee
// membership check, mldsaVerify return value) but weren't exercised by the
// happy-path / simple-reject tests above.
// ═══════════════════════════════════════════════════════════════════════════
describe("§14 snapshot ack verification hardening", () => {
  const { mldsaSign, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));

  test("ack from a signer not in the committee does NOT count toward quorum", async () => {
    // committee of 2, drop 1 sig → only 1 valid committee ack. Then inject
    // an extra ack from a signer who is NOT in the committee. Quorum needs
    // 2 valid committee sigs; only 1 is available → client must reject.
    const extraKey = generateMLDSAKeypair();
    const fx = buildCommittedDag({
      committeeSize: 2,
      dropSigs: 1,
      ackTransform: (acks, ctx) => {
        acks.signerIds.push("NON_COMMITTEE_NODE");
        acks.signatures.push(
          mldsaSign(`ack:${ctx.anchorBatchHash}:NON_COMMITTEE_NODE`, extraKey.privateKey)
        );
        return acks;
      },
    });
    const destDag = initDAG({ dbPath: ":memory:" });
    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    await expect(Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ])).rejects.toThrow(/insufficient ack quorum/i);

    expect(destDag.getCommit(2)).toBeNull();
  });

  test("duplicate signers are counted once — cannot inflate quorum by repeating", async () => {
    // committee=2, quorum=2. Start with only committee[0]'s sig, then
    // DUPLICATE it (same signer, same sig). A naive count would say "2
    // signatures present" but `seen` dedupes → only 1 unique signer →
    // quorum shortfall.
    const fx = buildCommittedDag({
      committeeSize: 2,
      dropSigs: 2,   // wipe the default acks — we're building from scratch
      ackTransform: (_, ctx) => {
        const { nodeId, privateKey } = ctx.committeeKeys[0];
        const sig = mldsaSign(`ack:${ctx.anchorBatchHash}:${nodeId}`, privateKey);
        return { signerIds: [nodeId, nodeId], signatures: [sig, sig] };
      },
    });
    const destDag = initDAG({ dbPath: ":memory:" });
    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    await expect(Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ])).rejects.toThrow(/insufficient ack quorum/i);

    expect(destDag.getCommit(2)).toBeNull();
  });

  test("invalid signature bytes do not count toward quorum", async () => {
    // committee=1, quorum=1. Replace the one valid sig with garbage bytes.
    // mldsaVerify returns false → ack not counted → quorum unmet.
    const fx = buildCommittedDag({
      committeeSize: 1,
      ackTransform: (acks) => {
        // Preserve the signer id so the payload reconstruction still
        // matches; the bytes themselves are deliberately wrong.
        acks.signatures[0] = "00".repeat(64);  // obviously invalid sig
        return acks;
      },
    });
    const destDag = initDAG({ dbPath: ":memory:" });
    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    await expect(Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ])).rejects.toThrow(/insufficient ack quorum/i);

    expect(destDag.getCommit(2)).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Framing / reliability checks — defend against malformed-wire payloads
// that a buggy or hostile peer could send. All cases must be caught by
// the client's frame parser / end-marker sanity check BEFORE anything
// is installed on the destination DAG.
// ═══════════════════════════════════════════════════════════════════════════
describe("§14 snapshot framing & reliability", () => {
  test("truncated response (header only, no SnapshotEnd) is rejected", async () => {
    const fx = buildCommittedDag({ committeeSize: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { client, server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    // MITM: yield only the very first frame (the header) and drop
    // everything else — client should see frames.length < 2 and throw.
    const originalServerSink = server.sink;
    server.sink = async (src) => {
      await originalServerSink((async function* () {
        let sent = false;
        for await (const frame of src) {
          if (!sent) { sent = true; yield frame; }
          // drop the rest
        }
      })());
    };

    await expect(Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ])).rejects.toThrow(/missing SnapshotEnd terminator/i);

    expect(destDag.getCommit(2)).toBeNull();
    // Reference client so eslint doesn't flag it in the makeHandlers destructure.
    expect(client).toBeTruthy();
  });

  test("frame declaring a size beyond MAX_FRAME_BYTES is rejected", async () => {
    const fx = buildCommittedDag({ committeeSize: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    // MITM: overwrite the header frame's length prefix with UINT32_MAX (4 GB)
    // so the client's parser trips `frame exceeds max size` before decoding.
    const originalServerSink = server.sink;
    server.sink = async (src) => {
      await originalServerSink((async function* () {
        let first = true;
        for await (const frame of src) {
          if (first) {
            first = false;
            const out = Buffer.from(frame);
            // 4-byte big-endian length prefix at offset 0 — crank it to max.
            out.writeUInt32BE(0xffffffff, 0);
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
    ])).rejects.toThrow(/frame exceeds max size/i);

    expect(destDag.getCommit(2)).toBeNull();
  });

  test("row count mismatch (SnapshotEnd claims N, we received N-1) is rejected", async () => {
    const fx = buildCommittedDag({ committeeSize: 1 });
    const destDag = initDAG({ dbPath: ":memory:" });

    const { server, sourceHandler, destHandler } = makeHandlers({ sourceDag: fx.sourceDag, destDag });

    // MITM: drop exactly one state-row frame (the first row after the
    // header). The server's SnapshotEnd.rowCount still reflects the
    // original count, so the client's received-row tally falls short
    // by 1 → "row count mismatch" throws.
    const originalServerSink = server.sink;
    server.sink = async (src) => {
      await originalServerSink((async function* () {
        let headerSent = false;
        let oneRowDropped = false;
        for await (const frame of src) {
          if (!headerSent) { headerSent = true; yield frame; continue; }
          if (!oneRowDropped) { oneRowDropped = true; continue; }  // drop this one
          yield frame;  // pass remaining rows + SnapshotEnd unchanged
        }
      })());
    };

    await expect(Promise.all([
      sourceHandler._handleIncomingSnapshot(server, "test-client"),
      destHandler.requestSnapshotFromPeer("test-server", {}),
    ])).rejects.toThrow(/row count mismatch/i);

    expect(destDag.getCommit(2)).toBeNull();
  });
});
