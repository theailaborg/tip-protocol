/**
 * @file tests/consensus/multinode-consensus.test.js
 * @description In-process multi-node consensus simulation harness.
 *
 * Wires N copies of the REAL Narwhal+Bullshark engine to an in-memory message
 * bus that fakes the libp2p surface (publish / sendAckDirect / handle), so we
 * can drive a real committee in one process, inject faults (drop acks), and
 * assert the BFT invariants:
 *
 *   - liveness : every healthy node keeps advancing anchor commits
 *   - safety   : no two nodes commit a divergent order at the same index
 *   - no-loss  : every submitted tx commits exactly once
 *
 * The oracle is the invariants, not a second "reference" consensus engine.
 *
 * Step 1 here is a liveness smoke test: prove the harness can drive a real
 * commit in-process across a committee. Fault injection and the sub-quorum /
 * committee-rotation halt reproduction build on this skeleton.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { createNarwhal } = require(path.join(SRC, "consensus", "narwhal"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const participants = require(path.join(SRC, "consensus", "participants"));
const { loadTypes } = require(path.join(SRC, "network", "proto"));

beforeAll(async () => { await initCrypto(); await loadTypes(); });

const T0 = 1767225600000;

// node-local public-key lookup (mirrors index.js getNodeKey).
const getNodeKey = (dag, nodeId) => (dag.getNode(nodeId)?.public_key || null);

// ── in-memory network bus ─────────────────────────────────────────────────────
//
// Fakes the slice of the libp2p network interface the consensus engine calls:
// gossip publish (batches/acks/certs) + direct-stream acks + protocol handlers.
// A fault is a predicate over message metadata; matching messages are dropped.

function fakeStream(buf) {
  return {
    source: (async function* () { yield buf; })(),
    sink: async (it) => { for await (const _c of it) { /* drain */ } },
    close() { /* noop */ },
  };
}

function createNet() {
  const topicHandlers = new Map(); // nodeId -> { [topic]: (buf) => void }
  const protoHandlers = new Map(); // nodeId -> { [protocol]: ({stream,connection}) => void }
  const faults = [];
  const drop = (meta) => faults.some((f) => f(meta));

  function adapterFor(nodeId) {
    if (!protoHandlers.has(nodeId)) protoHandlers.set(nodeId, {});
    const TOPICS = { MEMPOOL: "mempool", CONSENSUS: "consensus", CERTIFICATES: "certificates" };
    const ACK = "/tip/consensus-ack/1.0.0";
    const conn = () => ({ remotePeer: { toString: () => nodeId } });

    function publish(topic, buf) {
      for (const [otherId, h] of topicHandlers) {
        if (otherId === nodeId) continue;
        if (drop({ from: nodeId, to: otherId, topic })) continue;
        const fn = h[topic];
        if (fn) setImmediate(() => { try { fn(buf); } catch (_e) { /* ignore */ } });
      }
      return Promise.resolve();
    }
    function sendAckDirect(buf, toNodeId) {
      if (drop({ from: nodeId, to: toNodeId, kind: "ack" })) return Promise.resolve(false);
      const handler = protoHandlers.get(toNodeId)?.[ACK];
      if (!handler) return Promise.resolve(false);
      setImmediate(() => { try { handler({ stream: fakeStream(buf), connection: conn() }); } catch (_e) { /* ignore */ } });
      return Promise.resolve(true);
    }
    function broadcastToAuthorized(buf, protocol) {
      for (const [otherId, ph] of protoHandlers) {
        if (otherId === nodeId) continue;
        const handler = ph[protocol];
        if (handler) setImmediate(() => { try { handler({ stream: fakeStream(buf), connection: conn() }); } catch (_e) { /* ignore */ } });
      }
      return Promise.resolve();
    }
    function handle(protocol, handler) { protoHandlers.get(nodeId)[protocol] = handler; return Promise.resolve(); }

    return {
      TOPICS,
      CONSENSUS_ACK_PROTOCOL: ACK,
      CONSENSUS_ACK_REQUEST_PROTOCOL: "/tip/consensus-ack-request/1.0.0",
      ROTATION_COORD_PROTOCOL: "/tip/rotation-coord/1.0.0",
      publish, sendAckDirect, broadcastToAuthorized, handle,
      sendAckRequest: () => Promise.resolve(null),
      onPeerAuthorized: () => { },
    };
  }

  return {
    adapterFor,
    setTopicHandlers: (nodeId, h) => topicHandlers.set(nodeId, h),
    addFault: (f) => faults.push(f),
    clearFaults: () => { faults.length = 0; },
  };
}

// ── node factory ──────────────────────────────────────────────────────────────
//
// Lean wiring: createNarwhal + createBullshark directly (mirrors the core of
// consensus/index.js), committee injected via getCommittee, no anti-entropy /
// heartbeat / snapshot subsystems (those are operational, not part of the
// ack -> quorum -> cert -> anchor path the sub-quorum halt lives in).

function makeNode(nodeId, kp, committee, net) {
  const dag = initDAG({ dbPath: ":memory:" });
  // Every node knows the full committee's pubkeys so acks verify cross-node.
  for (const m of committee) {
    dag.saveNode({ node_id: m.nodeId, name: m.nodeId, public_key: m.publicKey, status: "active", registered_at: T0 });
  }
  const config = {
    nodeId, nodeRegisteredId: nodeId,
    nodePrivateKey: kp.privateKey, nodePublicKey: kp.publicKey,
  };
  const scoring = initScoring(dag, config);
  const mempool = createMempool(dag, { nodeId });
  const commitHandler = createCommitHandler({ dag, scoring, config, nodeId });

  const committeeIds = committee.map((m) => m.nodeId).sort();
  const getCommittee = () => committeeIds;
  const network = net.adapterFor(nodeId);

  const bullshark = createBullshark({
    dag,
    getNodeIds: getCommittee,
    onMissingCertsTimeout: () => { /* step 1: no resync subsystem */ },
    onOrderedTxs: (orderedTxs, round, certTimestamp) =>
      commitHandler.commitOrderedTxs(orderedTxs, round, { certTimestamp }),
    proposer: {
      nodeId, nodePrivateKey: kp.privateKey, nodePublicKey: kp.publicKey,
      submitTx: (tx) => mempool.add(tx),
      coordinator: null, // rotation coordinator wired in the rotation-boundary test
    },
  });

  const narwhal = createNarwhal({
    dag, mempool, network, config,
    getNodeKey: (nId) => getNodeKey(dag, nId),
    getNodeCount: () => participants.getNodeCount(dag),
    getCommittee,
    onCommit: (certificates, round) => bullshark.onRoundComplete(certificates, round),
    onCertSaved: (cert) => { if (typeof bullshark.onCertSaved === "function") bullshark.onCertSaved(cert.hash); },
    onProducerPaused: (round, missingRotation) => {
      if (typeof bullshark.tryRotationProposal === "function") bullshark.tryRotationProposal(round, missingRotation);
    },
    isPeerDivergent: () => false,
    peerJoinState: () => "ready",
    divergentPeers: () => [],
  });

  // Direct-stream ack receiver (mirrors index.js _registerAckReceiver).
  network.handle(network.CONSENSUS_ACK_PROTOCOL, async ({ stream }) => {
    const chunks = [];
    for await (const chunk of stream.source) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    narwhal.handleIncomingAck(Buffer.concat(chunks));
    try { stream.close(); } catch (_e) { /* ignore */ }
  });

  // Route incoming gossip topics to this node's narwhal handlers.
  net.setTopicHandlers(nodeId, {
    [network.TOPICS.MEMPOOL]: (buf) => narwhal.handleIncomingBatch(buf),
    [network.TOPICS.CONSENSUS]: (buf) => narwhal.handleIncomingAck(buf),
    [network.TOPICS.CERTIFICATES]: (buf) => narwhal.handleIncomingCertificate(buf),
  });

  return { nodeId, dag, mempool, narwhal, bullshark, commitHandler, config };
}

function waitFor(predicate, { timeoutMs = 30000, intervalMs = 100 } = {}) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = () => {
      let ok = false;
      try { ok = predicate(); } catch (_e) { ok = false; }
      if (ok) return resolve(true);
      if (Date.now() - start > timeoutMs) return reject(new Error("waitFor: timed out"));
      setTimeout(tick, intervalMs);
    };
    tick();
  });
}

// Boot a committee of `size` real consensus nodes wired to one bus.
function bootCommittee(net, size) {
  const committee = Array.from({ length: size }, (_, i) => {
    const kp = generateMLDSAKeypair();
    return { nodeId: `tip://node/n${i}`, ...kp };
  });
  const nodes = committee.map((m) => makeNode(m.nodeId, m, committee, net));
  nodes.forEach((n) => n.narwhal.start());
  return nodes;
}

function stopAll(nodes) {
  nodes.forEach((n) => { try { n.narwhal.stop(); } catch (_e) { /* ignore */ } });
  nodes.forEach((n) => { try { if (n.dag.close) n.dag.close(); } catch (_e) { /* ignore */ } });
}

// ── step 1: liveness smoke tests (prove the harness drives a real commit) ──────

describe("multi-node consensus harness, liveness", () => {
  // Liveness: every node must commit at least one anchor round through the real
  // batch -> ack -> cert -> bullshark-order path. Empty batches are enough; the
  // signal is the pipeline advancing, not a specific tx.
  for (const size of [2, 4]) {
    test(`${size} nodes form a committee and advance anchor commits`, async () => {
      const net = createNet();
      const nodes = bootCommittee(net, size);
      try {
        await waitFor(() => nodes.every((n) => n.bullshark.lastCommittedRound() > 0), { timeoutMs: 30000 });
        for (const n of nodes) expect(n.bullshark.lastCommittedRound()).toBeGreaterThan(0);
      } finally {
        stopAll(nodes);
      }
    }, 60000);
  }
});
