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

// Speed: shrink the round cadence so this real-loop simulation runs in seconds
// instead of the production 2s/round. A fresh module registry lets us re-init
// the frozen ProtocolConstants with short timings before the consensus modules
// bind to it. Healthy rounds seal on quorum immediately, so the dominant cost is
// the inter-round wait (batch_wait_ms).
jest.resetModules();
const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));
const _pc = JSON.parse(JSON.stringify(getGenesisPayload().protocol_constants));
_pc.consensus.round_timeout_ms = 50;   // round retry interval (default 2000)
_pc.consensus.batch_wait_ms = 5;       // inter-round delay (default 500)
PC.init(_pc);

const { initCrypto, generateMLDSAKeypair, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
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
    removeFault: (f) => { const i = faults.indexOf(f); if (i >= 0) faults.splice(i, 1); },
    clearFaults: () => { faults.length = 0; },
  };
}

// ── node factory ──────────────────────────────────────────────────────────────
//
// Lean wiring: createNarwhal + createBullshark directly (mirrors the core of
// consensus/index.js), committee injected via getCommittee, no anti-entropy /
// heartbeat / snapshot subsystems (those are operational, not part of the
// ack -> quorum -> cert -> anchor path the sub-quorum halt lives in).

function makeNode(nodeId, kp, registered, committeeIds, net) {
  const dag = initDAG({ dbPath: ":memory:" });
  // Every node knows all registered nodes' pubkeys so acks verify cross-node.
  for (const m of registered) {
    dag.saveNode({ node_id: m.nodeId, name: m.nodeId, public_key: m.publicKey, status: "active", registered_at: T0 });
  }
  const config = {
    nodeId, nodeRegisteredId: nodeId,
    nodePrivateKey: kp.privateKey, nodePublicKey: kp.publicKey,
  };
  const scoring = initScoring(dag, config);
  const mempool = createMempool(dag, { nodeId });
  const commitHandler = createCommitHandler({ dag, scoring, config, nodeId });

  // The committee is the subset of registered nodes that signs this epoch
  // (production: 5 nodes registered, committee of 4). Injected so the fault /
  // halt scenarios control quorum directly.
  const committee = [...committeeIds].sort();
  const getCommittee = () => committee;
  const network = net.adapterFor(nodeId);

  // Record every tx id this node orders, in commit order, for the cross-node
  // ordering + no-loss invariants. Captured at onOrderedTxs (the consensus
  // output) so it reflects the agreed order regardless of commit-handler.
  const orderedTxIds = [];

  const bullshark = createBullshark({
    dag,
    getNodeIds: getCommittee,
    onMissingCertsTimeout: () => { /* no resync subsystem in this harness */ },
    onOrderedTxs: (orderedTxs, round, certTimestamp) => {
      for (const t of orderedTxs) orderedTxIds.push(t.tx_id);
      return commitHandler.commitOrderedTxs(orderedTxs, round, { certTimestamp });
    },
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

  return { nodeId, dag, mempool, narwhal, bullshark, commitHandler, config, orderedTxIds };
}

function waitFor(predicate, { timeoutMs = 30000, intervalMs = 100 } = {}) {
  return new Promise((resolve, reject) => {
    const start = nowMs();
    const tick = () => {
      let ok = false;
      try { ok = predicate(); } catch (_e) { ok = false; }
      if (ok) return resolve(true);
      if (nowMs() - start > timeoutMs) return reject(new Error("waitFor: timed out"));
      setTimeout(tick, intervalMs);
    };
    tick();
  });
}

// Boot `registered` real consensus nodes, of which the first `committee` form
// the signing committee (default: all registered). Every node instance runs,
// but only committee members count toward quorum. Returns all node instances.
function bootCommittee(net, { registered, committee = registered } = {}) {
  const all = Array.from({ length: registered }, (_, i) => {
    const kp = generateMLDSAKeypair();
    return { nodeId: `tip://node/n${i}`, ...kp };
  });
  const committeeIds = all.slice(0, committee).map((m) => m.nodeId);
  const nodes = all.map((m) => makeNode(m.nodeId, m, all, committeeIds, net));
  nodes.forEach((n) => n.narwhal.start());
  // Surface which nodes are committee members for fault scenarios.
  nodes.forEach((n) => { n.isCommittee = committeeIds.includes(n.nodeId); });
  return nodes;
}

function stopAll(nodes) {
  nodes.forEach((n) => { try { n.narwhal.stop(); } catch (_e) { /* ignore */ } });
  nodes.forEach((n) => { try { if (n.dag.close) n.dag.close(); } catch (_e) { /* ignore */ } });
}

// Submit a minimal, content-addressed tx to one node's mempool. Ordering is
// decided before commit-handler, so a structurally-minimal tx is enough to
// exercise the consensus ordering + no-loss invariants.
function submitTestTx(node, i) {
  const body = {
    tx_type: "REGISTER_CONTENT", timestamp: T0 + i, prev: [],
    data: { ctid: `tip://content/soak-${i}`, content_hash: shake256(`soak-${i}`), seq: i },
  };
  body.tx_id = computeTxId(body);
  node.mempool.add(body);
  return body.tx_id;
}

// ── step 1: liveness smoke tests (prove the harness drives a real commit) ──────

describe("multi-node consensus harness, liveness", () => {
  // Liveness: every node must commit at least one anchor round through the real
  // batch -> ack -> cert -> bullshark-order path. Empty batches are enough; the
  // signal is the pipeline advancing, not a specific tx.
  for (const size of [2, 4]) {
    test(`${size} nodes form a committee and advance anchor commits`, async () => {
      const net = createNet();
      const nodes = bootCommittee(net, { registered: size });
      try {
        await waitFor(() => nodes.every((n) => n.bullshark.lastCommittedRound() > 0), { timeoutMs: 30000 });
        for (const n of nodes) expect(n.bullshark.lastCommittedRound()).toBeGreaterThan(0);
      } finally {
        stopAll(nodes);
      }
    }, 60000);
  }
});


// ── step 2a: tx no-loss + identical ordering across nodes ──────────────────────

describe("multi-node consensus harness, tx ordering", () => {
  test("every node orders the same submitted txs in the same order (no-loss + agreement)", async () => {
    const net = createNet();
    const nodes = bootCommittee(net, { registered: 4 });
    try {
      // Submit distinct txs round-robin to different nodes' mempools.
      const K = 12;
      const submitted = [];
      for (let i = 0; i < K; i++) submitted.push(submitTestTx(nodes[i % nodes.length], i));
      const submittedSet = new Set(submitted);

      // No-loss: every node must eventually order all K submitted txs.
      await waitFor(() => nodes.every((n) =>
        new Set(n.orderedTxIds.filter((id) => submittedSet.has(id))).size === K),
      { timeoutMs: 30000 });

      // Agreement: each node's ordered sequence (restricted to the submitted
      // set) is the SAME sequence, with no duplicates and nothing missing.
      const seqs = nodes.map((n) => n.orderedTxIds.filter((id) => submittedSet.has(id)));
      const reference = seqs[0];
      expect(reference.length).toBe(K);          // no-loss
      expect(new Set(reference).size).toBe(K);   // no duplicate ordering
      for (const s of seqs) expect(s).toEqual(reference); // identical order on every node
    } finally {
      stopAll(nodes);
    }
  }, 60000);
});

// Note: fault-tolerance and sub-quorum-halt are deliberately NOT re-tested here.
// The quorum boundary (1 crash tolerated, 2 crashes halt) is already pinned by
// the faster single-instance tests narwhal-partition-safety.test.js and
// narwhal-disconnect-halt.test.js. This file keeps only the Layer-1 properties
// those don't cover: real multi-node liveness, tx ordering/no-loss, and soak.

// ── step 2c: soak - no halt over sustained operation ───────────────────────────
//
// Default round target is CI-friendly; set TIP_SOAK_ROUNDS to crank it up for a
// long-running soak (the engine should run indefinitely without halting).

describe("multi-node consensus harness, soak", () => {
  test("sustained operation advances without halting and stays converged", async () => {
    const TARGET = Number(process.env.TIP_SOAK_ROUNDS || 12);
    const net = createNet();
    const nodes = bootCommittee(net, { registered: 4 });
    try {
      // No-halt: every node must reach the round target (a stall fails waitFor).
      await waitFor(() => nodes.every((n) => n.bullshark.lastCommittedRound() >= TARGET), { timeoutMs: 120000 });
      const rounds = nodes.map((n) => n.bullshark.lastCommittedRound());
      // Safety: no node falls far behind the leader.
      expect(Math.min(...rounds)).toBeGreaterThanOrEqual(TARGET);
      expect(Math.max(...rounds) - Math.min(...rounds)).toBeLessThanOrEqual(5);
    } finally {
      stopAll(nodes);
    }
  }, 150000);
});
