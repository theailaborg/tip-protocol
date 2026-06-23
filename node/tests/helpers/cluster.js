/**
 * @file tests/helpers/cluster.js
 * @description Deterministic in-process N-node consensus cluster.
 *
 * Wires N copies of the REAL Narwhal+Bullshark+commit-handler over a controllable
 * in-memory bus, driven by a VIRTUAL CLOCK (jest fake timers) instead of the wall
 * clock. Rounds advance explicitly via `tickRound()`, so timing-dependent bugs
 * are reproducible and the whole simulation runs in milliseconds, not seconds.
 *
 *   const cluster = createInProcessCluster({ nodeCount: 3 });
 *   const id = cluster.nodes[0].submitTx(buildTx());
 *   cluster.setDelay(0, 1, 2);          // delay node0 -> node1 by 2 ticks
 *   await cluster.tickRounds(10);
 *   // invariant: every submitted tx is on every DAG OR explicitly rejected
 *   assert(cluster.nodes.every(n => n.dag.getTx(id)) || cluster.commitHandlerRejections.has(id));
 *
 * Only the network is faked; narwhal/bullshark/commit-handler are the real code.
 *
 * Usage contract: the test enables fake timers before creating the cluster:
 *   beforeAll(async () => { await initCrypto(); await loadTypes(); });
 *   beforeEach(() => jest.useFakeTimers({ doNotFake: ["setImmediate", "queueMicrotask", "nextTick"] }));
 *   afterEach(() => jest.useRealTimers());
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { generateMLDSAKeypair, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { createNarwhal } = require(path.join(SRC, "consensus", "narwhal"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const participants = require(path.join(SRC, "consensus", "participants"));

const T0 = 1773532801000; // 1ms past the genesis BFT-time floor
const getNodeKey = (dag, nodeId) => (dag.getNode(nodeId)?.public_key || null);

// Flush the real microtask + setImmediate queue (fake timers leave these real).
const flush = () => new Promise((r) => setImmediate(r));

const ACK = "/tip/consensus-ack/1.0.0";

// ── controllable, queued bus ──────────────────────────────────────────────────
//
// Messages are ENQUEUED, not delivered immediately, and drained per tick in a
// deterministic order. setDelay(from, to, ticks) holds a sender->receiver edge's
// messages for N ticks, the hook for reproducing message-ordering bugs.

function createBus() {
  const topicHandlers = new Map(); // nodeId -> { [topic]: (buf) => void }
  const protoHandlers = new Map(); // nodeId -> { [protocol]: ({stream,connection}) => void }
  const delays = new Map();        // "from->to" -> ticks
  const partitioned = new Set();   // node ids cut off from the bus
  const certBufs = [];             // every CERTIFICATES buf ever published (for cert-tail replay)
  const queue = [];
  let tick = 0;

  const fakeStream = (buf) => ({
    source: (async function* () { yield buf; })(),
    sink: async (it) => { for await (const _c of it) { /* drain */ } },
    close() { /* noop */ },
  });
  const delayFor = (from, to) => delays.get(`${from}->${to}`) || 0;
  const enqueue = (from, to, run) => {
    if (partitioned.has(from) || partitioned.has(to)) return; // dropped: node is offline
    queue.push({ to, dueTick: tick + delayFor(from, to), run });
  };

  function adapterFor(nodeId) {
    if (!protoHandlers.has(nodeId)) protoHandlers.set(nodeId, {});
    const TOPICS = { MEMPOOL: "mempool", CONSENSUS: "consensus", CERTIFICATES: "certificates" };
    const conn = () => ({ remotePeer: { toString: () => nodeId } });
    const toStream = (toId, protocol, buf) => enqueue(nodeId, toId, () => {
      const h = protoHandlers.get(toId)?.[protocol];
      if (h) return h({ stream: fakeStream(buf), connection: conn() });
    });

    return {
      TOPICS,
      CONSENSUS_ACK_PROTOCOL: ACK,
      CONSENSUS_ACK_REQUEST_PROTOCOL: "/tip/consensus-ack-request/1.0.0",
      ROTATION_COORD_PROTOCOL: "/tip/rotation-coord/1.0.0",
      publish(topic, buf) {
        if (topic === TOPICS.CERTIFICATES) certBufs.push(buf); // captured for cert-tail replay
        for (const [otherId, h] of topicHandlers) {
          if (otherId === nodeId) continue;
          const fn = h[topic];
          if (fn) enqueue(nodeId, otherId, () => fn(buf));
        }
        return Promise.resolve();
      },
      sendAckDirect(buf, toNodeId) {
        if (!protoHandlers.get(toNodeId)?.[ACK]) return Promise.resolve(false);
        toStream(toNodeId, ACK, buf);
        return Promise.resolve(true);
      },
      broadcastToAuthorized(buf, protocol) {
        for (const [otherId] of protoHandlers) {
          if (otherId === nodeId) continue;
          toStream(otherId, protocol, buf);
        }
        return Promise.resolve();
      },
      handle(protocol, handler) { protoHandlers.get(nodeId)[protocol] = handler; return Promise.resolve(); },
      sendAckRequest: () => Promise.resolve(null),
      onPeerAuthorized: () => { },
    };
  }

  async function drain() {
    let guard = 0;
    while (guard++ < 10000) {
      const due = queue.filter((m) => m.dueTick <= tick);
      if (due.length === 0) break;
      for (const m of due) queue.splice(queue.indexOf(m), 1);
      // Deliver this pass's messages in FIFO order; `await` flushes each
      // handler's microtasks. One setImmediate flush per pass settles any
      // macrotask work before re-checking for cascaded messages.
      for (const m of due) { try { await m.run(); } catch (_e) { /* ignore */ } }
      await flush();
    }
  }

  return {
    adapterFor,
    setTopicHandlers: (nodeId, h) => topicHandlers.set(nodeId, h),
    setDelay: (from, to, ticks) => delays.set(`${from}->${to}`, ticks),
    partition: (nodeId) => partitioned.add(nodeId),
    heal: (nodeId) => partitioned.delete(nodeId),
    certBufs,
    advanceTick: () => { tick += 1; },
    drain,
  };
}

// ── node factory (real narwhal+bullshark+commit-handler) ──────────────────────

function makeNode(nodeId, kp, registered, committeeIds, bus, rejections) {
  const dag = initDAG({ dbPath: ":memory:" });
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
  const committee = [...committeeIds].sort();
  const getCommittee = () => committee;
  const network = bus.adapterFor(nodeId);

  const bullshark = createBullshark({
    dag,
    getNodeIds: getCommittee,
    onMissingCertsTimeout: () => { },
    onOrderedTxs: (orderedTxs, round, certTimestamp) => {
      const res = commitHandler.commitOrderedTxs(orderedTxs, round, { certTimestamp });
      // No-loss bookkeeping: an ordered tx that did NOT persist was explicitly
      // rejected by commit-handler (recorded, not silently lost).
      for (const t of orderedTxs) if (!dag.getTx(t.tx_id)) rejections.add(t.tx_id);
      return res;
    },
    proposer: {
      nodeId, nodePrivateKey: kp.privateKey, nodePublicKey: kp.publicKey,
      submitTx: (tx) => mempool.add(tx), coordinator: null,
    },
  });

  const narwhal = createNarwhal({
    dag, mempool, network, config,
    getNodeKey: (nId) => getNodeKey(dag, nId),
    getNodeCount: () => participants.getNodeCount(dag),
    getCommittee,
    onCommit: (certs, round) => bullshark.onRoundComplete(certs, round),
    onCertSaved: (cert) => { if (typeof bullshark.onCertSaved === "function") bullshark.onCertSaved(cert.hash); },
    onProducerPaused: (round, mr) => { if (typeof bullshark.tryRotationProposal === "function") bullshark.tryRotationProposal(round, mr); },
    isPeerDivergent: () => false,
    peerJoinState: () => "ready",
    divergentPeers: () => [],
  });

  network.handle(ACK, async ({ stream }) => {
    const chunks = [];
    for await (const chunk of stream.source) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    narwhal.handleIncomingAck(Buffer.concat(chunks));
    try { stream.close(); } catch (_e) { /* ignore */ }
  });
  bus.setTopicHandlers(nodeId, {
    [network.TOPICS.MEMPOOL]: (buf) => narwhal.handleIncomingBatch(buf),
    [network.TOPICS.CONSENSUS]: (buf) => narwhal.handleIncomingAck(buf),
    [network.TOPICS.CERTIFICATES]: (buf) => narwhal.handleIncomingCertificate(buf),
  });

  let _seq = 0;
  function submitTx(tx) {
    // Accept a prebuilt tx, or synthesize a minimal content-addressed one.
    const body = tx || {
      tx_type: "REGISTER_CONTENT", timestamp: T0, prev: [],
      data: { ctid: `tip://content/${nodeId}-${_seq}`, content_hash: shake256(`${nodeId}-${_seq}`), seq: _seq },
    };
    _seq += 1;
    if (!body.tx_id) body.tx_id = computeTxId(body);
    mempool.add(body);
    return body.tx_id;
  }

  return { nodeId, dag, mempool, narwhal, bullshark, commitHandler, submitTx };
}

// ── the cluster ────────────────────────────────────────────────────────────────

function createInProcessCluster({ nodeCount = 3, committeeSize = nodeCount } = {}) {
  // Virtual clock: tests enable jest fake timers; pin the system clock so the
  // BFT-time floor is satisfied and nowMs() advances deterministically.
  if (typeof jest !== "undefined" && jest.setSystemTime) jest.setSystemTime(T0);

  const bus = createBus();
  const rejections = new Set();
  const all = Array.from({ length: nodeCount }, (_, i) => {
    const kp = generateMLDSAKeypair();
    return { nodeId: `tip://node/n${i}`, ...kp };
  });
  const committeeIds = all.slice(0, committeeSize).map((m) => m.nodeId);
  const nodes = all.map((m) => makeNode(m.nodeId, m, all, committeeIds, bus, rejections));
  nodes.forEach((n) => n.narwhal.start());

  // Index helpers: setDelay accepts node indices or node-id strings.
  const idOf = (x) => (typeof x === "number" ? all[x].nodeId : x);

  async function tickRound() {
    bus.advanceTick();
    // Advance one round of virtual time so narwhal's scheduled _beginRound fires.
    await jest.advanceTimersByTimeAsync(CONSENSUS.ROUND_TIMEOUT_MS);
    await flush();
    await bus.drain();   // deliver this tick's messages + cascade (acks, certs, commits)
    await flush();
  }
  async function tickRounds(n) { for (let i = 0; i < n; i++) await tickRound(); }

  function stop() {
    nodes.forEach((n) => { try { n.narwhal.stop(); } catch (_e) { /* ignore */ } });
    nodes.forEach((n) => { try { if (n.dag.close) n.dag.close(); } catch (_e) { /* ignore */ } });
  }

  // Replay every certificate ever broadcast to a (rejoining) node, the test
  // standing in for peer-sync's cert-tail fetch. Idempotent: certs the node
  // already has are ignored; the missing tail gets processed.
  async function feedCertTail(x) {
    const node = nodes[typeof x === "number" ? x : all.findIndex((m) => m.nodeId === x)];
    for (const buf of bus.certBufs) { try { node.narwhal.handleIncomingCertificate(buf); } catch (_e) { /* ignore */ } }
    await flush();
  }

  return {
    nodes,
    tickRound,
    tickRounds,
    setDelay: (from, to, ticks) => bus.setDelay(idOf(from), idOf(to), ticks),
    partition: (x) => bus.partition(idOf(x)),
    heal: (x) => bus.heal(idOf(x)),
    feedCertTail,
    commitHandlerRejections: rejections,
    stop,
  };
}

module.exports = { createInProcessCluster };
