/**
 * @file tests/consensus/multinode-rotation.test.js
 * @description In-process multi-node committee-rotation tests.
 *
 * The critical safety property: a COMMITTEE_ROTATION tx must commit BEFORE the
 * epoch boundary. If it doesn't, the producer-pause gate (which refuses to
 * advance past a boundary whose rotation isn't in committee_history) trips and
 * the whole network halts intentionally. This is the class of halt observed in
 * a live 5-node / committee-4 federation.
 *
 * This file drives N real Narwhal+Bullshark nodes (with the real rotation
 * coordinator wired) over an in-memory bus, through a real epoch boundary, and
 * asserts the rotation lands in time so the network never halts.
 *
 * To make a boundary reachable in seconds (the real genesis uses a 100-commit
 * interval => 200-round epoch), a fresh module registry lets us re-init the
 * frozen ProtocolConstants singleton with a tiny rotation interval.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

// ── shrink the rotation interval so an epoch boundary lands in a few rounds ────
jest.resetModules();
const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));
// Epoch must exceed the rotation submit lead window (>= 20 rounds) so the
// rotation is proposed LATE in the epoch, after members have accumulated
// participation credits (a too-early proposal qualifies almost no one and the
// committee collapses). interval * 2 = 30-round epoch clears the 20-round lead.
const ROTATION_INTERVAL = 15;
const EPOCH_ROUNDS = ROTATION_INTERVAL * 2;   // EPOCH_LENGTH_ROUNDS = 30
const _pc = JSON.parse(JSON.stringify(getGenesisPayload().protocol_constants));
_pc.consensus.committee_rotation_interval_commits = ROTATION_INTERVAL;
// Lead window = max(20, lead_anchors * 3). The default lead_anchors is large
// (window would open at round 2, before any participation accrues -> committee
// collapses). Pin it small so the window opens at round 10 (= 30 - 20), after
// the committee has accumulated participation credits.
_pc.consensus.committee_rotation_submit_lead_anchors = 2;
// Low admission threshold so every active committee member qualifies within the
// shrunk epoch (production: 70% of 100 commits; here a couple of anchors).
_pc.consensus.committee_rotation_participation_pct_of_interval = 5;
PC.init(_pc);

// Requires AFTER the re-init so every module binds to the tiny-interval config.
const { initCrypto, generateMLDSAKeypair } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { createNarwhal } = require(path.join(SRC, "consensus", "narwhal"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createRotationCoordinator } = require(path.join(SRC, "consensus", "rotation-coordinator"));
const participants = require(path.join(SRC, "consensus", "participants"));
const { loadTypes, encode, decode } = require(path.join(SRC, "network", "proto"));

beforeAll(async () => { await initCrypto(); await loadTypes(); });

const T0 = 1767225600000;
const getNodeKey = (dag, nodeId) => (dag.getNode(nodeId)?.public_key || null);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function waitFor(predicate, { timeoutMs = 60000, intervalMs = 100 } = {}) {
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

// ── in-memory bus (fakes the libp2p surface, including rotation-coord stream) ──

function fakeStream(buf) {
  return {
    source: (async function* () { yield buf; })(),
    sink: async (it) => { for await (const _c of it) { /* drain */ } },
    close() { /* noop */ },
  };
}

function createNet() {
  const topicHandlers = new Map();
  const protoHandlers = new Map();
  const faults = [];
  const drop = (meta) => faults.some((f) => f(meta));

  function adapterFor(nodeId) {
    if (!protoHandlers.has(nodeId)) protoHandlers.set(nodeId, {});
    const TOPICS = { MEMPOOL: "mempool", CONSENSUS: "consensus", CERTIFICATES: "certificates" };
    const ACK = "/tip/consensus-ack/1.0.0";
    const ROTATION = "/tip/rotation-coord/1.0.0";
    const conn = () => ({ remotePeer: { toString: () => nodeId } });
    const deliver = (toId, protocol, buf) => {
      const handler = protoHandlers.get(toId)?.[protocol];
      if (handler) setImmediate(() => { try { handler({ stream: fakeStream(buf), connection: conn() }); } catch (_e) { /* ignore */ } });
    };

    return {
      TOPICS,
      CONSENSUS_ACK_PROTOCOL: ACK,
      CONSENSUS_ACK_REQUEST_PROTOCOL: "/tip/consensus-ack-request/1.0.0",
      ROTATION_COORD_PROTOCOL: ROTATION,
      publish(topic, buf) {
        for (const [otherId, h] of topicHandlers) {
          if (otherId === nodeId || drop({ from: nodeId, to: otherId, topic })) continue;
          const fn = h[topic];
          if (fn) setImmediate(() => { try { fn(buf); } catch (_e) { /* ignore */ } });
        }
        return Promise.resolve();
      },
      sendAckDirect(buf, toNodeId) {
        if (drop({ from: nodeId, to: toNodeId, kind: "ack" })) return Promise.resolve(false);
        if (!protoHandlers.get(toNodeId)?.[ACK]) return Promise.resolve(false);
        deliver(toNodeId, ACK, buf);
        return Promise.resolve(true);
      },
      broadcastToAuthorized(buf, protocol) {
        for (const [otherId] of protoHandlers) {
          if (otherId === nodeId || drop({ from: nodeId, to: otherId, protocol })) continue;
          deliver(otherId, protocol, buf);
        }
        return Promise.resolve();
      },
      handle(protocol, handler) { protoHandlers.get(nodeId)[protocol] = handler; return Promise.resolve(); },
      sendAckRequest: () => Promise.resolve(null),
      onPeerAuthorized: () => { },
    };
  }

  return {
    adapterFor,
    setTopicHandlers: (nodeId, h) => topicHandlers.set(nodeId, h),
    addFault: (f) => faults.push(f),
    removeFault: (f) => { const i = faults.indexOf(f); if (i >= 0) faults.splice(i, 1); },
  };
}

// ── rotation-aware node factory ────────────────────────────────────────────────
//
// Uses the REAL committee derivation (getActiveCommittee reads committee_history)
// and wires the REAL rotation coordinator, so a rotation actually flows through
// proposal -> 2f+1 sigs -> aggregated tx -> consensus -> committee_history.

async function makeRotationNode(nodeId, kp, registered, committee0, net) {
  const dag = initDAG({ dbPath: ":memory:" });
  for (const m of registered) {
    dag.saveNode({ node_id: m.nodeId, name: m.nodeId, public_key: m.publicKey, status: "active", registered_at: T0 });
  }
  // initDAG bootstraps a genesis founding node; it is always admitted via the
  // genesis exemption and would inflate the rotated committee. Deactivate any
  // node outside our test topology so the committee is exactly our N nodes.
  const mine = new Set(registered.map((m) => m.nodeId));
  for (const n of dag.getAllNodes()) {
    if (!mine.has(n.node_id)) dag.saveNode({ ...n, status: "inactive" });
  }
  // Seed rotation 0 (effective at round 0) so the real committee derivation has
  // a starting committee instead of falling back to the single genesis node.
  dag.saveCommitteeRotation({
    rotation_number: 0, effective_round: 0,
    committee: committee0.map((m) => ({ node_id: m.nodeId, public_key: m.publicKey })),
    prev_rotation: null, signer_node_ids: [], signatures: [], payload_hash: null,
  });

  const config = {
    nodeId, nodeRegisteredId: nodeId,
    nodePrivateKey: kp.privateKey, nodePublicKey: kp.publicKey,
  };
  const scoring = initScoring(dag, config);
  const mempool = createMempool(dag, { nodeId });
  const commitHandler = createCommitHandler({ dag, scoring, config, nodeId });
  const getCommittee = (round) => participants.getActiveCommittee(dag, round);
  const network = net.adapterFor(nodeId);

  const coordinator = createRotationCoordinator({
    dag, network, proto: { encode, decode },
    identity: { nodeId, privateKey: kp.privateKey, publicKey: kp.publicKey },
    submitTx: (tx) => mempool.add(tx),
  });

  const bullshark = createBullshark({
    dag,
    getNodeIds: getCommittee,
    onMissingCertsTimeout: () => { },
    onOrderedTxs: (orderedTxs, round, certTimestamp) =>
      commitHandler.commitOrderedTxs(orderedTxs, round, { certTimestamp }),
    proposer: {
      nodeId, nodePrivateKey: kp.privateKey, nodePublicKey: kp.publicKey,
      submitTx: (tx) => mempool.add(tx),
      coordinator,
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

  network.handle(network.CONSENSUS_ACK_PROTOCOL, async ({ stream }) => {
    const chunks = [];
    for await (const chunk of stream.source) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    narwhal.handleIncomingAck(Buffer.concat(chunks));
    try { stream.close(); } catch (_e) { /* ignore */ }
  });
  await coordinator.registerProtocol();

  net.setTopicHandlers(nodeId, {
    [network.TOPICS.MEMPOOL]: (buf) => narwhal.handleIncomingBatch(buf),
    [network.TOPICS.CONSENSUS]: (buf) => narwhal.handleIncomingAck(buf),
    [network.TOPICS.CERTIFICATES]: (buf) => narwhal.handleIncomingCertificate(buf),
  });

  return { nodeId, dag, mempool, narwhal, bullshark, coordinator, config };
}

async function bootRotationCommittee(net, { registered, committee = registered } = {}) {
  const all = Array.from({ length: registered }, (_, i) => {
    const kp = generateMLDSAKeypair();
    return { nodeId: `tip://node/n${i}`, ...kp };
  });
  const committee0 = all.slice(0, committee);
  const committeeSet = new Set(committee0.map((m) => m.nodeId));
  const nodes = [];
  for (const m of all) nodes.push(await makeRotationNode(m.nodeId, m, all, committee0, net));
  nodes.forEach((n) => { n.isCommittee = committeeSet.has(n.nodeId); });
  nodes.forEach((n) => n.narwhal.start());
  return nodes;
}

function stopAll(nodes) {
  nodes.forEach((n) => { try { n.narwhal.stop(); } catch (_e) { /* ignore */ } });
  nodes.forEach((n) => { try { if (n.coordinator && n.coordinator.stop) n.coordinator.stop(); } catch (_e) { /* ignore */ } });
  nodes.forEach((n) => { try { if (n.dag.close) n.dag.close(); } catch (_e) { /* ignore */ } });
}

// ── the core property: rotation lands before the boundary, no halt ─────────────

describe("multi-node consensus harness, committee rotation", () => {
  // The real question behind the live incident: left to run NORMALLY (no fault
  // injection, nothing dropped), does the actual consensus halt itself at a
  // rotation boundary because the rotation tx didn't commit in time?
  //
  // Production topology: 5 nodes registered, committee of 4 (quorum 3). Drive the
  // real system through one or more epoch boundaries and assert:
  //   - it never freezes at a boundary (the producer-pause gate halts AT the
  //     boundary if that rotation isn't in committee_history; advancing past it
  //     proves the rotation landed in time, a timeout here IS the halt),
  //   - each rotation is effective exactly at its boundary, and
  //   - the 5th node is admitted at the first rotation, growing the committee 4->5.
  //
  // Default is one boundary for a fast CI run; set TIP_ROTATION_EPOCHS to cross
  // more (the docker soak does the long, real-network version).
  test("real system rotates across boundaries with no self-inflicted halt; committee grows 4 -> 5 (5 nodes, committee 4)", async () => {
    const EPOCHS = Number(process.env.TIP_ROTATION_EPOCHS || 1);
    const net = createNet();
    const nodes = await bootRotationCommittee(net, { registered: 5, committee: 4 });
    const target = EPOCH_ROUNDS * EPOCHS + 2;
    try {
      await waitFor(() => nodes.every((n) => n.bullshark.lastCommittedRound() > target), { timeoutMs: 220000 });
      for (const n of nodes) {
        expect(n.bullshark.lastCommittedRound()).toBeGreaterThan(target);
        for (let r = 1; r <= EPOCHS; r++) {
          const rot = n.dag.getCommitteeRotation(r);
          expect(rot).toBeTruthy();                           // rotation r committed in time
          expect(rot.effective_round).toBe(EPOCH_ROUNDS * r); // effective at its boundary
        }
        // The 5th node qualified by participation at the first rotation.
        expect(n.dag.getCommitteeRotation(1).committee.length).toBe(5);
      }
    } finally {
      stopAll(nodes);
    }
  }, 260000);

  // Regression for the premature-quorum bug: a single-member committee admitting
  // a second node. The 1->2 rotation commits, then _getQuorum() must stay 1 until
  // the rotation's effective_round (not jump to 2 the instant it commits), or the
  // lone producer starves on a 2nd ack that no active member can give. With the
  // round-aware _getQuorum fix this grows cleanly; without it, it stalls ~1 round
  // after the rotation commits.
  test("single-member committee grows 1 -> 2 cleanly (premature-quorum regression)", async () => {
    const net = createNet();
    const nodes = await bootRotationCommittee(net, { registered: 2, committee: 1 });
    const target = EPOCH_ROUNDS + 2; // just past the first boundary (rotation effective)
    try {
      await waitFor(() => nodes.every((n) => n.bullshark.lastCommittedRound() > target), { timeoutMs: 90000 });
      for (const n of nodes) expect(n.bullshark.lastCommittedRound()).toBeGreaterThan(target);
      const rot1 = nodes[0].dag.getCommitteeRotation(1);
      expect(rot1).toBeTruthy();              // rotation 1 committed
      expect(rot1.committee.length).toBe(2);  // committee actually grew 1 -> 2
    } finally {
      stopAll(nodes);
    }
  }, 110000);
});
