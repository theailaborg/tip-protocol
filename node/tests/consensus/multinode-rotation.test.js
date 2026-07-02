/**
 * @file tests/consensus/multinode-rotation.test.js
 * @description In-process multi-node E2E of TIME-BASED committee rotation.
 *
 * Model under test (time-targeted, round-executed):
 *   - Trigger: at an anchor commit, bullshark proposes rotation latest+1 when
 *     epochIndexOfTime(anchorCertTs) > epochIndexOfTime(latest.committed_at).
 *   - Activation: effective_round = max(detectionRound + ACTIVATION_LEAD,
 *     latest.effective_round + 2). The OLD committee keeps producing until the
 *     cluster's round reaches it; production never pauses for a rotation.
 *   - Retry: the boundary condition stays true at every anchor until the
 *     rotation commits, so a lost proposal is re-fired organically.
 *
 * This file drives N real Narwhal+Bullshark nodes (real rotation coordinator,
 * real committee derivation) over an in-memory bus through real wall-clock
 * epoch boundaries. Nothing is forced: rotations must fire, aggregate, commit
 * and activate on their own.
 *
 * To make boundaries land in seconds, the frozen ProtocolConstants singleton
 * is re-inited with a small epoch duration + activation lead (Tier-2 genesis
 * keys), and the Tier-3 round cadence env knobs are shrunk for this file.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

// Tier-3 cadence knobs (per-node tunables, env-driven): shrink so a wall-clock
// epoch spans many rounds without waiting for the production 2s round pace.
// Saved/restored so later test files in the same worker see the real defaults.
const _envOverrides = {
  TIP_ROUND_TIMEOUT_MS: "400",
  TIP_BATCH_WAIT_MS: "50",
  TIP_ROTATION_COORD_REBROADCAST_INTERVAL_MS: "250",
};
const _envSaved = {};
for (const [k, v] of Object.entries(_envOverrides)) {
  _envSaved[k] = process.env[k];
  process.env[k] = v;
}
afterAll(() => {
  for (const [k, v] of Object.entries(_envSaved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

// Re-init the frozen ProtocolConstants with test-scale rotation epochs.
jest.resetModules();
const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));
// 6s epochs: long enough for participation accrual + activation inside one
// epoch, short enough that a boundary crossing lands within seconds.
const EPOCH_MS = 6000;
// Small activation lead so a rotation activates a couple seconds after its
// detection anchor (production: 200 rounds).
const LEAD_ROUNDS = 12;
const _pc = JSON.parse(JSON.stringify(getGenesisPayload().protocol_constants));
_pc.consensus.epoch_duration_ms = EPOCH_MS;
_pc.consensus.rotation_activation_lead_rounds = LEAD_ROUNDS;
// Low admission threshold (threshold = max(1, ceil(maxBuckets * pct/100)) on
// DISTINCT presence buckets) so every active node qualifies within a shrunk
// epoch. Production: 70.
_pc.consensus.committee_rotation_participation_pct_of_interval = 5;
PC.init(_pc);
const { CONSENSUS } = PC;

// Requires AFTER the re-init so every module binds to the test-scale config.
const { initCrypto, generateMLDSAKeypair, mldsaSign, shake256, canonicalJson } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createMempool } = require(path.join(SRC, "consensus", "mempool"));
const { createNarwhal } = require(path.join(SRC, "consensus", "narwhal"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createRotationCoordinator, buildRotationTx } = require(path.join(SRC, "consensus", "rotation-coordinator"));
const { computeQuorum } = require(path.join(SRC, "consensus", "certificate"));
const participants = require(path.join(SRC, "consensus", "participants"));
const { loadTypes, encode, decode } = require(path.join(SRC, "network", "proto"));

beforeAll(async () => { await initCrypto(); await loadTypes(); });

const T0 = 1767225600000;
const ROTATION_PROTO = "/tip/rotation-coord/1.0.0";
const getNodeKey = (dag, nodeId) => (dag.getNode(nodeId)?.public_key || null);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function waitFor(predicate, { timeoutMs = 60000, intervalMs = 100, label = "condition" } = {}) {
  return new Promise((resolve, reject) => {
    const start = nowMs();
    const tick = () => {
      let ok = false;
      try { ok = predicate(); } catch (_e) { ok = false; }
      if (ok) return resolve(true);
      if (nowMs() - start > timeoutMs) return reject(new Error(`waitFor timed out (${timeoutMs}ms): ${label}`));
      setTimeout(tick, intervalMs);
    };
    tick();
  });
}

// Rotation-0 seed timestamps (boundary detection compares epoch indices of the
// anchor cert timestamp vs the latest rotation's committed_at):
//   - seedForAccrual: committed_at in the current epoch, but bumped one epoch
//     forward when the next absolute boundary is closer than minAccrualMs, so
//     members accrue participation before the first rotation fires.
//   - seedOneEpochBack: the very first committed anchor already crosses a
//     boundary, so the rotation condition is live from round 2.
function seedForAccrual(minAccrualMs) {
  const now = nowMs();
  const dur = CONSENSUS.EPOCH_DURATION_MS;
  const untilNext = dur - ((now - CONSENSUS.BFT_TIME_GENESIS_MS) % dur);
  return untilNext >= minAccrualMs ? now : now + untilNext;
}
function seedOneEpochBack() {
  return nowMs() - CONSENSUS.EPOCH_DURATION_MS;
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
    const conn = () => ({ remotePeer: { toString: () => nodeId } });
    const deliver = (toId, protocol, buf) => {
      const handler = protoHandlers.get(toId)?.[protocol];
      if (handler) setImmediate(() => { try { handler({ stream: fakeStream(buf), connection: conn() }); } catch (_e) { /* ignore */ } });
    };

    const REPAIR = "/tip/rotation-repair/1.0.0";
    return {
      TOPICS,
      CONSENSUS_ACK_PROTOCOL: ACK,
      CONSENSUS_ACK_REQUEST_PROTOCOL: "/tip/consensus-ack-request/1.0.0",
      ROTATION_COORD_PROTOCOL: ROTATION_PROTO,
      ROTATION_REPAIR_PROTOCOL: REPAIR,
      // Request/response: the responder answers on the requester's stream, so
      // repair is not subject to the rotation-coord push faults.
      peers: () => [...protoHandlers.keys()].filter((id) => id !== nodeId),
      async openStream(peerId, protocol) {
        const handler = protoHandlers.get(peerId)?.[protocol];
        const responseChunks = [];
        return {
          sink: async (it) => {
            const parts = [];
            for await (const c of it) parts.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
            if (!handler) return;
            const serverStream = {
              source: (async function* () { yield Buffer.concat(parts); })(),
              sink: async (sit) => { for await (const sc of sit) responseChunks.push(Buffer.isBuffer(sc) ? sc : Buffer.from(sc)); },
              close: async () => { },
            };
            await handler({ stream: serverStream, connection: conn() });
          },
          source: (async function* () { for (const c of responseChunks) yield c; })(),
          close: async () => { },
        };
      },
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
// boundary detection -> proposal -> 2f+1 sigs -> aggregated tx -> consensus ->
// committee_history -> round-executed activation.

async function makeRotationNode(nodeId, kp, registered, committee0, net, { rotation0At }) {
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
  // a starting committee. committed_at is the epoch marker the first boundary
  // detection compares against; identical on every node so detection agrees.
  dag.saveCommitteeRotation({
    rotation_number: 0, effective_round: 0,
    committee: committee0.map((m) => ({ node_id: m.nodeId, public_key: m.publicKey })),
    prev_rotation: null, signer_node_ids: [], signatures: [], payload_hash: null,
    committed_at: rotation0At,
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
    dag, network, mempool, proto: { encode, decode },
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

async function bootRotationCommittee(net, { registered, committee = registered, rotation0At }) {
  const all = Array.from({ length: registered }, (_, i) => {
    const kp = generateMLDSAKeypair();
    return { nodeId: `tip://node/n${i}`, ...kp };
  });
  const committee0 = all.slice(0, committee);
  const committeeSet = new Set(committee0.map((m) => m.nodeId));
  const nodes = [];
  for (const m of all) nodes.push(await makeRotationNode(m.nodeId, m, all, committee0, net, { rotation0At }));
  nodes.forEach((n) => { n.isCommittee = committeeSet.has(n.nodeId); });
  nodes.forEach((n) => n.narwhal.start());
  return nodes;
}

function stopAll(nodes) {
  nodes.forEach((n) => { try { n.narwhal.stop(); } catch (_e) { /* ignore */ } });
  nodes.forEach((n) => { try { if (n.coordinator && n.coordinator.stop) n.coordinator.stop(); } catch (_e) { /* ignore */ } });
  nodes.forEach((n) => { try { if (n.dag.close) n.dag.close(); } catch (_e) { /* ignore */ } });
}

// ── the core property: organic time-boundary rotations, production never pauses ─

describe("multi-node consensus harness, time-based committee rotation", () => {
  // Production topology: 5 nodes registered, committee of 4 (quorum 3). Left to
  // run NORMALLY (no faults), the cluster must cross real epoch boundaries and:
  //   - fire exactly one rotation per crossed boundary (committed_at epoch
  //     indices strictly increase; a re-fire for the same boundary would break
  //     this),
  //   - keep producing through commit AND activation (production never pauses),
  //   - activate at effective_round with the lead + monotonicity rule,
  //   - admit the 5th node by participation at the first rotation (4 -> 5).
  test("rotations fire per epoch boundary, activate round-executed, committee grows 4 -> 5", async () => {
    const EPOCHS = Number(process.env.TIP_ROTATION_EPOCHS || 2);
    const net = createNet();
    // Seed the epoch marker so members accrue participation before the first
    // boundary; the crossing itself happens organically on the BFT clock.
    const nodes = await bootRotationCommittee(net, { registered: 5, committee: 4, rotation0At: seedForAccrual(3000) });
    try {
      let prev = nodes[0].dag.getCommitteeRotation(0);
      for (let r = 1; r <= EPOCHS; r++) {
        await waitFor(() => nodes.every((n) => !!n.dag.getCommitteeRotation(r)),
          { timeoutMs: 60000, label: `rotation ${r} committed on all nodes` });
        const rot = nodes[0].dag.getCommitteeRotation(r);

        // Identical BFT-committed record on every node.
        for (const n of nodes) {
          const own = n.dag.getCommitteeRotation(r);
          expect(own.payload_hash).toBe(rot.payload_hash);
          expect(own.effective_round).toBe(rot.effective_round);
          expect(own.committee.map((m) => m.node_id)).toEqual(rot.committee.map((m) => m.node_id));
        }

        // The 5th node qualified by participation at the first rotation and
        // every member re-attests thereafter.
        expect(rot.committee.map((m) => m.node_id)).toContain(nodes[4].nodeId);
        expect(rot.committee.length).toBe(5);

        // effective_round monotonicity + future activation.
        expect(rot.effective_round).toBeGreaterThanOrEqual(prev.effective_round + 2);
        // One rotation per boundary: each rotation commits in a strictly later
        // epoch than the previous one's marker.
        expect(participants.epochIndexOfTime(rot.committed_at))
          .toBeGreaterThan(participants.epochIndexOfTime(prev.committed_at));

        // Production continues from commit through activation and past it.
        await waitFor(() => nodes.every((n) => n.bullshark.lastCommittedRound() > rot.effective_round + 2),
          { timeoutMs: 60000, label: `cluster advanced past rotation ${r} activation (round ${rot.effective_round})` });
        prev = rot;
      }

      // Round-executed activation: the old committee held every round before
      // effective_round; the new one applies exactly at it.
      const rot1 = nodes[0].dag.getCommitteeRotation(1);
      for (const n of nodes) {
        const before = participants.getActiveCommittee(n.dag, rot1.effective_round - 1);
        const after = participants.getActiveCommittee(n.dag, rot1.effective_round);
        expect(before.length).toBe(4);
        expect(before).not.toContain(nodes[4].nodeId);
        expect(after.length).toBe(5);
        expect(after).toContain(nodes[4].nodeId);
      }
    } finally {
      stopAll(nodes);
    }
  }, 200000);

  // Regression for the premature-quorum bug: a single-member committee admitting
  // a second node (solo-committee bootstrap exception). Quorum must stay 1 from
  // the rotation's commit until its effective_round; if it jumped to 2 at commit
  // the lone producer would starve on a 2nd ack and never reach activation, so
  // the liveness wait below IS the regression assertion.
  test("single-member committee grows 1 -> 2 cleanly (premature-quorum regression)", async () => {
    const net = createNet();
    // Marker one epoch back: the first committed anchor crosses the boundary,
    // no participation needed (solo-mode admits all registered+active).
    const nodes = await bootRotationCommittee(net, { registered: 2, committee: 1, rotation0At: seedOneEpochBack() });
    try {
      await waitFor(() => nodes.every((n) => !!n.dag.getCommitteeRotation(1)),
        { timeoutMs: 60000, label: "rotation 1 committed on both nodes" });
      const rot1 = nodes[0].dag.getCommitteeRotation(1);
      expect(rot1.committee.length).toBe(2);  // solo bootstrap admitted the joiner

      await waitFor(() => nodes.every((n) => n.bullshark.lastCommittedRound() > rot1.effective_round + 2),
        { timeoutMs: 90000, label: `both nodes advanced past activation round ${rot1.effective_round}` });
      for (const n of nodes) {
        expect(participants.getActiveCommittee(n.dag, rot1.effective_round - 1)).toEqual([nodes[0].nodeId]);
        expect(participants.getActiveCommittee(n.dag, rot1.effective_round).length).toBe(2);
      }
    } finally {
      stopAll(nodes);
    }
  }, 150000);
});

// The natural wedge needs a rare sig-delay that can't be manufactured on demand,
// so we CONSTRUCT its exact 2-hold / 3-stuck state (drop all rotation-coord, drive
// to participation, inject the valid tx into 2 nodes) and assert pull-repair lets
// the 3 stuck nodes fetch the tx that only the holders built.
describe("surgical 2-hold / 3-stuck rotation-tx wedge", () => {
  // Build the deterministic, quorum-signed rotation-1 tx from the live committee
  // derivation + the nodes' own keys (signerCount = quorum of the prev committee).
  // effective_round mirrors the src formula (detection round + activation lead).
  function buildRotation1Tx(nodes, signerCount) {
    const dag0 = nodes[0].dag;
    const newCommittee = participants.computeNextRotationCommittee(dag0, 0); // finishing rotation 0
    // Tripwire: by the drive target every producer must have accrued distinct
    // presence buckets in rotation 0's tally. A shrink here means participation
    // attribution broke, not the repair path under test.
    expect(newCommittee.map((m) => m.node_id).sort()).toEqual(nodes.map((n) => n.nodeId).sort());
    const rotation_number = 1;
    const effective_round = nodes[0].bullshark.lastCommittedRound() + CONSENSUS.ROTATION_ACTIVATION_LEAD_ROUNDS;
    const payload_hash = shake256(canonicalJson({ rotation_number, effective_round, committee: newCommittee }));
    const keyByNodeId = new Map(nodes.map((n) => [n.nodeId, n.config.nodePrivateKey]));
    const signers = newCommittee.slice(0, signerCount).map((m) => m.node_id).sort();
    const signatures = signers.map((id) => mldsaSign(`rotation:${payload_hash}:${id}`, keyByNodeId.get(id)));
    return buildRotationTx(dag0, { rotation_number, effective_round, new_committee: newCommittee, payload_hash }, signers, signatures);
  }

  test("the 3 stuck nodes pull the assembled rotation tx from the 2 holders (repair) and cannot get it without (control)", async () => {
    const net = createNet();
    const nodes = await bootRotationCommittee(net, { registered: 5, committee: 5, rotation0At: seedForAccrual(3000) });
    net.addFault((meta) => meta.protocol === ROTATION_PROTO);
    try {
      // A handful of committed rounds give every member deterministic
      // participation in rotation 0's tally. All rotation-coord is dropped, so
      // no rotation can aggregate and latest stays 0.
      await waitFor(() => nodes.every((n) => n.bullshark.lastCommittedRound() >= 8),
        { timeoutMs: 90000, label: "participation accrual (round 8 on all nodes)" });
      // Freeze consensus so the injected wedge state is stable: narwhal would
      // otherwise drain the injected tx within a round, masking the repair path.
      nodes.forEach((n) => n.narwhal.stop());
      await sleep(500);

      // Construct the exact 2-hold / 3-stuck state: the valid quorum-signed
      // rotation-1 tx lives only in the 2 holders' mempools.
      const tx = buildRotation1Tx(nodes, computeQuorum(5)); // quorum(5) = 4 sigs
      const [h0, h1, s0, s1, s2] = nodes;
      h0.mempool.add(tx);
      h1.mempool.add(tx);

      // Control: without repair the 3 stuck nodes have no path to the tx.
      expect([h0, h1].every((n) => !!n.mempool.peekRotationTx(1))).toBe(true);
      expect([s0, s1, s2].every((n) => !n.mempool.peekRotationTx(1))).toBe(true);

      // Repair: each stuck node fetches the tx from a holder via the REAL serve
      // handler + committee/quorum validation across five coordinators, not a mock.
      for (const n of [s0, s1, s2]) {
        const ok = await n.coordinator.requestTxRepair();
        expect(ok).toBe(true);
      }

      // All five now hold the tx. The commit is ordinary consensus (the no-halt
      // tests above); the novel step is the stuck nodes OBTAINING it.
      expect(nodes.every((n) => !!n.mempool.peekRotationTx(1))).toBe(true);
      // The repaired tx is the same canonical rotation-1 tx (deterministic rebuild).
      for (const n of [s0, s1, s2]) {
        expect(Number(n.mempool.peekRotationTx(1).data.rotation_number)).toBe(1);
      }
    } finally {
      stopAll(nodes);
    }
  }, 240000);
});

// New-model liveness invariant (replaces the deleted producer-pause metric
// test): when rotation aggregation is completely blocked, the boundary
// condition re-fires at every anchor and the cluster keeps committing anchors
// indefinitely. Under the old model this exact scenario paused production at
// the boundary; production must now NEVER pause for an uncommitted rotation.
describe("blocked rotation aggregation: boundary re-fires, production continues", () => {
  test("cluster keeps committing anchors indefinitely while the rotation tx cannot aggregate", async () => {
    const net = createNet();
    // Marker one epoch back: the rotation condition is live from the first
    // anchor. All rotation-coord traffic is dropped, so quorum (4 of 5 prev
    // committee sigs) is unreachable and rotation 1 can never commit.
    const nodes = await bootRotationCommittee(net, { registered: 5, committee: 5, rotation0At: seedOneEpochBack() });
    net.addFault((meta) => meta.protocol === ROTATION_PROTO);
    const proposalsFired = () =>
      nodes.reduce((sum, n) => sum + n.bullshark.stats().metrics.committee_rotation_proposals, 0);
    try {
      // Re-fire: each committed anchor's leader proposes again (leaders rotate
      // round-robin), so cluster-wide proposals keep climbing for the SAME
      // stuck rotation while rounds keep advancing past the boundary.
      await waitFor(() => proposalsFired() >= 3 && nodes.every((n) => n.bullshark.lastCommittedRound() >= 8),
        { timeoutMs: 90000, label: ">=3 rotation proposals fired and round 8 reached with rotation stuck" });
      expect(nodes.every((n) => !n.dag.getCommitteeRotation(1))).toBe(true);

      // Indefinite continuation: from any point, the cluster commits several
      // more anchors while the rotation is still uncommitted. The old model's
      // producer pause would freeze rounds right here.
      const mark = Math.max(...nodes.map((n) => n.bullshark.lastCommittedRound()));
      const proposalsMark = proposalsFired();
      await waitFor(() => nodes.every((n) => n.bullshark.lastCommittedRound() > mark + 6),
        { timeoutMs: 60000, label: `rounds advanced ${mark} -> ${mark + 6}+ with rotation still blocked` });
      expect(nodes.every((n) => !n.dag.getCommitteeRotation(1))).toBe(true);
      // The boundary condition kept re-firing across those anchors too.
      expect(proposalsFired()).toBeGreaterThan(proposalsMark);
    } finally {
      stopAll(nodes);
    }
  }, 180000);
});
