/**
 * @file tests/consensus/rotation-deadlock-recovery.test.js
 * @description Regression guard for rotation-coordinator self-recovery from a
 * boundary halt (the live incident that needed a manual restart).
 *
 * Root cause: when a rotation aggregation fails to reach 2f+1 before its
 * deadline, the coordinator re-broadcast the SAME stale proposal forever and
 * never rebuilt a fresh one, and nothing in consensus drove `pruneExpired`. A
 * wedged aggregation therefore persisted with no path to a fresh attempt.
 *
 * The fix is two-sided and this file pins both halves:
 *   1. coordinator.proposeRotation rebuilds a fresh aggregation (new deadline,
 *      proposer-only sigs) once the in-flight is past its deadline, instead of
 *      re-broadcasting the stale one.
 *   2. bullshark.tryRotationProposal (the producer-pause retry that fires on
 *      every stuck node) drives coordinator.pruneExpired before re-proposing.
 *
 * Layer note: the guard is at the coordinator/wiring layer, NOT a multi-node
 * "drop the proposer, assert recovery" sim. In the clean in-process harness
 * that scenario recovers even WITHOUT the fix: _onProposal merges other
 * proposers' sigs into an existing in-flight regardless of deadline, and
 * _maybeSubmit has no deadline gate, so cross-proposer merging reaches quorum
 * on its own. The genuine permanent wedge needs payload-hash divergence under
 * real network loss, which is the docker soak's job. A green-without-the-fix
 * sim would be a false guard, so we pin the load-bearing lines here instead.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, mldsaSign, shake256, canonicalJson,
} = require(path.join(SHARED, "crypto"));
const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { createRotationCoordinator } = require(path.join(SRC, "consensus", "rotation-coordinator"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));
const { loadTypes, encode, decode, hexToBytes } = require(path.join(SRC, "network", "proto"));

beforeAll(async () => { await initCrypto(); await loadTypes(); });
beforeEach(() => jest.useFakeTimers({ doNotFake: ["setImmediate", "queueMicrotask", "nextTick"] }));
afterEach(() => jest.useRealTimers());

const T0 = 1767225600000; // 2026-01-01, clears the BFT-time floor

function mockNetwork() {
  const published = [];
  return { publish: (topic, buf) => { published.push({ topic, buf }); }, _published: published };
}

function makeCommittee(n) {
  return Array.from({ length: n }, (_, i) => {
    const kp = generateMLDSAKeypair();
    return { node_id: `tip://node/n${i}`, public_key: kp.publicKey, privateKey: kp.privateKey };
  });
}

function proposalArgs(committee, { rotation_number = 1, effective_round = 30 } = {}) {
  const new_committee = committee.map((m) => ({ node_id: m.node_id, public_key: m.public_key }));
  const payload_hash = shake256(canonicalJson({ rotation_number, effective_round, committee: new_committee }));
  return {
    rotation_number, effective_round, new_committee, payload_hash,
    prevCommitteeNodeIds: committee.map((m) => m.node_id),
    prevPubkeys: Object.fromEntries(committee.map((m) => [m.node_id, m.public_key])),
  };
}

// Feed a peer's RotationSignature in as if it arrived from gossip.
function feedSig(coord, args, signer) {
  const sig = mldsaSign(`rotation:${args.payload_hash}:${signer.node_id}`, signer.privateKey);
  const buf = encode("RotationCoordMessage", {
    signature: {
      rotationNumber: args.rotation_number, payloadHash: args.payload_hash,
      signerNodeId: signer.node_id, signature: hexToBytes(sig),
    },
  });
  coord.handleIncoming(buf, "peer");
}

describe("rotation-coordinator self-recovery", () => {
  test("an expired in-flight is rebuilt fresh on the next proposeRotation, not re-broadcast stale", () => {
    jest.setSystemTime(T0);
    const committee = makeCommittee(4); // quorum = 3
    const proposer = committee[0];
    const dag = initDAG({ inMemory: true });
    const coord = createRotationCoordinator({
      dag, network: mockNetwork(), proto: { encode, decode },
      identity: { nodeId: proposer.node_id, privateKey: proposer.privateKey, publicKey: proposer.public_key },
      submitTx: () => {}, deadlineMs: 1000,
    });
    try {
      const args = proposalArgs(committee);
      coord.proposeRotation(args);
      // One peer sig arrives but quorum (3) is never met before the deadline.
      feedSig(coord, args, committee[1]);
      const first = coord._state().get(args.rotation_number);
      expect(first.sigs.size).toBe(2);
      const firstDeadline = first.deadline;

      // The aggregation window closes without quorum (sigs lost mid-flight).
      jest.setSystemTime(firstDeadline + 1);

      // The producer-pause retry re-enters proposeRotation.
      coord.proposeRotation(args);
      const second = coord._state().get(args.rotation_number);

      // Fixed: a fresh aggregation (new deadline, sigs reset to proposer-only).
      // Pre-fix the stale entry was re-broadcast unchanged (same deadline, 2 sigs).
      expect(second.deadline).toBeGreaterThan(firstDeadline);
      expect(second.sigs.size).toBe(1);
    } finally {
      coord.stop();
    }
  });

  test("pruneExpired drops an expired unsubmitted aggregation and keeps a live one", () => {
    jest.setSystemTime(T0);
    const committee = makeCommittee(4);
    const dag = initDAG({ inMemory: true });
    const coord = createRotationCoordinator({
      dag, network: mockNetwork(), proto: { encode, decode },
      identity: { nodeId: committee[0].node_id, privateKey: committee[0].privateKey, publicKey: committee[0].public_key },
      submitTx: () => {}, deadlineMs: 1000,
    });
    try {
      const args = proposalArgs(committee);
      coord.proposeRotation(args);
      expect(coord._state().has(args.rotation_number)).toBe(true);

      jest.setSystemTime(T0 + 500);   // still within deadline
      coord.pruneExpired();
      expect(coord._state().has(args.rotation_number)).toBe(true);

      jest.setSystemTime(T0 + 1001);  // past deadline
      coord.pruneExpired();
      expect(coord._state().has(args.rotation_number)).toBe(false);
    } finally {
      coord.stop();
    }
  });

  test("bullshark.tryRotationProposal drives coordinator.pruneExpired before re-proposing", () => {
    jest.setSystemTime(T0);
    const kp = generateMLDSAKeypair();
    const dag = initDAG({ inMemory: true }); // auto-bootstraps rotation 0 → latest = 0
    let pruneCalls = 0;
    const coordinator = { proposeRotation: () => true, pruneExpired: () => { pruneCalls += 1; } };
    const bullshark = createBullshark({
      dag,
      getNodeIds: () => ["tip://node/n0"],
      onOrderedTxs: () => {},
      onMissingCertsTimeout: () => {},
      proposer: {
        nodeId: "tip://node/n0", nodePrivateKey: kp.privateKey, nodePublicKey: kp.publicKey,
        submitTx: () => {}, coordinator,
      },
    });

    // currentRound at epoch 1's boundary so epochOf(round) === missingRotation === 1 > latest 0.
    bullshark.tryRotationProposal(CONSENSUS.EPOCH_LENGTH_ROUNDS, 1);
    expect(pruneCalls).toBe(1);
  });

  test("a live in-flight is rebuilt when the recomputed committee changes, before the deadline", () => {
    jest.setSystemTime(T0);
    const committee = makeCommittee(4);
    const proposer = committee[0];
    const dag = initDAG({ inMemory: true });
    const coord = createRotationCoordinator({
      dag, network: mockNetwork(), proto: { encode, decode },
      identity: { nodeId: proposer.node_id, privateKey: proposer.privateKey, publicKey: proposer.public_key },
      submitTx: () => {}, deadlineMs: 30000,
    });
    try {
      const args1 = proposalArgs(committee);
      coord.proposeRotation(args1);
      feedSig(coord, args1, committee[1]);
      expect(coord._state().get(args1.rotation_number).sigs.size).toBe(2);

      // The DAG heals under us: the next committee now differs (a member dropped),
      // so bullshark recomputes a different payload_hash. Still well within deadline.
      jest.setSystemTime(T0 + 1000);
      const nextCommittee = committee.slice(0, 3).map((m) => ({ node_id: m.node_id, public_key: m.public_key }));
      const args2 = {
        ...args1,
        new_committee: nextCommittee,
        payload_hash: shake256(canonicalJson({
          rotation_number: args1.rotation_number, effective_round: args1.effective_round, committee: nextCommittee,
        })),
      };
      coord.proposeRotation(args2);
      const entry = coord._state().get(args1.rotation_number);

      // Fixed: rebuilt to the new committee (proposer-only sigs), not re-broadcast
      // stale. Deadline-only reuse would keep the old hash with 2 sigs.
      expect(entry.proposal.payload_hash).toBe(args2.payload_hash);
      expect(entry.sigs.size).toBe(1);
    } finally {
      coord.stop();
    }
  });

  test("a submitTx failure clears submittedAt so the next attempt re-submits (no 60s wedge)", () => {
    jest.setSystemTime(T0);
    const solo = makeCommittee(1); // quorum 1: the proposer's own sig submits immediately
    const proposer = solo[0];
    const dag = initDAG({ inMemory: true });
    let calls = 0;
    const submitTx = () => { calls += 1; if (calls === 1) throw new Error("mempool rejected"); };
    const coord = createRotationCoordinator({
      dag, network: mockNetwork(), proto: { encode, decode },
      identity: { nodeId: proposer.node_id, privateKey: proposer.privateKey, publicKey: proposer.public_key },
      submitTx, deadlineMs: 30000,
    });
    try {
      const args = proposalArgs(solo);
      coord.proposeRotation(args);            // reaches quorum, submitTx throws
      expect(calls).toBe(1);
      // Fixed: submittedAt rolled back, so the entry is not wedged as "submitted".
      expect(coord._state().get(args.rotation_number).submittedAt).toBeNull();

      // The next producer-pause retry re-submits, and this time it succeeds.
      coord.proposeRotation(args);
      expect(calls).toBe(2);
      expect(coord._state().get(args.rotation_number).submittedAt).not.toBeNull();
    } finally {
      coord.stop();
    }
  });
});
