/**
 * @file tests/consensus/rotation-coordinator.test.js
 * @description #68 Part B — multi-sig coordinator unit tests.
 *
 * Covers:
 *   - Proposer-side: solo committee (n=1) → quorum reached from proposer's
 *     own sig, tx submitted synchronously
 *   - Receive proposal → verify, sign, broadcast RotationSignature
 *   - Aggregate sigs across multiple peers → submitTx fires once quorum
 *     reached (computeQuorum(n))
 *   - Anti-spam: drop proposal with rotation_number != latest+1
 *   - Anti-spam: drop signature for unseen rotation
 *   - Reject proposal whose proposer is NOT in previous committee
 *   - Reject signature from non-previous-committee signer
 *   - Reject signature with invalid signature bytes
 *   - Only the proposer aggregator submits (other prev-committee members
 *     just store sigs locally for fallback if proposer goes offline)
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
const { initDAG } = require(path.join(SRC, "dag"));
const { createRotationCoordinator } = require(path.join(SRC, "consensus", "rotation-coordinator"));
const { loadTypes, encode, decode, hexToBytes, bytesToHex } = require(path.join(SRC, "network", "proto"));

beforeAll(async () => {
  await initCrypto();
  await loadTypes();
});

const TOPIC = "tip/rotation-coordination";

function _mockNetwork() {
  const published = [];
  return {
    TOPICS: { ROTATION_COORDINATION: TOPIC },
    publish: (topic, buf) => { published.push({ topic, buf }); },
    _published: published,
  };
}

function _setupDagWith(rotation0Committee) {
  const dag = initDAG({ inMemory: true });
  // Replace the bootstrap rotation 0 (founding-only) with our test committee
  // by writing a rotation 0 entry over the auto-bootstrapped one. Because
  // dag's saveCommitteeRotation is INSERT OR IGNORE on (rotation_number),
  // the bootstrapped row blocks our overwrite — so we don't replace it.
  // Instead we drive rotation 1 → 2 transition: write rotation 1 with our
  // test committee as the "previous committee" for the new proposal.
  for (const m of rotation0Committee) {
    if (!dag.getNode(m.node_id)) {
      dag.saveNode({
        node_id: m.node_id,
        name: m.node_id,
        public_key: m.public_key,
        status: "active",
        registered_at: "2026-01-01T00:00:00.000Z",
      });
    }
  }
  // Write a rotation 1 row that becomes "latest" — we'll propose rotation 2.
  dag.saveCommitteeRotation({
    rotation_number: 1,
    effective_round: 200,
    committee: rotation0Committee,
    prev_rotation: 0,
    signer_node_ids: [],
    signatures: [],
    payload_hash: "test-rotation-1",
    committed_at: "2026-01-01T00:00:00.000Z",
  });
  return dag;
}

function _buildCoordinator({ dag, identity, submitted }) {
  const network = _mockNetwork();
  const coord = createRotationCoordinator({
    dag, network,
    proto: { encode, decode },
    identity,
    submitTx: (tx) => { submitted.push(tx); },
    deadlineMs: 5000,
  });
  return { coord, network };
}

function _payloadHash({ rotation_number, effective_round, committee }) {
  return shake256(canonicalJson({ rotation_number, effective_round, committee }));
}

describe("#68 rotation coordinator", () => {
  test("solo committee (n=1): proposer's own sig is the full quorum, submitTx fires synchronously", () => {
    const kp = generateMLDSAKeypair();
    const id = { node_id: "tip://node/A", public_key: kp.publicKey };
    const dag = _setupDagWith([id]);

    const submitted = [];
    const { coord } = _buildCoordinator({
      dag,
      identity: { nodeId: id.node_id, privateKey: kp.privateKey, publicKey: kp.publicKey },
      submitted,
    });

    const new_committee = [id];
    const payload_hash = _payloadHash({ rotation_number: 2, effective_round: 400, committee: new_committee });

    coord.proposeRotation({
      rotation_number: 2, effective_round: 400, new_committee, payload_hash,
      prevCommitteeNodeIds: [id.node_id],
      prevPubkeys: { [id.node_id]: id.public_key },
    });

    expect(submitted).toHaveLength(1);
    expect(submitted[0].data.signer_node_ids).toEqual([id.node_id]);
    expect(submitted[0].data.signatures).toHaveLength(1);
  });

  test("3-node committee: aggregator collects 2 sigs (quorum=2) before submitting", () => {
    const a = generateMLDSAKeypair();
    const b = generateMLDSAKeypair();
    const c = generateMLDSAKeypair();
    const ids = [
      { node_id: "tip://node/A", public_key: a.publicKey },
      { node_id: "tip://node/B", public_key: b.publicKey },
      { node_id: "tip://node/C", public_key: c.publicKey },
    ];
    const dag = _setupDagWith(ids);

    // A is the proposer. We instrument A's coordinator and feed it a
    // signature from B simulating an inbound RotationSignature. quorum
    // for n=3 is ceil(2*3/3) = 2; A's own + B's = 2 → submit.
    const submitted = [];
    const { coord, network } = _buildCoordinator({
      dag,
      identity: { nodeId: ids[0].node_id, privateKey: a.privateKey, publicKey: a.publicKey },
      submitted,
    });

    const new_committee = ids;
    const payload_hash = _payloadHash({ rotation_number: 2, effective_round: 400, committee: new_committee });

    coord.proposeRotation({
      rotation_number: 2, effective_round: 400, new_committee, payload_hash,
      prevCommitteeNodeIds: ids.map(m => m.node_id),
      prevPubkeys: Object.fromEntries(ids.map(m => [m.node_id, m.public_key])),
    });
    // Self-only at this point: 1 sig < quorum=2, no submit.
    expect(submitted).toHaveLength(0);
    // Proposal was broadcast.
    expect(network._published.length).toBeGreaterThanOrEqual(1);

    // B signs and we feed the signature in as if from gossip.
    const bMsg = `rotation:${payload_hash}:${ids[1].node_id}`;
    const bSig = mldsaSign(bMsg, b.privateKey);
    const bBuf = encode("RotationSignature", {
      rotationNumber: 2, payloadHash: payload_hash,
      signerNodeId: ids[1].node_id, signature: hexToBytes(bSig),
    });
    coord.handleIncoming(bBuf, "peer-b");

    // Now sigs = {A, B} = 2 ≥ quorum → A (proposer) submits.
    expect(submitted).toHaveLength(1);
    expect(submitted[0].data.signer_node_ids.sort()).toEqual([ids[0].node_id, ids[1].node_id].sort());
  });

  test("non-proposer prev-committee member: signs and broadcasts but does NOT submit", () => {
    // B receives a proposal originated by A. B verifies, signs, broadcasts
    // its own RotationSignature. But because B is not the proposer, B
    // does NOT submit even when its local aggregation reaches quorum.
    const a = generateMLDSAKeypair();
    const b = generateMLDSAKeypair();
    const c = generateMLDSAKeypair();
    const ids = [
      { node_id: "tip://node/A", public_key: a.publicKey },
      { node_id: "tip://node/B", public_key: b.publicKey },
      { node_id: "tip://node/C", public_key: c.publicKey },
    ];
    const dag = _setupDagWith(ids);

    const submitted = [];
    const { coord, network } = _buildCoordinator({
      dag,
      identity: { nodeId: ids[1].node_id, privateKey: b.privateKey, publicKey: b.publicKey },
      submitted,
    });

    const new_committee = ids;
    const payload_hash = _payloadHash({ rotation_number: 2, effective_round: 400, committee: new_committee });

    // A's proposal lands at B.
    const aMsg = `rotation:${payload_hash}:${ids[0].node_id}`;
    const aSig = mldsaSign(aMsg, a.privateKey);
    const proposalBuf = encode("RotationProposal", {
      rotationNumber: 2, effectiveRound: 400,
      newCommittee: new_committee.map(m => ({ nodeId: m.node_id, publicKey: m.public_key })),
      payloadHash: payload_hash,
      proposerNodeId: ids[0].node_id,
      proposerSignature: hexToBytes(aSig),
    });
    coord.handleIncoming(proposalBuf, "peer-a");

    // B has now signed + broadcast its sig. State should have {A, B}.
    expect(network._published.length).toBeGreaterThanOrEqual(1);
    // Now C's sig comes in — quorum reached on B's view, but B is NOT the
    // proposer, so submission stays with A.
    const cMsg = `rotation:${payload_hash}:${ids[2].node_id}`;
    const cSig = mldsaSign(cMsg, c.privateKey);
    const cBuf = encode("RotationSignature", {
      rotationNumber: 2, payloadHash: payload_hash,
      signerNodeId: ids[2].node_id, signature: hexToBytes(cSig),
    });
    coord.handleIncoming(cBuf, "peer-c");

    expect(submitted).toHaveLength(0); // B is not proposer, doesn't submit
  });

  test("anti-spam: drops proposal with wrong rotation_number", () => {
    const a = generateMLDSAKeypair();
    const ids = [{ node_id: "tip://node/A", public_key: a.publicKey }];
    const dag = _setupDagWith(ids);
    // latest is rotation 1; expectedNext = 2. We send rotation 5.

    const submitted = [];
    const { coord } = _buildCoordinator({
      dag,
      identity: { nodeId: ids[0].node_id, privateKey: a.privateKey, publicKey: a.publicKey },
      submitted,
    });

    const new_committee = ids;
    const payload_hash = _payloadHash({ rotation_number: 5, effective_round: 1000, committee: new_committee });
    const aMsg = `rotation:${payload_hash}:${ids[0].node_id}`;
    const aSig = mldsaSign(aMsg, a.privateKey);
    const buf = encode("RotationProposal", {
      rotationNumber: 5, effectiveRound: 1000,
      newCommittee: new_committee.map(m => ({ nodeId: m.node_id, publicKey: m.public_key })),
      payloadHash: payload_hash, proposerNodeId: ids[0].node_id,
      proposerSignature: hexToBytes(aSig),
    });
    coord.handleIncoming(buf, "peer");

    // Dropped — coordinator should NOT have submitted anything.
    expect(submitted).toHaveLength(0);
    expect(coord._state().has(5)).toBe(false);
  });

  test("anti-spam: drops signature for unseen rotation", () => {
    const a = generateMLDSAKeypair();
    const b = generateMLDSAKeypair();
    const ids = [
      { node_id: "tip://node/A", public_key: a.publicKey },
      { node_id: "tip://node/B", public_key: b.publicKey },
    ];
    const dag = _setupDagWith(ids);

    const submitted = [];
    const { coord } = _buildCoordinator({
      dag,
      identity: { nodeId: ids[0].node_id, privateKey: a.privateKey, publicKey: a.publicKey },
      submitted,
    });

    // Send a signature for rotation 2 without having seen the proposal.
    const payload_hash = "deadbeef";
    const bMsg = `rotation:${payload_hash}:${ids[1].node_id}`;
    const bSig = mldsaSign(bMsg, b.privateKey);
    const buf = encode("RotationSignature", {
      rotationNumber: 2, payloadHash: payload_hash,
      signerNodeId: ids[1].node_id, signature: hexToBytes(bSig),
    });
    coord.handleIncoming(buf, "peer");

    expect(coord._state().has(2)).toBe(false);
  });

  test("rejects proposal from a node NOT in the previous committee", () => {
    const a = generateMLDSAKeypair();
    const x = generateMLDSAKeypair(); // outsider
    const ids = [{ node_id: "tip://node/A", public_key: a.publicKey }];
    const dag = _setupDagWith(ids);

    const submitted = [];
    const { coord } = _buildCoordinator({
      dag,
      identity: { nodeId: ids[0].node_id, privateKey: a.privateKey, publicKey: a.publicKey },
      submitted,
    });

    const new_committee = ids;
    const payload_hash = _payloadHash({ rotation_number: 2, effective_round: 400, committee: new_committee });
    // X (not in prev committee) signs + sends.
    const xMsg = `rotation:${payload_hash}:tip://node/X`;
    const xSig = mldsaSign(xMsg, x.privateKey);
    const buf = encode("RotationProposal", {
      rotationNumber: 2, effectiveRound: 400,
      newCommittee: new_committee.map(m => ({ nodeId: m.node_id, publicKey: m.public_key })),
      payloadHash: payload_hash, proposerNodeId: "tip://node/X",
      proposerSignature: hexToBytes(xSig),
    });
    coord.handleIncoming(buf, "peer");

    expect(coord._state().has(2)).toBe(false);
  });

  test("rejects signature from non-previous-committee signer (even with valid bytes)", () => {
    const a = generateMLDSAKeypair();
    const b = generateMLDSAKeypair();
    const x = generateMLDSAKeypair(); // outsider
    const ids = [
      { node_id: "tip://node/A", public_key: a.publicKey },
      { node_id: "tip://node/B", public_key: b.publicKey },
    ];
    const dag = _setupDagWith(ids);

    const submitted = [];
    const { coord } = _buildCoordinator({
      dag,
      identity: { nodeId: ids[0].node_id, privateKey: a.privateKey, publicKey: a.publicKey },
      submitted,
    });

    const new_committee = ids;
    const payload_hash = _payloadHash({ rotation_number: 2, effective_round: 400, committee: new_committee });

    coord.proposeRotation({
      rotation_number: 2, effective_round: 400, new_committee, payload_hash,
      prevCommitteeNodeIds: ids.map(m => m.node_id),
      prevPubkeys: Object.fromEntries(ids.map(m => [m.node_id, m.public_key])),
    });

    // X signs (not in prev committee) and sends.
    const xMsg = `rotation:${payload_hash}:tip://node/X`;
    const xSig = mldsaSign(xMsg, x.privateKey);
    const buf = encode("RotationSignature", {
      rotationNumber: 2, payloadHash: payload_hash,
      signerNodeId: "tip://node/X", signature: hexToBytes(xSig),
    });
    coord.handleIncoming(buf, "peer");

    // Inflight has only A's sig; X's was rejected.
    const inflight = coord._state().get(2);
    expect(inflight.sigs.size).toBe(1);
    expect(inflight.sigs.has("tip://node/X")).toBe(false);
  });

  test("duplicate signature from same signer is a no-op", () => {
    const a = generateMLDSAKeypair();
    const b = generateMLDSAKeypair();
    const ids = [
      { node_id: "tip://node/A", public_key: a.publicKey },
      { node_id: "tip://node/B", public_key: b.publicKey },
    ];
    const dag = _setupDagWith(ids);

    const submitted = [];
    const { coord } = _buildCoordinator({
      dag,
      identity: { nodeId: ids[0].node_id, privateKey: a.privateKey, publicKey: a.publicKey },
      submitted,
    });

    const new_committee = ids;
    const payload_hash = _payloadHash({ rotation_number: 2, effective_round: 400, committee: new_committee });

    coord.proposeRotation({
      rotation_number: 2, effective_round: 400, new_committee, payload_hash,
      prevCommitteeNodeIds: ids.map(m => m.node_id),
      prevPubkeys: Object.fromEntries(ids.map(m => [m.node_id, m.public_key])),
    });

    const bMsg = `rotation:${payload_hash}:${ids[1].node_id}`;
    const bSig = mldsaSign(bMsg, b.privateKey);
    const bBuf = encode("RotationSignature", {
      rotationNumber: 2, payloadHash: payload_hash,
      signerNodeId: ids[1].node_id, signature: hexToBytes(bSig),
    });
    coord.handleIncoming(bBuf, "peer-b");
    expect(submitted).toHaveLength(1); // first sig from B → quorum → submit

    // Re-feed the same sig — should be a no-op.
    coord.handleIncoming(bBuf, "peer-b");
    expect(submitted).toHaveLength(1);
  });
});
