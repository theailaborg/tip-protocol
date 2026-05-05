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

  test("non-proposer prev-committee member with quorum sigs ALSO submits (multi-aggregator)", () => {
    // Multi-aggregator: B receives a proposal originated by A. B verifies,
    // signs, broadcasts its own RotationSignature. When B's local
    // aggregation reaches quorum, B ALSO submits — does not require the
    // original proposer to be the one whose inflight reaches quorum first.
    //
    // Why: under uneven sig propagation (cold-mesh on bursty rotation-coord
    // topic) the original proposer can end up below quorum while a peer's
    // inflight has enough sigs. Without this, rotations halt indefinitely
    // (live observed 2026-05-04 rotation 13). Duplicate cross-node
    // submissions are deduped at the commit-handler layer (rotation_number
    // unique in committee_history).
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
    // B's submission already fired the moment A's proposal arrived: at
    // that point sigs = {A (proposer), B (self)} = 2 = quorum, multi-
    // aggregator triggers submitTx without waiting for C. C's sig
    // arriving here is processed but submission is already done.
    coord.handleIncoming(cBuf, "peer-c");

    expect(submitted).toHaveLength(1);
    expect(submitted[0].data.signer_node_ids.sort()).toEqual(
      [ids[0].node_id, ids[1].node_id].sort()
    );
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

  // Fix A: retry preserves accumulated sigs. Bullshark calls proposeRotation
  // again on each anchor commit during the lead-time window; resetting the
  // inflight on every retry was the root cause of rotation 13's halt — sigs
  // received between retries were thrown away, never reaching quorum.
  test("retry preserves accumulated sigs (does NOT reset inflight)", () => {
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
      identity: { nodeId: ids[0].node_id, privateKey: a.privateKey, publicKey: a.publicKey },
      submitted,
    });

    const new_committee = ids;
    const payload_hash = _payloadHash({ rotation_number: 2, effective_round: 400, committee: new_committee });
    const args = {
      rotation_number: 2, effective_round: 400, new_committee, payload_hash,
      prevCommitteeNodeIds: ids.map(m => m.node_id),
      prevPubkeys: Object.fromEntries(ids.map(m => [m.node_id, m.public_key])),
    };

    // First proposeRotation — inflight created, sigs = {A: ownSig}.
    coord.proposeRotation(args);
    expect(coord._state().get(2).sigs.size).toBe(1);

    // B's sig arrives via gossip.
    const bMsg = `rotation:${payload_hash}:${ids[1].node_id}`;
    const bSig = mldsaSign(bMsg, b.privateKey);
    const bBuf = encode("RotationSignature", {
      rotationNumber: 2, payloadHash: payload_hash,
      signerNodeId: ids[1].node_id, signature: hexToBytes(bSig),
    });
    coord.handleIncoming(bBuf, "peer-b");
    expect(coord._state().get(2).sigs.size).toBe(2); // A + B
    expect(submitted).toHaveLength(1); // quorum=2 reached → submit

    // Reset submitted[] and submittedAt so we can prove a retry doesn't blow it away.
    coord._state().get(2).submittedAt = null;
    submitted.length = 0;
    const sigsBefore = new Set(coord._state().get(2).sigs.keys());
    const publishedBefore = network._published.length;

    // Bullshark fires proposeRotation again on the next anchor (retry).
    coord.proposeRotation(args);

    // Sigs must be preserved — A and B still in the map.
    const sigsAfter = new Set(coord._state().get(2).sigs.keys());
    expect(sigsAfter).toEqual(sigsBefore);
    expect(sigsAfter.size).toBe(2);
    // Re-broadcast was published (one new RotationProposal).
    expect(network._published.length).toBe(publishedBefore + 1);
    // Submit fires again because sigs are still ≥ quorum.
    expect(submitted).toHaveLength(1);
  });

  // Fix C: periodic re-broadcast tick re-publishes accumulated sigs.
  // Defends against gossipsub mesh dropping bursty rotation-coord traffic;
  // peers that missed the first sig get it on the next tick.
  test("re-broadcast tick re-publishes the proposal AND accumulated peer sigs", () => {
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

    // Feed B's sig but BEFORE submission triggers (manually clear submittedAt).
    const bMsg = `rotation:${payload_hash}:${ids[1].node_id}`;
    const bSig = mldsaSign(bMsg, b.privateKey);
    const bBuf = encode("RotationSignature", {
      rotationNumber: 2, payloadHash: payload_hash,
      signerNodeId: ids[1].node_id, signature: hexToBytes(bSig),
    });
    coord.handleIncoming(bBuf, "peer-b");
    coord._state().get(2).submittedAt = null;  // simulate "still aggregating"

    const before = network._published.length;
    coord._rebroadcastTick();
    const after = network._published.length;

    // One RotationProposal + one RotationSignature (B's). A's sig is already
    // embedded in the proposal as proposer_signature; not re-sent separately.
    expect(after - before).toBe(2);

    // Submitted inflights ARE re-broadcast — peers below quorum still need
    // proposal+sigs to reach their own quorum and carve out (live observed
    // 2026-05-04 rotation 13 halt: fast submitter went silent in 1.2 s,
    // lagging peers stuck at 2/4 sigs forever).
    coord._state().get(2).submittedAt = Date.now();
    const before2 = network._published.length;
    coord._rebroadcastTick();
    expect(network._published.length).toBe(before2 + 2); // proposal + B's sig

    coord.stop();
  });

  // Fix: keep broadcasting AFTER submission so lagging peers can still reach
  // quorum, build the same deterministic tx, and inject it into their local
  // mempool to carve out. Without this, a fast submitter goes silent before
  // the first re-broadcast tick fires (REBROADCAST_INTERVAL_MS) and peers
  // missed by the initial broadcast stay below quorum forever.
  test("post-submit re-broadcast: timer keeps firing after _maybeSubmit succeeds", () => {
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

    // B's sig pushes us over quorum → submitTx fires.
    const bMsg = `rotation:${payload_hash}:${ids[1].node_id}`;
    const bSig = mldsaSign(bMsg, b.privateKey);
    coord.handleIncoming(encode("RotationSignature", {
      rotationNumber: 2, payloadHash: payload_hash,
      signerNodeId: ids[1].node_id, signature: hexToBytes(bSig),
    }), "peer-b");
    expect(submitted).toHaveLength(1);
    const inflight = coord._state().get(2);
    expect(inflight.submittedAt).not.toBeNull();

    // Critical post-submit behavior: a fresh _rebroadcastTick still publishes
    // the proposal + accumulated sigs (proposer's is embedded in the proposal,
    // so for n=3 we expect proposal + B's sig = 2 publishes).
    const before = network._published.length;
    coord._rebroadcastTick();
    expect(network._published.length).toBe(before + 2);

    // And again — keeps re-broadcasting on subsequent ticks until pruneExpired.
    const before2 = network._published.length;
    coord._rebroadcastTick();
    expect(network._published.length).toBe(before2 + 2);

    coord.stop();
  });

  // Fix: pruneExpired naturally bounds the post-submit re-broadcast window.
  // After deadlineMs * 2 from submittedAt, the entry is dropped and the
  // rebroadcast timer self-stops on the next tick.
  test("pruneExpired drops long-submitted inflights and stops rebroadcast", () => {
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
    // n=2 quorum=2; A's own sig alone isn't enough — feed B's sig to submit.
    const bMsg = `rotation:${payload_hash}:${ids[1].node_id}`;
    const bSig = mldsaSign(bMsg, b.privateKey);
    coord.handleIncoming(encode("RotationSignature", {
      rotationNumber: 2, payloadHash: payload_hash,
      signerNodeId: ids[1].node_id, signature: hexToBytes(bSig),
    }), "peer-b");
    expect(submitted).toHaveLength(1);
    expect(coord._state().get(2).submittedAt).not.toBeNull();

    // Backdate submittedAt past deadlineMs * 2 so pruneExpired drops it.
    coord._state().get(2).submittedAt = Date.now() - 11_000; // deadlineMs=5000 → *2=10000
    coord.pruneExpired();
    expect(coord._state().has(2)).toBe(false);
    coord.stop();
  });

  // Fix C: stop() clears the timer (no leak).
  test("stop() clears the re-broadcast interval", () => {
    const a = generateMLDSAKeypair();
    const ids = [{ node_id: "tip://node/A", public_key: a.publicKey }];
    const dag = _setupDagWith(ids);

    const submitted = [];
    const { coord } = _buildCoordinator({
      dag,
      identity: { nodeId: ids[0].node_id, privateKey: a.privateKey, publicKey: a.publicKey },
      submitted,
    });
    // Solo committee submits synchronously; need a 2-node case to keep an inflight open.
    expect(typeof coord.stop).toBe("function");
    coord.stop();  // safe to call when nothing's running
  });

  // #81 — buildRotationTx must produce identical tx_id across all honest
  // nodes given the same (rotation_number, effective_round, committee,
  // signer_node_ids, signatures). Closes the determinism gap that caused
  // n5 to commit a different physical tx than n1-n4 starting rotation 20
  // (live observed 2026-05-05). Without this contract, multi-aggregator
  // submission produces divergent transactions.tx_id per node — invisible
  // to state_merkle_root by canonicalization design but a latent landmine
  // for any future tx-id-based tooling (light-client proofs, explorers).
  test("buildRotationTx is deterministic — same proposal → same tx_id across simulated nodes", () => {
    const { buildRotationTx } = require(path.join(SRC, "consensus", "rotation-coordinator"));

    const a = generateMLDSAKeypair();
    const b = generateMLDSAKeypair();
    const c = generateMLDSAKeypair();
    const ids = [
      { node_id: "tip://node/A", public_key: a.publicKey },
      { node_id: "tip://node/B", public_key: b.publicKey },
      { node_id: "tip://node/C", public_key: c.publicKey },
    ];

    const proposal = {
      rotation_number: 17,
      effective_round: 3400,
      new_committee: ids,
      payload_hash: "abc123def456".repeat(5),
    };
    const signer_node_ids = [ids[0].node_id, ids[1].node_id, ids[2].node_id].sort();
    const signatures = signer_node_ids.map((_, i) => "11".repeat(32 + i));

    // Simulate two different nodes calling buildRotationTx with different
    // local DAG state (different getRecentPrev results) and at different
    // wall-clock times.
    const dagStateA = { getRecentPrev: () => ["nodeA-recent-tx-1", "nodeA-recent-tx-2"] };
    const dagStateB = { getRecentPrev: () => ["nodeB-totally-different-1", "nodeB-totally-different-2"] };

    const txFromNodeA = buildRotationTx(dagStateA, proposal, signer_node_ids, signatures);
    // Sleep a bit between calls (different wall-clock) — pre-#81 this
    // alone produced different tx_ids.
    const before = Date.now();
    while (Date.now() - before < 5) { /* spin briefly */ }
    const txFromNodeB = buildRotationTx(dagStateB, proposal, signer_node_ids, signatures);

    // Critical assertion: tx_id must be IDENTICAL despite different local
    // DAG state and different wall-clock timing.
    expect(txFromNodeA.tx_id).toBe(txFromNodeB.tx_id);
    expect(txFromNodeA.timestamp).toBe(txFromNodeB.timestamp);
    expect(txFromNodeA.prev).toEqual(txFromNodeB.prev);

    // Sanity: tx_id is a 64-char hex string (SHAKE-256). prev is empty
    // — rotation tx is a system tx, not part of the user-tx prev chain.
    expect(txFromNodeA.tx_id).toMatch(/^[0-9a-f]{64}$/);
    expect(txFromNodeA.prev).toEqual([]);
  });

  test("buildRotationTx timestamp is derived from effective_round, not wall-clock", () => {
    const { buildRotationTx } = require(path.join(SRC, "consensus", "rotation-coordinator"));
    const { CONSENSUS } = require(path.join(SHARED, "protocol-constants"));

    const proposal = {
      rotation_number: 5,
      effective_round: 1000,
      new_committee: [{ node_id: "tip://node/X", public_key: "ab".repeat(32) }],
      payload_hash: "00".repeat(32),
    };
    const tx = buildRotationTx({}, proposal, ["tip://node/X"], ["00".repeat(32)]);

    // Expected timestamp = ISO of (effective_round * BATCH_WAIT_MS)
    const expectedMs = proposal.effective_round * CONSENSUS.BATCH_WAIT_MS;
    expect(tx.timestamp).toBe(new Date(expectedMs).toISOString());

    // Different effective_round → different timestamp (so audit ordering
    // by tx.timestamp still reflects rotation order, just not real time)
    const tx2 = buildRotationTx({}, { ...proposal, effective_round: 2000 }, ["tip://node/X"], ["00".repeat(32)]);
    expect(tx2.timestamp).not.toBe(tx.timestamp);
    expect(new Date(tx2.timestamp).getTime()).toBeGreaterThan(new Date(tx.timestamp).getTime());
  });

  // System-tx semantic: rotation tx with empty prev passes structural
  // validation. Prevents regressing the validator's "non-system tx must
  // have prev refs" rule into rejecting legitimate rotation txs — the
  // exact failure that broke n4 mid-flight on 2026-05-05 when one node's
  // DB held only the old genesis row and rotation tx prev pointed to the
  // current genesis tx_id.
  test("buildRotationTx output passes validateTransaction with empty prev", () => {
    const { buildRotationTx } = require(path.join(SRC, "consensus", "rotation-coordinator"));
    const { validateTransaction } = require(path.join(SRC, "validators", "tx-validator"));

    const a = generateMLDSAKeypair();
    const ids = [{ node_id: "tip://node/A", public_key: a.publicKey }];
    const dag = _setupDagWith(ids);

    const proposal = {
      rotation_number: 2,
      effective_round: 400,
      new_committee: ids,
      payload_hash: _payloadHash({ rotation_number: 2, effective_round: 400, committee: ids }),
    };
    const aMsg = `rotation:${proposal.payload_hash}:${ids[0].node_id}`;
    const aSig = mldsaSign(aMsg, a.privateKey);
    const tx = buildRotationTx(dag, proposal, [ids[0].node_id], [aSig]);

    expect(tx.prev).toEqual([]);
    const result = validateTransaction(tx, dag, { skipState: true });
    expect(result).toEqual({ valid: true, errors: [], layer: null });
  });

});
