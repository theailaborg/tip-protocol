/**
 * @file tests/consensus/bullshark-rotation-proposer.test.js
 * @description Tests for the time-based epoch-boundary rotation proposer.
 *
 * Rotation model (time-targeted, round-executed):
 *   - Boundary trigger: in the anchor-commit path, rotation latest+1 is
 *     proposed when epochIndexOfTime(anchorCertTs) >
 *     epochIndexOfTime(latestRotation.committed_at), where
 *     epochIndexOfTime(T) = floor((T - BFT_TIME_GENESIS_MS) / EPOCH_DURATION_MS).
 *   - effective_round = max(voteRound + ROTATION_ACTIVATION_LEAD_ROUNDS,
 *     latest.effective_round + 2).
 *   - Participation is tallied per (node, rotation, presence bucket);
 *     admission needs >= ceil(maxBuckets * PCT / 100) DISTINCT buckets.
 *   - Cert participation is attributed to the rotation active at cert.round
 *     (committee_history lookup), not to local replay state.
 *
 * Test pattern: pin the latest rotation's committed_at to an epoch-aligned
 * marker, then commit ONE anchor whose cert timestamp is either inside the
 * marker's epoch (no proposal) or one EPOCH_DURATION_MS later (proposal).
 * Anchor timestamps respect the BFT-time strict-monotonicity gate.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256, canonicalJson } = require(SHARED + "/crypto");
const { TX_TYPES } = require(SHARED + "/constants");
const { CONSENSUS } = require(SHARED + "/protocol-constants");
const { initDAG } = require(path.join(SRC, "dag"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));
const { getGenesisPayload, getGenesisCommittee } = require(path.join(SRC, "genesis"));

beforeAll(async () => { await initCrypto(); });

const FOUNDING = getGenesisPayload().founding_nodes[0];
const GENESIS_IDS = [...getGenesisCommittee()].sort();

const GEN = CONSENSUS.BFT_TIME_GENESIS_MS;
const EPOCH = CONSENSUS.EPOCH_DURATION_MS;
const LEAD = CONSENSUS.ROTATION_ACTIVATION_LEAD_ROUNDS;
const BUCKETS = CONSENSUS.EPOCH_PARTICIPATION_BUCKETS;
const PCT = CONSENSUS.COMMITTEE_ROTATION_PARTICIPATION_PCT_OF_INTERVAL;
// Admission bar when the best-observed node covers all buckets.
const THRESHOLD = Math.max(1, Math.ceil((BUCKETS * PCT) / 100));

// Epoch-aligned marker for the latest rotation's committed_at. Certs default
// to timestamps inside this epoch; boundary tests pass a next-epoch ts.
const MARKER = GEN + 1000 * EPOCH;
const SAME_EPOCH_TS = (round) => MARKER + round * 20;
const NEXT_EPOCH_TS = (round) => MARKER + EPOCH + round * 20;

function _buildCert({ round, author, hash, ts }) {
  const t = ts ?? SAME_EPOCH_TS(round);
  return {
    hash: hash || shake256(`cert-${round}-${author}`),
    round,
    author_node_id: author,
    timestamp: t,
    signature: "00",
    batch: { txs: [], hash: shake256(`batch-${round}-${author}`) },
    parent_hashes: [],
    acknowledgments: [
      { acker_node_id: author, signature: "00", signed_at: t },
    ],
  };
}

/**
 * Fresh in-memory DAG + bullshark. Registers every genesis founding node and
 * pins rotation 0's committed_at to MARKER so tests control epoch crossing
 * purely via anchor cert timestamps.
 */
function _setup({ withProposer = true, nodeIds, submitTx } = {}) {
  const dag = initDAG({ inMemory: true });

  for (const f of getGenesisPayload().founding_nodes) {
    if (!dag.getNode(f.node_id)) {
      dag.saveNode({
        node_id: f.node_id, name: "founding", public_key: f.public_key,
        status: "active", registered_at: GEN,
      });
    }
  }

  const rot0 = dag.getCommitteeRotation(0);
  dag.saveCommitteeRotation({ ...rot0, committed_at: MARKER });

  const submittedTxs = [];
  const proposer = withProposer ? {
    nodeId: FOUNDING.node_id,
    nodePrivateKey: generateMLDSAKeypair().privateKey,
    nodePublicKey: FOUNDING.public_key,
    submitTx: submitTx || ((tx) => {
      submittedTxs.push(tx);
      return { tx_id: tx.tx_id };
    }),
  } : null;

  const committee = [...(nodeIds || [FOUNDING.node_id])].sort();
  const bullshark = createBullshark({
    dag,
    getNodeIds: () => committee,
    onOrderedTxs: () => {},
    proposer,
  });

  return { dag, bullshark, submittedTxs };
}

/**
 * Drive an anchor commit: seed propose+vote certs, call onRoundComplete.
 * anchorTs sets the propose (anchor) cert timestamp, the boundary input.
 */
function _driveAnchorCommit(dag, bullshark, { proposeRound, voteRound, leader, voteAuthors, anchorTs }) {
  const proposeCert = _buildCert({ round: proposeRound, author: leader, ts: anchorTs });
  dag.saveCertificate(proposeCert);

  const voteCerts = voteAuthors.map(author => _buildCert({
    round: voteRound,
    author,
    hash: shake256(`vc-${voteRound}-${author}`),
  }));
  for (const vc of voteCerts) {
    vc.parent_hashes = [proposeCert.hash];
    dag.saveCertificate(vc);
  }
  bullshark.onRoundComplete(voteCerts, voteRound);
}

/**
 * Seed a committable anchor's certs into the DAG WITHOUT calling onRoundComplete
 * (mirrors cert-sync import: certs land in the DAG but nothing drives commit).
 */
function _seedAnchorCerts(dag, { proposeRound, voteRound, leader, voteAuthors }) {
  const proposeCert = _buildCert({ round: proposeRound, author: leader });
  dag.saveCertificate(proposeCert);
  for (const author of voteAuthors) {
    const vc = _buildCert({ round: voteRound, author, hash: shake256(`vc-${voteRound}-${author}`) });
    vc.parent_hashes = [proposeCert.hash];
    dag.saveCertificate(vc);
  }
}

// One increment per distinct presence bucket 0..n-1 for each node.
function _seedBuckets(dag, rotationNumber, byNode) {
  for (const [node_id, n] of Object.entries(byNode)) {
    for (let b = 0; b < n; b++) {
      dag.incrementRotationParticipation(node_id, rotationNumber, b);
    }
  }
}

describe("bullshark rotation proposer (time-based epoch boundary)", () => {
  test("does NOT fire when the anchor timestamp stays in the latest rotation's epoch", () => {
    const fx = _setup();
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 3, voteRound: 4, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: SAME_EPOCH_TS(3),
    });

    expect(fx.submittedTxs).toHaveLength(0);
    // Anchor itself still commits; only the proposal is skipped.
    expect(fx.bullshark.lastCommittedRound()).toBe(4);
  });

  test("fires when the anchor crosses an epoch boundary; re-attestation when membership unchanged", () => {
    // No participation seeded beyond the anchor's own walk. Genesis members
    // get the admission free pass, so next committee == rotation 0 committee.
    // Re-attestation still submits (matches Sui/Aptos epoch attestation).
    const fx = _setup();
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 3, voteRound: 4, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: NEXT_EPOCH_TS(3),
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const tx = fx.submittedTxs[0];
    expect(tx.tx_type).toBe(TX_TYPES.COMMITTEE_ROTATION);
    expect(tx.data.rotation_number).toBe(1);
    expect(tx.data.effective_round).toBe(4 + LEAD);
    const ids = tx.data.new_committee.map(m => m.node_id);
    expect(ids).toEqual(GENESIS_IDS);
  });

  test("halt spanning several boundaries yields ONE catch-up rotation, not one per missed epoch", () => {
    // Live drill 2026-07-02: 390s outage across ~1.6 dev boundaries resumed
    // with exactly rotation N+1. Contiguity is a snapshot chain-of-trust
    // requirement, so a rotation per missed epoch would be a protocol bug.
    const fx = _setup();
    const resumeTs = MARKER + 5 * EPOCH + 60_000;
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 3, voteRound: 4, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: resumeTs,
    });
    expect(fx.submittedTxs).toHaveLength(1);
    expect(fx.submittedTxs[0].data.rotation_number).toBe(1);

    // Once the catch-up rotation is committed, a later anchor in the SAME
    // bucket does not fire again.
    const rot0 = fx.dag.getCommitteeRotation(0);
    fx.dag.saveCommitteeRotation({
      ...rot0, rotation_number: 1, prev_rotation: 0,
      effective_round: 4 + LEAD, committed_at: resumeTs + 2_000,
    });
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 5, voteRound: 6, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: resumeTs + 30_000,
    });
    expect(fx.submittedTxs).toHaveLength(1);
  });

  test("after a mid-bucket catch-up rotation the next boundary is the calendar line, not commit+EPOCH", () => {
    // Live drill: catch-up committed at grid+106.5s; the next rotation fired
    // 137.2s later at grid+3.7s. Boundaries re-anchor to the genesis grid.
    const fx = _setup();
    const catchUpCommit = MARKER + 5 * EPOCH + 100_000;  // 100s into the bucket
    const rot0 = fx.dag.getCommitteeRotation(0);
    fx.dag.saveCommitteeRotation({
      ...rot0, rotation_number: 1, prev_rotation: 0,
      effective_round: 500, committed_at: catchUpCommit,
    });

    // 50s after the catch-up commit: same bucket, no proposal.
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 501, voteRound: 502, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: catchUpCommit + 50_000,
    });
    expect(fx.submittedTxs).toHaveLength(0);

    // The next grid line arrives EPOCH - 100s after the commit; crossing it
    // fires even though a full EPOCH has not elapsed since the commit.
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 503, voteRound: 504, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: MARKER + 6 * EPOCH + 1_000,
    });
    expect(fx.submittedTxs).toHaveLength(1);
    expect(fx.submittedTxs[0].data.rotation_number).toBe(2);
  });

  test("an uncommitted proposal is re-proposed at a later anchor with a FRESH activation window", () => {
    // The crossing condition stays true until a rotation record lands, so a
    // proposal that never commits (wedged aggregation) is retried with
    // effective_round rebased on the retry round; a stale window is never
    // reused after the future-activation gate rejects it.
    const fx = _setup();
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 3, voteRound: 4, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: NEXT_EPOCH_TS(3),
    });
    expect(fx.submittedTxs).toHaveLength(1);
    expect(fx.submittedTxs[0].data.effective_round).toBe(4 + LEAD);

    // Nothing landed in CH; a much later anchor re-fires with a new window.
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 299, voteRound: 300, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: NEXT_EPOCH_TS(299),
    });
    expect(fx.submittedTxs).toHaveLength(2);
    expect(fx.submittedTxs[1].data.rotation_number).toBe(1);
    expect(fx.submittedTxs[1].data.effective_round).toBe(300 + LEAD);
  });

  test("admits a peer meeting the distinct-bucket threshold, excludes one below it", () => {
    const fx = _setup();
    fx.dag.saveNode({
      node_id: "tip://node/peer", name: "peer", public_key: "peer-pubkey",
      status: "active", registered_at: GEN,
    });
    fx.dag.saveNode({
      node_id: "tip://node/below", name: "below", public_key: "below-pubkey",
      status: "active", registered_at: GEN,
    });
    _seedBuckets(fx.dag, 0, {
      [FOUNDING.node_id]: BUCKETS,          // maxBuckets, sets the bar
      "tip://node/peer": THRESHOLD,          // exactly at the bar
      "tip://node/below": THRESHOLD - 1,     // one distinct bucket short
    });

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 3, voteRound: 4, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: NEXT_EPOCH_TS(3),
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const tx = fx.submittedTxs[0];
    expect(tx.tx_type).toBe(TX_TYPES.COMMITTEE_ROTATION);
    expect(tx.data.rotation_number).toBe(1);
    expect(tx.data.effective_round).toBe(4 + LEAD);

    const ids = tx.data.new_committee.map(m => m.node_id);
    expect(ids).toEqual([...ids].sort());
    expect(ids).toContain(FOUNDING.node_id);
    expect(ids).toContain("tip://node/peer");
    expect(ids).not.toContain("tip://node/below");
    expect(tx.data.cosignatures).toHaveLength(1);
    expect(tx.data.cosignatures[0].signer_kind).toBe("node");
    expect(tx.data.cosignatures[0].signer_ref).toBe(FOUNDING.node_id);
    expect(typeof tx.data.cosignatures[0].signature).toBe("string");
  });

  test("effective_round is floored at latest.effective_round + 2", () => {
    const fx = _setup();
    // Latest rotation activates far in the future: the floor arm wins over
    // voteRound + LEAD.
    const rot0 = fx.dag.getCommitteeRotation(0);
    fx.dag.saveCommitteeRotation({
      rotation_number: 1, effective_round: 5000, committee: rot0.committee,
      prev_rotation: 0, signer_node_ids: [], signatures: [],
      payload_hash: shake256("test-rot1-far-future"), committed_at: MARKER,
    });

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 3, voteRound: 4, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: NEXT_EPOCH_TS(3),
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const tx = fx.submittedTxs[0];
    expect(tx.data.rotation_number).toBe(2);
    expect(tx.data.effective_round).toBe(5002);
  });

  test("does NOT fire when proposer config is omitted (test/legacy mode)", () => {
    const fx = _setup({ withProposer: false });
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 3, voteRound: 4, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: NEXT_EPOCH_TS(3),
    });
    expect(fx.submittedTxs).toHaveLength(0);
    expect(fx.bullshark.lastCommittedRound()).toBe(4);
  });

  test("only the boundary anchor's leader fires; non-leaders skip", () => {
    const other = "tip://node/0-aaa";
    const fx = _setup({ nodeIds: [other, FOUNDING.node_id] });
    fx.dag.saveNode({
      node_id: other, name: "a", public_key: "kA",
      status: "active", registered_at: GEN,
    });

    // Precondition: wave 0's leader is the OTHER node, not us.
    expect(fx.bullshark.getLeader(1)).toBe(other);

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 1, voteRound: 2, leader: other,
      voteAuthors: [other, FOUNDING.node_id],
      anchorTs: NEXT_EPOCH_TS(1),
    });

    // Boundary crossed and anchor committed, but the leader gate skips us.
    expect(fx.bullshark.lastCommittedRound()).toBe(2);
    expect(fx.submittedTxs).toHaveLength(0);
  });

  test("submitTx throws synchronously; bullshark catches, anchor commit unaffected", () => {
    let submitCalls = 0;
    const fx = _setup({
      submitTx: () => {
        submitCalls++;
        throw new Error("consensus not wired");
      },
    });

    expect(() => _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 3, voteRound: 4, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: NEXT_EPOCH_TS(3),
    })).not.toThrow();

    expect(submitCalls).toBe(1);
    expect(fx.bullshark.lastCommittedRound()).toBe(4);
    expect(fx.bullshark.stats().metrics.committee_rotation_proposals).toBe(1);
  });

  test("payload_hash matches canonical claim shake256(rotation_number, effective_round, new_committee)", () => {
    const fx = _setup();
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 3, voteRound: 4, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: NEXT_EPOCH_TS(3),
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const tx = fx.submittedTxs[0];

    const expectedHash = shake256(canonicalJson({
      rotation_number: tx.data.rotation_number,
      effective_round: tx.data.effective_round,
      committee: tx.data.new_committee,
    }));
    expect(tx.data.payload_hash).toBe(expectedHash);
  });

  test("filters nodes with no public_key from new_committee", () => {
    const fx = _setup();
    // Both above the bucket threshold; the no-pubkey one must be filtered.
    fx.dag.saveNode({
      node_id: "tip://node/no-key", name: "no-key", public_key: "",
      status: "active", registered_at: GEN,
    });
    fx.dag.saveNode({
      node_id: "tip://node/with-key", name: "with-key", public_key: "real-pubkey",
      status: "active", registered_at: GEN,
    });
    _seedBuckets(fx.dag, 0, {
      [FOUNDING.node_id]: BUCKETS,
      "tip://node/no-key": THRESHOLD,
      "tip://node/with-key": THRESHOLD,
    });

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 3, voteRound: 4, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
      anchorTs: NEXT_EPOCH_TS(3),
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const ids = fx.submittedTxs[0].data.new_committee.map(m => m.node_id);
    expect(ids).toContain(FOUNDING.node_id);
    expect(ids).toContain("tip://node/with-key");
    expect(ids).not.toContain("tip://node/no-key");
  });
});

describe("bullshark tryRotationProposal (producer-pause retry path)", () => {
  test("proposes only latest+1; stale and gapped rotations are no-ops", () => {
    const fx = _setup();

    fx.bullshark.tryRotationProposal(50, 0);   // already landed
    expect(fx.submittedTxs).toHaveLength(0);

    fx.bullshark.tryRotationProposal(50, 2);   // gap: latest is 0, only 1 allowed
    expect(fx.submittedTxs).toHaveLength(0);

    fx.bullshark.tryRotationProposal(50, 1);   // latest+1: fires, leader gate bypassed
    expect(fx.submittedTxs).toHaveLength(1);
    const tx = fx.submittedTxs[0];
    expect(tx.tx_type).toBe(TX_TYPES.COMMITTEE_ROTATION);
    expect(tx.data.rotation_number).toBe(1);
    expect(tx.data.effective_round).toBe(50 + LEAD);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// RP attribution: each walked cert credits the rotation ACTIVE at cert.round,
// resolved from committee_history (getCommitteeAtRound), never from local
// replay state. Record-based attribution keeps RP rows bit-identical across
// nodes regardless of each node's catch-up position.
// ═══════════════════════════════════════════════════════════════════════════
describe("bullshark RP attribution by committee_history at cert.round", () => {
  function _saveRotation1(dag, effective_round) {
    const rot0 = dag.getCommitteeRotation(0);
    dag.saveCommitteeRotation({
      rotation_number: 1, effective_round, committee: rot0.committee,
      prev_rotation: 0, signer_node_ids: [], signatures: [],
      payload_hash: shake256(`test-rot1-${effective_round}`), committed_at: MARKER,
    });
  }

  test("cert at round R credits the rotation whose effective_round covers R", () => {
    const fx = _setup({ withProposer: false });
    _saveRotation1(fx.dag, 100);

    // Anchor deep inside rotation 1's activation span.
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 105, voteRound: 106, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });

    const rot1 = fx.dag.getRotationParticipation(1).find(r => r.node_id === FOUNDING.node_id);
    expect(rot1).toBeTruthy();
    expect(rot1.count).toBeGreaterThan(0);
    expect(rot1.buckets).toBeGreaterThan(0);

    // Nothing leaked into rotation 0: attribution follows cert.round, not
    // whatever rotation local consensus replay happens to be in.
    const rot0 = fx.dag.getRotationParticipation(0);
    expect(rot0.find(r => r.node_id === FOUNDING.node_id)).toBeUndefined();
  });

  test("walks spanning an activation boundary attribute each cert to its own rotation", () => {
    // Chain crossing rotation 1's effective_round=600:
    //   ancestor round 599  rotation 0
    //   mid      round 600  rotation 1
    //   leader   round 601  rotation 1  (anchor cert)
    //   vote     round 602  (drives the commit, not part of the walk)
    const fx = _setup({ withProposer: false });
    _saveRotation1(fx.dag, 600);

    const ancestor = _buildCert({
      round: 599, author: FOUNDING.node_id, hash: shake256("attr-anc-599"),
    });
    fx.dag.saveCertificate(ancestor);

    const mid = _buildCert({
      round: 600, author: FOUNDING.node_id, hash: shake256("attr-mid-600"),
    });
    mid.parent_hashes = [ancestor.hash];
    fx.dag.saveCertificate(mid);

    const leader = _buildCert({ round: 601, author: FOUNDING.node_id });
    leader.parent_hashes = [mid.hash];
    fx.dag.saveCertificate(leader);

    const vote = _buildCert({
      round: 602, author: FOUNDING.node_id, hash: shake256("attr-vc-602"),
    });
    vote.parent_hashes = [leader.hash];
    fx.dag.saveCertificate(vote);

    fx.bullshark.onRoundComplete([vote], 602);

    const rot0 = fx.dag.getRotationParticipation(0).find(r => r.node_id === FOUNDING.node_id);
    const rot1 = fx.dag.getRotationParticipation(1).find(r => r.node_id === FOUNDING.node_id);

    // ancestor: author + self-ack = 2 credits to rotation 0.
    expect(rot0).toBeTruthy();
    expect(rot0.count).toBe(2);
    // mid + leader: 2 certs x (author + self-ack) = 4 credits to rotation 1.
    expect(rot1).toBeTruthy();
    expect(rot1.count).toBe(4);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// #73 — `commits` row written ONLY when commit-handler accepts >= 1 tx.
// Anchor commits that order N txs but have all N rejected at commit-handler
// (e.g., duplicate rotation_number under a multi-proposer cycle) must NOT
// inflate the commits table with no-state-change rows. Anchor still ticks
// _consensusIndex (consensus-success counter), only the commits-row write
// is gated.
// ═══════════════════════════════════════════════════════════════════════════
describe("bullshark commit row gating on accepted-tx count (#73)", () => {
  function _setupWithApplier({ applyResult }) {
    const dag = initDAG({ inMemory: true });
    if (!dag.getNode(FOUNDING.node_id)) {
      dag.saveNode({
        node_id: FOUNDING.node_id, name: "founding", public_key: FOUNDING.public_key,
        status: "active", registered_at: GEN,
      });
    }
    const savedCommits = [];
    // Wrap dag.saveCommit to spy on calls without changing storage semantics.
    const realSaveCommit = dag.saveCommit;
    dag.saveCommit = (row) => { savedCommits.push(row); return realSaveCommit ? realSaveCommit(row) : undefined; };

    const bullshark = createBullshark({
      dag,
      getNodeIds: () => [FOUNDING.node_id],
      onOrderedTxs: () => applyResult,
      proposer: null,
    });
    return { dag, bullshark, savedCommits };
  }

  function _driveOneTx(dag, bullshark) {
    // One tx in the leader's batch. No proposer wired, so the epoch-boundary
    // path can't add rotation noise regardless of timestamps.
    const proposeRound = 51;
    const voteRound = 52;
    const proposeCert = _buildCert({ round: proposeRound, author: FOUNDING.node_id });
    proposeCert.batch.txs = [{ tx_id: "fake-tx-1", tx_type: "REGISTER_IDENTITY", data: {}, prev: [], timestamp: SAME_EPOCH_TS(proposeRound) }];
    dag.saveCertificate(proposeCert);

    const voteCert = _buildCert({
      round: voteRound, author: FOUNDING.node_id,
      hash: shake256(`vc73-${voteRound}`),
    });
    voteCert.parent_hashes = [proposeCert.hash];
    dag.saveCertificate(voteCert);
    bullshark.onRoundComplete([voteCert], voteRound);
  }

  test("all-dropped: orderedTxs > 0 but committed=0 → NO commit row written", () => {
    const fx = _setupWithApplier({ applyResult: { committed: 0, dropped: 1 } });
    _driveOneTx(fx.dag, fx.bullshark);

    expect(fx.savedCommits).toHaveLength(0);
    // Anchor still counted as a consensus event (cs_idx ticked).
    expect(fx.bullshark.stats().consensusIndex).toBeGreaterThan(0);
  });

  test("any-committed: committed=1 dropped=0 → commit row IS written", () => {
    const fx = _setupWithApplier({ applyResult: { committed: 1, dropped: 0 } });
    _driveOneTx(fx.dag, fx.bullshark);

    expect(fx.savedCommits).toHaveLength(1);
    expect(fx.savedCommits[0].round).toBe(52);
  });

  test("missing applyResult (legacy onOrderedTxs): falls back to ordered count → commit row IS written", () => {
    // Older callers may not return { committed, dropped }. Bullshark falls
    // back to assuming all ordered txs were committed (preserves pre-#73
    // behavior for callers that haven't been updated).
    const fx = _setupWithApplier({ applyResult: undefined });
    _driveOneTx(fx.dag, fx.bullshark);

    expect(fx.savedCommits).toHaveLength(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// driveCommit: catch up the committed frontier from already-synced certs.
// Gossip-received certs commit via onCertSaved; cert-sync-imported ones don't,
// so a behind node would hold the certs but never advance committed_round.
// ═══════════════════════════════════════════════════════════════════════════
describe("bullshark driveCommit (cert-sync catch-up)", () => {
  test("commits anchors that are in the DAG but were never driven", () => {
    const fx = _setup({ withProposer: false });
    // As if cert-sync imported three committable anchors: certs are in the DAG,
    // but onRoundComplete was never called (sync does not drive commit).
    for (const r of [2, 4, 6]) {
      _seedAnchorCerts(fx.dag, {
        proposeRound: r - 1, voteRound: r,
        leader: FOUNDING.node_id, voteAuthors: [FOUNDING.node_id],
      });
    }

    // The bug: all the certs are present, but nothing is committed.
    expect(fx.bullshark.lastCommittedRound()).toBe(0);

    // The fix: driveCommit walks the synced rounds and commits them.
    const after = fx.bullshark.driveCommit(6);
    expect(after).toBeGreaterThan(0);
    expect(fx.bullshark.lastCommittedRound()).toBe(after);
  });

  test("driveCommit is a no-op when there is nothing new to commit", () => {
    const fx = _setup({ withProposer: false });
    expect(fx.bullshark.driveCommit(0)).toBe(0);
    expect(fx.bullshark.lastCommittedRound()).toBe(0);
  });
});
