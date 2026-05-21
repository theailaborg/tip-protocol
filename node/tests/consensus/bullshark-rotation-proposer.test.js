/**
 * @file tests/consensus/bullshark-rotation-proposer.test.js
 * @description Tests for #75 boundary-fired rotation proposer.
 *
 * Under the rotation-period model the proposer fires ONLY at rotation
 * boundaries — every COMMITTEE_ROTATION_INTERVAL_COMMITS anchor commits.
 * This eliminates the per-round multi-proposer flap that was #74's
 * symptom. The boundary's anchor leader is the deterministic single
 * proposer; other nodes don't fire (#74 fixed at the source).
 *
 * Test pattern:
 *   - Pre-set `last_consensus_index` so the next anchor commit lands AT
 *     the boundary (consensus_index % INTERVAL_COMMITS == 0).
 *   - Drive ONE anchor commit. Boundary handler runs, computes next
 *     committee from rotation_participation tally, leader submits the
 *     COMMITTEE_ROTATION tx via the stub submitTx.
 *   - Assert tx shape and contents.
 *
 * Covers:
 *   - Proposer does NOT fire at non-boundary anchor commits
 *   - Proposer fires at boundary anchor commits
 *   - Only the boundary anchor's leader fires (single proposer)
 *   - Computes next committee from rotation_participation tally
 *   - Doesn't fire when committee unchanged
 *   - Tx shape (rotation_number, effective_round, committee, signers)
 *   - submitTx throwing is caught (anchor commit unaffected)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256 } = require(SHARED + "/crypto");
const { TX_TYPES } = require(SHARED + "/constants");
const { CONSENSUS } = require(SHARED + "/protocol-constants");
const { initDAG } = require(path.join(SRC, "dag"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

beforeAll(async () => { await initCrypto(); });

const FOUNDING = getGenesisPayload().founding_node;

// Use the configured interval and threshold for boundary calculation.
const INTERVAL = CONSENSUS.COMMITTEE_ROTATION_INTERVAL_COMMITS;
const PCT = CONSENSUS.COMMITTEE_ROTATION_PARTICIPATION_PCT_OF_INTERVAL;
const THRESHOLD = Math.ceil((INTERVAL * PCT) / 100);

// Round-based submission window: voteRound within `leadRounds` of next
// boundary round (= next multiple of EPOCH_LENGTH_ROUNDS).
//   leadRounds = max(20, LEAD_ANCHORS * 3) — see bullshark.js
// IN_WINDOW_VOTE_ROUND lands inside the window for boundary 1 (round
// EPOCH_LENGTH_ROUNDS). Round must be even (vote round). Use 2 rounds
// before the boundary so we're comfortably inside the window for any
// reasonable leadRounds.
const IN_WINDOW_VOTE_ROUND = CONSENSUS.EPOCH_LENGTH_ROUNDS - 2;
const IN_WINDOW_PROPOSE_ROUND = IN_WINDOW_VOTE_ROUND - 1;

const POST_GENESIS_BASE = new Date(1775001600000).getTime();

function _buildCert({ round, author, hash }) {
  const ts = POST_GENESIS_BASE + round * 2000;
  return {
    hash: hash || shake256(`cert-${round}-${author}`),
    round,
    author_node_id: author,
    timestamp: ts,
    signature: "00",
    batch: { txs: [], hash: shake256(`batch-${round}-${author}`) },
    parent_hashes: [],
    acknowledgments: [
      { acker_node_id: author, signature: "00", signed_at: ts },
    ],
  };
}

/**
 * Set up a bullshark instance with consensus_index pre-loaded so the
 * NEXT successful anchor commit lands at a boundary (or just before, if
 * `boundary` is false). Uses the genesis founding_node as the leader.
 */
function _setup({ withProposer = true, atBoundary = true } = {}) {
  const dag = initDAG({ inMemory: true });

  if (!dag.getNode(FOUNDING.node_id)) {
    dag.saveNode({
      node_id: FOUNDING.node_id, name: "founding", public_key: FOUNDING.public_key,
      status: "active", registered_at: 1767225600000,
    });
  }

  // Under #75 atomic boundary, submission fires during the ROUND-based
  // window: voteRound within `leadRounds` of the next boundary round
  // (multiple of EPOCH_LENGTH_ROUNDS). The trigger is voteRound (passed
  // by the caller via _driveAnchorCommit), NOT consensus_index. So this
  // helper no longer pre-loads cs_idx — the test controls window membership
  // by choosing IN_WINDOW_VOTE_ROUND vs an out-of-window value.
  // The atBoundary flag is kept for documentation: tests that want to
  // trigger submission pass atBoundary=true and use IN_WINDOW_VOTE_ROUND.

  const submittedTxs = [];
  const proposer = withProposer ? {
    nodeId: FOUNDING.node_id,
    nodePrivateKey: generateMLDSAKeypair().privateKey,
    nodePublicKey: FOUNDING.public_key,
    submitTx: (tx) => {
      submittedTxs.push(tx);
      return { tx_id: tx.tx_id };
    },
  } : null;

  const bullshark = createBullshark({
    dag,
    getNodeIds: () => [FOUNDING.node_id],
    onOrderedTxs: () => {},
    proposer,
  });

  return { dag, bullshark, submittedTxs };
}

/**
 * Drive an anchor commit: seed propose+vote certs, call onRoundComplete.
 */
function _driveAnchorCommit(dag, bullshark, { proposeRound, voteRound, leader, voteAuthors }) {
  const proposeCert = _buildCert({ round: proposeRound, author: leader });
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
 * Pre-populate rotation_participation for a rotation. Useful for
 * driving the boundary computation deterministically.
 */
function _seedParticipation(dag, rotationNumber, byNode) {
  for (const [node_id, count] of Object.entries(byNode)) {
    for (let i = 0; i < count; i++) {
      dag.incrementRotationParticipation(node_id, rotationNumber);
    }
  }
}

describe("bullshark — rotation proposer (#75 boundary-fired)", () => {
  test("does NOT fire at non-boundary anchor commits", () => {
    const fx = _setup({ atBoundary: false });
    // voteRound=2 is far from the next boundary round (EPOCH_LENGTH_ROUNDS),
    // so the round-based submission window check fails and no rotation tx
    // is submitted.
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 1, voteRound: 2, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });

    expect(fx.submittedTxs).toHaveLength(0);
  });

  test("re-attestation: fires at boundary even when committee is unchanged (#75)", () => {
    // Under #75 atomic boundary, every epoch must have a corresponding
    // rotation row in committee_history (so producer-pause's
    // getCommitteeRotation(epochOf(round)) check succeeds for every
    // round). So we always submit a rotation tx at the boundary, even
    // if the new committee equals the previous one — this is a
    // re-attestation rotation (matches Sui/Aptos epoch-attestation).
    const fx = _setup({ atBoundary: true });
    // No participation seeded → next committee is just genesis (founding),
    // identical to rotation 0. Pre-#75 we'd skip; under #75 we still
    // submit a re-attestation rotation.
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: IN_WINDOW_PROPOSE_ROUND,
      voteRound: IN_WINDOW_VOTE_ROUND,
      leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const tx = fx.submittedTxs[0];
    expect(tx.tx_type).toBe(TX_TYPES.COMMITTEE_ROTATION);
    expect(tx.data.rotation_number).toBe(1);
    // committee unchanged (just founding)
    const ids = tx.data.new_committee.map(m => m.node_id);
    expect(ids).toEqual([FOUNDING.node_id]);
  });

  test("fires at boundary when participation tally yields a different committee", () => {
    const fx = _setup({ atBoundary: true });
    // Register a new node and seed participation above threshold for
    // rotation 0. At the boundary, computeNextRotationCommittee will
    // include this peer → committee grows → rotation tx fires.
    fx.dag.saveNode({
      node_id: "tip://node/peer", name: "peer", public_key: "peer-pubkey",
      status: "active", registered_at: 1767225600000,
    });
    _seedParticipation(fx.dag, 0, {
      [FOUNDING.node_id]: INTERVAL,
      "tip://node/peer": THRESHOLD,
    });

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: IN_WINDOW_PROPOSE_ROUND,
      voteRound: IN_WINDOW_VOTE_ROUND,
      leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const tx = fx.submittedTxs[0];
    expect(tx.tx_type).toBe(TX_TYPES.COMMITTEE_ROTATION);
    expect(tx.data.rotation_number).toBe(1);  // rotation 0 → 1
    expect(tx.data.effective_round).toBe(CONSENSUS.EPOCH_LENGTH_ROUNDS);

    const ids = tx.data.new_committee.map(m => m.node_id);
    expect(ids).toEqual([...ids].sort());
    expect(ids).toContain(FOUNDING.node_id);
    expect(ids).toContain("tip://node/peer");
    expect(tx.data.signer_node_ids).toEqual([FOUNDING.node_id]);
    expect(tx.data.signatures).toHaveLength(1);
  });

  test("does NOT fire when proposer config is omitted (test/legacy mode)", () => {
    const fx = _setup({ atBoundary: true, withProposer: false });
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: IN_WINDOW_PROPOSE_ROUND,
      voteRound: IN_WINDOW_VOTE_ROUND,
      leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });
    expect(fx.submittedTxs).toHaveLength(0);
  });

  test("only the boundary anchor's leader fires; non-leaders skip", () => {
    // Set up a 2-node committee where the boundary anchor's leader is
    // NOT us. The boundary handler should skip submission on non-leaders.
    const dag = initDAG({ inMemory: true });
    if (!dag.getNode(FOUNDING.node_id)) {
      dag.saveNode({
        node_id: FOUNDING.node_id, name: "founding", public_key: FOUNDING.public_key,
        status: "active", registered_at: 1767225600000,
      });
    }
    dag.saveNode({
      node_id: "tip://node/0-aaa", name: "a", public_key: "kA",
      status: "active", registered_at: 1767225600000,
    });

    const submittedTxs = [];
    const proposer = {
      nodeId: FOUNDING.node_id,  // we're founding, NOT the boundary leader
      nodePrivateKey: generateMLDSAKeypair().privateKey,
      nodePublicKey: FOUNDING.public_key,
      submitTx: (tx) => { submittedTxs.push(tx); return { tx_id: tx.tx_id }; },
    };
    const bullshark = createBullshark({
      dag,
      getNodeIds: () => ["tip://node/0-aaa", FOUNDING.node_id].sort(),
      onOrderedTxs: () => {},
      proposer,
    });

    // Drive boundary commit with leader = 0-aaa (not founding).
    _driveAnchorCommit(dag, bullshark, {
      proposeRound: IN_WINDOW_PROPOSE_ROUND,
      voteRound: IN_WINDOW_VOTE_ROUND,
      leader: "tip://node/0-aaa",
      voteAuthors: ["tip://node/0-aaa", FOUNDING.node_id],
    });

    // We're founding, leader is 0-aaa → leader gate skips us.
    expect(submittedTxs).toHaveLength(0);
  });

  test("submitTx throws synchronously → bullshark catches, anchor commit unaffected", () => {
    const dag = initDAG({ inMemory: true });
    if (!dag.getNode(FOUNDING.node_id)) {
      dag.saveNode({
        node_id: FOUNDING.node_id, name: "founding", public_key: FOUNDING.public_key,
        status: "active", registered_at: 1767225600000,
      });
    }
    dag.saveNode({
      node_id: "tip://node/peer", name: "peer", public_key: "peer-pubkey",
      status: "active", registered_at: 1767225600000,
    });
    // Seed participation so the boundary triggers a rotation submit.
    for (let i = 0; i < THRESHOLD; i++) {
      dag.incrementRotationParticipation("tip://node/peer", 0);
    }

    let submitCalls = 0;
    const proposer = {
      nodeId: FOUNDING.node_id,
      nodePrivateKey: generateMLDSAKeypair().privateKey,
      nodePublicKey: FOUNDING.public_key,
      submitTx: () => {
        submitCalls++;
        throw new Error("consensus not wired");
      },
    };
    const bullshark = createBullshark({
      dag,
      getNodeIds: () => [FOUNDING.node_id],
      onOrderedTxs: () => {},
      proposer,
    });

    expect(() => _driveAnchorCommit(dag, bullshark, {
      proposeRound: IN_WINDOW_PROPOSE_ROUND,
      voteRound: IN_WINDOW_VOTE_ROUND,
      leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    })).not.toThrow();

    expect(submitCalls).toBe(1);
    expect(bullshark.lastCommittedRound()).toBe(IN_WINDOW_VOTE_ROUND);
    expect(bullshark.stats().metrics.committee_rotation_proposals).toBe(1);
  });

  test("payload_hash matches canonical claim shake256(rotation_number, effective_round, new_committee)", () => {
    const fx = _setup({ atBoundary: true });
    fx.dag.saveNode({
      node_id: "tip://node/peer", name: "peer", public_key: "peer-pubkey",
      status: "active", registered_at: 1767225600000,
    });
    _seedParticipation(fx.dag, 0, {
      [FOUNDING.node_id]: INTERVAL,
      "tip://node/peer": THRESHOLD,
    });

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: IN_WINDOW_PROPOSE_ROUND,
      voteRound: IN_WINDOW_VOTE_ROUND,
      leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const tx = fx.submittedTxs[0];

    const { canonicalJson, shake256: hash } = require(SHARED + "/crypto");
    const expectedHash = hash(canonicalJson({
      rotation_number: tx.data.rotation_number,
      effective_round: tx.data.effective_round,
      committee: tx.data.new_committee,
    }));
    expect(tx.data.payload_hash).toBe(expectedHash);
  });

  test("filters nodes with no public_key from new_committee", () => {
    const fx = _setup({ atBoundary: true });
    // Register one node WITH pubkey, one WITHOUT. Both above participation
    // threshold. The no-pubkey one must be filtered out.
    fx.dag.saveNode({
      node_id: "tip://node/no-key", name: "no-key", public_key: "",
      status: "active", registered_at: 1767225600000,
    });
    fx.dag.saveNode({
      node_id: "tip://node/with-key", name: "with-key", public_key: "real-pubkey",
      status: "active", registered_at: 1767225600000,
    });
    _seedParticipation(fx.dag, 0, {
      [FOUNDING.node_id]: INTERVAL,
      "tip://node/no-key": THRESHOLD,
      "tip://node/with-key": THRESHOLD,
    });

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: IN_WINDOW_PROPOSE_ROUND,
      voteRound: IN_WINDOW_VOTE_ROUND,
      leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const ids = fx.submittedTxs[0].data.new_committee.map(m => m.node_id);
    expect(ids).toContain(FOUNDING.node_id);
    expect(ids).toContain("tip://node/with-key");
    expect(ids).not.toContain("tip://node/no-key");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Fix A — rotation-participation attribution uses epochOf(cert.round),
// NOT floor(local _consensusIndex / INTERVAL_COMMITS). Without Fix A, a node
// whose cs_idx lags during catch-up would credit OLD rotations with certs
// from NEW rotations — producing divergent RP across nodes and ultimately
// divergent committee derivations. The walk increment must be a function
// of the cert (deterministic across nodes) not local replay state.
// ═══════════════════════════════════════════════════════════════════════════
describe("bullshark — RP attribution by cert.round (Fix A)", () => {
  test("cert at round R credits rotation epochOf(R), regardless of local cs_idx", () => {
    const fx = _setup({ atBoundary: false });
    const epochLen = CONSENSUS.EPOCH_LENGTH_ROUNDS;
    // Drive an anchor commit deep inside rotation 2 (rounds [2*epochLen,
    // 3*epochLen)). The propose+vote certs both have round in rotation 2.
    // Bullshark's walk increments rotation_participation for them — must
    // attribute to rotation 2 (= epochOf(round)), regardless of what
    // floor(_consensusIndex/INTERVAL) happens to be at this moment.
    const proposeRound = 2 * epochLen + 5;     // mid rotation 2
    const voteRound = proposeRound + 1;
    expect(Math.floor(proposeRound / epochLen)).toBe(2);
    expect(Math.floor(voteRound / epochLen)).toBe(2);

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound, voteRound, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });

    // Rotation 2 received increments — that's the correct attribution by
    // cert.round. Rotation 0 (where local cs_idx happens to be — first
    // anchor commit, _consensusIndex jumps from 0 → 1, epochOf-by-cs_idx
    // would say rotation 0) must NOT have these increments.
    const rot2 = fx.dag.getRotationParticipation(2);
    const rot0 = fx.dag.getRotationParticipation(0);

    const rot2Founding = rot2.find(r => r.node_id === FOUNDING.node_id);
    expect(rot2Founding).toBeTruthy();
    expect(rot2Founding.count).toBeGreaterThan(0);

    // Rotation 0 should have NO row for the founding node — Fix A's
    // attribution sent the credits to rotation 2.
    expect(rot0.find(r => r.node_id === FOUNDING.node_id)).toBeUndefined();
  });

  test("walks spanning a rotation boundary attribute each cert to its own rotation", () => {
    // Build a 3-cert chain crossing the rotation 2 → 3 boundary so the
    // walk visits certs from both rotations in a single anchor commit.
    // With Fix A, each cert credits its OWN epochOf(cert.round). Without
    // Fix A, all three would be credited to whichever rotation local
    // _consensusIndex maps to at walk time.
    //
    // Layout (epochLen=200, boundary at round 600):
    //   ancestor  round 599  rotation 2  ← in walk via parent_hashes
    //   mid       round 600  rotation 3  ← in walk via parent_hashes
    //   leader    round 601  rotation 3  ← anchor cert (proposeRound)
    //   vote      round 602  rotation 3  ← voteRound (even, required)
    const fx = _setup({ atBoundary: false });
    const epochLen = CONSENSUS.EPOCH_LENGTH_ROUNDS;
    const boundaryRound = 3 * epochLen;
    const proposeRound = boundaryRound + 1;     // odd, leader cert here
    const voteRound = boundaryRound + 2;        // even — bullshark gate

    const ancestor = _buildCert({
      round: boundaryRound - 1, author: FOUNDING.node_id,
      hash: shake256(`fixA-anc-${boundaryRound - 1}`),
    });
    fx.dag.saveCertificate(ancestor);

    const mid = _buildCert({
      round: boundaryRound, author: FOUNDING.node_id,
      hash: shake256(`fixA-mid-${boundaryRound}`),
    });
    mid.parent_hashes = [ancestor.hash];
    fx.dag.saveCertificate(mid);

    const leader = _buildCert({ round: proposeRound, author: FOUNDING.node_id });
    leader.parent_hashes = [mid.hash];
    fx.dag.saveCertificate(leader);

    const vote = _buildCert({
      round: voteRound, author: FOUNDING.node_id,
      hash: shake256(`fixA-vc-${voteRound}`),
    });
    vote.parent_hashes = [leader.hash];
    fx.dag.saveCertificate(vote);

    fx.bullshark.onRoundComplete([vote], voteRound);

    const rot2 = fx.dag.getRotationParticipation(2).find(r => r.node_id === FOUNDING.node_id);
    const rot3 = fx.dag.getRotationParticipation(3).find(r => r.node_id === FOUNDING.node_id);

    // ancestor (rotation 2) credited to rotation 2; mid + leader (rotation 3)
    // credited to rotation 3. Per-cert epoch attribution holds.
    expect(rot2).toBeTruthy();
    expect(rot2.count).toBeGreaterThan(0);
    expect(rot3).toBeTruthy();
    expect(rot3.count).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// #73 — `commits` row written ONLY when commit-handler accepts ≥1 tx.
// Anchor commits that order N txs but have all N rejected at commit-handler
// (e.g., duplicate rotation_number under a multi-proposer cycle) must NOT
// inflate the commits table with no-state-change rows. Anchor still ticks
// _consensusIndex (consensus-success counter) — only the commits-row write
// is gated. We drive a tx through onRoundComplete with an onOrderedTxs that
// reports all-dropped and assert no commit row is saved; with at-least-one-
// committed we assert the row IS saved.
// ═══════════════════════════════════════════════════════════════════════════
describe("bullshark — commit row gating on accepted-tx count (#73)", () => {
  function _setupWithApplier({ applyResult }) {
    const dag = initDAG({ inMemory: true });
    if (!dag.getNode(FOUNDING.node_id)) {
      dag.saveNode({
        node_id: FOUNDING.node_id, name: "founding", public_key: FOUNDING.public_key,
        status: "active", registered_at: 1767225600000,
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
    // Drive an anchor commit that has 1 tx in the leader's batch. Round
    // chosen far from any boundary so no rotation-submission noise.
    const proposeRound = 51;
    const voteRound = 52;
    const proposeCert = _buildCert({ round: proposeRound, author: FOUNDING.node_id });
    proposeCert.batch.txs = [{ tx_id: "fake-tx-1", tx_type: "REGISTER_IDENTITY", data: {}, prev: [], timestamp: 1775001600000 }];
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
