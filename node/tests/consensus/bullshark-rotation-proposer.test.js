/**
 * @file tests/consensus/bullshark-rotation-proposer.test.js
 * @description Tests for §4 + #34 step 6 — bullshark's
 * `_maybeProposeCommitteeRotation`.
 *
 * Covers:
 *   - Proposer doesn't fire when committee unchanged and not periodic-due
 *   - Proposer fires when would-be committee differs from latest rotation
 *     (event-driven trigger)
 *   - Proposer fires when 7-day periodic backstop elapses with no change
 *     (committee_rotation_interval_rounds round-count proxy)
 *   - Only the anchor-commit leader fires (others skip)
 *   - Submitted tx has correct shape: rotation_number+1, effective_round
 *     monotonic, payload_hash matches canonical claim, signed by self
 *
 * Tests bullshark in isolation with a stub submitTx that captures the
 * tx instead of running it through real consensus. The full end-to-end
 * (proposer → mempool → commit-handler → committee_history updated) is
 * exercised in the multi-step integration coverage from
 * commit-handler-committee-rotation.test.js.
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
const { initDAG } = require(path.join(SRC, "dag"));
const { createBullshark } = require(path.join(SRC, "consensus", "bullshark"));
const { getGenesisPayload } = require(path.join(SRC, "genesis"));

beforeAll(async () => { await initCrypto(); });

const FOUNDING = getGenesisPayload().founding_node;

// BFT-Time floor: cert timestamps must be > genesis. Anchor cert's
// timestamp is checked monotonically vs `_lastAnchorTimestamp ||
// BFT_TIME_GENESIS_MS`, so all test certs need to be safely after.
const POST_GENESIS_BASE = new Date("2026-04-01T00:00:00.000Z").getTime();

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

function _setup({ withProposer = true } = {}) {
  const dag = initDAG({ inMemory: true });

  // The genesis founding_node is in committee_history rotation 0 already
  // (from initDAG bootstrap). Register it in nodes table too — required
  // for deriveLiveCommittee's `registered ∩ producers` intersection.
  // (bootstrap _writeGenesisBlock already does this; this is belt-and-suspenders.)
  if (!dag.getNode(FOUNDING.node_id)) {
    dag.saveNode({
      node_id: FOUNDING.node_id, name: "founding", public_key: FOUNDING.public_key,
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
  }

  const submittedTxs = [];
  const proposer = withProposer ? {
    nodeId: FOUNDING.node_id,
    nodePrivateKey: generateMLDSAKeypair().privateKey,  // stub key; sig won't pass commit-handler verify but proposer still builds & submits
    nodePublicKey: FOUNDING.public_key,
    submitTx: (tx) => {
      submittedTxs.push(tx);
      return { tx_id: tx.tx_id };
    },
  } : null;

  const bullshark = createBullshark({
    dag,
    getNodeIds: () => [FOUNDING.node_id],
    onOrderedTxs: () => { /* no-op */ },
    proposer,
  });

  return { dag, bullshark, submittedTxs };
}

function _seedCertsByRound(dag, byRound) {
  for (const [roundStr, authors] of Object.entries(byRound)) {
    const round = Number(roundStr);
    for (const author of authors) {
      dag.saveCertificate(_buildCert({ round, author }));
    }
  }
}

// Drive an anchor commit by seeding propose+vote certs and calling
// onRoundComplete with the vote round's certs. Returns success bool.
function _driveAnchorCommit(dag, bullshark, { proposeRound, voteRound, leader, voteAuthors }) {
  const proposeCert = _buildCert({ round: proposeRound, author: leader });
  dag.saveCertificate(proposeCert);

  const voteCerts = voteAuthors.map(author => _buildCert({
    round: voteRound,
    author,
    hash: shake256(`vc-${voteRound}-${author}`),
  }));
  // Make each vote cert reference the leader's cert (commit rule: 2/3+ of
  // vote-round certs reference the propose-round leader cert).
  for (const vc of voteCerts) {
    vc.parent_hashes = [proposeCert.hash];
    dag.saveCertificate(vc);
  }
  bullshark.onRoundComplete(voteCerts, voteRound);
}

describe("bullshark — rotation proposer (§4 + #34 step 6)", () => {
  test("does NOT fire when committee unchanged and < 7d elapsed", () => {
    const fx = _setup();
    // Latest rotation 0 = [founding_node]. Register only founding_node
    // as a producer at recent rounds — so deriveLiveCommittee returns
    // [founding_node], matching latest_rotation.committee.
    _seedCertsByRound(fx.dag, {
      1: [FOUNDING.node_id],
      2: [FOUNDING.node_id],
    });

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 1, voteRound: 2, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });

    expect(fx.submittedTxs).toHaveLength(0);
  });

  test("fires when would-be committee differs from latest rotation (event-driven)", () => {
    const fx = _setup();
    // Register a SECOND node and have it produce certs. would-be committee
    // expands beyond rotation 0's [founding_node] → diff detected.
    fx.dag.saveNode({
      node_id: "tip://node/peer", name: "peer", public_key: "peer-pubkey",
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
    _seedCertsByRound(fx.dag, {
      1: [FOUNDING.node_id, "tip://node/peer"],
      2: [FOUNDING.node_id, "tip://node/peer"],
    });

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 1, voteRound: 2, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id, "tip://node/peer"],
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const tx = fx.submittedTxs[0];
    expect(tx.tx_type).toBe(TX_TYPES.COMMITTEE_ROTATION);
    expect(tx.data.rotation_number).toBe(1);  // rotation 0 → 1
    expect(tx.data.effective_round).toBeGreaterThan(0);

    // new_committee carries [{node_id, public_key}] sorted by node_id
    const ids = tx.data.new_committee.map(m => m.node_id);
    expect(ids).toEqual([...ids].sort());
    // Includes BOTH the founding node and the peer
    expect(ids).toContain(FOUNDING.node_id);
    expect(ids).toContain("tip://node/peer");

    // Single signer (MVP — only own key; multi-sig coordination is a
    // follow-up). Quorum for previous committee size 1 = 1 → meets.
    expect(tx.data.signer_node_ids).toEqual([FOUNDING.node_id]);
    expect(tx.data.signatures).toHaveLength(1);
  });

  test("does NOT fire when proposer config is omitted (test/legacy mode)", () => {
    const fx = _setup({ withProposer: false });
    _seedCertsByRound(fx.dag, { 1: [FOUNDING.node_id] });
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 1, voteRound: 2, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });
    expect(fx.submittedTxs).toHaveLength(0);
  });

  test("only the leader fires; non-leaders skip", () => {
    const fx = _setup();
    // Set up a 2-node "committee" where the leader is NOT us.
    // Wave 1's leader = sorted([nodeA, nodeB])[wave % 2]. wave for round 1 = 0.
    // So leader = sorted[0] = whichever node_id sorts first.
    fx.dag.saveNode({
      node_id: "tip://node/0-aaa", name: "a", public_key: "kA",
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });

    // Override getNodeIds to return both nodes — committee for the wave
    const dag = fx.dag;
    const submittedTxs = [];
    const proposer = {
      nodeId: FOUNDING.node_id,  // we're the founding_node, NOT the wave leader
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

    // Wave 1: leader is sorted[0] = "tip://node/0-aaa" (sorts before founding's tip://node/f612...)
    _seedCertsByRound(dag, {
      1: ["tip://node/0-aaa"],
      2: ["tip://node/0-aaa", FOUNDING.node_id],
    });
    _driveAnchorCommit(dag, bullshark, {
      proposeRound: 1, voteRound: 2, leader: "tip://node/0-aaa",
      voteAuthors: ["tip://node/0-aaa", FOUNDING.node_id],
    });

    // Our nodeId is FOUNDING.node_id, but the leader was 0-aaa →
    // we should NOT have fired the proposer.
    expect(submittedTxs).toHaveLength(0);
  });

  test("fires on 7-day periodic backstop even when committee unchanged", () => {
    // Set up: only founding_node is registered + producing. Committee is
    // unchanged from rotation 0. Normally proposer wouldn't fire — but
    // the backstop forces a re-attestation rotation when more than
    // committee_rotation_interval_rounds (302400 ≈ 7d) have elapsed
    // since the last rotation's effective_round.
    const fx = _setup();

    // Rotation 0's effective_round=0 (genesis bootstrap), so any current
    // round >= 302400 triggers the periodic backstop. Drive an anchor
    // commit at round 302402 (vote round of wave 150700).
    const proposeRound = 302401;
    const voteRound = 302402;

    _seedCertsByRound(fx.dag, {
      [proposeRound]: [FOUNDING.node_id],
      [voteRound]: [FOUNDING.node_id],
    });

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound, voteRound, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id],
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const tx = fx.submittedTxs[0];
    expect(tx.tx_type).toBe(TX_TYPES.COMMITTEE_ROTATION);
    expect(tx.data.rotation_number).toBe(1);
    expect(tx.data.effective_round).toBe(voteRound + 1);
    // Periodic re-attestation: committee composition is the same single
    // founding_node, but the rotation entry refreshes the chain's signed
    // claim of "the committee is X as of this round".
    const ids = tx.data.new_committee.map(m => m.node_id);
    expect(ids).toEqual([FOUNDING.node_id]);
  });

  test("payload_hash matches canonical claim shake256(rotation_number, effective_round, new_committee)", () => {
    const fx = _setup();
    fx.dag.saveNode({
      node_id: "tip://node/peer", name: "peer", public_key: "peer-pubkey",
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
    _seedCertsByRound(fx.dag, {
      1: [FOUNDING.node_id, "tip://node/peer"],
      2: [FOUNDING.node_id, "tip://node/peer"],
    });

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 1, voteRound: 2, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id, "tip://node/peer"],
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
});
