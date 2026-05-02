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

// Seed a CONTIGUOUS range of certs so proposer's cert-history guard
// passes. Required for tests that want the proposer to fire — the
// guard refuses to propose unless history >= COMMITTEE_ROTATION_HYSTERESIS_ROUNDS
// (default K=300). Pass `authors` as the producers in every round of
// the range.
function _seedCertRange(dag, fromRound, toRound, authors) {
  const byRound = {};
  for (let r = fromRound; r <= toRound; r++) byRound[r] = authors;
  _seedCertsByRound(dag, byRound);
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
    // Seed enough cert history to pass the K=300 cert-history guard.
    // Both founding and peer produce in every round of the range.
    _seedCertRange(fx.dag, 1, 400, [FOUNDING.node_id, "tip://node/peer"]);

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 401, voteRound: 402, leader: FOUNDING.node_id,
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

    // Seed continuous cert range from round 1 so the cert-history guard
    // passes (history = currentRound - 1 >> K=300).
    _seedCertRange(fx.dag, 1, voteRound, [FOUNDING.node_id]);

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

  test("does NOT fire when local cert history is shorter than K (post-snapshot joiner)", () => {
    // Simulates a fresh joiner that snapshot-installed at round N. Its
    // certificates table only has certs from N+1 onwards (snapshot
    // doesn't ship raw certs; cert sync only goes forward). When this
    // node tries to propose a rotation at round N+50, its K=300 window
    // [N+50-300, N+50-1] is mostly EMPTY for it but full for peers who
    // have been running since round 1 — they'd disagree → flap.
    //
    // The cert-history guard refuses to propose until the node has
    // accumulated COMMITTEE_ROTATION_HYSTERESIS_ROUNDS of cert history,
    // by which point its view matches peers'.
    const fx = _setup();
    fx.dag.saveNode({
      node_id: "tip://node/peer", name: "peer", public_key: "peer-pubkey",
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });

    // Simulate post-snapshot state: certs only exist from round 100000 onward
    // (joiner snapshot-installed at round 99999, started producing at 100000).
    // K=300 hysteresis. waveStartRound = 100049 → window = [99749, 100048].
    // earliest_cert = 100000. history = 100049 - 100000 = 49 rounds — much
    // less than K=300 → proposer must skip.
    _seedCertsByRound(fx.dag, {
      100000: [FOUNDING.node_id],
      100001: [FOUNDING.node_id, "tip://node/peer"],
      // ... etc — only post-join certs
    });

    // Drive an anchor commit at round 100050. waveStartRound = 100049,
    // founding leads (only single committee member). Without the guard,
    // founding would see "peer never produced before round 100001"
    // and propose dropping peer.
    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 100049, voteRound: 100050, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id, "tip://node/peer"],
    });

    expect(fx.submittedTxs).toHaveLength(0);  // skipped due to insufficient history
  });

  test("fires once cert history covers full K-window", () => {
    const fx = _setup();
    fx.dag.saveNode({
      node_id: "tip://node/peer", name: "peer", public_key: "peer-pubkey",
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });

    // Seed certs from round 1 onwards so the cert-history check passes
    // (history = currentRound - 1 >> K=300). Both nodes have been
    // producing the entire time → wouldBe correctly includes peer.
    const certs = {};
    for (let r = 1; r <= 400; r++) {
      certs[r] = [FOUNDING.node_id, "tip://node/peer"];
    }
    _seedCertsByRound(fx.dag, certs);

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 401, voteRound: 402, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id, "tip://node/peer"],
    });

    // Has full history, sees peer producing → proposes adding peer to committee
    expect(fx.submittedTxs).toHaveLength(1);
    const ids = fx.submittedTxs[0].data.new_committee.map(m => m.node_id);
    expect(ids).toContain("tip://node/peer");
  });

  test("filters nodes with no public_key in the nodes table from new_committee", () => {
    const fx = _setup();
    // Register a node WITHOUT a public_key, plus one WITH. Both produce
    // certs in the K window. Filter must drop the no-pubkey one so the
    // resulting rotation has only verifiable members.
    fx.dag.saveNode({
      node_id: "tip://node/no-key", name: "no-key",
      public_key: "",   // empty pubkey
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
    fx.dag.saveNode({
      node_id: "tip://node/with-key", name: "with-key",
      public_key: "real-pubkey-hex",
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
    // Seed enough cert history to pass the K=300 cert-history guard.
    _seedCertRange(fx.dag, 1, 400, [FOUNDING.node_id, "tip://node/no-key", "tip://node/with-key"]);

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 401, voteRound: 402, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id, "tip://node/no-key", "tip://node/with-key"],
    });

    expect(fx.submittedTxs).toHaveLength(1);
    const ids = fx.submittedTxs[0].data.new_committee.map(m => m.node_id);
    // founding + with-key included; no-key filtered out
    expect(ids).toContain(FOUNDING.node_id);
    expect(ids).toContain("tip://node/with-key");
    expect(ids).not.toContain("tip://node/no-key");
  });

  test("submitTx throws synchronously → bullshark catches, anchor commit unaffected", () => {
    // Wire a proposer whose submitTx throws (simulates triggerSubmitter
    // raising 503 when consensus isn't fully wired). Bullshark must
    // catch + log + continue — never propagate up to the anchor commit
    // path.
    const dag = initDAG({ inMemory: true });
    if (!dag.getNode(FOUNDING.node_id)) {
      dag.saveNode({
        node_id: FOUNDING.node_id, name: "founding", public_key: FOUNDING.public_key,
        status: "active", registered_at: "2026-01-01T00:00:00.000Z",
      });
    }
    dag.saveNode({
      node_id: "tip://node/peer", name: "peer", public_key: "peer-pubkey",
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });

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

    // Seed K rounds of cert history so the cert-history guard passes
    // and the proposer actually attempts to submit (so we can test
    // submitTx-throws path).
    for (let r = 1; r <= 400; r++) {
      dag.saveCertificate(_buildCert({ round: r, author: FOUNDING.node_id }));
      dag.saveCertificate(_buildCert({ round: r, author: "tip://node/peer", hash: shake256(`peer-${r}`) }));
    }

    // Should NOT throw — bullshark's _checkAnchorCommit catches the
    // proposer's synchronous throw and logs it.
    expect(() => _driveAnchorCommit(dag, bullshark, {
      proposeRound: 401, voteRound: 402, leader: FOUNDING.node_id,
      voteAuthors: [FOUNDING.node_id, "tip://node/peer"],
    })).not.toThrow();

    expect(submitCalls).toBe(1);  // proposer attempted to submit

    // Anchor commit still landed despite proposer failure
    expect(bullshark.lastCommittedRound()).toBe(402);

    // Proposal counter incremented even on submit failure (operators
    // care about "leader tried" regardless of downstream success).
    expect(bullshark.stats().metrics.committee_rotation_proposals).toBe(1);
  });

  test("payload_hash matches canonical claim shake256(rotation_number, effective_round, new_committee)", () => {
    const fx = _setup();
    fx.dag.saveNode({
      node_id: "tip://node/peer", name: "peer", public_key: "peer-pubkey",
      status: "active", registered_at: "2026-01-01T00:00:00.000Z",
    });
    // Seed enough cert history to pass the K=300 cert-history guard.
    _seedCertRange(fx.dag, 1, 400, [FOUNDING.node_id, "tip://node/peer"]);

    _driveAnchorCommit(fx.dag, fx.bullshark, {
      proposeRound: 401, voteRound: 402, leader: FOUNDING.node_id,
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
