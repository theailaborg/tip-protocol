/**
 * @file tests/consensus/commit-handler-jury.test.js
 * @description Issue #13 + #15 commit-handler tests — verifies that:
 *
 *   - Jury / appeal score effects are applied via SCORE_UPDATE handler
 *     (not via in-line scoring.applyScoreEvent in jury.js).
 *   - First-wins dedup catches multi-node race when two competing
 *     schedulers each submit a verdict batch for the same ctid.
 *   - SCORE_UPDATE dedup prevents double-counting per (tip_id, ctid, reason).
 *   - APPEAL_RESULT applies content-state reversal across all four
 *     overturn / confirm branches.
 *   - JURY_VOTE_REVEAL is rejected at commit time when its tx.timestamp
 *     exceeds the JURY_SUMMONS reveal_deadline.
 *
 * Drives commit-handler directly with synthetic txs (skips the consensus
 * round-trip — bullshark's anchor commit path is covered by the BFT-Time
 * tests). Each test seeds the DAG with the prerequisites then invokes
 * `commitOrderedTxs` with the candidate txs.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, signTransaction, computeTxId, shake256 } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, VERDICT, VOTE, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { JURY, APPEAL, DISPUTE } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));

beforeAll(async () => {
  await initCrypto();
});

// ═══════════════════════════════════════════════════════════════════════════
// Test fixture — minimal dispute setup (author, disputer, juror, content,
// dispute, summons) so commit-handler can exercise verdict-time logic.
// ═══════════════════════════════════════════════════════════════════════════
function _setupDisputeFixture(opts = {}) {
  const dag = initDAG({ dbPath: ":memory:" });
  // Two real node keypairs so commit-handler's signature verifier accepts
  // node-signed synthetic txs from both "competing" nodes — needed to
  // drive the multi-node race tests.
  const nodes = ["tip://node/n1", "tip://node/n2"].map(nodeId => {
    const kp = generateMLDSAKeypair();
    dag.saveNode({
      node_id: nodeId, name: nodeId.split("/").pop(), public_key: kp.publicKey,
      status: "active", registered_at: 1767225600000,
    });
    return { nodeId, ...kp };
  });
  const config = {
    nodeId: nodes[0].nodeId,
    nodeRegisteredId: nodes[0].nodeId,
    nodePrivateKey: nodes[0].privateKey,
  };
  const scoring = initScoring(dag, config);
  const handler = createCommitHandler({ dag, scoring, config });

  const ctid = "tip://content/test-1";
  const authorTipId = "tip://id/author";
  const disputerTipId = "tip://id/disputer";
  const jurorTipIds = (opts.jurorTipIds || ["tip://id/juror0", "tip://id/juror1", "tip://id/juror2"]);

  // Identities — keypairs preserved on the fixture so tests that need to
  // sign user-attributed txs (reveals signed by jurors, etc.) can do so.
  const identityKeys = {};
  for (const tipId of [authorTipId, disputerTipId, ...jurorTipIds]) {
    const kp = generateMLDSAKeypair();
    identityKeys[tipId] = kp;
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: "00", vp_id: "tip://vp/v1",
      verification_tier: "T1", founding: false, status: "active",
      registered_at: 1767225600000, tx_id: shake256(`id:${tipId}`),
    });
    dag.setScore(tipId, 750, 0, 1767225600000);
  }

  // Content + dispute
  dag.saveContent({
    ctid, origin_code: "OH", content_hash: shake256("content-1"),
    author_tip_id: authorTipId, status: CONTENT_STATUS.DISPUTED,
    registered_at: 1767225600000, tx_id: shake256(`content:${ctid}`),
  });

  // Backdated reveal_deadline so test reveals don't trip the window guard
  // by accident. Tests that DO need the guard use their own deadline.
  const revealDeadline = opts.revealDeadline || 4070908800000;

  const disputeTxBody = {
    tx_type: TX_TYPES.CONTENT_DISPUTED,
    timestamp: 1767225600000,
    prev: [],
    data: {
      ctid, disputer_tip_id: disputerTipId, reason: "origin_mismatch",
      claimed_origin: "AG", declared_origin: "OH",
      author_tip_id: authorTipId, pre_dispute_status: CONTENT_STATUS.REGISTERED,
      stake: DISPUTE.DISPUTER_STAKE,
    },
  };
  disputeTxBody.tx_id = computeTxId(disputeTxBody);
  disputeTxBody.signature = "00";
  dag.addTx(disputeTxBody);

  // Summons for each juror
  for (const jurorTipId of jurorTipIds) {
    const summonsBody = {
      tx_type: TX_TYPES.JURY_SUMMONS,
      timestamp: 1767225600000,
      prev: [],
      data: {
        ctid, dispute_tx_id: disputeTxBody.tx_id, juror_tip_id: jurorTipId,
        commit_deadline: 1767312000000,
        reveal_deadline: revealDeadline,
        node_id: "tip://node/n1",
      },
    };
    summonsBody.tx_id = computeTxId(summonsBody);
    summonsBody.signature = "00";
    dag.addTx(summonsBody);
  }

  return { dag, scoring, handler, config, ctid, authorTipId, disputerTipId, jurorTipIds, disputeTx: disputeTxBody, nodes, identityKeys };
}

// Helper to build a node-signed tx for any tx_type — uses one of the two
// fixture nodes. Caller picks which (default: 0 = primary). prev is
// resolved at build-time from the live DAG ring.
function _signByNode(fx, nodeIndex, txBody) {
  const node = fx.nodes[nodeIndex];
  txBody.prev = txBody.prev && txBody.prev.length ? txBody.prev : fx.dag.getRecentPrev();
  txBody.data = txBody.data || {};
  txBody.data.node_id = node.nodeId;
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, node.privateKey);
}

function _scoreUpdateTx(fx, { tipId, delta, reason, ctid, relatedTxId, nodeIndex = 0 }) {
  return _signByNode(fx, nodeIndex, {
    tx_type: TX_TYPES.SCORE_UPDATE,
    timestamp: 1767398400000,
    prev: [],
    data: {
      tip_id: tipId, delta, reason,
      ctid: ctid || null,
      related_tx_id: relatedTxId || null,
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. SCORE_UPDATE handler — real cache mutation (#15)
// ═══════════════════════════════════════════════════════════════════════════
describe("commit-handler SCORE_UPDATE: real cache mutation", () => {
  test("applies positive delta to tip_id's score cache", () => {
    const fx = _setupDisputeFixture();
    const before = fx.dag.getScore(fx.jurorTipIds[0]).score;

    const tx = _scoreUpdateTx(fx, {
      tipId: fx.jurorTipIds[0],
      delta: JURY.JUROR_MAJORITY_BONUS,
      reason: `Jury majority vote on ${fx.ctid}`,
      ctid: fx.ctid,
      relatedTxId: "adj-1",
    });

    fx.handler.commitOrderedTxs([tx], 100);

    const after = fx.dag.getScore(fx.jurorTipIds[0]).score;
    expect(after).toBe(before + JURY.JUROR_MAJORITY_BONUS);
  });

  test("applies negative delta correctly (no-commit penalty)", () => {
    const fx = _setupDisputeFixture();
    const before = fx.dag.getScore(fx.jurorTipIds[1]).score;

    const tx = _scoreUpdateTx(fx, {
      tipId: fx.jurorTipIds[1],
      delta: -JURY.JUROR_NO_COMMIT_PENALTY,
      reason: `Jury no-commit on ${fx.ctid}`,
      ctid: fx.ctid,
    });

    fx.handler.commitOrderedTxs([tx], 100);

    const after = fx.dag.getScore(fx.jurorTipIds[1]).score;
    expect(after).toBe(before - JURY.JUROR_NO_COMMIT_PENALTY);
  });

  test("clamps to [0, 1000] regardless of delta magnitude", () => {
    const fx = _setupDisputeFixture();
    fx.dag.setScore(fx.jurorTipIds[0], 990, 0, 1767225600000);
    const tx = _scoreUpdateTx(fx, {
      tipId: fx.jurorTipIds[0], delta: 100, reason: "test-overflow", ctid: null,
    });
    fx.handler.commitOrderedTxs([tx], 100);
    expect(fx.dag.getScore(fx.jurorTipIds[0]).score).toBe(1000);

    fx.dag.setScore(fx.jurorTipIds[0], 5, 0, 1767225600000);
    const tx2 = _scoreUpdateTx(fx, {
      tipId: fx.jurorTipIds[0], delta: -100, reason: "test-underflow", ctid: null,
    });
    fx.handler.commitOrderedTxs([tx2], 101);
    expect(fx.dag.getScore(fx.jurorTipIds[0]).score).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. SCORE_UPDATE first-wins dedup
// ═══════════════════════════════════════════════════════════════════════════
describe("commit-handler SCORE_UPDATE: first-wins dedup", () => {
  test("two SCORE_UPDATEs with identical (tip_id, ctid, reason) — only first applies", () => {
    const fx = _setupDisputeFixture();
    fx.dag.setScore(fx.jurorTipIds[0], 750, 0, 1767225600000);

    const reason = `Jury majority vote on ${fx.ctid}`;
    // Two competing nodes submit the SAME logical SCORE_UPDATE — different
    // signers → different tx_ids — but identical (tip_id, ctid, reason)
    // tuple. Dedup at commit-handler must drop one of them.
    const tx1 = _scoreUpdateTx(fx, { tipId: fx.jurorTipIds[0], delta: JURY.JUROR_MAJORITY_BONUS, reason, ctid: fx.ctid, nodeIndex: 0 });
    const tx2 = _scoreUpdateTx(fx, { tipId: fx.jurorTipIds[0], delta: JURY.JUROR_MAJORITY_BONUS, reason, ctid: fx.ctid, nodeIndex: 1 });

    const result = fx.handler.commitOrderedTxs([tx1, tx2], 100);
    expect(result.committed).toBe(1);
    expect(result.dropped).toBe(1);

    const after = fx.dag.getScore(fx.jurorTipIds[0]).score;
    expect(after).toBe(750 + JURY.JUROR_MAJORITY_BONUS);  // applied ONCE, not twice
  });

  test("same tip_id + ctid + DIFFERENT reason → both apply (legitimately distinct events)", () => {
    const fx = _setupDisputeFixture();
    fx.dag.setScore(fx.jurorTipIds[0], 750, 0, 1767225600000);

    const tx1 = _scoreUpdateTx(fx, {
      tipId: fx.jurorTipIds[0], delta: JURY.JUROR_MAJORITY_BONUS,
      reason: `Jury majority vote on ${fx.ctid}`, ctid: fx.ctid,
    });
    const tx2 = _scoreUpdateTx(fx, {
      tipId: fx.jurorTipIds[0], delta: -JURY.JUROR_MINORITY_PENALTY,
      reason: `Expert minority vote on ${fx.ctid}`, ctid: fx.ctid,
    });

    const result = fx.handler.commitOrderedTxs([tx1, tx2], 100);
    expect(result.committed).toBe(2);
    expect(result.dropped).toBe(0);
  });

  test("dedup applies across rounds — same SCORE_UPDATE arriving in round R+1 is dropped", () => {
    const fx = _setupDisputeFixture();
    fx.dag.setScore(fx.jurorTipIds[0], 750, 0, 1767225600000);

    const reason = `Jury majority vote on ${fx.ctid}`;
    const tx1 = _scoreUpdateTx(fx, { tipId: fx.jurorTipIds[0], delta: JURY.JUROR_MAJORITY_BONUS, reason, ctid: fx.ctid, nodeIndex: 0 });
    fx.handler.commitOrderedTxs([tx1], 100);
    const after1 = fx.dag.getScore(fx.jurorTipIds[0]).score;

    // Different node submits same logical SCORE_UPDATE in a later round.
    const tx2 = _scoreUpdateTx(fx, { tipId: fx.jurorTipIds[0], delta: JURY.JUROR_MAJORITY_BONUS, reason, ctid: fx.ctid, nodeIndex: 1 });
    const result = fx.handler.commitOrderedTxs([tx2], 101);
    const after2 = fx.dag.getScore(fx.jurorTipIds[0]).score;

    expect(result.dropped).toBe(1);
    expect(after2).toBe(after1);  // unchanged
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. ADJUDICATION_RESULT first-wins per ctid
// ═══════════════════════════════════════════════════════════════════════════
describe("commit-handler ADJUDICATION_RESULT: first-wins per ctid", () => {
  function _adjTx(fx, nodeIndex, ctid, verdict) {
    return _signByNode(fx, nodeIndex, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: 1767398400000,
      prev: [],
      data: {
        ctid, verdict, declared_origin: "OH",
        confirmed_origin: verdict === VERDICT.UPHELD ? "AG" : null,
        author_tip_id: "tip://id/author",
        author_score_delta: verdict === VERDICT.UPHELD ? -50 : 0,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
        match_count: 1, mismatch_count: 2, abstain_count: 0,
      },
    });
  }

  test("two ADJUDICATION_RESULTs for same ctid in same batch — only first lands", () => {
    const fx = _setupDisputeFixture();

    const tx1 = _adjTx(fx, 0, fx.ctid, VERDICT.UPHELD);
    const tx2 = _adjTx(fx, 1, fx.ctid, VERDICT.DISMISSED);

    const result = fx.handler.commitOrderedTxs([tx1, tx2], 100);
    expect(result.committed).toBe(1);
    expect(result.dropped).toBe(1);

    // Content origin should reflect tx1 (UPHELD → AG, VERIFIED).
    const c = fx.dag.getContent(fx.ctid);
    expect(c.origin_code).toBe("AG");
    expect(c.status).toBe(CONTENT_STATUS.VERIFIED);
  });

  test("ADJUDICATION_RESULT in round R+1 dropped if one already exists from round R", () => {
    const fx = _setupDisputeFixture();

    const tx1 = _adjTx(fx, 0, fx.ctid, VERDICT.UPHELD);
    fx.handler.commitOrderedTxs([tx1], 100);

    const tx2 = _adjTx(fx, 1, fx.ctid, VERDICT.UPHELD);
    const result = fx.handler.commitOrderedTxs([tx2], 101);
    expect(result.dropped).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3b. ADJUDICATION_RESULT NO_QUORUM — terminal restores content, non-terminal
//     leaves it parked for the escalated appeal to finalise.
// ═══════════════════════════════════════════════════════════════════════════
describe("commit-handler ADJUDICATION_RESULT: NO_QUORUM content status", () => {
  function _noQuorumAdjTx(fx, ctid, terminal) {
    return _signByNode(fx, 0, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: 1767398400000,
      prev: [],
      data: {
        ctid, verdict: VERDICT.NO_QUORUM, terminal,
        declared_origin: "OH", confirmed_origin: null,
        author_tip_id: "tip://id/author", author_score_delta: 0,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
        match_count: 0, mismatch_count: 0, abstain_count: 0,
      },
    });
  }

  test("terminal NO_QUORUM restores content to pre-dispute status", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.DISPUTED);

    fx.handler.commitOrderedTxs([_noQuorumAdjTx(fx, fx.ctid, true)], 100);

    // No Stage-3 panel was formable, so there will be no APPEAL_RESULT —
    // the content must not be left parked in DISPUTED forever.
    expect(fx.dag.getContent(fx.ctid).status).toBe(CONTENT_STATUS.REGISTERED);
  });

  test("non-terminal NO_QUORUM leaves content parked (appeal will finalise)", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.DISPUTED);

    fx.handler.commitOrderedTxs([_noQuorumAdjTx(fx, fx.ctid, false)], 100);

    // The case escalated to Stage 3; its APPEAL_RESULT will set the final
    // status. Touching it here would race that outcome.
    expect(fx.dag.getContent(fx.ctid).status).toBe(CONTENT_STATUS.DISPUTED);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. APPEAL_RESULT — content-state reversal effects (#15)
// ═══════════════════════════════════════════════════════════════════════════
describe("commit-handler APPEAL_RESULT: content-state effects", () => {
  function _appealTx(fx, ctid, opts) {
    return _signByNode(fx, 0, {
      tx_type: TX_TYPES.APPEAL_RESULT,
      timestamp: 1767484800000,
      prev: [],
      data: {
        ctid,
        verdict: opts.verdict,
        overturned: opts.overturned,
        stage2_verdict: opts.stage2_verdict,
        declared_origin: opts.declared_origin || "OH",
        confirmed_origin: opts.confirmed_origin || null,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
        original_author_delta: opts.original_author_delta || 0,
        overturn_author_delta: opts.overturn_author_delta || 0,
        match_count: 1, mismatch_count: 2, abstain_count: 0,
      },
    });
  }

  test("OVERTURN UPHELD→DISMISSED: restores declared origin + pre-dispute status", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentOrigin(fx.ctid, "AG", CONTENT_STATUS.VERIFIED);  // simulate stage2 UPHELD

    const tx = _appealTx(fx, fx.ctid, {
      verdict: VERDICT.DISMISSED, overturned: true,
      stage2_verdict: VERDICT.UPHELD, declared_origin: "OH",
    });
    fx.handler.commitOrderedTxs([tx], 200);

    const c = fx.dag.getContent(fx.ctid);
    expect(c.origin_code).toBe("OH");
    expect(c.status).toBe(CONTENT_STATUS.REGISTERED);
  });

  test("OVERTURN DISMISSED→UPHELD: sets confirmed origin + verified status", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.REGISTERED);

    const tx = _appealTx(fx, fx.ctid, {
      verdict: VERDICT.UPHELD, overturned: true,
      stage2_verdict: VERDICT.DISMISSED,
      declared_origin: "OH", confirmed_origin: "AG",
    });
    fx.handler.commitOrderedTxs([tx], 200);

    const c = fx.dag.getContent(fx.ctid);
    expect(c.origin_code).toBe("AG");
    expect(c.status).toBe(CONTENT_STATUS.VERIFIED);
  });

  test("CONFIRM UPHELD: experts agree with stage2 — verified with confirmed origin", () => {
    const fx = _setupDisputeFixture();
    const tx = _appealTx(fx, fx.ctid, {
      verdict: VERDICT.UPHELD, overturned: false,
      stage2_verdict: VERDICT.UPHELD,
      declared_origin: "OH", confirmed_origin: "AG",
    });
    fx.handler.commitOrderedTxs([tx], 200);

    const c = fx.dag.getContent(fx.ctid);
    expect(c.origin_code).toBe("AG");
    expect(c.status).toBe(CONTENT_STATUS.VERIFIED);
  });

  test("CONFIRM DISMISSED: experts agree with stage2 — restored to pre-dispute status", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.DISPUTED);  // mid-dispute

    const tx = _appealTx(fx, fx.ctid, {
      verdict: VERDICT.DISMISSED, overturned: false,
      stage2_verdict: VERDICT.DISMISSED, declared_origin: "OH",
    });
    fx.handler.commitOrderedTxs([tx], 200);

    const c = fx.dag.getContent(fx.ctid);
    expect(c.status).toBe(CONTENT_STATUS.REGISTERED);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4b. Post-resolution status: PENDING_REVIEW must not be replayed verbatim
//
// When a prescan review was open at escalation time, pre_dispute_status
// captures PENDING_REVIEW. Once the dispute resolves in the author's favor
// the review row is terminal (ESCALATED_TO_DISPUTE) — restoring
// PENDING_REVIEW would leave the UI showing "Under Review" forever even
// though no reviewer is waiting. The dispute outcome positively cleared
// the content → VERIFIED.
// ═══════════════════════════════════════════════════════════════════════════
describe("commit-handler post-resolution status: pre_dispute_status=PENDING_REVIEW", () => {
  function _adjTxWithPreReview(fx, ctid, verdict) {
    return _signByNode(fx, 0, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: 1767398400000,
      prev: [],
      data: {
        ctid, verdict, declared_origin: "OH", confirmed_origin: null,
        author_tip_id: "tip://id/author", author_score_delta: 0,
        pre_dispute_status: CONTENT_STATUS.PENDING_REVIEW,
        match_count: 2, mismatch_count: 1, abstain_count: 0,
      },
    });
  }

  function _appealTxWithPreReview(fx, ctid, opts) {
    return _signByNode(fx, 0, {
      tx_type: TX_TYPES.APPEAL_RESULT,
      timestamp: 1767484800000,
      prev: [],
      data: {
        ctid,
        verdict: opts.verdict,
        overturned: opts.overturned,
        stage2_verdict: opts.stage2_verdict,
        declared_origin: opts.declared_origin || "OH",
        confirmed_origin: opts.confirmed_origin || null,
        pre_dispute_status: CONTENT_STATUS.PENDING_REVIEW,
        original_author_delta: 0, overturn_author_delta: 0,
        match_count: 2, mismatch_count: 1, abstain_count: 0,
      },
    });
  }

  test("ADJUDICATION_RESULT DISMISSED with pre_dispute_status=PENDING_REVIEW → VERIFIED", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.DISPUTED);

    const tx = _adjTxWithPreReview(fx, fx.ctid, VERDICT.DISMISSED);
    fx.handler.commitOrderedTxs([tx], 100);

    expect(fx.dag.getContent(fx.ctid).status).toBe(CONTENT_STATUS.VERIFIED);
  });

  test("ADJUDICATION_RESULT CONSERVATIVE_LABEL with pre_dispute_status=PENDING_REVIEW → VERIFIED", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.DISPUTED);

    const tx = _adjTxWithPreReview(fx, fx.ctid, VERDICT.CONSERVATIVE_LABEL);
    fx.handler.commitOrderedTxs([tx], 100);

    expect(fx.dag.getContent(fx.ctid).status).toBe(CONTENT_STATUS.VERIFIED);
  });

  test("APPEAL_RESULT overturn UPHELD→DISMISSED with pre_dispute_status=PENDING_REVIEW → VERIFIED", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentOrigin(fx.ctid, "AG", CONTENT_STATUS.VERIFIED);  // simulate stage2 UPHELD

    const tx = _appealTxWithPreReview(fx, fx.ctid, {
      verdict: VERDICT.DISMISSED, overturned: true,
      stage2_verdict: VERDICT.UPHELD, declared_origin: "OH",
    });
    fx.handler.commitOrderedTxs([tx], 200);

    const c = fx.dag.getContent(fx.ctid);
    expect(c.origin_code).toBe("OH");
    expect(c.status).toBe(CONTENT_STATUS.VERIFIED);
  });

  test("APPEAL_RESULT CONFIRM DISMISSED with pre_dispute_status=PENDING_REVIEW → VERIFIED", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.DISPUTED);

    const tx = _appealTxWithPreReview(fx, fx.ctid, {
      verdict: VERDICT.DISMISSED, overturned: false,
      stage2_verdict: VERDICT.DISMISSED, declared_origin: "OH",
    });
    fx.handler.commitOrderedTxs([tx], 200);

    expect(fx.dag.getContent(fx.ctid).status).toBe(CONTENT_STATUS.VERIFIED);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4c. Non-resolution paths — content.status liveness
//
// "Nobody voted" / "deadline crossed without enough reveals" outcomes:
//   - Stage-2 NO_QUORUM is emitted but does NOT mutate content.status —
//     content stays `disputed` while Stage-3 auto-escalation runs.
//   - Stage-3 defaulted DISMISSED (insufficient experts) lands the same
//     as a real DISMISSED — _postResolutionStatus applies, so a review-
//     escalated dispute resolves cleanly to VERIFIED even with zero votes.
// Together with verdict-trigger's heap-driven retry, this guarantees the
// content cannot remain in `disputed` indefinitely.
// ═══════════════════════════════════════════════════════════════════════════
describe("commit-handler non-resolution paths: status liveness", () => {
  test("ADJUDICATION_RESULT NO_QUORUM does not mutate content.status (stays disputed)", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.DISPUTED);

    const tx = _signByNode(fx, 0, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: 1767398400000,
      prev: [],
      data: {
        ctid: fx.ctid, verdict: VERDICT.NO_QUORUM,
        declared_origin: "OH", confirmed_origin: null,
        author_tip_id: "tip://id/author", author_score_delta: 0,
        pre_dispute_status: CONTENT_STATUS.PENDING_REVIEW,
        match_count: 0, mismatch_count: 0, abstain_count: 0,
      },
    });
    fx.handler.commitOrderedTxs([tx], 100);

    expect(fx.dag.getContent(fx.ctid).status).toBe(CONTENT_STATUS.DISPUTED);
  });

  test("APPEAL_RESULT defaulted DISMISSED (no expert reveals) with pre=REGISTERED → REGISTERED", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.DISPUTED);

    const tx = _signByNode(fx, 0, {
      tx_type: TX_TYPES.APPEAL_RESULT,
      timestamp: 1767484800000,
      prev: [],
      data: {
        ctid: fx.ctid,
        verdict: VERDICT.DISMISSED, overturned: false, defaulted: true,
        stage2_verdict: VERDICT.NO_QUORUM,
        declared_origin: "OH", confirmed_origin: null,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
        original_author_delta: 0, overturn_author_delta: 0,
        match_count: 0, mismatch_count: 0, abstain_count: 0,
      },
    });
    fx.handler.commitOrderedTxs([tx], 200);

    expect(fx.dag.getContent(fx.ctid).status).toBe(CONTENT_STATUS.REGISTERED);
  });

  test("APPEAL_RESULT defaulted DISMISSED (no expert reveals) with pre=PENDING_REVIEW → VERIFIED", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.DISPUTED);

    const tx = _signByNode(fx, 0, {
      tx_type: TX_TYPES.APPEAL_RESULT,
      timestamp: 1767484800000,
      prev: [],
      data: {
        ctid: fx.ctid,
        verdict: VERDICT.DISMISSED, overturned: false, defaulted: true,
        stage2_verdict: VERDICT.NO_QUORUM,
        declared_origin: "OH", confirmed_origin: null,
        pre_dispute_status: CONTENT_STATUS.PENDING_REVIEW,
        original_author_delta: 0, overturn_author_delta: 0,
        match_count: 0, mismatch_count: 0, abstain_count: 0,
      },
    });
    fx.handler.commitOrderedTxs([tx], 200);

    expect(fx.dag.getContent(fx.ctid).status).toBe(CONTENT_STATUS.VERIFIED);
  });

  test("ADJUDICATION_RESULT with unknown verdict does not mutate content.status", () => {
    const fx = _setupDisputeFixture();
    fx.dag.updateContentStatus(fx.ctid, CONTENT_STATUS.DISPUTED);

    const tx = _signByNode(fx, 0, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: 1767398400000,
      prev: [],
      data: {
        ctid: fx.ctid, verdict: "UNKNOWN_FUTURE_VERDICT",
        declared_origin: "OH", confirmed_origin: null,
        author_tip_id: "tip://id/author", author_score_delta: 0,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
        match_count: 0, mismatch_count: 0, abstain_count: 0,
      },
    });
    fx.handler.commitOrderedTxs([tx], 100);

    expect(fx.dag.getContent(fx.ctid).status).toBe(CONTENT_STATUS.DISPUTED);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. JURY_VOTE_REVEAL window enforcement (#13 third guard)
// ═══════════════════════════════════════════════════════════════════════════
describe("commit-handler JURY_VOTE_REVEAL: reveal-window enforcement", () => {
  // Save a matching JURY_VOTE_COMMIT for the juror so the reveal's
  // commitment-match check (canRevealVote) passes — these tests target
  // the window guard, not the commitment guard.
  function _saveMatchingCommit(fx, jurorTipId) {
    const commitBody = {
      tx_type: TX_TYPES.JURY_VOTE_COMMIT,
      timestamp: 1767312000000,
      prev: [],
      data: {
        ctid: fx.ctid, juror_tip_id: jurorTipId,
        commitment: shake256(`${VOTE.MISMATCH}:abc`),
        signature: "00",
      },
    };
    commitBody.tx_id = computeTxId(commitBody);
    fx.dag.addTx(commitBody);
  }

  // Properly signs the reveal body with the juror's keypair so signature
  // verification passes — this isolates the window-guard test from the
  // signature-gate behavior. We use the canonical body fields the
  // verifier checks (juror_tip_id, vote, salt, confirmed_origin) and a
  // body-signature flow matching the real client path.
  function _revealTx(fx, jurorTipId, timestampISO) {
    const { signBody } = require(path.join(SHARED, "crypto"));
    const kp = fx.identityKeys[jurorTipId];
    // The signed payload is exactly the fields the verifier checks
    // (juror_tip_id, vote, salt, confirmed_origin).
    const signedFields = {
      juror_tip_id: jurorTipId, vote: VOTE.MISMATCH, salt: "abc", confirmed_origin: "AG",
    };
    const data = { ...signedFields, ctid: fx.ctid };
    const signature = signBody(signedFields, kp.privateKey);
    const txBody = {
      tx_type: TX_TYPES.JURY_VOTE_REVEAL,
      timestamp: timestampISO,
      prev: fx.dag.getRecentPrev(),
      data,
      signature,
    };
    txBody.tx_id = computeTxId(txBody);
    return txBody;
  }

  // Use past/historical dates so validator's "timestamp in future" check
  // doesn't fire. Deadline > reveal_at exercises the BEFORE branch;
  // deadline < reveal_at exercises the AFTER branch.
  const HIST_DEADLINE = 1776211200000;

  test("reveal arriving BEFORE deadline is accepted by guard (committed)", () => {
    const fx = _setupDisputeFixture({ revealDeadline: HIST_DEADLINE });
    _saveMatchingCommit(fx, fx.jurorTipIds[0]);
    const tx = _revealTx(fx, fx.jurorTipIds[0], 1775779200000);

    const result = fx.handler.commitOrderedTxs([tx], 300);
    expect(result.committed).toBe(1);
    expect(result.dropped).toBe(0);
  });

  test("reveal arriving AFTER deadline is rejected by guard (dropped)", () => {
    // deadline before the reveal's tx.timestamp — guard fires.
    const fx = _setupDisputeFixture({ revealDeadline: 1775001600000 });
    _saveMatchingCommit(fx, fx.jurorTipIds[0]);
    const tx = _revealTx(fx, fx.jurorTipIds[0], 1776211200000);

    const result = fx.handler.commitOrderedTxs([tx], 300);
    expect(result.committed).toBe(0);
    expect(result.dropped).toBe(1);
  });

  test("reveal AT EXACTLY the deadline is accepted (boundary <=)", () => {
    const fx = _setupDisputeFixture({ revealDeadline: HIST_DEADLINE });
    _saveMatchingCommit(fx, fx.jurorTipIds[0]);
    const tx = _revealTx(fx, fx.jurorTipIds[0], HIST_DEADLINE);

    const result = fx.handler.commitOrderedTxs([tx], 300);
    expect(result.committed).toBe(1);
    expect(result.dropped).toBe(0);
  });
});
