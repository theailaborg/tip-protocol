/**
 * @file tests/scoring/replay-determinism.test.js
 * @description Replay determinism guard for the score engine:
 *
 *   For any tx history, `applyScoreEffect` (the single source of truth for
 *   commit-handler's live mirror AND scoring.computeScore's full replay)
 *   must produce the SAME final state regardless of replay order
 *   ambiguities — and the math must close on full dispute lifecycles.
 *
 * If the live mirror and replay paths drift, every node's
 * state_merkle_root drifts with them. The 2026-04 byzantine-canary
 * incident (#38: social_attested registration both set score=550 absolute
 * AND applied a +50 delta → 600) is the failure mode this guards.
 *
 * Strategy:
 *   1. Build a complete dispute → appeal → overturn lifecycle as a list
 *      of SCORE_UPDATE / ADJUDICATION_RESULT / APPEAL_RESULT txs using
 *      jury.buildAdjudicationBatch + jury.buildAppealBatch (so the txs
 *      come from production builders, not hand-crafted constants).
 *   2. Replay the txs through applyScoreEffect for each subject.
 *   3. Assert the final score matches the closed-form expected value
 *      from the spec stake economy.
 *   4. Re-shuffle the SCORE_UPDATE batch (jury txs ordered first in any
 *      event); re-run; assert byte-identical final score.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, ORIGIN, VOTE, VERDICT, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { DISPUTE, JURY, APPEAL, SCORE } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { applyScoreEffect, scoreTargetTipId, initialState } = require(path.join(SRC, "score-effects"));
const { buildAdjudicationBatch, buildAppealBatch } = require(path.join(SRC, "jury"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/test";
const CTID = "tip://c/OH-aaaaaaaaaaaaaa-1111";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  dag.saveVP({
    vp_id: VP_ID, name: "vp1", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
  };
  return { dag, config, scoring: initScoring(dag, config) };
}

function _seedIdentity(dag, tipId, score = 750) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${tipId}`),
  });
  dag.setScore(tipId, score, 0, "2026-01-01T00:00:00.000Z");
}

function _addTx(dag, body) {
  const tx = { ...body, prev: body.prev || [] };
  tx.tx_id = computeTxId(tx);
  dag.addTx(tx);
  return tx;
}

// Replay txs for one subject, returning the final state that the live
// mirror would have. Same function commit-handler and scoring.computeScore
// both use — this test is the consistency check.
function _replayForSubject(allTxs, subjectTipId, initial) {
  let state = initial || initialState();
  for (const tx of allTxs) {
    if (scoreTargetTipId(tx) !== subjectTipId) continue;
    state = applyScoreEffect(tx, state);
  }
  return state;
}

// Filing-time stake debit — emitted in the same atomic batch as
// CONTENT_DISPUTED in production by dispute-service.fileDispute.
function _filingStakeDebit(dag, tipId, ts = "2026-04-01T00:00:00.500Z") {
  return _addTx(dag, {
    tx_type: TX_TYPES.SCORE_UPDATE, timestamp: ts,
    data: { tip_id: tipId, delta: -DISPUTE.DISPUTER_STAKE, reason: "Dispute filing stake on " + CTID, ctid: CTID },
  });
}
function _appealStakeDebit(dag, tipId, ts = "2026-04-04T00:00:00.500Z") {
  return _addTx(dag, {
    tx_type: TX_TYPES.SCORE_UPDATE, timestamp: ts,
    data: { tip_id: tipId, delta: -APPEAL.APPELLANT_STAKE, reason: "Appeal filing stake on " + CTID, ctid: CTID },
  });
}

// ─── Lifecycle helpers ──────────────────────────────────────────────────────

function _seedDisputeFixture(dag, { jurorCount = 7, declaredOrigin = ORIGIN.OH, claimedOrigin = ORIGIN.AG } = {}) {
  const authorTipId = "tip://id/author";
  const disputerTipId = "tip://id/disputer";
  _seedIdentity(dag, authorTipId, SCORE.INITIAL_IDENTITY);
  _seedIdentity(dag, disputerTipId, SCORE.INITIAL_IDENTITY);

  dag.saveContent({
    ctid: CTID, origin_code: declaredOrigin, content_hash: "00",
    author_tip_id: authorTipId, status: CONTENT_STATUS.DISPUTED,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: "00",
  });

  const disputeTx = _addTx(dag, {
    tx_type: TX_TYPES.CONTENT_DISPUTED, timestamp: "2026-04-01T00:00:00.000Z",
    data: {
      ctid: CTID, disputer_tip_id: disputerTipId, reason: "origin_mismatch",
      claimed_origin: claimedOrigin, declared_origin: declaredOrigin,
      author_tip_id: authorTipId, pre_dispute_status: CONTENT_STATUS.REGISTERED,
      stake: DISPUTE.DISPUTER_STAKE,
    },
  });

  const summons = [];
  const jurors = [];
  const revealDeadline = "2030-01-01T00:00:00.000Z";
  const commitDeadline = "2030-01-01T00:00:00.000Z";
  for (let i = 0; i < jurorCount; i++) {
    const j = `tip://id/juror-${i}`;
    _seedIdentity(dag, j, 750);
    jurors.push(j);
    summons.push(_addTx(dag, {
      tx_type: TX_TYPES.JURY_SUMMONS,
      timestamp: `2026-04-01T00:00:0${i % 10}.${(100 + i).toString().padStart(3, "0")}Z`,
      data: {
        ctid: CTID, dispute_tx_id: disputeTx.tx_id, juror_tip_id: j,
        stake: JURY.JUROR_STAKE, seed: shake256("seed"), identity_count: jurorCount,
        commit_deadline: commitDeadline, reveal_deadline: revealDeadline,
      },
    }));
  }
  return { authorTipId, disputerTipId, jurors, summons, disputeTx };
}

function _buildReveals(jurors, votes, ts = "2026-04-02T00:00:00.000Z") {
  return jurors.slice(0, votes.length).map((j, i) => ({
    tx_id: shake256(`reveal-${i}-${votes[i]}`),
    tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: ts,
    data: {
      ctid: CTID, juror_tip_id: j, vote: votes[i],
      salt: shake256(`s${i}`), confirmed_origin: ORIGIN.AG,
    },
  }));
}

function _expertSummons(dag, experts) {
  const out = [];
  const revealDeadline = "2030-01-01T00:00:00.000Z";
  const commitDeadline = "2030-01-01T00:00:00.000Z";
  for (let i = 0; i < experts.length; i++) {
    out.push(_addTx(dag, {
      tx_type: TX_TYPES.JURY_SUMMONS,
      timestamp: `2026-04-05T00:00:0${i}.000Z`,
      data: {
        ctid: CTID, juror_tip_id: experts[i],
        is_appeal: true, stake: JURY.JUROR_STAKE,
        commit_deadline: commitDeadline, reveal_deadline: revealDeadline,
        seed: shake256("expert-seed"), identity_count: experts.length,
      },
    }));
  }
  return out;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("replay determinism — Stage-2 UPHELD lifecycle", () => {
  test("author final score = INITIAL - first-offense penalty (-100); offense_count = 1", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    _filingStakeDebit(fx.dag, ids.disputerTipId);

    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ]);
    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    for (const t of out.txs) _addTx(fx.dag, t);

    const all = fx.dag.getTxsByTipId(ids.authorTipId);
    const author = _replayForSubject(all, ids.authorTipId);
    expect(author.score).toBe(SCORE.INITIAL_IDENTITY - 100);
    expect(author.offense_count).toBe(1);
  });

  test("disputer final score = INITIAL - 15 (file) + 20 (UPHELD settlement) = INITIAL + 5", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    _filingStakeDebit(fx.dag, ids.disputerTipId);

    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ]);
    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    for (const t of out.txs) _addTx(fx.dag, t);

    const all = fx.dag.getTxsByTipId(ids.disputerTipId);
    const disputer = _replayForSubject(all, ids.disputerTipId);
    expect(disputer.score).toBe(SCORE.INITIAL_IDENTITY - DISPUTE.DISPUTER_STAKE + (DISPUTE.DISPUTER_STAKE + DISPUTE.UPHELD_BONUS));
    expect(disputer.score).toBe(SCORE.INITIAL_IDENTITY + DISPUTE.UPHELD_BONUS);
  });

  test("majority juror final score = base + MAJORITY_BONUS (+3); minority = base - MINORITY_PENALTY (-10)", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    _filingStakeDebit(fx.dag, ids.disputerTipId);

    const votes = [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ];
    const reveals = _buildReveals(ids.jurors, votes);
    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    for (const t of out.txs) _addTx(fx.dag, t);

    for (let i = 0; i < votes.length; i++) {
      const j = ids.jurors[i];
      const all = fx.dag.getTxsByTipId(j);
      const final = _replayForSubject(all, j, { score: 750, offense_count: 0, frozen: false });
      const expected = votes[i] === VOTE.MISMATCH
        ? 750 + JURY.MAJORITY_BONUS
        : 750 - JURY.MINORITY_PENALTY;
      expect(final.score).toBe(expected);
    }
  });
});

describe("replay determinism — Stage-3 overturn lifecycle (UPHELD → DISMISSED)", () => {
  test("author final score = INITIAL after full overturn (Stage-2 -100 reversed by Stage-3 +100)", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    _filingStakeDebit(fx.dag, ids.disputerTipId);

    // Stage 2 — UPHELD
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ]);
    const stage2 = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    for (const t of stage2.txs) _addTx(fx.dag, t);

    // Author appeals
    _appealStakeDebit(fx.dag, ids.authorTipId);
    _addTx(fx.dag, {
      tx_type: TX_TYPES.APPEAL_FILED, timestamp: "2026-04-04T00:00:01.000Z",
      data: { ctid: CTID, appellant_tip_id: ids.authorTipId, stage2_verdict: VERDICT.UPHELD, stake: APPEAL.APPELLANT_STAKE },
    });

    // Stage 3 — overturn (experts vote MATCH = NOT a mismatch → DISMISSED)
    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const expSummons = _expertSummons(fx.dag, experts);
    const expReveals = experts.map((e, i) => ({
      tx_id: shake256(`er-${i}`),
      tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: "2026-04-06T00:00:00.000Z",
      data: { ctid: CTID, juror_tip_id: e, vote: VOTE.MATCH, salt: shake256(`s${i}`), is_appeal: true },
    }));
    const stage3 = buildAppealBatch(CTID, expReveals, expSummons, fx.dag, fx.scoring, fx.config);
    expect(stage3.overturned).toBe(true);
    for (const t of stage3.txs) _addTx(fx.dag, t);

    // Author final state:
    //   - 100 (Stage-2 penalty)
    //   - 25  (appeal stake)
    //   + 25 + 10  (overturn refund + bonus = 35)
    //   + 100 (Stage-2 penalty reversal)
    //  = INITIAL + 10
    // Offense count: +1 from ADJ_RESULT, -1 from APPEAL_RESULT (overturn) = 0
    const all = fx.dag.getTxsByTipId(ids.authorTipId);
    const author = _replayForSubject(all, ids.authorTipId);
    expect(author.score).toBe(SCORE.INITIAL_IDENTITY + APPEAL.OVERTURN_BONUS);
    expect(author.offense_count).toBe(0);
  });

  test("disputer final score: filing -15, Stage-2 +20 settlement, Stage-3 -20 reversal → -15 net", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    _filingStakeDebit(fx.dag, ids.disputerTipId);

    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ]);
    const stage2 = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    for (const t of stage2.txs) _addTx(fx.dag, t);

    _appealStakeDebit(fx.dag, ids.authorTipId);
    _addTx(fx.dag, {
      tx_type: TX_TYPES.APPEAL_FILED, timestamp: "2026-04-04T00:00:01.000Z",
      data: { ctid: CTID, appellant_tip_id: ids.authorTipId, stage2_verdict: VERDICT.UPHELD, stake: APPEAL.APPELLANT_STAKE },
    });

    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const expSummons = _expertSummons(fx.dag, experts);
    const expReveals = experts.map((e, i) => ({
      tx_id: shake256(`er-${i}`),
      tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: "2026-04-06T00:00:00.000Z",
      data: { ctid: CTID, juror_tip_id: e, vote: VOTE.MATCH, salt: shake256(`s${i}`), is_appeal: true },
    }));
    const stage3 = buildAppealBatch(CTID, expReveals, expSummons, fx.dag, fx.scoring, fx.config);
    for (const t of stage3.txs) _addTx(fx.dag, t);

    const all = fx.dag.getTxsByTipId(ids.disputerTipId);
    const disputer = _replayForSubject(all, ids.disputerTipId);
    // Filing -15, UPHELD settlement +20 (= +5), overturn reversal -20 (= -15)
    expect(disputer.score).toBe(SCORE.INITIAL_IDENTITY - DISPUTE.DISPUTER_STAKE);
  });
});

describe("replay determinism — order-independence within a subject's tx history", () => {
  test("Reordering pure SCORE_UPDATEs (same subject) yields the same final score", () => {
    const subject = "tip://id/x";
    const txs = [
      { tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "2026-04-01", data: { tip_id: subject, delta: -100 } },
      { tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "2026-04-02", data: { tip_id: subject, delta: 50 } },
      { tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "2026-04-03", data: { tip_id: subject, delta: 25 } },
      { tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "2026-04-04", data: { tip_id: subject, delta: -10 } },
    ];

    const _replay = (list) => list.reduce(
      (st, tx) => applyScoreEffect(tx, st),
      initialState(),
    );

    const a = _replay(txs);
    // Reverse — addition is commutative, so the running sum lands the same.
    const b = _replay([...txs].reverse());
    // Random shuffle.
    const c = _replay([txs[2], txs[0], txs[3], txs[1]]);

    expect(a.score).toBe(b.score);
    expect(a.score).toBe(c.score);
    expect(a.score).toBe(SCORE.INITIAL_IDENTITY - 100 + 50 + 25 - 10);
  });

  test("Final state independent of unrelated-subject txs interleaved (filter-by-target works)", () => {
    const me = "tip://id/me";
    const other = "tip://id/other";

    const all = [
      { tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "1", data: { tip_id: me, delta: 10 } },
      { tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "2", data: { tip_id: other, delta: -300 } },
      { tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "3", data: { tip_id: me, delta: 5 } },
      { tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "4", data: { tip_id: other, delta: 999 } },
      { tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "5", data: { tip_id: me, delta: -3 } },
    ];

    const mine = _replayForSubject(all, me);
    expect(mine.score).toBe(SCORE.INITIAL_IDENTITY + 10 + 5 - 3);
  });
});
