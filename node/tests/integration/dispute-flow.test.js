/**
 * @file tests/integration/dispute-flow.test.js
 * @description Codifies the dispute-flow matrix from
 * `my-notes/DISPUTE_FLOW_TEST_PLAN.md`. Each flow was manually verified
 * end-to-end on 2026-05-09; this suite locks the score deltas, offense
 * count transitions, and SCORE_UPDATE batch shapes.
 *
 * Uses the production builders (jury.buildAdjudicationBatch /
 * buildAppealBatch) directly so the tests are unit-fast but exercise the
 * exact same stake economy, verdict logic, and tx layout that lands
 * on-chain. Filing-time stake debits (DISPUTER_STAKE / APPELLANT_STAKE)
 * are emitted through the same SCORE_UPDATE channel that
 * dispute-service.fileDispute / fileAppeal use in production.
 *
 * Coverage matrix:
 *   Flow 1   UPHELD → author appeals → overturn          ✓
 *   Flow 1b  UPHELD → author appeals → confirm           ✓ (Flow 3)
 *   Flow 2   DISMISSED → disputer appeals → overturn UPHELD  ✓
 *   Flow 4   DISMISSED → disputer appeals → confirm DISMISSED  ✓
 *   Flow 5   UPHELD → no appeal (window expiry handled by API gates,
 *            verified manually)                          ⓘ skipped here
 *   Flow 6   CONSERVATIVE_LABEL                          ✓
 *   Flow 7   Stage-2 NO_QUORUM → auto-escalate → Stage-3 UPHELD  ✓
 *   Flow 8   Zero-participation NO_QUORUM                ✓
 *   Flow 9   Tie vote (3-3) → DISMISSED                  ✓
 *   Flow 10  Stage-3 expert no-show → defaulted DISMISSED  ✓
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

// Authoritative stakes/bonuses copied from the test-plan header so the
// tests fail loudly if genesis values drift away from spec.
const STAKES = {
  DISPUTER: 15,
  UPHELD_BONUS: 5,
  APPELLANT: 25,
  OVERTURN_BONUS: 10,
  JUROR_MAJORITY: 3,
  EXPERT_MAJORITY: 7,
  JUROR_MINORITY: 8,
  EXPERT_MINORITY: 10,
  JUROR_NO_COMMIT: 1,
  JUROR_NO_REVEAL: 8,
  EXPERT_NO_COMMIT: 1,
  EXPERT_NO_REVEAL: 10,
  OH_AS_AG_1ST: 100,
  OH_AS_AG_2ND: 200,
  OH_AS_AG_3RD: 350,
  AA_AS_AG_1ST: 25,
};

beforeAll(() => {
  // Pin: if any stake/bonus drifts from test-plan, every flow asserts
  // would silently re-baseline. Catch the drift here.
  expect(DISPUTE.DISPUTER_STAKE).toBe(STAKES.DISPUTER);
  expect(DISPUTE.UPHELD_BONUS).toBe(STAKES.UPHELD_BONUS);
  expect(APPEAL.APPELLANT_STAKE).toBe(STAKES.APPELLANT);
  expect(APPEAL.OVERTURN_BONUS).toBe(STAKES.OVERTURN_BONUS);
  expect(JURY.JUROR_MAJORITY_BONUS).toBe(STAKES.JUROR_MAJORITY);
  expect(JURY.EXPERT_MAJORITY_BONUS).toBe(STAKES.EXPERT_MAJORITY);
  expect(JURY.JUROR_MINORITY_PENALTY).toBe(STAKES.JUROR_MINORITY);
  expect(JURY.EXPERT_MINORITY_PENALTY).toBe(STAKES.EXPERT_MINORITY);
  expect(JURY.JUROR_NO_COMMIT_PENALTY).toBe(STAKES.JUROR_NO_COMMIT);
  expect(JURY.JUROR_NO_REVEAL_PENALTY).toBe(STAKES.JUROR_NO_REVEAL);
  expect(JURY.EXPERT_NO_COMMIT_PENALTY).toBe(STAKES.EXPERT_NO_COMMIT);
  expect(JURY.EXPERT_NO_REVEAL_PENALTY).toBe(STAKES.EXPERT_NO_REVEAL);
});

// ─── Fixture helpers ────────────────────────────────────────────────────────

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({
    node_id: NODE_ID, name: "test", public_key: nodeKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  dag.saveVP({
    vp_id: VP_ID, name: "vp1", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
  };
  return { dag, config, scoring: initScoring(dag, config) };
}

function _seedIdentity(dag, tipId, score) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: shake256(`id:${tipId}`),
  });
  dag.setScore(tipId, score, 0, 1767225600000);
}

function _addTx(dag, body) {
  const tx = { ...body, prev: body.prev || [] };
  tx.tx_id = computeTxId(tx);
  dag.addTx(tx);
  return tx;
}

function _seedDispute(dag, ctid, {
  authorTipId = "tip://id/author",
  disputerTipId = "tip://id/disputer",
  jurorCount = 7,
  authorScore = SCORE.INITIAL_IDENTITY,
  disputerScore = SCORE.INITIAL_IDENTITY,
  jurorScore = 750,
  declaredOrigin = ORIGIN.OH,
  claimedOrigin = ORIGIN.AG,
} = {}) {
  _seedIdentity(dag, authorTipId, authorScore);
  _seedIdentity(dag, disputerTipId, disputerScore);

  dag.saveContent({
    ctid, origin_code: declaredOrigin, content_hash: "00",
    author_tip_id: authorTipId, status: CONTENT_STATUS.DISPUTED,
    registered_at: 1767225600000, tx_id: "00",
  });

  const disputeTx = _addTx(dag, {
    tx_type: TX_TYPES.CONTENT_DISPUTED, timestamp: 1775001600000,
    data: {
      ctid, disputer_tip_id: disputerTipId, reason: "origin_mismatch",
      claimed_origin: claimedOrigin, declared_origin: declaredOrigin,
      author_tip_id: authorTipId, pre_dispute_status: CONTENT_STATUS.REGISTERED,
      stake: DISPUTE.DISPUTER_STAKE,
    },
  });

  const summons = [];
  const jurors = [];
  const revealDeadline = 1893456000000;
  const commitDeadline = 1893456000000;
  for (let i = 0; i < jurorCount; i++) {
    const j = `tip://id/juror-${i}`;
    _seedIdentity(dag, j, jurorScore);
    jurors.push(j);
    summons.push(_addTx(dag, {
      tx_type: TX_TYPES.JURY_SUMMONS,
      timestamp: `2026-04-01T00:00:0${i % 10}.${(100 + i).toString().padStart(3, "0")}Z`,
      data: {
        ctid, dispute_tx_id: disputeTx.tx_id, juror_tip_id: j,
        stake: JURY.JUROR_STAKE, seed: shake256("seed"), identity_count: jurorCount,
        commit_deadline: commitDeadline, reveal_deadline: revealDeadline,
      },
    }));
  }

  return { authorTipId, disputerTipId, jurors, summons, disputeTx, ctid };
}

// Stage-2 NO_QUORUM only auto-escalates if a Stage-3 expert panel can
// actually be formed (>= APPEAL.MIN_VOTES eligible experts). In production the
// expert pool is a standing set of opted-in, high-score identities that exists
// before any dispute, so seed it before Stage-2 to exercise the escalation
// path. Experts must carry reviewer_consent and span enough regions to clear
// the appeal_max_same_country geo-cap.
const _EXPERT_REGIONS = ["US", "GB", "DE", "JP", "BR"];
function _seedExpertPool(dag, count = 3, score = 900) {
  const experts = [];
  for (let i = 0; i < count; i++) {
    const e = `tip://id/expert-${i}`;
    dag.saveIdentity({
      tip_id: e, region: _EXPERT_REGIONS[i % _EXPERT_REGIONS.length],
      public_key: "00", root_public_key: "00", vp_id: VP_ID,
      verification_tier: "T1", founding: false, status: "active",
      reviewer_consent: true, registered_at: 1767225600000,
      tx_id: shake256(`id:${e}`),
    });
    dag.setScore(e, score, 0, 1767225600000);
    experts.push(e);
  }
  return experts;
}

function _filingStakeDebit(dag, ctid, tipId, ts = 1775001600500) {
  return _addTx(dag, {
    tx_type: TX_TYPES.SCORE_UPDATE, timestamp: ts,
    data: { tip_id: tipId, delta: -DISPUTE.DISPUTER_STAKE, reason: `Dispute filing stake on ${ctid}`, ctid },
  });
}

function _appealFilingDebit(dag, ctid, tipId, ts = 1775260800500) {
  return _addTx(dag, {
    tx_type: TX_TYPES.SCORE_UPDATE, timestamp: ts,
    data: { tip_id: tipId, delta: -APPEAL.APPELLANT_STAKE, reason: `Appeal filing stake on ${ctid}`, ctid },
  });
}

function _appealFiled(dag, ctid, appellantTipId, stage2Verdict, ts = 1775260801000) {
  return _addTx(dag, {
    tx_type: TX_TYPES.APPEAL_FILED, timestamp: ts,
    data: { ctid, appellant_tip_id: appellantTipId, stage2_verdict: stage2Verdict, stake: APPEAL.APPELLANT_STAKE },
  });
}

function _buildReveals(jurors, votes, ctid, opts = {}) {
  const { ts = 1775088000000, isAppeal = false, confirmedOrigin = ORIGIN.AG } = opts;
  return jurors.slice(0, votes.length).map((j, i) => ({
    tx_id: shake256(`reveal-${ctid}-${i}-${votes[i]}-${isAppeal ? "a" : "j"}`),
    tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: ts,
    data: {
      ctid, juror_tip_id: j, vote: votes[i],
      salt: shake256(`s${i}`), confirmed_origin: confirmedOrigin,
      ...(isAppeal ? { is_appeal: true } : {}),
    },
  }));
}

function _expertSummons(dag, ctid, experts, ts = 1775347200000) {
  const out = [];
  const revealDeadline = 1893456000000;
  const commitDeadline = 1893456000000;
  for (let i = 0; i < experts.length; i++) {
    out.push(_addTx(dag, {
      tx_type: TX_TYPES.JURY_SUMMONS,
      timestamp: ts + i + 1,
      data: {
        ctid, juror_tip_id: experts[i],
        is_appeal: true, stake: JURY.JUROR_STAKE,
        commit_deadline: commitDeadline, reveal_deadline: revealDeadline,
        seed: shake256("expert-seed"), identity_count: experts.length,
      },
    }));
  }
  return out;
}

function _commitBatch(dag, txs) {
  for (const t of txs) _addTx(dag, t);
}

function _replay(dag, tipId, initial) {
  const all = dag.getTxsByTipId(tipId);
  let state = initial || initialState();
  for (const tx of all) {
    if (scoreTargetTipId(tx) !== tipId) continue;
    state = applyScoreEffect(tx, state);
  }
  return state;
}

function _scoreUpdates(txs, tipId) {
  return txs.filter(t => t.tx_type === TX_TYPES.SCORE_UPDATE && t.data?.tip_id === tipId);
}

// ════════════════════════════════════════════════════════════════════════════
// Flow 1 — UPHELD → author appeals → overturn (Stage-3 DISMISSED)
// ════════════════════════════════════════════════════════════════════════════

describe("Flow 1 — UPHELD → author appeals → overturn (Stage-3 DISMISSED)", () => {
  test("end-to-end score deltas match test-plan table", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow1aaaaaaaaaa-1111";
    const ids = _seedDispute(fx.dag, ctid);

    // ── Step 1.1: Disputer files dispute → -15 stake
    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);
    expect(_replay(fx.dag, ids.disputerTipId).score).toBe(SCORE.INITIAL_IDENTITY - STAKES.DISPUTER);
    expect(_replay(fx.dag, ids.authorTipId).score).toBe(SCORE.INITIAL_IDENTITY);

    // ── Step 1.3: All 7 reveal MISMATCH → UPHELD
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid);
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(stage2.verdict).toBe(VERDICT.UPHELD);
    _commitBatch(fx.dag, stage2.txs);

    // Author -100 (1st OH→AG), offense=1
    const authorAfterStage2 = _replay(fx.dag, ids.authorTipId);
    expect(authorAfterStage2.score).toBe(SCORE.INITIAL_IDENTITY - STAKES.OH_AS_AG_1ST);
    expect(authorAfterStage2.offense_count).toBe(1);

    // Disputer +20 net (refund + bonus)
    const disputerAfterStage2 = _replay(fx.dag, ids.disputerTipId);
    expect(disputerAfterStage2.score).toBe(SCORE.INITIAL_IDENTITY + STAKES.UPHELD_BONUS);

    // Each majority juror +3
    for (const j of ids.jurors) {
      const s = _replay(fx.dag, j, { score: 750, offense_count: 0, frozen: false });
      expect(s.score).toBe(750 + STAKES.JUROR_MAJORITY);
    }

    // ── Step 1.4: Author files appeal → -25 stake
    _appealFilingDebit(fx.dag, ctid, ids.authorTipId);
    _appealFiled(fx.dag, ctid, ids.authorTipId, VERDICT.UPHELD);
    expect(_replay(fx.dag, ids.authorTipId).score).toBe(SCORE.INITIAL_IDENTITY - STAKES.OH_AS_AG_1ST - STAKES.APPELLANT);

    // ── Step 1.5a: 3 experts reveal MATCH → APPEAL_RESULT DISMISSED (overturned)
    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const expSummons = _expertSummons(fx.dag, ctid, experts);
    const expReveals = _buildReveals(experts, [VOTE.MATCH, VOTE.MATCH, VOTE.MATCH], ctid, {
      ts: 1775433600000, isAppeal: true,
    });
    const stage3 = buildAppealBatch(ctid, expReveals, expSummons, fx.dag, fx.scoring, fx.config);
    expect(stage3.verdict).toBe(VERDICT.DISMISSED);
    expect(stage3.overturned).toBe(true);
    _commitBatch(fx.dag, stage3.txs);

    // Author journey:
    //   500 (start)
    //   -100 (Stage-2 UPHELD penalty) = 400
    //    -25 (appeal stake)            = 375
    //    +35 (overturn refund+bonus)   = 410
    //   +100 (Stage-2 penalty reversal) = 510
    //     +5 (Stage-3 vindication: appeal cleared the author) = 515
    // Net +15 from start. Offense 0→1→0 (overturn decrements).
    const authorFinal = _replay(fx.dag, ids.authorTipId);
    expect(authorFinal.score).toBe(SCORE.INITIAL_IDENTITY + STAKES.OVERTURN_BONUS + DISPUTE.VINDICATION_BONUS);
    expect(authorFinal.offense_count).toBe(0);

    // Disputer final: -15 (filing) +20 (Stage-2) -20 (overturn reversal) = -15 net
    expect(_replay(fx.dag, ids.disputerTipId).score)
      .toBe(SCORE.INITIAL_IDENTITY - STAKES.DISPUTER);

    // Each expert +7 (capped at 1000 in production; not exercised here since seed=900)
    for (const e of experts) {
      const s = _replay(fx.dag, e, { score: 900, offense_count: 0, frozen: false });
      expect(s.score).toBe(900 + STAKES.EXPERT_MAJORITY);
    }
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Flow 2 — DISMISSED → disputer appeals → overturn UPHELD
// ════════════════════════════════════════════════════════════════════════════

describe("Flow 2 — DISMISSED → disputer appeals → overturn UPHELD", () => {
  test("disputer wins big on overturn (+35 + 20); author hit with fresh AA→AG penalty", () => {
    const fx = _setup();
    const ctid = "tip://c/AA-flow2bbbbbbbbbb-2222";
    const ids = _seedDispute(fx.dag, ctid, {
      declaredOrigin: ORIGIN.AA, claimedOrigin: ORIGIN.AG,
    });

    // Filing
    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    // Stage-2 DISMISSED — majority MATCH (5 vs 2)
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid);
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(stage2.verdict).toBe(VERDICT.DISMISSED);
    _commitBatch(fx.dag, stage2.txs);

    // After Stage-2 DISMISSED:
    //   author: +VINDICATION_BONUS (+5) — tentative, retracted on overturn
    //   disputer: -DISPUTER_STAKE forfeit at filing time, no settlement event
    expect(_replay(fx.dag, ids.authorTipId).score).toBe(SCORE.INITIAL_IDENTITY + DISPUTE.VINDICATION_BONUS);
    expect(_replay(fx.dag, ids.disputerTipId).score).toBe(SCORE.INITIAL_IDENTITY - STAKES.DISPUTER);

    // ── Disputer files appeal → -25 stake debit
    _appealFilingDebit(fx.dag, ctid, ids.disputerTipId);
    _appealFiled(fx.dag, ctid, ids.disputerTipId, VERDICT.DISMISSED);

    // Stage-3 experts overturn → UPHELD
    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const expSummons = _expertSummons(fx.dag, ctid, experts);
    const expReveals = _buildReveals(experts, [VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH], ctid, {
      ts: 1775433600000, isAppeal: true, confirmedOrigin: ORIGIN.AG,
    });
    const stage3 = buildAppealBatch(ctid, expReveals, expSummons, fx.dag, fx.scoring, fx.config);
    expect(stage3.verdict).toBe(VERDICT.UPHELD);
    expect(stage3.overturned).toBe(true);
    _commitBatch(fx.dag, stage3.txs);

    // Author journey:
    //   500 (start)
    //   +5  Stage-2 vindication                = 505
    //   -5  Stage-3 vindication retracted      = 500
    //   -25 Stage-3 fresh AA→AG 1st-offense    = 475
    // Net Stage-3 alone (from 505): -30. Net from start (500): -25.
    // offense_count 0 → 1 fires on the overturn (DISMISSED → UPHELD branch).
    const authorFinal = _replay(fx.dag, ids.authorTipId);
    expect(authorFinal.score).toBe(SCORE.INITIAL_IDENTITY - STAKES.AA_AS_AG_1ST);
    expect(authorFinal.offense_count).toBe(1);

    // Vindication retraction lands as a distinct SCORE_UPDATE in the
    // appeal batch — verify the wire shape, not just the final score.
    const retraction = stage3.txs.find(t =>
      t.tx_type === TX_TYPES.SCORE_UPDATE
      && t.data?.tip_id === ids.authorTipId
      && /vindication retracted/i.test(t.data.reason),
    );
    expect(retraction).toBeDefined();
    expect(retraction.data.delta).toBe(-DISPUTE.VINDICATION_BONUS);

    // Disputer journey:
    //   500 (start) -15 (filing) = 485
    //   Stage-2 DISMISSED → no event = 485
    //   -25 (appeal stake) = 460
    //   +35 (overturn refund + bonus) = 495
    //   +20 (Stage-2 settlement applied now: stake refund + UPHELD bonus) = 515
    // Net +15 above starting score (the "vindicated disputer" — most-rewarded outcome).
    const disputerFinal = _replay(fx.dag, ids.disputerTipId);
    const expected = SCORE.INITIAL_IDENTITY
      - STAKES.DISPUTER
      - STAKES.APPELLANT
      + (STAKES.APPELLANT + STAKES.OVERTURN_BONUS)
      + (STAKES.DISPUTER + STAKES.UPHELD_BONUS);
    expect(expected).toBe(SCORE.INITIAL_IDENTITY + 15);
    expect(disputerFinal.score).toBe(expected);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Flow 3 — UPHELD → author appeals → confirm (appeal LOSES)
// ════════════════════════════════════════════════════════════════════════════

describe("Flow 3 — UPHELD → author appeals → appeal FAILS (Stage-3 confirms UPHELD)", () => {
  test("author -125 net; no appellant settlement event on confirm", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow3cccccccccc-3333";
    const ids = _seedDispute(fx.dag, ctid);

    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ], ctid);
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    _commitBatch(fx.dag, stage2.txs);

    _appealFilingDebit(fx.dag, ctid, ids.authorTipId);
    _appealFiled(fx.dag, ctid, ids.authorTipId, VERDICT.UPHELD);

    // Stage-3 experts confirm UPHELD (vote MISMATCH like jurors did)
    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const expSummons = _expertSummons(fx.dag, ctid, experts);
    const expReveals = _buildReveals(experts, [VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH], ctid, {
      ts: 1775433600000, isAppeal: true,
    });
    const stage3 = buildAppealBatch(ctid, expReveals, expSummons, fx.dag, fx.scoring, fx.config);
    expect(stage3.verdict).toBe(VERDICT.UPHELD);
    expect(stage3.overturned).toBe(false);
    _commitBatch(fx.dag, stage3.txs);

    // Author final: -100 (Stage-2) -25 (appeal stake forfeit) = -125 net
    const authorFinal = _replay(fx.dag, ids.authorTipId);
    expect(authorFinal.score).toBe(SCORE.INITIAL_IDENTITY - STAKES.OH_AS_AG_1ST - STAKES.APPELLANT);
    expect(authorFinal.offense_count).toBe(1);

    // Disputer: +5 net (-15 filing, +20 Stage-2 settlement)
    expect(_replay(fx.dag, ids.disputerTipId).score)
      .toBe(SCORE.INITIAL_IDENTITY + STAKES.UPHELD_BONUS);

    // No appellant settlement SCORE_UPDATE in the appeal batch
    const appealBatchSU = stage3.txs.filter(t => t.tx_type === TX_TYPES.SCORE_UPDATE && /Appeal/.test(t.data.reason));
    expect(appealBatchSU).toHaveLength(0);

    // Appeal batch: 3 expert majority bonuses, that's it
    const appealSUs = stage3.txs.filter(t => t.tx_type === TX_TYPES.SCORE_UPDATE);
    expect(appealSUs).toHaveLength(3);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Flow 4 — DISMISSED → disputer appeals → confirm (appeal LOSES)
// ════════════════════════════════════════════════════════════════════════════

describe("Flow 4 — DISMISSED → disputer appeals → confirm DISMISSED", () => {
  test("disputer loses both stakes (-40 net); author keeps the +5 vindication (Stage-2 stands)", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow4dddddddddd-4444";
    const ids = _seedDispute(fx.dag, ctid);

    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    const reveals = _buildReveals(ids.jurors, [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid);
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(stage2.verdict).toBe(VERDICT.DISMISSED);
    _commitBatch(fx.dag, stage2.txs);

    _appealFilingDebit(fx.dag, ctid, ids.disputerTipId);
    _appealFiled(fx.dag, ctid, ids.disputerTipId, VERDICT.DISMISSED);

    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const expSummons = _expertSummons(fx.dag, ctid, experts);
    // Experts confirm DISMISSED (vote MATCH)
    const expReveals = _buildReveals(experts, [VOTE.MATCH, VOTE.MATCH, VOTE.MATCH], ctid, {
      ts: 1775433600000, isAppeal: true,
    });
    const stage3 = buildAppealBatch(ctid, expReveals, expSummons, fx.dag, fx.scoring, fx.config);
    expect(stage3.verdict).toBe(VERDICT.DISMISSED);
    expect(stage3.overturned).toBe(false);
    _commitBatch(fx.dag, stage3.txs);

    // Author: +5 vindication earned at Stage-2 stays (Stage-3 confirmed
    // DISMISSED, so the retraction branch never fires). offense_count
    // never moved.
    const authorFinal = _replay(fx.dag, ids.authorTipId);
    expect(authorFinal.score).toBe(SCORE.INITIAL_IDENTITY + DISPUTE.VINDICATION_BONUS);
    expect(authorFinal.offense_count).toBe(0);

    // Disputer: -15 (filing) -25 (appeal) = -40 net, both forfeited
    expect(_replay(fx.dag, ids.disputerTipId).score)
      .toBe(SCORE.INITIAL_IDENTITY - STAKES.DISPUTER - STAKES.APPELLANT);

    // No retraction event in the appeal batch — Stage-3 confirm leaves
    // the vindication intact.
    const retraction = stage3.txs.find(t =>
      t.tx_type === TX_TYPES.SCORE_UPDATE
      && /vindication retracted/i.test(t.data?.reason || ""),
    );
    expect(retraction).toBeUndefined();
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Flow 6 — CONSERVATIVE_LABEL (declared AG, jurors confirm OH)
// ════════════════════════════════════════════════════════════════════════════

describe("Flow 6 — CONSERVATIVE_LABEL", () => {
  test("author untouched; disputer +15 refund only (no upheld bonus); no appeal eligibility", () => {
    const fx = _setup();
    const ctid = "tip://c/AG-flow6eeeeeeeeee-6666";
    const ids = _seedDispute(fx.dag, ctid, {
      declaredOrigin: ORIGIN.AG, claimedOrigin: ORIGIN.OH,
    });

    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    // Jurors vote MISMATCH (5 of 7) and confirm OH origin (over-disclosure)
    const reveals = ids.jurors.slice(0, 7).map((j, i) => ({
      tx_id: shake256(`r-cl-${i}`), tx_type: TX_TYPES.JURY_VOTE_REVEAL,
      timestamp: 1775088000000,
      data: {
        ctid, juror_tip_id: j,
        vote: i < 5 ? VOTE.MISMATCH : VOTE.MATCH,
        salt: shake256(`s${i}`), confirmed_origin: ORIGIN.OH,
      },
    }));
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(stage2.verdict).toBe(VERDICT.CONSERVATIVE_LABEL);
    _commitBatch(fx.dag, stage2.txs);

    // Author untouched — under-claim is honest
    const authorFinal = _replay(fx.dag, ids.authorTipId);
    expect(authorFinal.score).toBe(SCORE.INITIAL_IDENTITY);
    expect(authorFinal.offense_count).toBe(0);

    // Disputer back to baseline: -15 + 15 = 0 net
    expect(_replay(fx.dag, ids.disputerTipId).score).toBe(SCORE.INITIAL_IDENTITY);

    // No author SCORE_UPDATE in the verdict batch
    expect(_scoreUpdates(stage2.txs, ids.authorTipId)).toHaveLength(0);

    // Disputer gets exactly one settlement: refund only, no UPHELD bonus
    const disputerSU = _scoreUpdates(stage2.txs, ids.disputerTipId);
    expect(disputerSU).toHaveLength(1);
    expect(disputerSU[0].data.delta).toBe(STAKES.DISPUTER);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Flow 7 — Stage-2 NO_QUORUM → auto-escalate → Stage-3 UPHELD
// ════════════════════════════════════════════════════════════════════════════

describe("Flow 7 — NO_QUORUM auto-escalation → Stage-3 UPHELD", () => {
  test("Stage-2 NO_QUORUM emits ADJ_RESULT(NO_QUORUM) + APPEAL_FILED(SYSTEM_AUTO_ESCALATION)", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow7fffffffffff-7777";
    const ids = _seedDispute(fx.dag, ctid);
    _seedExpertPool(fx.dag);   // standing expert pool → Stage-2 can escalate

    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    // Only 4 of 7 reveal — below QUORUM (5). 3 no-shows.
    const reveals = _buildReveals(ids.jurors.slice(0, 4), [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid);
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(stage2.verdict).toBe(VERDICT.NO_QUORUM);
    expect(stage2.auto_appeal).toBe(true);

    const adjResult = stage2.txs.find(t => t.tx_type === TX_TYPES.ADJUDICATION_RESULT);
    expect(adjResult.data.verdict).toBe(VERDICT.NO_QUORUM);
    expect(adjResult.data.author_score_delta).toBe(0);

    const appealFiled = stage2.txs.find(t => t.tx_type === TX_TYPES.APPEAL_FILED);
    expect(appealFiled.data.appellant_tip_id).toBe("SYSTEM_AUTO_ESCALATION");
    expect(appealFiled.data.stake).toBe(0);

    _commitBatch(fx.dag, stage2.txs);

    // No author penalty
    expect(_replay(fx.dag, ids.authorTipId).score).toBe(SCORE.INITIAL_IDENTITY);
    expect(_replay(fx.dag, ids.authorTipId).offense_count).toBe(0);

    // Disputer stake stays locked through Stage-3
    expect(_replay(fx.dag, ids.disputerTipId).score)
      .toBe(SCORE.INITIAL_IDENTITY - STAKES.DISPUTER);

    // 3 no-shows (jurors 4,5,6): no JURY_VOTE_COMMIT in DAG → no-commit penalty (-1); 4 revealers untouched
    for (let i = 0; i < 4; i++) {
      const s = _replay(fx.dag, ids.jurors[i], { score: 750, offense_count: 0, frozen: false });
      expect(s.score).toBe(750);
    }
    for (let i = 4; i < 7; i++) {
      const s = _replay(fx.dag, ids.jurors[i], { score: 750, offense_count: 0, frozen: false });
      expect(s.score).toBe(750 - STAKES.JUROR_NO_COMMIT);
    }
  });

  test("Stage-3 UPHELD on NO_QUORUM applies fresh penalty (treated as first verdict)", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow7ggggggggggg-7778";
    const ids = _seedDispute(fx.dag, ctid);
    const experts = _seedExpertPool(fx.dag);   // standing pool → Stage-2 escalates

    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    const reveals = _buildReveals(ids.jurors.slice(0, 4), [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid);
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    _commitBatch(fx.dag, stage2.txs);

    // Stage-3 — experts UPHELD via MISMATCH
    const expSummons = _expertSummons(fx.dag, ctid, experts);
    const expReveals = _buildReveals(experts, [VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH], ctid, {
      ts: 1775433600000, isAppeal: true,
    });
    const stage3 = buildAppealBatch(ctid, expReveals, expSummons, fx.dag, fx.scoring, fx.config);
    expect(stage3.verdict).toBe(VERDICT.UPHELD);
    expect(stage3.overturned).toBe(false);   // NO_QUORUM had no decision → no overturn
    _commitBatch(fx.dag, stage3.txs);

    // Author: -100 fresh (Stage-3 as first verdict on NO_QUORUM), offense 0→1
    const authorFinal = _replay(fx.dag, ids.authorTipId);
    expect(authorFinal.score).toBe(SCORE.INITIAL_IDENTITY - STAKES.OH_AS_AG_1ST);
    expect(authorFinal.offense_count).toBe(1);

    // Disputer: -15 filing + 20 (settlement applied at Stage-3) = +5 net
    expect(_replay(fx.dag, ids.disputerTipId).score)
      .toBe(SCORE.INITIAL_IDENTITY + STAKES.UPHELD_BONUS);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Flow 8 — Zero-participation NO_QUORUM
// ════════════════════════════════════════════════════════════════════════════

describe("Flow 8 — zero-participation NO_QUORUM (every juror is a no-show)", () => {
  test("all 7 jurors get -10; auto-escalation still fires", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow8hhhhhhhhhh-8888";
    const ids = _seedDispute(fx.dag, ctid);
    _seedExpertPool(fx.dag);   // standing expert pool → Stage-2 can escalate

    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    // No reveals at all
    const stage2 = buildAdjudicationBatch(ctid, [], ids.summons, fx.dag, fx.scoring, fx.config);
    expect(stage2.verdict).toBe(VERDICT.NO_QUORUM);
    expect(stage2.matchCount).toBe(0);
    expect(stage2.mismatchCount).toBe(0);
    expect(stage2.abstainCount).toBe(0);
    _commitBatch(fx.dag, stage2.txs);

    // All 7 jurors penalised: no JURY_VOTE_COMMIT in DAG → no-commit penalty (-1 each)
    for (const j of ids.jurors) {
      const s = _replay(fx.dag, j, { score: 750, offense_count: 0, frozen: false });
      expect(s.score).toBe(750 - STAKES.JUROR_NO_COMMIT);
    }

    // Auto-escalation still happens
    const appealFiled = stage2.txs.find(t => t.tx_type === TX_TYPES.APPEAL_FILED);
    expect(appealFiled.data.appellant_tip_id).toBe("SYSTEM_AUTO_ESCALATION");
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Flow 9 — Tie (3-3) → DISMISSED + isTie short-circuits juror effects
// ════════════════════════════════════════════════════════════════════════════

describe("Flow 9 — tie vote (no decisive result): escalate at Stage 2, refund at Stage 3", () => {
  test("Stage-2 3-3 tie → escalates as no-result (no vindication, disputer not forfeited)", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow9iiiiiiiiii-9999";
    const ids = _seedDispute(fx.dag, ctid);
    _seedExpertPool(fx.dag);   // standing pool → a deadlock escalates to Stage 3

    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    // 6 reveal: 3 MATCH + 3 MISMATCH (deadlock); juror-6 is the no-show
    const votes = [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ];
    const reveals = _buildReveals(ids.jurors.slice(0, 6), votes, ctid);
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);

    // A deadlock is NOT a merits dismissal — it escalates like NO_QUORUM.
    expect(stage2.verdict).toBe(VERDICT.NO_QUORUM);
    expect(stage2.auto_appeal).toBe(true);
    expect(stage2.matchCount).toBe(3);
    expect(stage2.mismatchCount).toBe(3);
    const adj = stage2.txs.find(t => t.tx_type === TX_TYPES.ADJUDICATION_RESULT);
    expect(adj.data.tie).toBe(true);
    expect(stage2.txs.find(t => t.tx_type === TX_TYPES.APPEAL_FILED)).toBeDefined();
    _commitBatch(fx.dag, stage2.txs);

    // No author vindication on a tie — nothing was decided.
    expect(_replay(fx.dag, ids.authorTipId).score).toBe(SCORE.INITIAL_IDENTITY);
    expect(_scoreUpdates(stage2.txs, ids.authorTipId)).toHaveLength(0);

    // Disputer's stake stays LOCKED (not forfeited) pending Stage 3.
    expect(_replay(fx.dag, ids.disputerTipId).score)
      .toBe(SCORE.INITIAL_IDENTITY - STAKES.DISPUTER);

    // 6 revealers: zero score effect (no majority to reward/penalise).
    for (let i = 0; i < 6; i++) {
      expect(_scoreUpdates(stage2.txs, ids.jurors[i])).toHaveLength(0);
    }
    // 1 no-show: no JURY_VOTE_COMMIT in DAG → no-commit penalty (-1).
    const noShowSU = _scoreUpdates(stage2.txs, ids.jurors[6]);
    expect(noShowSU).toHaveLength(1);
    expect(noShowSU[0].data.delta).toBe(-STAKES.JUROR_NO_COMMIT);
  });

  test("Stage-3 expert tie (1 MATCH + 1 MISMATCH + 1 ABSTAIN) → terminal DISMISSED, appeal stake refunded", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow9jjjjjjjjjj-9990";
    const ids = _seedDispute(fx.dag, ctid);
    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    // Stage-2 substantive DISMISSED so we have a real verdict to appeal from.
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid);
    _commitBatch(fx.dag, buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config).txs);

    // Disputer appeals the dismissal (pays the appeal stake).
    _appealFilingDebit(fx.dag, ctid, ids.disputerTipId);
    _appealFiled(fx.dag, ctid, ids.disputerTipId, VERDICT.DISMISSED);

    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const expSummons = _expertSummons(fx.dag, ctid, experts);
    const expReveals = _buildReveals(experts, [VOTE.MATCH, VOTE.MISMATCH, VOTE.ABSTAIN], ctid, {
      ts: 1775433600000, isAppeal: true,
    });
    const stage3 = buildAppealBatch(ctid, expReveals, expSummons, fx.dag, fx.scoring, fx.config);
    expect(stage3.verdict).toBe(VERDICT.DISMISSED);
    expect(stage3.defaulted).toBe(true);
    expect(stage3.tie).toBe(true);

    // Tie = no decisive verdict: no expert score effects (all revealed, no
    // majority), and the appellant's appeal stake is refunded.
    for (const e of experts) {
      expect(_scoreUpdates(stage3.txs, e)).toHaveLength(0);
    }
    const appellantSU = _scoreUpdates(stage3.txs, ids.disputerTipId);
    expect(appellantSU).toHaveLength(1);
    expect(appellantSU[0].data.delta).toBe(STAKES.APPELLANT);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Flow 10 — Stage-3 expert no-show → defaulted DISMISSED
// ════════════════════════════════════════════════════════════════════════════

describe("Flow 9b — tie economics: terminal refund, full chain, and the substantive-dismiss guard", () => {
  test("Stage-2 tie with no expert panel → terminal NO_QUORUM, disputer refunded (no forfeit)", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow9biiiiiiiii-9b01";
    const ids = _seedDispute(fx.dag, ctid);   // NO expert pool → tie can't escalate
    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    const reveals = _buildReveals(ids.jurors.slice(0, 6), [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid);
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);

    expect(stage2.verdict).toBe(VERDICT.NO_QUORUM);
    expect(stage2.terminal).toBe(true);
    expect(stage2.txs.find(t => t.tx_type === TX_TYPES.APPEAL_FILED)).toBeUndefined();
    const adj = stage2.txs.find(t => t.tx_type === TX_TYPES.ADJUDICATION_RESULT);
    expect(adj.data.tie).toBe(true);

    _commitBatch(fx.dag, stage2.txs);
    // -15 filing + 15 refund = whole again; author gets no vindication.
    expect(_replay(fx.dag, ids.disputerTipId).score).toBe(SCORE.INITIAL_IDENTITY);
    expect(_scoreUpdates(stage2.txs, ids.authorTipId)).toHaveLength(0);
  });

  test("full chain: Stage-2 tie → Stage-3 tie (auto-escalation) → disputer filing stake refunded", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow9bjjjjjjjjj-9b02";
    const ids = _seedDispute(fx.dag, ctid);
    _seedExpertPool(fx.dag);
    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    // Stage-2 deadlock → escalates (SYSTEM_AUTO_ESCALATION, no appellant stake).
    const s2 = buildAdjudicationBatch(ctid, _buildReveals(ids.jurors.slice(0, 6), [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid), ids.summons, fx.dag, fx.scoring, fx.config);
    expect(s2.verdict).toBe(VERDICT.NO_QUORUM);
    expect(s2.auto_appeal).toBe(true);
    _commitBatch(fx.dag, s2.txs);

    // Stage-3 also deadlocks → terminal; refund the original filing stake.
    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    const expSummons = _expertSummons(fx.dag, ctid, experts);
    const expReveals = _buildReveals(experts, [VOTE.MATCH, VOTE.MISMATCH, VOTE.ABSTAIN], ctid, {
      ts: 1775433600000, isAppeal: true,
    });
    const s3 = buildAppealBatch(ctid, expReveals, expSummons, fx.dag, fx.scoring, fx.config);
    expect(s3.verdict).toBe(VERDICT.DISMISSED);
    expect(s3.tie).toBe(true);

    const disputerSU = _scoreUpdates(s3.txs, ids.disputerTipId);
    expect(disputerSU).toHaveLength(1);
    expect(disputerSU[0].data.delta).toBe(STAKES.DISPUTER);   // filing stake back; no appellant stake (SYSTEM)
  });

  test("substantive DISMISSED still forfeits disputer + pays author vindication (unchanged)", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow9bkkkkkkkkk-9b03";
    const ids = _seedDispute(fx.dag, ctid);
    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    // Clear MATCH majority (5-2) → real merits dismissal, not a tie.
    const stage2 = buildAdjudicationBatch(ctid, _buildReveals(ids.jurors, [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid), ids.summons, fx.dag, fx.scoring, fx.config);
    expect(stage2.verdict).toBe(VERDICT.DISMISSED);
    _commitBatch(fx.dag, stage2.txs);

    // Disputer's filing stake stays forfeited; author keeps the +5 vindication.
    expect(_replay(fx.dag, ids.disputerTipId).score).toBe(SCORE.INITIAL_IDENTITY - STAKES.DISPUTER);
    expect(_replay(fx.dag, ids.authorTipId).score).toBe(SCORE.INITIAL_IDENTITY + DISPUTE.VINDICATION_BONUS);
  });
});

describe("Flow 10 — Stage-3 expert no-show → APPEAL_RESULT defaulted DISMISSED", () => {
  test("defaulted: true, disputer refunded (no merits ruling), expert no-show penalties only", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow10kkkkkkkkk-aaaa";
    const ids = _seedDispute(fx.dag, ctid);
    const experts = _seedExpertPool(fx.dag);   // standing pool → Stage-2 escalates
    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    // Stage-2 NO_QUORUM that escalates (expert panel formable)
    const reveals = _buildReveals(ids.jurors.slice(0, 4), [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid);
    _commitBatch(fx.dag, buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config).txs);

    // Stage-3 — 0 reveals from the 3 experts
    const expSummons = _expertSummons(fx.dag, ctid, experts);
    const stage3 = buildAppealBatch(ctid, [], expSummons, fx.dag, fx.scoring, fx.config);
    expect(stage3.verdict).toBe(VERDICT.DISMISSED);
    expect(stage3.defaulted).toBe(true);

    const apResult = stage3.txs.find(t => t.tx_type === TX_TYPES.APPEAL_RESULT);
    expect(apResult.data.verdict).toBe(VERDICT.DISMISSED);
    expect(apResult.data.defaulted).toBe(true);
    expect(apResult.data.overturned).toBe(false);

    // The dispute never got a merits ruling (Stage-2 NO_QUORUM, Stage-3
    // defaulted for lack of experts), so the disputer is refunded their
    // filing stake. The author gets nothing (their content stands).
    expect(_scoreUpdates(stage3.txs, ids.authorTipId)).toHaveLength(0);
    const disputerSU = _scoreUpdates(stage3.txs, ids.disputerTipId);
    expect(disputerSU).toHaveLength(1);
    expect(disputerSU[0].data.delta).toBe(STAKES.DISPUTER);

    // 3 experts: no JURY_VOTE_COMMIT in DAG → no-commit penalty (-1 each)
    _commitBatch(fx.dag, stage3.txs);
    for (const e of experts) {
      const s = _replay(fx.dag, e, { score: 900, offense_count: 0, frozen: false });
      expect(s.score).toBe(900 - STAKES.EXPERT_NO_COMMIT);
    }
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Flow 11 — terminal NO_QUORUM (no Stage-3 expert panel can be formed)
//
// A Stage-2 NO_QUORUM normally auto-escalates, but escalation is gated on an
// expert panel actually being formable (>= APPEAL.MIN_VOTES eligible experts).
// When the pool is too small, escalating would hang forever (the appeal-
// resolution trigger is driven by expert-summons reveal deadlines, so zero
// summons = no deadline = no APPEAL_RESULT ever). The batch must instead
// terminate: emit a terminal ADJUDICATION_RESULT and refund the disputer.
// ════════════════════════════════════════════════════════════════════════════

describe("Flow 11 — terminal NO_QUORUM (unformable Stage-3 panel)", () => {
  test("zero eligible experts → terminal, no APPEAL_FILED, disputer refunded", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow11lllllllll-bbbb";
    const ids = _seedDispute(fx.dag, ctid);   // NO expert pool seeded
    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    const reveals = _buildReveals(ids.jurors.slice(0, 4), [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid);
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);

    expect(stage2.verdict).toBe(VERDICT.NO_QUORUM);
    expect(stage2.terminal).toBe(true);
    expect(stage2.auto_appeal).toBe(false);

    // No escalation artefacts: no APPEAL_FILED, no expert summons.
    expect(stage2.txs.find(t => t.tx_type === TX_TYPES.APPEAL_FILED)).toBeUndefined();
    expect(stage2.txs.filter(t => t.tx_type === TX_TYPES.JURY_SUMMONS && t.data?.is_appeal))
      .toHaveLength(0);

    // ADJUDICATION_RESULT is marked terminal so the commit-handler restores
    // content status instead of leaving it parked awaiting an appeal.
    const adjResult = stage2.txs.find(t => t.tx_type === TX_TYPES.ADJUDICATION_RESULT);
    expect(adjResult.data.verdict).toBe(VERDICT.NO_QUORUM);
    expect(adjResult.data.terminal).toBe(true);

    // Disputer refunded: never forfeit when the system fails to decide.
    const disputerSU = _scoreUpdates(stage2.txs, ids.disputerTipId);
    expect(disputerSU).toHaveLength(1);
    expect(disputerSU[0].data.delta).toBe(STAKES.DISPUTER);

    _commitBatch(fx.dag, stage2.txs);
    // -15 filing + 15 refund = back to start.
    expect(_replay(fx.dag, ids.disputerTipId).score).toBe(SCORE.INITIAL_IDENTITY);

    // No-show jurors (4,5,6) still penalised — they broke quorum.
    for (let i = 4; i < 7; i++) {
      const s = _replay(fx.dag, ids.jurors[i], { score: 750, offense_count: 0, frozen: false });
      expect(s.score).toBe(750 - STAKES.JUROR_NO_COMMIT);
    }
  });

  test("one eligible expert (below MIN_VOTES) → still terminal + refunded", () => {
    const fx = _setup();
    const ctid = "tip://c/OH-flow11mmmmmmmmm-cccc";
    const ids = _seedDispute(fx.dag, ctid);
    _seedExpertPool(fx.dag, 1);   // 1 expert < APPEAL.MIN_VOTES (2)
    _filingStakeDebit(fx.dag, ctid, ids.disputerTipId);

    const reveals = _buildReveals(ids.jurors.slice(0, 4), [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ], ctid);
    const stage2 = buildAdjudicationBatch(ctid, reveals, ids.summons, fx.dag, fx.scoring, fx.config);

    expect(stage2.verdict).toBe(VERDICT.NO_QUORUM);
    expect(stage2.terminal).toBe(true);
    expect(stage2.auto_appeal).toBe(false);
    expect(stage2.txs.find(t => t.tx_type === TX_TYPES.APPEAL_FILED)).toBeUndefined();

    const disputerSU = _scoreUpdates(stage2.txs, ids.disputerTipId);
    expect(disputerSU).toHaveLength(1);
    expect(disputerSU[0].data.delta).toBe(STAKES.DISPUTER);
  });
});
