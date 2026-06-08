/**
 * @file tests/scoring/dispute-stake-economy.test.js
 * @description Stake-on-file dispute economy from TIP_Scoring_v2:
 *
 *   Disputer  — stakes 15 at file time. UPHELD: refund + 5 bonus (+20 net).
 *               DISMISSED: stake stays forfeited (no settlement event;
 *               filing-time -15 IS the penalty). CONSERVATIVE_LABEL:
 *               refund only (+15).
 *   Juror     — stakes 10 implicit. Majority: +3 bonus. Minority: -10
 *               forfeit. No-show: -10. Abstain: neutral.
 *   Appellant — stakes 25 at file time. Overturn: refund + 10 bonus
 *               (+35 net). Confirm: stake stays forfeited.
 *   Appeal restore_percent = 50 — informational; the actual reversal in
 *               buildAppealBatch is the exact original delta when
 *               overturn-of-UPHELD reverses Stage-2 (-1 * stage2_delta).
 *
 * These tests exercise the pure builders (buildAdjudicationBatch /
 * buildAppealBatch) so they can run without consensus or commit-handler.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256, signBody, computeTxId,
} = require(path.join(SHARED, "crypto"));
const { TX_TYPES, ORIGIN, VOTE, VERDICT, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { DISPUTE, JURY, APPEAL } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { buildAdjudicationBatch, buildAppealBatch } = require(path.join(SRC, "jury"));

const PROTO_CONSTANTS = require(path.resolve(__dirname, "../../../genesis-data/genesis.json")).protocol_constants;

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/test";
const CTID = "tip://c/OH-aaaaaaaaaaaaaa-1111";

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

// dag.addTx hashes (tx_type, timestamp, prev, data) and rejects on tx_id
// mismatch. Build the tx body, compute the canonical tx_id, then add.
function _addTx(dag, body) {
  const tx = { ...body };
  if (!tx.prev) tx.prev = [];
  tx.tx_id = computeTxId(tx);
  dag.addTx(tx);
  return tx;
}

function _seedIdentity(dag, tipId, score = 750) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: shake256(`id:${tipId}`),
  });
  dag.setScore(tipId, score, 0, 1767225600000);
}

// Seed a dispute setup: content + author + disputer + N jurors all in DAG,
// CONTENT_DISPUTED tx, JURY_SUMMONS txs. Returns the bag of identifiers.
function _seedDisputeFixture(dag, { jurorCount = 7, declaredOrigin = ORIGIN.OH, claimedOrigin = ORIGIN.AG } = {}) {
  const authorTipId = "tip://id/author";
  const disputerTipId = "tip://id/disputer";
  _seedIdentity(dag, authorTipId, 600);
  _seedIdentity(dag, disputerTipId, 800);

  dag.saveContent({
    ctid: CTID, origin_code: declaredOrigin, content_hash: "00",
    author_tip_id: authorTipId, status: CONTENT_STATUS.DISPUTED,
    registered_at: 1767225600000, tx_id: "00",
  });

  const disputeTx = _addTx(dag, {
    tx_type: TX_TYPES.CONTENT_DISPUTED, timestamp: 1775001600000,
    data: {
      ctid: CTID, disputer_tip_id: disputerTipId, reason: "origin_mismatch",
      claimed_origin: claimedOrigin, declared_origin: declaredOrigin,
      author_tip_id: authorTipId, pre_dispute_status: CONTENT_STATUS.REGISTERED,
      stake: DISPUTE.DISPUTER_STAKE,
    },
  });

  const summons = [];
  const jurors = [];
  // Reveal-deadline far in the future so reveal txs are accepted.
  const revealDeadline = 1893456000000;
  const commitDeadline = 1893456000000;
  for (let i = 0; i < jurorCount; i++) {
    const j = `tip://id/juror-${i}`;
    _seedIdentity(dag, j, 750);
    jurors.push(j);
    summons.push(_addTx(dag, {
      tx_type: TX_TYPES.JURY_SUMMONS,
      // Stagger timestamps so each tx has a unique tx_id.
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

// Build N reveal txs with a chosen vote distribution.
function _buildReveals(jurors, votes, ts = 1775088000000) {
  return jurors.slice(0, votes.length).map((j, i) => ({
    tx_id: shake256(`reveal-${i}-${votes[i]}`),
    tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: ts,
    data: {
      ctid: CTID, juror_tip_id: j, vote: votes[i],
      salt: shake256(`s${i}`), confirmed_origin: ORIGIN.AG,
    },
  }));
}

function _findSU(txs, tipId, predicate) {
  return txs.filter(t =>
    t.tx_type === TX_TYPES.SCORE_UPDATE
    && t.data?.tip_id === tipId
    && (!predicate || predicate(t)),
  );
}

// ─── Constants from genesis match the spec ──────────────────────────────────

describe("stake economy — constants from genesis match spec", () => {
  test("DISPUTER_STAKE = 15", () => expect(DISPUTE.DISPUTER_STAKE).toBe(15));
  test("FRIVOLOUS_PENALTY = 5", () => expect(DISPUTE.FRIVOLOUS_PENALTY).toBe(5));
  test("UPHELD_BONUS = 5", () => expect(DISPUTE.UPHELD_BONUS).toBe(5));
  test("VINDICATION_BONUS = 5", () => expect(DISPUTE.VINDICATION_BONUS).toBe(5));

  test("JUROR_STAKE = 10", () => expect(JURY.JUROR_STAKE).toBe(10));
  test("JUROR_MAJORITY_BONUS = 3", () => expect(JURY.JUROR_MAJORITY_BONUS).toBe(3));
  test("EXPERT_MAJORITY_BONUS = 7", () => expect(JURY.EXPERT_MAJORITY_BONUS).toBe(7));
  test("JUROR_MINORITY_PENALTY = 8 (positive value; code applies the minus)", () => {
    expect(JURY.JUROR_MINORITY_PENALTY).toBe(8);
  });
  test("EXPERT_MINORITY_PENALTY = 10 (positive value; code applies the minus)", () => {
    expect(JURY.EXPERT_MINORITY_PENALTY).toBe(10);
  });
  test("JUROR_NO_COMMIT_PENALTY = 1", () => expect(JURY.JUROR_NO_COMMIT_PENALTY).toBe(1));
  test("JUROR_NO_REVEAL_PENALTY = 8", () => expect(JURY.JUROR_NO_REVEAL_PENALTY).toBe(8));
  test("EXPERT_NO_COMMIT_PENALTY = 1", () => expect(JURY.EXPERT_NO_COMMIT_PENALTY).toBe(1));
  test("EXPERT_NO_REVEAL_PENALTY = 10", () => expect(JURY.EXPERT_NO_REVEAL_PENALTY).toBe(10));

  test("APPELLANT_STAKE = 25", () => expect(APPEAL.APPELLANT_STAKE).toBe(25));
  test("OVERTURN_BONUS = 10", () => expect(APPEAL.OVERTURN_BONUS).toBe(10));

  test("APPEAL_RESTORE_PERCENT = 50 (genesis source)", () => {
    expect(PROTO_CONSTANTS.penalties.appeal_restore_percent).toBe(50);
  });
});

// ─── Stage-2 settlement — disputer outcomes ─────────────────────────────────

describe("Stage-2 verdict — disputer settlement", () => {
  test("UPHELD: disputer gets +(stake + UPHELD_BONUS) = +20", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);

    const settlement = _findSU(out.txs, ids.disputerTipId);
    expect(settlement).toHaveLength(1);
    expect(settlement[0].data.delta).toBe(DISPUTE.DISPUTER_STAKE + DISPUTE.UPHELD_BONUS);
    expect(settlement[0].data.delta).toBe(20);
  });

  test("DISMISSED: no disputer settlement event (filing-time stake stays forfeited)", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);
    expect(_findSU(out.txs, ids.disputerTipId)).toHaveLength(0);
  });

  test("CONSERVATIVE_LABEL: disputer gets +stake refund only (+15, no bonus)", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag, {
      declaredOrigin: ORIGIN.AG, claimedOrigin: ORIGIN.OH,
    });
    // Reveals confirm OH (over-disclosure → conservative label).
    const reveals = ids.jurors.slice(0, 7).map((j, i) => ({
      tx_id: shake256(`r-cl-${i}`), tx_type: TX_TYPES.JURY_VOTE_REVEAL,
      timestamp: 1775088000000,
      data: {
        ctid: CTID, juror_tip_id: j,
        vote: i < 5 ? VOTE.MISMATCH : VOTE.MATCH,
        salt: shake256(`s${i}`), confirmed_origin: ORIGIN.OH,
      },
    }));

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.CONSERVATIVE_LABEL);

    const settlement = _findSU(out.txs, ids.disputerTipId);
    expect(settlement).toHaveLength(1);
    expect(settlement[0].data.delta).toBe(DISPUTE.DISPUTER_STAKE);
    expect(settlement[0].data.delta).toBe(15);
  });
});

// ─── Stage-2 settlement — author outcomes (UPHELD only) ─────────────────────

describe("Stage-2 verdict — author penalty rides on a paired SCORE_UPDATE", () => {
  test("UPHELD on OH→AG (1st offense): paired SCORE_UPDATE for author = -100", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    const adjResult = out.txs.find(t => t.tx_type === TX_TYPES.ADJUDICATION_RESULT);
    expect(adjResult.data.verdict).toBe(VERDICT.UPHELD);
    expect(adjResult.data.author_score_delta).toBe(-100);

    const authorPenalty = _findSU(out.txs, ids.authorTipId);
    expect(authorPenalty).toHaveLength(1);
    expect(authorPenalty[0].data.delta).toBe(-100);
  });

  test("DISMISSED: no penalty SCORE_UPDATE; author gets the +VINDICATION_BONUS", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);

    // Single SCORE_UPDATE for the author: the vindication bonus.
    const authorSU = _findSU(out.txs, ids.authorTipId);
    expect(authorSU).toHaveLength(1);
    expect(authorSU[0].data.delta).toBe(DISPUTE.VINDICATION_BONUS);
    expect(authorSU[0].data.reason).toMatch(/vindication/i);
  });
});

// ─── Stage-2 settlement — juror outcomes ────────────────────────────────────

describe("Stage-2 verdict — juror score effects", () => {
  test("Majority jurors get +MAJORITY_BONUS (+3); minority gets -MINORITY_PENALTY (-10)", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    const votes = [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH,
    ];
    const reveals = _buildReveals(ids.jurors, votes);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);

    for (let i = 0; i < votes.length; i++) {
      const su = _findSU(out.txs, ids.jurors[i]);
      expect(su).toHaveLength(1);
      const expected = votes[i] === VOTE.MISMATCH
        ? JURY.JUROR_MAJORITY_BONUS
        : -JURY.JUROR_MINORITY_PENALTY;
      expect(su[0].data.delta).toBe(expected);
    }
  });

  test("Abstaining jurors get no score event (neutral)", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    const votes = [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.ABSTAIN, VOTE.ABSTAIN, VOTE.MATCH,
    ];
    const reveals = _buildReveals(ids.jurors, votes);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);

    // Abstaining jurors (index 4 and 5) should have NO score event.
    expect(_findSU(out.txs, ids.jurors[4])).toHaveLength(0);
    expect(_findSU(out.txs, ids.jurors[5])).toHaveLength(0);
  });

  test("No-show jurors get -NO_SHOW_PENALTY (-10) on Stage-2 verdict", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    // Only first 5 jurors reveal (need 5 reveals = QUORUM); jurors 5 and 6
    // are no-shows.
    const reveals = _buildReveals(ids.jurors.slice(0, 5), [
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.MISMATCH, VOTE.MATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);

    for (const noShowIdx of [5, 6]) {
      // No JURY_VOTE_COMMIT in DAG → reason is "no-commit"
      const su = _findSU(out.txs, ids.jurors[noShowIdx], t => /no-commit|no-reveal/i.test(t.data.reason));
      expect(su).toHaveLength(1);
      expect(su[0].data.delta).toBe(-JURY.JUROR_NO_COMMIT_PENALTY);
    }
  });

  test("Tie (matchCount === mismatchCount): no juror majority/minority effects fire", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    // 3 MATCH + 3 MISMATCH + 1 ABSTAIN = tie among non-abstain.
    const votes = [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH,
      VOTE.ABSTAIN,
    ];
    const reveals = _buildReveals(ids.jurors, votes);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);

    for (let i = 0; i < votes.length; i++) {
      // No SCORE_UPDATE for any juror in a tie.
      expect(_findSU(out.txs, ids.jurors[i])).toHaveLength(0);
    }
  });
});

// ─── Stage-3 settlement — appellant outcomes ────────────────────────────────

describe("Stage-3 verdict — appellant settlement (overturn vs confirm)", () => {
  function _withStage2(dag, stage2Verdict, declared = ORIGIN.OH, confirmed = ORIGIN.AG, appellantTipId, authorScoreDelta = -100) {
    const adjResult = _addTx(dag, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT, timestamp: 1775174400000,
      data: {
        ctid: CTID, verdict: stage2Verdict,
        declared_origin: declared, confirmed_origin: stage2Verdict === VERDICT.UPHELD ? confirmed : null,
        author_tip_id: "tip://id/author",
        author_score_delta: stage2Verdict === VERDICT.UPHELD ? authorScoreDelta : 0,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
      },
    });

    const appealFiled = _addTx(dag, {
      tx_type: TX_TYPES.APPEAL_FILED, timestamp: 1775260800000,
      data: { ctid: CTID, appellant_tip_id: appellantTipId, stage2_verdict: stage2Verdict, stake: APPEAL.APPELLANT_STAKE },
    });

    return { adjResult, appealFiled };
  }

  function _expertSummons(dag, experts) {
    const out = [];
    const revealDeadline = 1893456000000;
    const commitDeadline = 1893456000000;
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

  test("Overturn UPHELD→DISMISSED: appellant +(APPELLANT_STAKE + OVERTURN_BONUS) = +35", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    // The author appeals after a Stage-2 UPHELD.
    _withStage2(fx.dag, VERDICT.UPHELD, ORIGIN.OH, ORIGIN.AG, ids.authorTipId);

    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const summons = _expertSummons(fx.dag, experts);
    const reveals = experts.map((e, i) => ({
      tx_id: shake256(`er-${i}`),
      tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: 1775433600000,
      data: { ctid: CTID, juror_tip_id: e, vote: VOTE.MATCH, salt: shake256(`s${i}`), is_appeal: true },
    }));

    const out = buildAppealBatch(CTID, reveals, summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);
    expect(out.overturned).toBe(true);

    const settlement = _findSU(out.txs, ids.authorTipId, t => /Appeal overturned/.test(t.data.reason));
    expect(settlement.length).toBeGreaterThanOrEqual(1);
    const refundBonus = settlement.find(t => t.data.delta === APPEAL.APPELLANT_STAKE + APPEAL.OVERTURN_BONUS);
    expect(refundBonus).toBeDefined();
    expect(refundBonus.data.delta).toBe(35);
  });

  test("Confirm (UPHELD→UPHELD): no appellant settlement event (stake stays forfeited)", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    _withStage2(fx.dag, VERDICT.UPHELD, ORIGIN.OH, ORIGIN.AG, ids.authorTipId);

    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const summons = _expertSummons(fx.dag, experts);
    // Experts also vote UPHELD (MISMATCH) — confirms Stage-2.
    const reveals = experts.map((e, i) => ({
      tx_id: shake256(`er-conf-${i}`),
      tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: 1775433600000,
      data: { ctid: CTID, juror_tip_id: e, vote: VOTE.MISMATCH, salt: shake256(`s${i}`), confirmed_origin: ORIGIN.AG, is_appeal: true },
    }));

    const out = buildAppealBatch(CTID, reveals, summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);
    expect(out.overturned).toBe(false);

    // No appellant SCORE_UPDATE on confirm.
    expect(_findSU(out.txs, ids.authorTipId, t => /Appeal /.test(t.data.reason))).toHaveLength(0);
  });

  test("Overturn UPHELD→DISMISSED: Stage-2 author penalty fully reversed (+exact_original)", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    _withStage2(fx.dag, VERDICT.UPHELD, ORIGIN.OH, ORIGIN.AG, ids.authorTipId, -100);

    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const summons = _expertSummons(fx.dag, experts);
    const reveals = experts.map((e, i) => ({
      tx_id: shake256(`er-rev-${i}`),
      tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: 1775433600000,
      data: { ctid: CTID, juror_tip_id: e, vote: VOTE.MATCH, salt: shake256(`s${i}`), is_appeal: true },
    }));

    const out = buildAppealBatch(CTID, reveals, summons, fx.dag, fx.scoring, fx.config);
    expect(out.overturned).toBe(true);

    // Author should get +100 (Stage-2 -100 reversed). buildAppealBatch
    // emits the EXACT original delta as a positive — same number, opposite sign.
    const reversal = _findSU(out.txs, ids.authorTipId, t => /Stage 2 penalty reversed/.test(t.data.reason));
    expect(reversal).toHaveLength(1);
    expect(reversal[0].data.delta).toBe(100);
  });
});

// ─── Spec-forward gaps (NOT YET ENFORCED) ───────────────────────────────────

describe("vindication +5 to author on DISMISSED", () => {
  test("DISMISSED emits a +VINDICATION_BONUS SCORE_UPDATE to the cleared author", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    const reveals = _buildReveals(ids.jurors, [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ]);

    const out = buildAdjudicationBatch(CTID, reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);

    const vindication = _findSU(out.txs, ids.authorTipId,
      t => /vindication/i.test(t.data.reason));
    expect(vindication).toHaveLength(1);
    expect(vindication[0].data.delta).toBe(DISPUTE.VINDICATION_BONUS);
  });

  test("Stage-3 overturn (DISMISSED → UPHELD) retracts the vindication", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);

    // Run Stage-2 DISMISSED to seed the vindication tx into the DAG.
    const stage2Reveals = _buildReveals(ids.jurors, [
      VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH,
      VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH,
    ]);
    const stage2 = buildAdjudicationBatch(CTID, stage2Reveals, ids.summons, fx.dag, fx.scoring, fx.config);
    for (const t of stage2.txs) fx.dag.addTx(t);

    _addTx(fx.dag, {
      tx_type: TX_TYPES.APPEAL_FILED, timestamp: 1775260801000,
      data: { ctid: CTID, appellant_tip_id: ids.disputerTipId, stage2_verdict: VERDICT.DISMISSED, stake: APPEAL.APPELLANT_STAKE },
    });

    const experts = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];
    for (const e of experts) _seedIdentity(fx.dag, e, 900);
    const expSummons = (() => {
      const out = [];
      for (let i = 0; i < experts.length; i++) {
        out.push(_addTx(fx.dag, {
          tx_type: TX_TYPES.JURY_SUMMONS,
          timestamp: `2026-04-05T00:00:0${i}.000Z`,
          data: {
            ctid: CTID, juror_tip_id: experts[i], is_appeal: true,
            stake: JURY.JUROR_STAKE,
            commit_deadline: 1893456000000,
            reveal_deadline: 1893456000000,
            seed: shake256("e"), identity_count: 3,
          },
        }));
      }
      return out;
    })();
    const expReveals = experts.map((e, i) => ({
      tx_id: shake256(`er-vind-${i}`),
      tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: 1775433600000,
      data: { ctid: CTID, juror_tip_id: e, vote: VOTE.MISMATCH, salt: shake256(`s${i}`), confirmed_origin: ORIGIN.AG, is_appeal: true },
    }));

    const stage3 = buildAppealBatch(CTID, expReveals, expSummons, fx.dag, fx.scoring, fx.config);
    expect(stage3.verdict).toBe(VERDICT.UPHELD);
    expect(stage3.overturned).toBe(true);

    const retraction = _findSU(stage3.txs, ids.authorTipId,
      t => /vindication retracted/i.test(t.data.reason));
    expect(retraction).toHaveLength(1);
    expect(retraction[0].data.delta).toBe(-DISPUTE.VINDICATION_BONUS);
  });
});
