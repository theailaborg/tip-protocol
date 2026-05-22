/**
 * @file tests/scoring/conservative-labeling.test.js
 * @description "Conservative labeling = zero penalty" rule from
 * TIP_Scoring_v2_Personal_Notes:
 *
 *   "If you declare AI-Generated when the content was actually
 *   human-written, you lose nothing. Ever. The system rewards honesty
 *   and over-disclosure, not under-disclosure."
 *
 * Where this lands in code:
 *   - score-effects.adjudicationDelta returns 0 for verdict
 *     CONSERVATIVE_LABEL regardless of offense_count.
 *   - business-rules.canDispute (ELIGIBLE_ORIGIN_MISMATCHES) refuses
 *     same-origin, MX, and other "no verdict effect" transitions
 *     up-front so frivolous disputes never burn jury cycles.
 *   - The single-eligible "downgrade" path is AG→OH, which the jury
 *     resolves as CONSERVATIVE_LABEL — origin updates on the content
 *     record, but the author takes no score hit.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { TX_TYPES, ORIGIN, VERDICT, CONTENT_STATUS } = require(SHARED + "/constants");
const { adjudicationDelta, applyScoreEffect, scoreTargetTipId } = require(path.join(SRC, "score-effects"));
const rules = require(path.join(SRC, "validators", "business-rules"));
const { initDAG } = require(path.join(SRC, "dag"));

// Stub-shaped scoring so canDispute can call .getScore — we don't run
// the engine here, the score gate is exercised in tiers-and-gates.test.js.
const _stubScoring = (score = 1000) => ({ getScore: () => ({ score }) });

function _seed(dag) {
  const tipId = "tip://id/disputer";
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
    vp_id: "tip://vp/v1", verification_tier: "T1", founding: false,
    status: "active", registered_at: 1767225600000,
    tx_id: "deadbeef",
  });
  dag.setScore(tipId, 1000, 0, 1767225600000);
  return tipId;
}
function _seedContent(dag, ctid, originCode) {
  dag.saveContent({
    ctid, origin_code: originCode, content_hash: "00",
    author_tip_id: "tip://id/author", status: CONTENT_STATUS.REGISTERED,
    registered_at: 1767225600000, tx_id: "00",
  });
}

// ─── adjudicationDelta — verdict-level conservatism ─────────────────────────

describe("adjudicationDelta — CONSERVATIVE_LABEL is zero-penalty regardless of offense count", () => {
  test.each([0, 1, 2, 5, 99])("offense_count=%i → 0", (n) => {
    const d = adjudicationDelta({
      declared_origin: ORIGIN.AG, confirmed_origin: ORIGIN.OH,
      verdict: VERDICT.CONSERVATIVE_LABEL,
    }, n);
    expect(d).toBe(0);
  });

  test("DISMISSED → 0 (creator was right; no penalty path is the spec rule)", () => {
    expect(adjudicationDelta({
      declared_origin: ORIGIN.OH, confirmed_origin: ORIGIN.AG,
      verdict: VERDICT.DISMISSED,
    }, 0)).toBe(0);
  });

  test("NO_QUORUM (other / unknown verdict) → 0 (only UPHELD penalises)", () => {
    expect(adjudicationDelta({
      declared_origin: ORIGIN.OH, confirmed_origin: ORIGIN.AG,
      verdict: VERDICT.NO_QUORUM,
    }, 0)).toBe(0);
  });
});

describe("adjudicationDelta — over-disclosure pairs cost nothing", () => {
  // Each row: declared was MORE-AI-than-actual (the honest direction).
  // None of these are in the penalty matrix; the rule layer also rejects
  // them at canDispute, but if one slipped through the verdict path
  // would still produce 0.
  test.each([
    [ORIGIN.AG, ORIGIN.OH],
    [ORIGIN.AG, ORIGIN.AA],
    [ORIGIN.AA, ORIGIN.OH],
    [ORIGIN.MX, ORIGIN.OH],
  ])("declared %s, confirmed %s, UPHELD → 0", (declared, confirmed) => {
    const d = adjudicationDelta({
      declared_origin: declared, confirmed_origin: confirmed,
      verdict: VERDICT.UPHELD,
    }, 0);
    expect(d).toBe(0);
  });
});

// ─── canDispute eligibility matrix — frivolous disputes blocked at filing ───

describe("canDispute — eligible origin transitions land", () => {
  test.each([
    [ORIGIN.OH, ORIGIN.AG],
    [ORIGIN.OH, ORIGIN.AA],
    [ORIGIN.AA, ORIGIN.AG],
    [ORIGIN.AG, ORIGIN.OH],
  ])("accepts %s → %s", (declared, claimed) => {
    const dag = initDAG({ dbPath: ":memory:" });
    const tipId = _seed(dag);
    const ctid = `tip://c/${declared}-aaaaaaaaaaaaaa-1111`;
    _seedContent(dag, ctid, declared);
    const r = rules.canDispute(dag, _stubScoring(1000), {
      ctid, disputer_tip_id: tipId, evidence_hash: null,
      reason: "origin_mismatch", claimed_origin: claimed,
    });
    expect(r.valid).toBe(true);
  });
});

describe("canDispute — ineligible origin transitions rejected up-front", () => {
  test.each([
    [ORIGIN.OH, ORIGIN.OH, /must differ from declared origin/i],
    [ORIGIN.AA, ORIGIN.OH, /not a disputable mismatch/i],   // honest downgrade
    [ORIGIN.AG, ORIGIN.AA, /not a disputable mismatch/i],   // partial downgrade
    [ORIGIN.MX, ORIGIN.OH, /not a disputable mismatch/i],
    [ORIGIN.OH, ORIGIN.MX, /not a disputable mismatch/i],
  ])("rejects %s → %s", (declared, claimed, msgRe) => {
    const dag = initDAG({ dbPath: ":memory:" });
    const tipId = _seed(dag);
    const ctid = `tip://c/${declared}-bbbbbbbbbbbbbb-2222`;
    _seedContent(dag, ctid, declared);
    const r = rules.canDispute(dag, _stubScoring(1000), {
      ctid, disputer_tip_id: tipId, evidence_hash: null,
      reason: "origin_mismatch", claimed_origin: claimed,
    });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(msgRe);
  });
});

// ─── ADJUDICATION_RESULT routing — conservative verdicts don't hit the author ─

describe("ADJUDICATION_RESULT routing — only UPHELD targets the author", () => {
  test("CONSERVATIVE_LABEL ADJ_RESULT does NOT route to author (no score effect)", () => {
    const tx = {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      data: {
        ctid: "tip://c/x", verdict: VERDICT.CONSERVATIVE_LABEL,
        author_tip_id: "tip://id/author", author_score_delta: 0,
      },
    };
    expect(scoreTargetTipId(tx)).toBeNull();
  });

  test("DISMISSED ADJ_RESULT does NOT route to author either", () => {
    const tx = {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      data: { ctid: "tip://c/x", verdict: VERDICT.DISMISSED, author_tip_id: "tip://id/author" },
    };
    expect(scoreTargetTipId(tx)).toBeNull();
  });

  test("UPHELD ADJ_RESULT routes to author so offense_count increments", () => {
    const tx = {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      data: {
        ctid: "tip://c/x", verdict: VERDICT.UPHELD,
        author_tip_id: "tip://id/author", author_score_delta: -100,
      },
    };
    expect(scoreTargetTipId(tx)).toBe("tip://id/author");
    const next = applyScoreEffect(tx, { score: 600, offense_count: 0, frozen: false });
    // Score delta itself rides on the paired SCORE_UPDATE (single-channel
    // rule); ADJ_RESULT only bumps offense_count.
    expect(next.score).toBe(600);
    expect(next.offense_count).toBe(1);
  });
});
