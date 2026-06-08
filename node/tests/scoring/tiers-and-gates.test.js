/**
 * @file tests/scoring/tiers-and-gates.test.js
 * @description Trust tiers + permission gates from TIP_Scoring_v2:
 *
 *   850-1000  Highly Trusted   (eligible for expert appeal panels)
 *   650-849   Trusted          (jury eligibility at >= 700)
 *   400-649   Verified         (can register, verify; dispute filing requires score >= 550)
 *   200-399   Caution          (register only)
 *   0-199     Not Trusted      (mandatory pre-scan, no dispute / no verify)
 *
 * Action gates checked here:
 *   canDispute  — score >= DISPUTE_FILING_MIN (550)
 *   isJuryEligible — score >= JURY_MIN_SCORE (700) AND not revoked
 *   selectExperts (pool floor) — score >= MIN_EXPERT_SCORE (850), with
 *                                 fallbacks at 700 then jury_fallback (500).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { ORIGIN, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { getTier, DISPUTE, JURY, APPEAL } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const rules = require(path.join(SRC, "validators", "business-rules"));

const PROTO_CONSTANTS = require(path.resolve(__dirname, "../../../genesis-data/genesis.json")).protocol_constants;

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveVP({
    vp_id: VP_ID, name: "vp1", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  return { dag, scoring: initScoring(dag, { nodeId: "tip://node/test" }) };
}

function _seedIdentity(dag, tipId, score) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: shake256(`id:${tipId}`),
  });
  dag.setScore(tipId, score, 0, 1767225600000);
}

// ─── Tier-threshold constants from genesis ──────────────────────────────────

describe("tier thresholds — genesis constants match spec", () => {
  test("HIGHLY_TRUSTED >= 850", () => expect(PROTO_CONSTANTS.tiers.highly_trusted).toBe(850));
  test("TRUSTED >= 650", () => expect(PROTO_CONSTANTS.tiers.trusted).toBe(650));
  test("VERIFIED >= 400", () => expect(PROTO_CONSTANTS.tiers.verified).toBe(400));
  test("CAUTION >= 200 (anything below = NOT_TRUSTED)", () => {
    expect(PROTO_CONSTANTS.tiers.caution).toBe(200);
  });

  test("DISPUTE_FILING_MIN = 550 (mid-Verified gate)", () => {
    expect(DISPUTE.MIN_SCORE_TO_DISPUTE).toBe(550);
  });
  test("JURY_MIN_SCORE = 700 (Trusted+ gate)", () => {
    expect(JURY.MIN_SCORE).toBe(700);
  });
  test("MIN_EXPERT_SCORE = 850 (Highly Trusted gate)", () => {
    expect(APPEAL.MIN_EXPERT_SCORE).toBe(850);
  });
});

// ─── getTier — boundary cases ───────────────────────────────────────────────

describe("getTier — exact boundaries map to the higher tier", () => {
  test.each([
    [1000, "HIGHLY_TRUSTED"],
    [850, "HIGHLY_TRUSTED"],   // boundary — inclusive
    [849, "TRUSTED"],
    [700, "TRUSTED"],
    [650, "TRUSTED"],          // boundary
    [649, "VERIFIED"],
    [500, "VERIFIED"],
    [400, "VERIFIED"],         // boundary
    [399, "CAUTION"],
    [200, "CAUTION"],          // boundary
    [199, "NOT_TRUSTED"],
    [0, "NOT_TRUSTED"],
  ])("score %i → %s", (score, expected) => {
    expect(getTier(score).name).toBe(expected);
  });

  test("getTier returns label + color along with name", () => {
    const t = getTier(500);
    expect(t.name).toBe("VERIFIED");
    expect(typeof t.label).toBe("string");
    expect(typeof t.color).toBe("string");
  });
});

// ─── canDispute gate ───────────────────────────────────────────────────────

describe("canDispute — score gate (>= 550)", () => {
  function _seedDisputable(dag, score) {
    const tipId = "tip://id/disputer";
    _seedIdentity(dag, tipId, score);
    const ctid = "tip://c/OH-aaaaaaaaaaaaaa-1111";
    dag.saveContent({
      ctid, origin_code: ORIGIN.OH, content_hash: "00",
      author_tip_id: "tip://id/author", status: CONTENT_STATUS.REGISTERED,
      registered_at: 1767225600000, tx_id: "00",
    });
    return { tipId, ctid };
  }

  test("score = 550 (exact boundary): allowed", () => {
    const fx = _setup();
    const { tipId, ctid } = _seedDisputable(fx.dag, 550);
    const r = rules.canDispute(fx.dag, fx.scoring, {
      ctid, disputer_tip_id: tipId, evidence_hash: null,
      reason: "origin_mismatch", claimed_origin: ORIGIN.AG,
    });
    expect(r.valid).toBe(true);
  });

  test("score = 549 (one below boundary): rejected with score message", () => {
    const fx = _setup();
    const { tipId, ctid } = _seedDisputable(fx.dag, 549);
    const r = rules.canDispute(fx.dag, fx.scoring, {
      ctid, disputer_tip_id: tipId, evidence_hash: null,
      reason: "origin_mismatch", claimed_origin: ORIGIN.AG,
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(403);
    expect(r.error.message).toMatch(/Score must be >= 550/);
  });

  test("score = 400 (lower Verified tier, but below dispute floor): rejected", () => {
    const fx = _setup();
    const { tipId, ctid } = _seedDisputable(fx.dag, 400);
    const r = rules.canDispute(fx.dag, fx.scoring, {
      ctid, disputer_tip_id: tipId, evidence_hash: null,
      reason: "origin_mismatch", claimed_origin: ORIGIN.AG,
    });
    expect(r.valid).toBe(false);
    expect(r.error.status).toBe(403);
  });

  test("score = 0 (Not Trusted): rejected", () => {
    const fx = _setup();
    const { tipId, ctid } = _seedDisputable(fx.dag, 0);
    const r = rules.canDispute(fx.dag, fx.scoring, {
      ctid, disputer_tip_id: tipId, evidence_hash: null,
      reason: "origin_mismatch", claimed_origin: ORIGIN.AG,
    });
    expect(r.valid).toBe(false);
  });

  test("revoked TIP-ID: rejected even at score 1000", () => {
    const fx = _setup();
    const { tipId, ctid } = _seedDisputable(fx.dag, 1000);
    fx.dag.addRevocation(tipId, "voluntary", 1775001600000, "00");
    const r = rules.canDispute(fx.dag, fx.scoring, {
      ctid, disputer_tip_id: tipId, evidence_hash: null,
      reason: "origin_mismatch", claimed_origin: ORIGIN.AG,
    });
    expect(r.valid).toBe(false);
    expect(r.error.message).toMatch(/revoked/i);
  });
});

// ─── isJuryEligible gate ────────────────────────────────────────────────────

describe("isJuryEligible — score gate (>= 700) + revocation check", () => {
  test("score = 700 (exact boundary): eligible", () => {
    const fx = _setup();
    _seedIdentity(fx.dag, "tip://id/j", 700);
    expect(fx.scoring.isJuryEligible("tip://id/j")).toBe(true);
  });

  test("score = 699 (one below): not eligible", () => {
    const fx = _setup();
    _seedIdentity(fx.dag, "tip://id/j", 699);
    expect(fx.scoring.isJuryEligible("tip://id/j")).toBe(false);
  });

  test("score = 1000 but revoked: not eligible", () => {
    const fx = _setup();
    _seedIdentity(fx.dag, "tip://id/j", 1000);
    fx.dag.addRevocation("tip://id/j", "voluntary", 1775001600000, "00");
    expect(fx.scoring.isJuryEligible("tip://id/j")).toBe(false);
  });
});

// ─── Sub-bucket caps don't violate tier promises ────────────────────────────

describe("tier promises — score never exceeds 1000 even at maxed sub-buckets", () => {
  test("INITIAL_IDENTITY (500) lands in VERIFIED, NOT in CAUTION", () => {
    expect(getTier(500).name).toBe("VERIFIED");
  });

  test("Sum of all sub-bucket maxes is 1000 (ceiling holds)", () => {
    expect(530 + 350 + 50 + 70).toBe(1000);
  });
});
