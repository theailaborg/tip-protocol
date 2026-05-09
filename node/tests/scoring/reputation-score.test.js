/**
 * @file tests/scoring/reputation-score.test.js
 * @description Reputation Score (0-50) rules from TIP_Scoring_v2:
 *
 *   90-day clean record   +10   (cap 50; "no content → no bonus" per spec)
 *   Dispute cleared (vindicated)   +5   (capped at 50)
 *   Reputation Score never decreases.
 *
 * Today's wiring:
 *   - REPUTATION.CLEAN_PERIOD_DAYS / CLEAN_PERIOD_BONUS load from genesis
 *     (90 / 10).
 *   - dag.getCleanRecordEligible filters identities with: active status,
 *     registered_at <= cutoff, activity since cutoff, no UPHELD ADJ_RESULT
 *     since cutoff, no clean_record_bonus already issued in the window.
 *   - The spec's "must have registered ≥1 OH or AA content" condition is
 *     NOT yet enforced — any activity in the window passes today.
 *   - The spec's per-bucket cap of 50 is NOT enforced (single combined
 *     `score`); pinned as a forward gap.
 *   - DISMISSED vindication +5 is NOT yet emitted; pinned with a skip-mark.
 *
 * Note: the trigger / cadence / leader-gating logic for clean-record bonus
 * already has dedicated tests in
 * tests/consensus/clean-record-trigger.test.js and
 * tests/dag/clean-record-eligibility.test.js. This file focuses on
 * reputation-bucket semantics.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { REPUTATION, DISPUTE, SCORE_EVENTS } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { applyScoreEffect } = require(path.join(SRC, "score-effects"));

const PROTO_CONSTANTS = require(path.resolve(__dirname, "../../../genesis-data/genesis.json")).protocol_constants;

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveVP({
    vp_id: VP_ID, name: "vp1", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  return { dag };
}

function _seedIdentity(dag, tipId, registeredAt) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: registeredAt, tx_id: shake256(`id:${tipId}`),
  });
}

function _addTx(dag, body) {
  const tx = { ...body, prev: body.prev || [] };
  tx.tx_id = computeTxId(tx);
  dag.addTx(tx);
  return tx;
}

const NOW = "2026-04-01T00:00:00.000Z";
const CUTOFF_90D_AGO = "2026-01-01T00:00:00.000Z"; // 90 days before NOW

// ─── Constants ──────────────────────────────────────────────────────────────

describe("reputation — constants from genesis match spec", () => {
  test("CLEAN_PERIOD_DAYS = 90", () => {
    expect(REPUTATION.CLEAN_PERIOD_DAYS).toBe(90);
  });

  test("CLEAN_PERIOD_BONUS = +10", () => {
    expect(REPUTATION.CLEAN_PERIOD_BONUS).toBe(10);
    expect(SCORE_EVENTS.CLEAN_90_DAYS.delta).toBe(10);
  });

  test("DISPUTE_CLEARED_BONUS = +5 (vindication)", () => {
    expect(REPUTATION.DISPUTE_CLEARED_BONUS).toBe(5);
    // VINDICATION_BONUS in DISPUTE namespace is the same value, surfaced
    // for stake-settlement code paths.
    expect(DISPUTE.VINDICATION_BONUS).toBe(5);
  });

  test("MAX_REPUTATION cap = 50 (spec)", () => {
    expect(PROTO_CONSTANTS.score.max_reputation).toBe(50);
  });
});

// ─── Eligibility — what blocks the +10 ──────────────────────────────────────

describe("clean-record eligibility — UPHELD verdict in window blocks the bonus", () => {
  test("a tip_id with an UPHELD ADJ_RESULT inside the window is NOT eligible", () => {
    const fx = _setup();
    const tipId = "tip://id/dirty";
    _seedIdentity(fx.dag, tipId, "2025-09-01T00:00:00.000Z");

    // Some activity inside the window so the "no activity" clause doesn't fire.
    _addTx(fx.dag, {
      tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "2026-02-01T00:00:00.000Z",
      data: { tip_id: tipId, delta: 1, reason: "noise" },
    });
    // UPHELD against this user inside the window — bonus must be denied.
    _addTx(fx.dag, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT, timestamp: "2026-02-15T00:00:00.000Z",
      data: { ctid: "tip://c/x", verdict: "UPHELD", author_tip_id: tipId, author_score_delta: -100 },
    });

    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).not.toContain(tipId);
  });

  test("identity registered AFTER cutoff (less than 90 days old) is NOT eligible", () => {
    const fx = _setup();
    const tipId = "tip://id/young";
    _seedIdentity(fx.dag, tipId, "2026-02-01T00:00:00.000Z"); // > cutoff
    _addTx(fx.dag, {
      tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "2026-03-01T00:00:00.000Z",
      data: { tip_id: tipId, delta: 1, reason: "noise" },
    });
    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).not.toContain(tipId);
  });

  test("identity already bonused in this window does NOT double-collect", () => {
    const fx = _setup();
    const tipId = "tip://id/already-bonused";
    _seedIdentity(fx.dag, tipId, "2025-09-01T00:00:00.000Z");

    _addTx(fx.dag, {
      tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "2026-02-01T00:00:00.000Z",
      data: { tip_id: tipId, delta: REPUTATION.CLEAN_PERIOD_BONUS, reason: "clean_record_bonus" },
    });
    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).not.toContain(tipId);
  });

  test("revoked identity (status != 'active') is NOT eligible", () => {
    const fx = _setup();
    const tipId = "tip://id/revoked";
    fx.dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: "00", root_public_key: "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "revoked",
      registered_at: "2025-09-01T00:00:00.000Z", tx_id: shake256(`id:${tipId}`),
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.SCORE_UPDATE, timestamp: "2026-02-01T00:00:00.000Z",
      data: { tip_id: tipId, delta: 1, reason: "noise" },
    });
    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).not.toContain(tipId);
  });
});

// ─── Pure-function: applying the +10 SCORE_UPDATE ───────────────────────────

describe("clean-record bonus delta application — applyScoreEffect", () => {
  test("SCORE_UPDATE with reason='clean_record_bonus' applies +10 (single channel)", () => {
    const tx = {
      tx_type: TX_TYPES.SCORE_UPDATE,
      data: { tip_id: "tip://id/x", delta: REPUTATION.CLEAN_PERIOD_BONUS, reason: "clean_record_bonus" },
    };
    const next = applyScoreEffect(tx, { score: 510, offense_count: 0, frozen: false });
    expect(next.score).toBe(520);
    expect(next.delta).toBe(10);
  });

  test("a frozen identity does NOT collect the +10 bonus (positive deltas zeroed post-freeze)", () => {
    const frozen = { score: 510, offense_count: 0, frozen: true };
    const tx = {
      tx_type: TX_TYPES.SCORE_UPDATE,
      data: { tip_id: "tip://id/x", delta: 10, reason: "clean_record_bonus" },
    };
    const next = applyScoreEffect(tx, frozen);
    expect(next.score).toBe(510);
    expect(next.delta).toBe(0);
  });
});

// ─── Spec-forward gaps ─────────────────────────────────────────────────────

describe.skip("reputation — spec rules not yet enforced in production", () => {
  test("'no content → no bonus' — identity must have registered ≥1 OH/AA content in the window", () => {
    // Spec: "If a user registers zero OH or AA content in a 90-day period,
    //   they do not earn the clean record bonus. This prevents idle score
    //   farming."
    // Today's getCleanRecordEligible accepts ANY activity in the window
    // (a SCORE_UPDATE noise tx, a JURY_VOTE_REVEAL, etc.) — so an idle user
    // who reveals one jury vote per quarter would qualify. When the OH/AA
    // requirement lands, this test should pass without modification.
  });

  test("Reputation Score capped at 50 — bucket-aware engine", () => {
    // Today the engine carries a single combined `score`, so the +10 bonus
    // and +5 vindication land directly on it, capped only by MAX_TOTAL.
    // The 50-point bucket cap is a spec goal awaiting the bucket engine.
  });

  test("Vindication +5 fires on Stage-2 DISMISSED to the cleared author", () => {
    // jury.buildAdjudicationBatch does NOT currently emit a +5 SCORE_UPDATE
    // for the author when verdict=DISMISSED. genesis exposes
    // dispute_cleared_bonus=5 and vindication_bonus=5 as the value to use.
  });
});
