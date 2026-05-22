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
    public_key: "00", status: "active", registered_at: 1767225600000,
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

const NOW = 1775001600000;
const CUTOFF_90D_AGO = 1767225600000; // 90 days before NOW

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
    _seedIdentity(fx.dag, tipId, 1756684800000);

    // Some activity inside the window so the "no activity" clause doesn't fire.
    _addTx(fx.dag, {
      tx_type: TX_TYPES.SCORE_UPDATE, timestamp: 1769904000000,
      data: { tip_id: tipId, delta: 1, reason: "noise" },
    });
    // UPHELD against this user inside the window — bonus must be denied.
    _addTx(fx.dag, {
      tx_type: TX_TYPES.ADJUDICATION_RESULT, timestamp: 1771113600000,
      data: { ctid: "tip://c/x", verdict: "UPHELD", author_tip_id: tipId, author_score_delta: -100 },
    });

    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).not.toContain(tipId);
  });

  test("identity registered AFTER cutoff (less than 90 days old) is NOT eligible", () => {
    const fx = _setup();
    const tipId = "tip://id/young";
    _seedIdentity(fx.dag, tipId, 1769904000000); // > cutoff
    _addTx(fx.dag, {
      tx_type: TX_TYPES.SCORE_UPDATE, timestamp: 1772323200000,
      data: { tip_id: tipId, delta: 1, reason: "noise" },
    });
    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).not.toContain(tipId);
  });

  test("identity already bonused in this window does NOT double-collect", () => {
    const fx = _setup();
    const tipId = "tip://id/already-bonused";
    _seedIdentity(fx.dag, tipId, 1756684800000);

    _addTx(fx.dag, {
      tx_type: TX_TYPES.SCORE_UPDATE, timestamp: 1769904000000,
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
      registered_at: 1756684800000, tx_id: shake256(`id:${tipId}`),
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.SCORE_UPDATE, timestamp: 1769904000000,
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

// ─── 'no content → no bonus' — anti-spam rule from spec ───────────────────

describe("clean-record eligibility — must register ≥1 OH/AA content in window", () => {
  test("idle juror with reveals but no OH/AA content registration is NOT eligible", () => {
    // Spec rationale: "If a user registers zero OH or AA content in a
    // 90-day period, they do not earn the clean record bonus. This
    // prevents idle score farming."
    const fx = _setup();
    const tipId = "tip://id/idle-juror";
    _seedIdentity(fx.dag, tipId, 1756684800000);

    // Plenty of activity — but it's all jury participation, not authored
    // content registrations. The user is "active" but hasn't published.
    _addTx(fx.dag, {
      tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: 1769904000000,
      data: { ctid: "tip://c/x", juror_tip_id: tipId, vote: "MATCH", salt: "00", confirmed_origin: "OH" },
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.SCORE_UPDATE, timestamp: 1771113600000,
      data: { tip_id: tipId, delta: 3, reason: "Jury majority vote on tip://c/x" },
    });

    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).not.toContain(tipId);
  });

  test("user with ≥1 OH content registration in window IS eligible", () => {
    const fx = _setup();
    const tipId = "tip://id/publisher";
    _seedIdentity(fx.dag, tipId, 1756684800000);
    _addTx(fx.dag, {
      tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: 1769904000000,
      data: { ctid: "tip://c/x", signer_tip_id: tipId, origin_code: "OH", content_hash: "00" },
    });
    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).toContain(tipId);
  });

  test("user with ≥1 AA content registration in window IS eligible", () => {
    const fx = _setup();
    const tipId = "tip://id/aa-publisher";
    _seedIdentity(fx.dag, tipId, 1756684800000);
    _addTx(fx.dag, {
      tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: 1769904000000,
      data: { ctid: "tip://c/y", signer_tip_id: tipId, origin_code: "AA", content_hash: "00" },
    });
    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).toContain(tipId);
  });

  test("only AG / MX content registrations do NOT qualify (must be OH or AA)", () => {
    // Spec is explicit: "at least one OH or AA content". AG / MX
    // registrations don't carry the same "creator effort" signal.
    const fx = _setup();
    const tipId = "tip://id/ag-only";
    _seedIdentity(fx.dag, tipId, 1756684800000);
    _addTx(fx.dag, {
      tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: 1769904000000,
      data: { ctid: "tip://c/z", signer_tip_id: tipId, origin_code: "AG", content_hash: "00" },
    });
    _addTx(fx.dag, {
      tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: 1771113600000,
      data: { ctid: "tip://c/zz", signer_tip_id: tipId, origin_code: "MX", content_hash: "00" },
    });
    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).not.toContain(tipId);
  });

  test("OH/AA registration BEFORE the window does not satisfy the rule", () => {
    const fx = _setup();
    const tipId = "tip://id/old-publisher";
    _seedIdentity(fx.dag, tipId, 1748736000000);
    // Registered before the cutoff — outside the window.
    _addTx(fx.dag, {
      tx_type: TX_TYPES.REGISTER_CONTENT, timestamp: 1754006400000,
      data: { ctid: "tip://c/old", signer_tip_id: tipId, origin_code: "OH", content_hash: "00" },
    });
    expect(fx.dag.getCleanRecordEligible(CUTOFF_90D_AGO)).not.toContain(tipId);
  });
});

// ─── Remaining spec-forward gaps ───────────────────────────────────────────

describe.skip("reputation — spec rules awaiting bucket-aware engine", () => {
  test("Reputation Score capped at 50 — bucket-aware engine", () => {
    // Today the engine carries a single combined `score`, so the +10 bonus
    // and +5 vindication land directly on it, capped only by MAX_TOTAL.
    // The 50-point bucket cap is a spec goal awaiting the bucket engine.
  });
  // Vindication +5 on Stage-2 DISMISSED is now wired — see
  // dispute-stake-economy.test.js "vindication +5 to author on DISMISSED".
});
