/**
 * @file tests/validators/update-origin-grace.test.js
 * @description Grace-window dispatch in business-rules.canUpdateOrigin.
 *
 * Tiered self-correction window:
 *   - Unflagged (LOW/ELEVATED tier): 24h grace
 *   - HIGH/CRITICAL + override=true: 48h grace (matches reviewer engagement at h=48)
 *   - HIGH/CRITICAL without override: shouldn't happen at registration (409
 *     gate enforces it), but if a row somehow lacks override, falls back to
 *     the unflagged 24h window (safer default)
 *
 * Tests drive canUpdateOrigin directly with controlled content rows so
 * the grace branch is the single variable under test.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../../../shared/time");

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const rules = require(path.join(SRC, "validators", "business-rules"));
const { PRESCAN_TIERS } = require(path.join(SHARED, "constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const AUTHOR_ID = "tip://id/US-aaaaaaaaaaaaaaaa";
const REGISTERED_AT = 1767225600000;
const REGISTERED_AT_MS = REGISTERED_AT;

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: REGISTERED_AT,
  });
  dag.saveIdentity({
    tip_id: AUTHOR_ID, region: "US",
    public_key: "deadbeef".repeat(488),
    root_public_key: "00", vp_id: VP_ID, verification_tier: "T1",
    founding: false, status: "active",
    reviewer_consent: false,
    registered_at: REGISTERED_AT, tx_id: "tx_a",
  });
  return { dag };
}

function _seedContent(dag, opts) {
  dag.saveContent({
    ctid: opts.ctid,
    origin_code: "OH",
    content_hash: "abcd".repeat(16),
    perceptual_hash: null,
    author_tip_id: AUTHOR_ID,
    signer_tip_id: AUTHOR_ID,
    authors: [{ tip_id: AUTHOR_ID, key_mode: "attribution", role: "byline", signed: false, tip_id_type: "personal" }],
    attribution_mode: "self",
    extras: {},
    cna_version: "CNA-2.2",
    status: "registered",
    prescan_flagged: opts.flagged === undefined ? false : opts.flagged,
    prescan_probability: opts.probability || 0,
    prescan_tier: opts.tier || PRESCAN_TIERS.LOW,
    override: opts.override === undefined ? false : opts.override,
    registered_at: REGISTERED_AT,
    registered_urls: [],
    tx_id: "tx_content",
  });
}

const HOUR_MS = 60 * 60 * 1000;
const args = (ctid) => ({ ctid, author_tip_id: AUTHOR_ID, new_origin_code: "AA" });

describe("canUpdateOrigin — grace window dispatch", () => {

  describe("Unflagged content (LOW tier) — 24h window", () => {
    test("succeeds at 23h (within window)", () => {
      const { dag } = _setup();
      _seedContent(dag, { ctid: "tip://c/OH-aaaa", tier: PRESCAN_TIERS.LOW });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-aaaa"), { now: REGISTERED_AT_MS + 23 * HOUR_MS });
      expect(result.valid).toBe(true);
    });

    test("succeeds exactly at 24h boundary", () => {
      const { dag } = _setup();
      _seedContent(dag, { ctid: "tip://c/OH-aabb", tier: PRESCAN_TIERS.LOW });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-aabb"), { now: REGISTERED_AT_MS + 24 * HOUR_MS });
      expect(result.valid).toBe(true);  // exactly at boundary still passes
    });

    test("rejects at 24h+1ms (just past)", () => {
      const { dag } = _setup();
      _seedContent(dag, { ctid: "tip://c/OH-aacc", tier: PRESCAN_TIERS.LOW });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-aacc"), { now: REGISTERED_AT_MS + 24 * HOUR_MS + 1 });
      expect(result.valid).toBe(false);
      expect(result.error.message).toMatch(/24-hour grace period has expired/);
    });

    test("rejects at 25h", () => {
      const { dag } = _setup();
      _seedContent(dag, { ctid: "tip://c/OH-aadd", tier: PRESCAN_TIERS.LOW });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-aadd"), { now: REGISTERED_AT_MS + 25 * HOUR_MS });
      expect(result.valid).toBe(false);
    });
  });

  describe("ELEVATED tier — 24h window (soft warning only, no override required at register)", () => {
    test("ELEVATED + no override → uses 24h window (rejects at 25h)", () => {
      const { dag } = _setup();
      _seedContent(dag, {
        ctid: "tip://c/OH-elev",
        tier: PRESCAN_TIERS.ELEVATED,
        probability: 0.75,
        flagged: false,
        override: false,
      });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-elev"), { now: REGISTERED_AT_MS + 25 * HOUR_MS });
      expect(result.valid).toBe(false);
      expect(result.error.message).toMatch(/24-hour/);
    });
  });

  describe("HIGH tier with override — 48h window", () => {
    test("succeeds at 47h (within window)", () => {
      const { dag } = _setup();
      _seedContent(dag, {
        ctid: "tip://c/OH-high1", tier: PRESCAN_TIERS.HIGH,
        probability: 0.92, flagged: true, override: true,
      });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-high1"), { now: REGISTERED_AT_MS + 47 * HOUR_MS });
      expect(result.valid).toBe(true);
    });

    test("succeeds exactly at 48h boundary", () => {
      const { dag } = _setup();
      _seedContent(dag, {
        ctid: "tip://c/OH-high2", tier: PRESCAN_TIERS.HIGH,
        probability: 0.92, flagged: true, override: true,
      });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-high2"), { now: REGISTERED_AT_MS + 48 * HOUR_MS });
      expect(result.valid).toBe(true);
    });

    test("rejects at 48h+1ms (just past)", () => {
      const { dag } = _setup();
      _seedContent(dag, {
        ctid: "tip://c/OH-high3", tier: PRESCAN_TIERS.HIGH,
        probability: 0.92, flagged: true, override: true,
      });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-high3"), { now: REGISTERED_AT_MS + 48 * HOUR_MS + 1 });
      expect(result.valid).toBe(false);
      expect(result.error.message).toMatch(/48-hour grace period has expired/);
    });

    test("rejects at 49h", () => {
      const { dag } = _setup();
      _seedContent(dag, {
        ctid: "tip://c/OH-high4", tier: PRESCAN_TIERS.HIGH,
        probability: 0.92, flagged: true, override: true,
      });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-high4"), { now: REGISTERED_AT_MS + 49 * HOUR_MS });
      expect(result.valid).toBe(false);
    });
  });

  describe("CRITICAL tier with override — 48h window", () => {
    test("succeeds at 47h", () => {
      const { dag } = _setup();
      _seedContent(dag, {
        ctid: "tip://c/OH-crit1", tier: PRESCAN_TIERS.CRITICAL,
        probability: 0.99, flagged: true, override: true,
      });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-crit1"), { now: REGISTERED_AT_MS + 47 * HOUR_MS });
      expect(result.valid).toBe(true);
    });

    test("rejects at 48h+1ms with 48-hour message", () => {
      const { dag } = _setup();
      _seedContent(dag, {
        ctid: "tip://c/OH-crit2", tier: PRESCAN_TIERS.CRITICAL,
        probability: 0.99, flagged: true, override: true,
      });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-crit2"), { now: REGISTERED_AT_MS + 48 * HOUR_MS + 1 });
      expect(result.valid).toBe(false);
      expect(result.error.message).toMatch(/48-hour/);
    });
  });

  describe("HIGH/CRITICAL without override — falls back to 24h (safer default)", () => {
    test("HIGH + override=false → 24h window applies", () => {
      const { dag } = _setup();
      _seedContent(dag, {
        ctid: "tip://c/OH-noov", tier: PRESCAN_TIERS.HIGH,
        probability: 0.92, flagged: true, override: false,
      });
      const result = rules.canUpdateOrigin(dag, args("tip://c/OH-noov"), { now: REGISTERED_AT_MS + 25 * HOUR_MS });
      expect(result.valid).toBe(false);
      expect(result.error.message).toMatch(/24-hour/);
    });
  });

  describe("open review lockout — creator can't update or retract while reviewer is engaged", () => {

    const CTID = "tip://c/OH-revlockout1234-aa49";

    function _seedWithOpenReview(state) {
      const { dag } = _setup();
      _seedContent(dag, {
        ctid: CTID, tier: PRESCAN_TIERS.HIGH,
        probability: 0.92, flagged: true, override: true,
      });
      // Override registered_at to "now" so the 48h grace-window branch
      // wouldn't reject by itself — the only failure path under test
      // here is the open-review gate.
      const seeded = dag.getContent(CTID);
      dag.saveContent({ ...seeded, registered_at: nowMs() });
      dag.savePrescanReview({
        review_id: "rv_open", ctid: CTID, creator_tip_id: AUTHOR_ID,
        assigned_reviewer: "tip://id/US-rrrrrrrrrrrrrrrr",
        triggered_at_round: 1,
        confirmed_at_round: state === "confirmed" ? 2 : null,
        confirmed_at_ms: state === "confirmed" ? nowMs() : null,
        state,
      });
      return dag;
    }

    test("canUpdateOrigin rejected while review is TRIGGERED — '...while a reviewer is evaluating...'", () => {
      const dag = _seedWithOpenReview("triggered");
      const result = rules.canUpdateOrigin(dag, args(CTID), { now: nowMs() });
      expect(result.valid).toBe(false);
      expect(result.error.status).toBe(403);
      expect(result.error.message).toMatch(/while a reviewer is evaluating/i);
    });

    test("canRetract rejected while review is TRIGGERED — '...while a reviewer is evaluating...'", () => {
      const dag = _seedWithOpenReview("triggered");
      const result = rules.canRetract(dag, { ctid: CTID, author_tip_id: AUTHOR_ID });
      expect(result.valid).toBe(false);
      expect(result.error.status).toBe(403);
      expect(result.error.message).toMatch(/while a reviewer is evaluating/i);
    });

    test("canRetract rejected while review is CONFIRMED", () => {
      const dag = _seedWithOpenReview("confirmed");
      const result = rules.canRetract(dag, { ctid: CTID, author_tip_id: AUTHOR_ID });
      expect(result.valid).toBe(false);
      expect(result.error.status).toBe(403);
    });

    test("canRetract allowed after review terminates in CLOSED_DISMISSED", () => {
      const dag = _seedWithOpenReview("closed_dismissed");
      const result = rules.canRetract(dag, { ctid: CTID, author_tip_id: AUTHOR_ID });
      expect(result.valid).toBe(true);
    });

    test("canRetract allowed while review is in transient RECUSED state (next-round re-trigger hasn't fired yet)", () => {
      // RECUSED is not "open" per getOpenPrescanReviewByCtid, which
      // matches TRIGGERED + CONFIRMED only. The next-round trigger
      // will create a fresh TRIGGERED row that re-locks retract.
      const dag = _seedWithOpenReview("recused");
      const result = rules.canRetract(dag, { ctid: CTID, author_tip_id: AUTHOR_ID });
      expect(result.valid).toBe(true);
    });
  });
});
