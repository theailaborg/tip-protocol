/**
 * @file tests/services/dashboard-content-flagged.test.js
 * @description Flagged-content notifications on the creator's
 * dashboard. Three states derived from DAG state inside
 * getUserDashboard; no separate notifications table.
 *
 *   content_flagged_for_review         h=0 → h=48, no review yet
 *   content_under_review               TRIGGERED — reviewer evaluating
 *   prescan_review_decision_required   CONFIRMED — creator has 24h
 *
 * Coverage:
 *   - All HIGH/CRITICAL OH content shows from h=0 (no warning-age delay,
 *     no override-flag gate — silent-registration compatible)
 *   - Hidden after h=48 *unless* a review is open (B/C take over)
 *   - Hidden when creator self-corrected (origin_code != OH)
 *   - Hidden for content owned by a different tipId
 *   - Transitions A → B (TRIGGERED) → C (CONFIRMED) reflect review state
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../../../shared/time");

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createDisputeService } = require(path.join(SRC, "services", "dispute-service"));
const { CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { CONTENT_GRACE, REVIEWER } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const CREATOR = "tip://id/US-cccccccccccccccc";
const OTHER   = "tip://id/US-dddddddddddddddd";
const CTID = "tip://c/OH-11111111111111-0001";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  for (const tip_id of [CREATOR, OTHER]) {
    dag.saveIdentity({
      tip_id, region: "US", public_key: "00", root_public_key: "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      registered_at: 1767225600000, tx_id: shake256(`id:${tip_id}`),
    });
  }
  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
  dag.setScore(CREATOR, 700, 0, nowMs());
  dag.setScore(OTHER, 700, 0, nowMs());

  const service = createDisputeService({
    dag, scoring, config: { nodeId: "tip://node/n1" },
    submitTx: () => {}, submitBatch: () => {},
  });
  return { dag, service };
}

function _seedFlagged(dag, opts = {}) {
  const {
    ctid = CTID,
    author = CREATOR,
    registeredAtMs,
    origin_code = "OH",
    status = CONTENT_STATUS.REGISTERED,
    prescan_tier = "high",
    override = true,
  } = opts;
  dag.saveContent({
    ctid, origin_code,
    content_hash: shake256(ctid),
    author_tip_id: author, signer_tip_id: author,
    authors: [{ tip_id: author, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status,
    prescan_flagged: true, prescan_probability: 0.95, prescan_tier, override,
    registered_at: registeredAtMs,
    registered_urls: [], tx_id: shake256(`c:${ctid}:${registeredAtMs}`),
  });
}

function _flaggedItem(dashboard) {
  return dashboard.items.find(i => i.type === "content_flagged_for_review");
}
function _underReviewItem(dashboard) {
  return dashboard.items.find(i => i.type === "content_under_review");
}
function _decisionRequiredItem(dashboard) {
  return dashboard.items.find(i => i.type === "prescan_review_decision_required");
}

describe("dashboard — content_flagged_for_review (no review yet)", () => {

  test("surfaces immediately on registration (no warning-age delay)", () => {
    const fx = _setup();
    const registeredAtMs = nowMs() - 60_000; // a minute old — would have been hidden before
    _seedFlagged(fx.dag, { registeredAtMs });

    const out = fx.service.getUserDashboard(CREATOR);
    const item = _flaggedItem(out);
    expect(item).toBeDefined();
    expect(item.priority).toBe("high");
    expect(item.ctid).toBe(CTID);
    expect(item.action.kind).toBe("update_origin");
    expect(item.metadata.prescan_tier).toBe("high");
    expect(item.metadata.hours_remaining).toBeGreaterThan(0);
    expect(item.deadline).toBe(registeredAtMs + CONTENT_GRACE.FLAGGED_MS);
  });

  test("surfaces regardless of `override` flag (silent-registration default is override=false)", () => {
    const fx = _setup();
    const registeredAtMs = nowMs() - 60_000;
    _seedFlagged(fx.dag, { registeredAtMs, override: false });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(_flaggedItem(out)).toBeDefined();
  });

  test("hidden after h=48 when no review is open yet (trigger imminent)", () => {
    const fx = _setup();
    const registeredAtMs = nowMs() - CONTENT_GRACE.FLAGGED_MS - 5 * 60_000;
    _seedFlagged(fx.dag, { registeredAtMs });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(_flaggedItem(out)).toBeUndefined();
  });

  test("hidden when creator already self-corrected (origin_code != OH)", () => {
    const fx = _setup();
    const registeredAtMs = nowMs() - 60_000;
    _seedFlagged(fx.dag, { registeredAtMs, origin_code: "AG" });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(_flaggedItem(out)).toBeUndefined();
    expect(_underReviewItem(out)).toBeUndefined();
    expect(_decisionRequiredItem(out)).toBeUndefined();
  });

  test("not shown to a non-author", () => {
    const fx = _setup();
    const registeredAtMs = nowMs() - 60_000;
    _seedFlagged(fx.dag, { registeredAtMs });

    const out = fx.service.getUserDashboard(OTHER);
    expect(_flaggedItem(out)).toBeUndefined();
  });

  test("hidden for low-tier content (not subject to review)", () => {
    const fx = _setup();
    const registeredAtMs = nowMs() - 60_000;
    _seedFlagged(fx.dag, { ctid: "tip://c/OH-low000000000000-0001", registeredAtMs, prescan_tier: "low", override: false });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(out.items.filter(i => i.type === "content_flagged_for_review")).toEqual([]);
  });
});

describe("dashboard — content_under_review (TRIGGERED)", () => {

  test("surfaces when a TRIGGERED review row exists; replaces content_flagged_for_review", () => {
    const fx = _setup();
    const registeredAtMs = nowMs() - CONTENT_GRACE.FLAGGED_MS - 60_000;
    _seedFlagged(fx.dag, { registeredAtMs, status: CONTENT_STATUS.PENDING_REVIEW });
    fx.dag.savePrescanReview({
      review_id: "rv_triggered_1",
      ctid: CTID,
      creator_tip_id: CREATOR,
      assigned_reviewer: "tip://id/US-reviewer000000",
      triggered_at_round: 100,
      triggered_at_ms: registeredAtMs + CONTENT_GRACE.FLAGGED_MS,
      state: "triggered",
    });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(_flaggedItem(out)).toBeUndefined();
    const item = _underReviewItem(out);
    expect(item).toBeDefined();
    expect(item.ctid).toBe(CTID);
    expect(item.priority).toBe("high");
    expect(item.action.kind).toBe("update_origin");
    expect(item.metadata.review_id).toBe("rv_triggered_1");
    expect(item.metadata.review_state).toBe("triggered");
    expect(item.metadata.prescan_tier).toBe("high");
    expect(item.metadata.assigned_reviewer).toBe("tip://id/US-reviewer000000");
  });
});

describe("dashboard — prescan_review_decision_required (CONFIRMED)", () => {

  test("surfaces when a CONFIRMED review row exists; carries 24h deadline + suggested_origin", () => {
    const fx = _setup();
    const registeredAtMs = nowMs() - CONTENT_GRACE.FLAGGED_MS - 3600000;
    const confirmedAtMs = nowMs() - 60_000;
    _seedFlagged(fx.dag, { registeredAtMs, status: CONTENT_STATUS.PENDING_REVIEW });
    fx.dag.savePrescanReview({
      review_id: "rv_confirmed_1",
      ctid: CTID,
      creator_tip_id: CREATOR,
      assigned_reviewer: "tip://id/US-reviewer000000",
      triggered_at_round: 100,
      triggered_at_ms: registeredAtMs + CONTENT_GRACE.FLAGGED_MS,
      decided_at_round: 105,
      confirmed_at_round: 105,
      confirmed_at_ms: confirmedAtMs,
      state: "confirmed",
      suggested_origin: "AA",
      decision_note: "Looks like LLM output to me.",
    });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(_flaggedItem(out)).toBeUndefined();
    expect(_underReviewItem(out)).toBeUndefined();
    const item = _decisionRequiredItem(out);
    expect(item).toBeDefined();
    expect(item.ctid).toBe(CTID);
    expect(item.priority).toBe("high");
    expect(item.action.kind).toBe("review_decision");
    expect(item.metadata.review_state).toBe("confirmed");
    expect(item.metadata.suggested_origin).toBe("AA");
    expect(item.metadata.confirmed_at_ms).toBe(confirmedAtMs);
    expect(item.metadata.decision_window_ends_at).toBe(confirmedAtMs + REVIEWER.CREATOR_DECISION_WINDOW_MS);
  });
});
