/**
 * @file tests/services/dashboard-review-assignment.test.js
 * @description review_assignment_pending notification on the reviewer's
 * dashboard. Derived from DAG state (prescan_reviews where
 * assigned_reviewer = me, state = TRIGGERED), no notifications table.
 *
 * Coverage:
 *   - Surfaces for the reviewer when state=TRIGGERED
 *   - hours_remaining + deadline reflect AUTO_RECUSE_AGE_MS since
 *     triggered_at_ms
 *   - Priority escalates to "urgent" inside the last 6h (or past SLA)
 *   - Hidden after decision (CLOSED_DISMISSED / CONFIRMED) or after
 *     recusal (RECUSED)
 *   - Not shown to non-assigned reviewers
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
const { PRESCAN_REVIEW_STATES } = require(path.join(SHARED, "constants"));
const { REVIEWER } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const CREATOR = "tip://id/US-cccccccccccccccc";
const REVIEWER_1 = "tip://id/US-1111aaaa1111aaaa";
const REVIEWER_2 = "tip://id/US-2222bbbb2222bbbb";
const CTID = "tip://c/OH-11111111111111-0001";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  for (const tip_id of [CREATOR, REVIEWER_1, REVIEWER_2]) {
    dag.saveIdentity({
      tip_id, region: "US", public_key: "00", root_public_key: "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      reviewer_consent: true,
      registered_at: 1767225600000, tx_id: shake256(`id:${tip_id}`),
    });
  }
  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
  dag.setScore(REVIEWER_1, 900, 0, nowMs());
  dag.setScore(REVIEWER_2, 900, 0, nowMs());
  dag.setScore(CREATOR, 700, 0, nowMs());

  const service = createDisputeService({
    dag, scoring, config: { nodeId: "tip://node/n1" },
    submitTx: () => {}, submitBatch: () => {},
  });
  return { dag, service };
}

function _pendingItem(dashboard) {
  return dashboard.items.find(i => i.type === "review_assignment_pending");
}

describe("dashboard — review_assignment_pending", () => {

  test("surfaces for the assigned reviewer; hours_remaining counts down", () => {
    const fx = _setup();
    const triggeredAtMs = nowMs() - 6 * 3600_000; // 6h ago
    fx.dag.savePrescanReview({
      review_id: "rv_open", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: triggeredAtMs,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });

    const out = fx.service.getUserDashboard(REVIEWER_1);
    const item = _pendingItem(out);
    expect(item).toBeDefined();
    expect(item.role).toBe("reviewer");
    expect(item.ctid).toBe(CTID);
    expect(item.action.kind).toBe("view_review");
    expect(item.metadata.review_id).toBe("rv_open");
    expect(item.metadata.creator_tip_id).toBe(CREATOR);
    // SLA - elapsed → ~42h remaining when AUTO_RECUSE_AGE_MS = 48h
    const expectedHours = Math.round((REVIEWER.AUTO_RECUSE_AGE_MS - 6 * 3600_000) / 3600000);
    expect(item.metadata.hours_remaining).toBe(expectedHours);
    expect(item.priority).toBe("high");
  });

  test("priority=urgent within 6h of SLA", () => {
    const fx = _setup();
    // 4h remaining = within 6h cutoff
    const triggeredAtMs = nowMs() - (REVIEWER.AUTO_RECUSE_AGE_MS - 4 * 3600_000);
    fx.dag.savePrescanReview({
      review_id: "rv_close", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: triggeredAtMs,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });

    const out = fx.service.getUserDashboard(REVIEWER_1);
    const item = _pendingItem(out);
    expect(item.priority).toBe("urgent");
  });

  test("priority=urgent + title past-SLA when overdue", () => {
    const fx = _setup();
    const triggeredAtMs = nowMs() - REVIEWER.AUTO_RECUSE_AGE_MS - 60_000;
    fx.dag.savePrescanReview({
      review_id: "rv_overdue", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: triggeredAtMs,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });

    const out = fx.service.getUserDashboard(REVIEWER_1);
    const item = _pendingItem(out);
    expect(item.priority).toBe("urgent");
    expect(item.title).toMatch(/past SLA|auto-recuse imminent/i);
    expect(item.metadata.hours_remaining).toBe(0);
  });

  test("hidden after dismissal", () => {
    const fx = _setup();
    fx.dag.savePrescanReview({
      review_id: "rv_done", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: nowMs() - 3600_000,
      decided_at_round: 2,
      state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
    });
    const out = fx.service.getUserDashboard(REVIEWER_1);
    expect(_pendingItem(out)).toBeUndefined();
  });

  test("hidden after recusal", () => {
    const fx = _setup();
    fx.dag.savePrescanReview({
      review_id: "rv_recused", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: nowMs() - 3600_000,
      decided_at_round: 2,
      state: PRESCAN_REVIEW_STATES.RECUSED,
    });
    const out = fx.service.getUserDashboard(REVIEWER_1);
    expect(_pendingItem(out)).toBeUndefined();
  });

  test("not shown to a non-assigned reviewer", () => {
    const fx = _setup();
    fx.dag.savePrescanReview({
      review_id: "rv_open_other", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: nowMs() - 3600_000,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });
    const out = fx.service.getUserDashboard(REVIEWER_2);
    expect(_pendingItem(out)).toBeUndefined();
  });
});
