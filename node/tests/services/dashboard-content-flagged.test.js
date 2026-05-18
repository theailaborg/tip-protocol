/**
 * @file tests/services/dashboard-content-flagged.test.js
 * @description Phase 2.7 — content_flagged_for_review notification on
 * the creator's dashboard. Derived from DAG state inside
 * getUserDashboard; no separate notifications table.
 *
 * Coverage:
 *   - Surfaces once age crosses REVIEWER.CREATOR_WARNING_AGE_MS
 *   - Hidden before the warning age (no premature alarm)
 *   - Hidden after h=48 (trigger takes over via status=PENDING_REVIEW)
 *   - Hidden when creator self-corrected (origin_code != OH)
 *   - Hidden for content owned by a different tipId
 *   - hours_remaining + deadline reflect the FLAGGED_MS window from
 *     registered_at, not from "now"
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

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
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  for (const tip_id of [CREATOR, OTHER]) {
    dag.saveIdentity({
      tip_id, region: "US", public_key: "00", root_public_key: "00",
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${tip_id}`),
    });
  }
  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
  dag.setScore(CREATOR, 700, 0, new Date().toISOString());
  dag.setScore(OTHER, 700, 0, new Date().toISOString());

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
    content_hash: shake256(ctid), perceptual_hash: null,
    author_tip_id: author, signer_tip_id: author,
    authors: [{ tip_id: author, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status,
    prescan_flagged: true, prescan_probability: 0.95, prescan_tier, override,
    registered_at: new Date(registeredAtMs).toISOString(),
    registered_urls: [], tx_id: shake256(`c:${ctid}:${registeredAtMs}`),
  });
}

function _flaggedItem(dashboard) {
  return dashboard.items.find(i => i.type === "content_flagged_for_review");
}

describe("dashboard — content_flagged_for_review", () => {

  test("surfaces once age crosses REVIEWER.CREATOR_WARNING_AGE_MS", () => {
    const fx = _setup();
    const registeredAtMs = Date.now() - REVIEWER.CREATOR_WARNING_AGE_MS - 60_000;
    _seedFlagged(fx.dag, { registeredAtMs });

    const out = fx.service.getUserDashboard(CREATOR);
    const item = _flaggedItem(out);
    expect(item).toBeDefined();
    expect(item.priority).toBe("high");
    expect(item.ctid).toBe(CTID);
    expect(item.action.kind).toBe("update_origin");
    expect(item.metadata.prescan_tier).toBe("high");
    expect(item.metadata.hours_remaining).toBeGreaterThan(0);
    expect(item.metadata.hours_remaining).toBeLessThanOrEqual(24);
    expect(item.deadline).toBe(new Date(registeredAtMs + CONTENT_GRACE.FLAGGED_MS).toISOString());
  });

  test("hidden before the warning age", () => {
    const fx = _setup();
    const registeredAtMs = Date.now() - 60_000; // a minute old
    _seedFlagged(fx.dag, { registeredAtMs });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(_flaggedItem(out)).toBeUndefined();
  });

  test("hidden after h=48 (PRESCAN_REVIEW_TRIGGERED takes over)", () => {
    const fx = _setup();
    const registeredAtMs = Date.now() - CONTENT_GRACE.FLAGGED_MS - 5 * 60_000;
    // status would be PENDING_REVIEW after the trigger applies. But
    // even with status=REGISTERED, the age-past-FLAGGED_MS gate hides
    // it — the trigger emits with its own messaging path.
    _seedFlagged(fx.dag, { registeredAtMs });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(_flaggedItem(out)).toBeUndefined();
  });

  test("hidden when creator already self-corrected (origin_code != OH)", () => {
    const fx = _setup();
    const registeredAtMs = Date.now() - REVIEWER.CREATOR_WARNING_AGE_MS - 60_000;
    _seedFlagged(fx.dag, { registeredAtMs, origin_code: "AG" });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(_flaggedItem(out)).toBeUndefined();
  });

  test("hidden when content has been status-flipped to PENDING_REVIEW", () => {
    const fx = _setup();
    const registeredAtMs = Date.now() - REVIEWER.CREATOR_WARNING_AGE_MS - 60_000;
    _seedFlagged(fx.dag, { registeredAtMs, status: CONTENT_STATUS.PENDING_REVIEW });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(_flaggedItem(out)).toBeUndefined();
  });

  test("not shown to a non-author", () => {
    const fx = _setup();
    const registeredAtMs = Date.now() - REVIEWER.CREATOR_WARNING_AGE_MS - 60_000;
    _seedFlagged(fx.dag, { registeredAtMs });

    const out = fx.service.getUserDashboard(OTHER);
    expect(_flaggedItem(out)).toBeUndefined();
  });

  test("hidden for non-flagged content (prescan_tier=low or no override)", () => {
    const fx = _setup();
    const registeredAtMs = Date.now() - REVIEWER.CREATOR_WARNING_AGE_MS - 60_000;
    // Low tier — not subject to review
    _seedFlagged(fx.dag, { ctid: "tip://c/OH-low000000000000-0001", registeredAtMs, prescan_tier: "low", override: false });
    // High tier without override — creator didn't accept the AI prescan
    // (registration would have been blocked by the 409); shouldn't happen,
    // but defensively hidden
    _seedFlagged(fx.dag, { ctid: "tip://c/OH-noover0000000-0001", registeredAtMs, override: false });

    const out = fx.service.getUserDashboard(CREATOR);
    expect(out.items.filter(i => i.type === "content_flagged_for_review")).toEqual([]);
  });
});
