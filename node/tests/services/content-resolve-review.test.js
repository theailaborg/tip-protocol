/**
 * @file tests/services/content-resolve-review.test.js
 * @description GET /v1/content/:ctid — Phase 7 additions: review_history
 * projection + consensus placeholder.
 *
 * Asserts that content.status (existing CONTENT_STATUS field) and
 * review_history.latest.state (new PRESCAN_REVIEW_STATES projection)
 * together carry the full state machine signal — clients render the
 * badge by combining the two; the server does not invent a parallel
 * badge_status field.
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
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const {
  TX_TYPES, PRESCAN_REVIEW_STATES, CONTENT_STATUS,
} = require(path.join(SHARED, "constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const CREATOR = "tip://id/US-cccccccccccccccc";
const REVIEWER = "tip://id/US-1111aaaa1111aaaa";
const CTID = "tip://c/OH-11111111111111-0001";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  dag.saveIdentity({
    tip_id: CREATOR, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: shake256("creator"),
  });
  dag.saveIdentity({
    tip_id: REVIEWER, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: true,
    registered_at: 1767225600000, tx_id: shake256("reviewer"),
  });
  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
  dag.setScore(CREATOR, 700, 0, Date.now());
  dag.setScore(REVIEWER, 900, 0, Date.now());

  const service = createContentService({
    dag, scoring, config: { mediaLimits: {} }, submitTx: () => {},
  });
  return { dag, service };
}

function _seedContent(dag, { status = CONTENT_STATUS.REGISTERED, origin_code = "OH" } = {}) {
  dag.saveContent({
    ctid: CTID, origin_code,
    content_hash: "ab".repeat(32), perceptual_hash: null,
    author_tip_id: CREATOR, signer_tip_id: CREATOR,
    authors: [{ tip_id: CREATOR, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status,
    prescan_flagged: true, prescan_probability: 0.95, prescan_tier: "high", override: true,
    registered_at: Date.now(),
    registered_urls: [], tx_id: shake256(`c:${CTID}`),
  });
}

describe("content-service.resolve — review_history + consensus", () => {

  test("no review ever → review_history.total=0, latest=null", () => {
    const fx = _setup();
    _seedContent(fx.dag);
    const out = fx.service.resolve(CTID);
    expect(out.status).toBe(CONTENT_STATUS.REGISTERED);
    expect(out.review_history).toEqual({ total: 0, latest: null });
    expect(out.consensus).toEqual({ available: false, status: "not_requested" });
  });

  test("trigger fired (review TRIGGERED) → content.status=PENDING_REVIEW + latest.state=TRIGGERED", () => {
    const fx = _setup();
    _seedContent(fx.dag, { status: CONTENT_STATUS.PENDING_REVIEW });
    fx.dag.savePrescanReview({
      review_id: "rv_t", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER, triggered_at_round: 1,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });
    const out = fx.service.resolve(CTID);
    expect(out.status).toBe(CONTENT_STATUS.PENDING_REVIEW);
    expect(out.review_history.total).toBe(1);
    expect(out.review_history.latest.state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
    expect(out.review_history.latest.assigned_reviewer).toBe(REVIEWER);
  });

  test("dismissed → content.status=REGISTERED + latest.state=CLOSED_DISMISSED (vindication signal)", () => {
    const fx = _setup();
    _seedContent(fx.dag, { status: CONTENT_STATUS.REGISTERED });
    fx.dag.savePrescanReview({
      review_id: "rv_d", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER, triggered_at_round: 1, decided_at_round: 2,
      state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
      decision_note: "human voice",
    });
    const out = fx.service.resolve(CTID);
    // Content is back to REGISTERED (green) BUT the review history
    // tells the client "cleared after AI flag was dismissed".
    expect(out.status).toBe(CONTENT_STATUS.REGISTERED);
    expect(out.review_history.latest.state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);
    expect(out.review_history.latest.decision_note).toBe("human voice");
  });

  test("confirmed (creator deciding) → content.status=PENDING_REVIEW + latest.state=CONFIRMED + suggested_origin", () => {
    const fx = _setup();
    _seedContent(fx.dag, { status: CONTENT_STATUS.PENDING_REVIEW });
    const confirmedAtMs = Date.now();
    fx.dag.savePrescanReview({
      review_id: "rv_c", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER, triggered_at_round: 1,
      decided_at_round: 2, confirmed_at_round: 2, confirmed_at_ms: confirmedAtMs,
      state: PRESCAN_REVIEW_STATES.CONFIRMED, suggested_origin: "AG",
    });
    const out = fx.service.resolve(CTID);
    expect(out.status).toBe(CONTENT_STATUS.PENDING_REVIEW);
    expect(out.review_history.latest.state).toBe(PRESCAN_REVIEW_STATES.CONFIRMED);
    expect(out.review_history.latest.suggested_origin).toBe("AG");
    expect(out.review_history.latest.confirmed_at_ms).toBe(confirmedAtMs);
  });

  test("accepted-private → content.status=REGISTERED + origin updated + latest.state=CLOSED_ACCEPTED_PRIVATE", () => {
    const fx = _setup();
    _seedContent(fx.dag, { status: CONTENT_STATUS.REGISTERED, origin_code: "AG" });
    fx.dag.savePrescanReview({
      review_id: "rv_ap", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER, triggered_at_round: 1,
      decided_at_round: 3, confirmed_at_round: 2, confirmed_at_ms: Date.now() - 3600_000,
      state: PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE, suggested_origin: "AG",
    });
    const out = fx.service.resolve(CTID);
    expect(out.status).toBe(CONTENT_STATUS.REGISTERED);
    expect(out.origin_code).toBe("AG");
    expect(out.review_history.latest.state).toBe(PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE);
  });

  test("escalated → content.status=DISPUTED + latest.state=ESCALATED_TO_DISPUTE", () => {
    const fx = _setup();
    _seedContent(fx.dag, { status: CONTENT_STATUS.DISPUTED });
    fx.dag.savePrescanReview({
      review_id: "rv_e", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER, triggered_at_round: 1,
      decided_at_round: 3, confirmed_at_round: 2, confirmed_at_ms: Date.now() - 25 * 3600_000,
      state: PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE, suggested_origin: "AG",
    });
    const out = fx.service.resolve(CTID);
    expect(out.status).toBe(CONTENT_STATUS.DISPUTED);
    expect(out.review_history.latest.state).toBe(PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE);
  });

  test("origin unchanged → original_origin_code=ctid prefix, origin_changed=false, change_origin in actions", () => {
    const fx = _setup();
    _seedContent(fx.dag, { origin_code: "OH" });
    const out = fx.service.resolve(CTID);
    expect(out.original_origin_code).toBe("OH");
    expect(out.origin_changed).toBe(false);
    expect(out.prescan.actions_available).toContain("change_origin");
    expect(out.prescan.next_step_if_kept).toBe("independent_reviewer_at_window_end");
  });

  test("origin changed (OH → AA) → origin_changed=true, change_origin removed from actions, next_step_if_kept=none", () => {
    const fx = _setup();
    // Seed at OH then mutate as the UPDATE_ORIGIN flow would (commit-handler
    // path is exercised end-to-end in the integration suite; this unit test
    // covers the resolve() projection logic in isolation).
    _seedContent(fx.dag, { origin_code: "AA" });
    const out = fx.service.resolve(CTID);
    expect(out.original_origin_code).toBe("OH");
    expect(out.origin_code).toBe("AA");
    expect(out.origin_changed).toBe(true);
    expect(out.prescan.actions_available).not.toContain("change_origin");
    expect(out.prescan.actions_available).toContain("keep");
    expect(out.prescan.actions_available).toContain("retract");
    // No reviewer step pending — the trigger SQL excludes non-OH rows.
    expect(out.prescan.next_step_if_kept).toBe("none");
  });
});
