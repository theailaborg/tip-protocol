/**
 * @file tests/services/review-service.test.js
 * @description Phase 2.6 — reviewer + creator decision endpoints.
 *
 * Covers:
 *   getReview         — projection + 404
 *   dismiss           — happy path, wrong reviewer, terminal review,
 *                       missing-signature
 *   confirm           — happy path, suggested_origin=OH rejected
 *   acceptCorrection  — happy path within window, wrong creator,
 *                       review not in CONFIRMED state, default
 *                       new_origin_code falls back to suggested_origin
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256, signBody,
} = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createReviewService } = require(path.join(SRC, "services", "review-service"));
const dismissedSchema = require(path.join(SRC, "schemas", "prescan-review-dismissed"));
const confirmedSchema = require(path.join(SRC, "schemas", "prescan-review-confirmed"));
const {
  TX_TYPES, PRESCAN_REVIEW_STATES, CONTENT_STATUS,
} = require(path.join(SHARED, "constants"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const CREATOR = "tip://id/US-cccccccccccccccc";
const REVIEWER_1 = "tip://id/US-1111aaaa1111aaaa";
const REVIEWER_2 = "tip://id/US-2222bbbb2222bbbb";
const CTID_1 = "tip://c/OH-11111111111111-0001";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const creatorKp = generateMLDSAKeypair();
  const reviewer1Kp = generateMLDSAKeypair();
  const reviewer2Kp = generateMLDSAKeypair();

  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  dag.saveIdentity({
    tip_id: CREATOR, region: "US",
    public_key: creatorKp.publicKey, root_public_key: creatorKp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: false,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("creator"),
  });
  dag.saveIdentity({
    tip_id: REVIEWER_1, region: "US",
    public_key: reviewer1Kp.publicKey, root_public_key: reviewer1Kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: true,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("reviewer1"),
  });
  dag.saveIdentity({
    tip_id: REVIEWER_2, region: "US",
    public_key: reviewer2Kp.publicKey, root_public_key: reviewer2Kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: true,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("reviewer2"),
  });

  const scoring = initScoring(dag, { nodeId: "tip://node/n1" });
  // Seed scores so listReviewerPool eligibility passes for any opted-in
  // reviewer in tests that don't explicitly set their own scores.
  const now = new Date().toISOString();
  dag.setScore(REVIEWER_1, 900, 0, now);
  dag.setScore(REVIEWER_2, 900, 0, now);

  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  const service = createReviewService({ dag, scoring, submitTx });

  return { dag, scoring, service, submitted, creatorKp, reviewer1Kp, reviewer2Kp };
}

function _seedTriggeredReview(fx, { reviewId = "rv_t", ctid = CTID_1 } = {}) {
  fx.dag.savePrescanReview({
    review_id: reviewId, ctid, creator_tip_id: CREATOR,
    assigned_reviewer: REVIEWER_1, triggered_at_round: 1,
    state: PRESCAN_REVIEW_STATES.TRIGGERED,
  });
  return reviewId;
}

function _seedConfirmedReview(fx, { reviewId = "rv_c", ctid = CTID_1, suggestedOrigin = "AG", confirmedAtMs = Date.now() } = {}) {
  fx.dag.savePrescanReview({
    review_id: reviewId, ctid, creator_tip_id: CREATOR,
    assigned_reviewer: REVIEWER_1, triggered_at_round: 1,
    decided_at_round: 2, confirmed_at_round: 2, confirmed_at_ms: confirmedAtMs,
    state: PRESCAN_REVIEW_STATES.CONFIRMED, suggested_origin: suggestedOrigin,
  });
  return reviewId;
}

// Schemas throw plain objects (status + error + code); helper to extract.
function _throws(fn) {
  try { fn(); return null; }
  catch (err) { return err; }
}

function _seedContent(fx, { ctid = CTID_1, status = CONTENT_STATUS.PENDING_REVIEW, registeredAtMs = Date.now() } = {}) {
  fx.dag.saveContent({
    ctid, origin_code: "OH",
    content_hash: "ab".repeat(32), perceptual_hash: null,
    author_tip_id: CREATOR, signer_tip_id: CREATOR,
    authors: [{ tip_id: CREATOR, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status, prescan_flagged: true, prescan_probability: 0.95, prescan_tier: "high",
    override: true,
    registered_at: new Date(registeredAtMs).toISOString(),
    registered_urls: [], tx_id: shake256(`c:${ctid}:${registeredAtMs}`),
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// getReview
// ═══════════════════════════════════════════════════════════════════════════

describe("review-service.getReview", () => {

  test("returns review + content projection", () => {
    const fx = _setup();
    _seedTriggeredReview(fx, { reviewId: "rv_get" });
    _seedContent(fx);
    const r = fx.service.getReview("rv_get");
    expect(r.review_id).toBe("rv_get");
    expect(r.state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
    expect(r.assigned_reviewer).toBe(REVIEWER_1);
    expect(r.content_status).toBe(CONTENT_STATUS.PENDING_REVIEW);
  });

  test("404 on unknown review_id", () => {
    const fx = _setup();
    expect(_throws(() => fx.service.getReview("rv_nope")).status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// dismiss
// ═══════════════════════════════════════════════════════════════════════════

describe("review-service.dismiss", () => {

  test("submits PRESCAN_REVIEW_DISMISSED on happy path", () => {
    const fx = _setup();
    _seedTriggeredReview(fx, { reviewId: "rv_d" });
    const payload = dismissedSchema.buildSigningPayload({
      review_id: "rv_d", reviewer_tip_id: REVIEWER_1, decision_note: "human voice",
    });
    const signature = dismissedSchema.sign(payload, fx.reviewer1Kp.privateKey);

    const out = fx.service.dismiss("rv_d", {
      reviewer_tip_id: REVIEWER_1, decision_note: "human voice", signature,
    });
    expect(fx.submitted.length).toBe(1);
    expect(fx.submitted[0].tx_type).toBe(TX_TYPES.PRESCAN_REVIEW_DISMISSED);
    expect(fx.submitted[0].data.review_id).toBe("rv_d");
    expect(fx.submitted[0].data.decision_note).toBe("human voice");
    expect(out.confirmation).toBe("proposed");
  });

  test("rejects when signed by non-assigned reviewer", () => {
    const fx = _setup();
    _seedTriggeredReview(fx, { reviewId: "rv_d2" });
    const payload = dismissedSchema.buildSigningPayload({
      review_id: "rv_d2", reviewer_tip_id: REVIEWER_2,
    });
    const signature = dismissedSchema.sign(payload, fx.reviewer2Kp.privateKey);
    const err = _throws(() => fx.service.dismiss("rv_d2", {
      reviewer_tip_id: REVIEWER_2, signature,
    }));
    expect(err.code).toBe("reviewer_not_assigned");
    expect(err.status).toBe(403);
  });

  test("rejects when review is already terminal", () => {
    const fx = _setup();
    fx.dag.savePrescanReview({
      review_id: "rv_d3", ctid: CTID_1, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1, triggered_at_round: 1, decided_at_round: 2,
      state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
    });
    const payload = dismissedSchema.buildSigningPayload({
      review_id: "rv_d3", reviewer_tip_id: REVIEWER_1,
    });
    const signature = dismissedSchema.sign(payload, fx.reviewer1Kp.privateKey);
    const err = _throws(() => fx.service.dismiss("rv_d3", {
      reviewer_tip_id: REVIEWER_1, signature,
    }));
    expect(err.code).toBe("review_state_invalid");
    expect(err.status).toBe(409);
  });

  test("rejects missing signature", () => {
    const fx = _setup();
    _seedTriggeredReview(fx, { reviewId: "rv_d4" });
    const err = _throws(() => fx.service.dismiss("rv_d4", {
      reviewer_tip_id: REVIEWER_1,
    }));
    expect(err.code).toBe("signature_required");
    expect(err.status).toBe(400);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// confirm
// ═══════════════════════════════════════════════════════════════════════════

describe("review-service.confirm", () => {

  test("submits PRESCAN_REVIEW_CONFIRMED with suggested_origin", () => {
    const fx = _setup();
    _seedTriggeredReview(fx, { reviewId: "rv_c1" });
    const payload = confirmedSchema.buildSigningPayload({
      review_id: "rv_c1", reviewer_tip_id: REVIEWER_1,
      suggested_origin: "AG", decision_note: "clearly AI",
    });
    const signature = confirmedSchema.sign(payload, fx.reviewer1Kp.privateKey);

    fx.service.confirm("rv_c1", {
      reviewer_tip_id: REVIEWER_1, suggested_origin: "AG",
      decision_note: "clearly AI", signature,
    });
    expect(fx.submitted.length).toBe(1);
    expect(fx.submitted[0].tx_type).toBe(TX_TYPES.PRESCAN_REVIEW_CONFIRMED);
    expect(fx.submitted[0].data.suggested_origin).toBe("AG");
  });

  test("rejects suggested_origin=OH", () => {
    const fx = _setup();
    _seedTriggeredReview(fx, { reviewId: "rv_c2" });
    const err = _throws(() => fx.service.confirm("rv_c2", {
      reviewer_tip_id: REVIEWER_1, suggested_origin: "OH", signature: "anything",
    }));
    expect(err.code).toBe("suggested_origin_invalid");
    expect(err.status).toBe(400);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// acceptCorrection
// ═══════════════════════════════════════════════════════════════════════════

describe("review-service.acceptCorrection", () => {

  function _signUpdate(creatorKp, { author_tip_id, new_origin_code }) {
    return signBody({ author_tip_id, new_origin_code }, creatorKp.privateKey);
  }

  test("emits UPDATE_ORIGIN with new_origin_code from body", () => {
    const fx = _setup();
    _seedConfirmedReview(fx, { reviewId: "rv_acc1", suggestedOrigin: "AG" });
    _seedContent(fx);

    const signature = _signUpdate(fx.creatorKp, { author_tip_id: CREATOR, new_origin_code: "AG" });
    const out = fx.service.acceptCorrection("rv_acc1", {
      author_tip_id: CREATOR, new_origin_code: "AG", signature,
    });
    expect(fx.submitted.length).toBe(1);
    expect(fx.submitted[0].tx_type).toBe(TX_TYPES.UPDATE_ORIGIN);
    expect(fx.submitted[0].data.new_origin_code).toBe("AG");
    expect(fx.submitted[0].data.author_tip_id).toBe(CREATOR);
    expect(out.new_origin_code).toBe("AG");
  });

  test("defaults new_origin_code to review.suggested_origin when omitted", () => {
    const fx = _setup();
    _seedConfirmedReview(fx, { reviewId: "rv_acc2", suggestedOrigin: "MX" });
    _seedContent(fx);

    const signature = _signUpdate(fx.creatorKp, { author_tip_id: CREATOR, new_origin_code: "MX" });
    fx.service.acceptCorrection("rv_acc2", {
      author_tip_id: CREATOR, signature,
    });
    expect(fx.submitted[0].data.new_origin_code).toBe("MX");
  });

  test("rejects when review is not in 'confirmed' state", () => {
    const fx = _setup();
    _seedTriggeredReview(fx, { reviewId: "rv_acc3" });
    _seedContent(fx);
    const err = _throws(() => fx.service.acceptCorrection("rv_acc3", {
      author_tip_id: CREATOR, new_origin_code: "AG", signature: "x",
    }));
    expect(err.code).toBe("review_state_invalid");
    expect(err.status).toBe(409);
  });

  test("rejects when author_tip_id != review.creator_tip_id", () => {
    const fx = _setup();
    _seedConfirmedReview(fx, { reviewId: "rv_acc4" });
    _seedContent(fx);
    const err = _throws(() => fx.service.acceptCorrection("rv_acc4", {
      author_tip_id: REVIEWER_2, new_origin_code: "AG", signature: "x",
    }));
    expect(err.code).toBe("not_creator");
    expect(err.status).toBe(403);
  });

  test("rejects new_origin_code=OH", () => {
    const fx = _setup();
    _seedConfirmedReview(fx, { reviewId: "rv_acc5" });
    _seedContent(fx);
    const err = _throws(() => fx.service.acceptCorrection("rv_acc5", {
      author_tip_id: CREATOR, new_origin_code: "OH", signature: "x",
    }));
    expect(err.code).toBe("new_origin_code_invalid");
    expect(err.status).toBe(400);
  });

  test("rejects when the 24h creator window has expired", () => {
    const fx = _setup();
    // confirmed 48h ago — far outside the 24h window
    _seedConfirmedReview(fx, {
      reviewId: "rv_acc6", suggestedOrigin: "AG",
      confirmedAtMs: Date.now() - 48 * 3600 * 1000,
    });
    _seedContent(fx);
    const signature = _signUpdate(fx.creatorKp, { author_tip_id: CREATOR, new_origin_code: "AG" });
    const err = _throws(() => fx.service.acceptCorrection("rv_acc6", {
      author_tip_id: CREATOR, new_origin_code: "AG", signature,
    }));
    expect(err.status).toBe(403);
    expect(err.error).toMatch(/24-hour|window has expired/i);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// listReviewerPool
// ═══════════════════════════════════════════════════════════════════════════

describe("review-service.listReviewerPool", () => {

  test("returns only identities that pass Pass 1 eligibility (sorted by tip_id)", () => {
    const fx = _setup();
    // _setup seeds two opted-in reviewers (REVIEWER_1, REVIEWER_2) with
    // score=900 and no decision history → both pass Pass 1 (accuracy=1.0
    // for no history; consent=true; not revoked).
    const { pool, count } = fx.service.listReviewerPool();
    expect(count).toBe(2);
    expect(pool.map(p => p.tip_id)).toEqual([REVIEWER_1, REVIEWER_2]);
    expect(pool[0]).toEqual(expect.objectContaining({
      tip_id: REVIEWER_1, region: "US", score: 900, accuracy: 1.0,
    }));
  });

  test("excludes identities without reviewer_consent", () => {
    const fx = _setup();
    // CREATOR has reviewer_consent=false in _setup → not in pool.
    const { pool } = fx.service.listReviewerPool();
    expect(pool.find(p => p.tip_id === CREATOR)).toBeUndefined();
  });

  test("excludes revoked identities", () => {
    const fx = _setup();
    fx.dag.addRevocation(REVIEWER_1, TX_TYPES.REVOKE_VOLUNTARY, new Date().toISOString(), shake256("rev"));
    const { pool, count } = fx.service.listReviewerPool();
    expect(count).toBe(1);
    expect(pool.map(p => p.tip_id)).toEqual([REVIEWER_2]);
  });

  test("excludes identities below REVIEWER.MIN_SCORE", () => {
    const fx = _setup();
    fx.dag.setScore(REVIEWER_1, 100, 0, new Date().toISOString());
    const { pool, count } = fx.service.listReviewerPool();
    expect(count).toBe(1);
    expect(pool.map(p => p.tip_id)).toEqual([REVIEWER_2]);
  });
});
