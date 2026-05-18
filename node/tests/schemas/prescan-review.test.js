/**
 * @file tests/schemas/prescan-review.test.js
 * @description End-to-end commit-handler flow for the three prescan-review
 * tx types: TRIGGERED (node-signed), DISMISSED (reviewer-signed),
 * CONFIRMED (reviewer-signed).
 *
 * Covers:
 *   - TRIGGERED: node-signature verification, persistence with state=triggered
 *   - DISMISSED: reviewer-signature, state transitions to closed_dismissed
 *   - CONFIRMED: reviewer-signature + suggested_origin, transitions to confirmed
 *   - Wrong reviewer rejected (reviewer_not_assigned)
 *   - DISMISSED on already-closed review rejected (review_state_invalid)
 *   - Invalid suggested_origin rejected (must be AA/AG/MX)
 *   - Duplicate trigger on same CTID rejected
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256, signTransaction, signBody, computeTxId,
} = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const dismissedSchema = require(path.join(SRC, "schemas", "prescan-review-dismissed"));
const confirmedSchema = require(path.join(SRC, "schemas", "prescan-review-confirmed"));
const contentRegisterSchema = require(path.join(SRC, "schemas", "content-register"));
const { TX_TYPES, PRESCAN_REVIEW_STATES, CONTENT_STATUS } = require(path.join(SHARED, "constants"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/n1";
const VP_ID = "tip://vp/v1";
const CREATOR = "tip://id/US-cccccccccccccccc";
const REVIEWER_1 = "tip://id/US-1111aaaa1111aaaa";
const REVIEWER_2 = "tip://id/US-2222bbbb2222bbbb";
const CTID_1 = "tip://c/OH-11111111111111-0001";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const reviewer1Kp = generateMLDSAKeypair();
  const reviewer2Kp = generateMLDSAKeypair();

  dag.saveNode({
    node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  // Creator identity
  dag.saveIdentity({
    tip_id: CREATOR, region: "US", public_key: nodeKp.publicKey, root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: false,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("creator"),
  });
  // Reviewer 1 (the legitimately-assigned reviewer)
  dag.saveIdentity({
    tip_id: REVIEWER_1, region: "US",
    public_key: reviewer1Kp.publicKey, root_public_key: reviewer1Kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: true,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("reviewer1"),
  });
  // Reviewer 2 (NOT assigned — used to test wrong-reviewer rejection)
  dag.saveIdentity({
    tip_id: REVIEWER_2, region: "US",
    public_key: reviewer2Kp.publicKey, root_public_key: reviewer2Kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: true,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("reviewer2"),
  });
  // Seed the content row so business-rules ctid existence check passes
  dag.saveContent({
    ctid: CTID_1, origin_code: "OH",
    content_hash: "abcd".repeat(16), perceptual_hash: null,
    author_tip_id: CREATOR, signer_tip_id: CREATOR,
    authors: [{ tip_id: CREATOR, key_mode: "attribution", role: "byline", signed: false, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status: "registered",
    prescan_flagged: true, prescan_probability: 0.92, prescan_tier: "high",
    override: true,
    registered_at: "2026-01-01T00:00:00.000Z",
    registered_urls: [], tx_id: shake256(`content:${CTID_1}`),
  });

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);
  const commitHandler = createCommitHandler({ dag, scoring, config, nodeId: NODE_ID });
  let round = 0;
  const commit = (txs) => {
    round++;
    commitHandler.commitOrderedTxs(txs, round, { certTimestamp: Date.now() });
    return round;
  };
  return { dag, commit, nodeKp, reviewer1Kp, reviewer2Kp };
}

function _buildTriggeredTx(fx, opts) {
  const data = {
    review_id: opts.review_id || "rv_t1",
    ctid: opts.ctid || CTID_1,
    creator_tip_id: opts.creator_tip_id || CREATOR,
    assigned_reviewer_tip_id: opts.assigned_reviewer_tip_id || REVIEWER_1,
    node_id: NODE_ID,
    triggered_at_round: opts.triggered_at_round || 1,
  };
  const txBody = {
    tx_type: TX_TYPES.PRESCAN_REVIEW_TRIGGERED,
    timestamp: new Date().toISOString(),
    prev: fx.dag.getRecentPrev(),
    data,
  };
  txBody.tx_id = computeTxId(txBody);
  return signTransaction(txBody, fx.nodeKp.privateKey);
}

function _buildDismissedTx(fx, opts) {
  const reviewerKp = opts.reviewerKp || fx.reviewer1Kp;
  const reviewerTipId = opts.reviewer_tip_id || REVIEWER_1;
  const payload = dismissedSchema.buildSigningPayload({
    review_id: opts.review_id,
    reviewer_tip_id: reviewerTipId,
    decision_note: opts.decision_note || null,
  });
  const signature = dismissedSchema.sign(payload, reviewerKp.privateKey);
  const data = {
    review_id: opts.review_id,
    reviewer_tip_id: reviewerTipId,
    decision_note: opts.decision_note || null,
    signature,
  };
  const txBody = {
    tx_type: TX_TYPES.PRESCAN_REVIEW_DISMISSED,
    timestamp: new Date().toISOString(),
    prev: fx.dag.getRecentPrev(),
    data,
  };
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

function _buildConfirmedTx(fx, opts) {
  const reviewerKp = opts.reviewerKp || fx.reviewer1Kp;
  const reviewerTipId = opts.reviewer_tip_id || REVIEWER_1;
  const payload = confirmedSchema.buildSigningPayload({
    review_id: opts.review_id,
    reviewer_tip_id: reviewerTipId,
    suggested_origin: opts.suggested_origin || "AG",
    decision_note: opts.decision_note || null,
  });
  const signature = confirmedSchema.sign(payload, reviewerKp.privateKey);
  const data = {
    review_id: opts.review_id,
    reviewer_tip_id: reviewerTipId,
    suggested_origin: opts.suggested_origin || "AG",
    decision_note: opts.decision_note || null,
    signature,
  };
  const txBody = {
    tx_type: TX_TYPES.PRESCAN_REVIEW_CONFIRMED,
    timestamp: new Date().toISOString(),
    prev: fx.dag.getRecentPrev(),
    data,
  };
  txBody.tx_id = computeTxId(txBody);
  return txBody;
}

describe("PRESCAN_REVIEW_TRIGGERED — node-signed system tx", () => {

  test("commits successfully; review row persisted with state=triggered", () => {
    const fx = _setup();
    const tx = _buildTriggeredTx(fx, { review_id: "rv_t1" });
    fx.commit([tx]);

    const review = fx.dag.getPrescanReview("rv_t1");
    expect(review).not.toBeNull();
    expect(review.ctid).toBe(CTID_1);
    expect(review.creator_tip_id).toBe(CREATOR);
    expect(review.assigned_reviewer).toBe(REVIEWER_1);
    expect(review.state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
  });

  test("rejects a second trigger for the same ctid while one is open", () => {
    const fx = _setup();
    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_first" })]);
    // Second trigger with different review_id should be rejected
    const txDup = _buildTriggeredTx(fx, { review_id: "rv_second" });
    fx.commit([txDup]);
    expect(fx.dag.getPrescanReview("rv_second")).toBeNull();
    // The first one is still the open review
    const open = fx.dag.getOpenPrescanReviewByCtid(CTID_1);
    expect(open.review_id).toBe("rv_first");
  });
});

describe("PRESCAN_REVIEW_DISMISSED — reviewer says AI was wrong", () => {

  test("transitions state to closed_dismissed", () => {
    const fx = _setup();
    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_d1" })]);
    expect(fx.dag.getPrescanReview("rv_d1").state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);

    fx.commit([_buildDismissedTx(fx, { review_id: "rv_d1", decision_note: "Looks human to me" })]);
    const review = fx.dag.getPrescanReview("rv_d1");
    expect(review.state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);
    expect(review.decision_note).toBe("Looks human to me");
    expect(review.decided_at_round).toBeGreaterThan(0);
  });

  test("rejects when signed by non-assigned reviewer", () => {
    const fx = _setup();
    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_d2" })]);
    // Reviewer 2 tries to dismiss a review assigned to Reviewer 1
    const tx = _buildDismissedTx(fx, {
      review_id: "rv_d2",
      reviewer_tip_id: REVIEWER_2,
      reviewerKp: fx.reviewer2Kp,
    });
    fx.commit([tx]);
    // State unchanged — tx was rejected
    expect(fx.dag.getPrescanReview("rv_d2").state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
  });

  test("rejects dismissal of an already-closed review", () => {
    const fx = _setup();
    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_d3" })]);
    fx.commit([_buildDismissedTx(fx, { review_id: "rv_d3" })]);  // closes it
    expect(fx.dag.getPrescanReview("rv_d3").state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);

    // Second dismissal attempt should be rejected (state already terminal)
    fx.commit([_buildDismissedTx(fx, { review_id: "rv_d3", decision_note: "again" })]);
    // Note didn't get applied — verifyTx rejected the tx at signature stage
    expect(fx.dag.getPrescanReview("rv_d3").state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);
  });
});

describe("PRESCAN_REVIEW_CONFIRMED — reviewer says AI was right", () => {

  test("transitions state to confirmed; captures suggested_origin + confirmed_at_round", () => {
    const fx = _setup();
    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_c1" })]);

    fx.commit([_buildConfirmedTx(fx, {
      review_id: "rv_c1",
      suggested_origin: "AG",
      decision_note: "Clearly AI-generated",
    })]);
    const review = fx.dag.getPrescanReview("rv_c1");
    expect(review.state).toBe(PRESCAN_REVIEW_STATES.CONFIRMED);
    expect(review.suggested_origin).toBe("AG");
    expect(review.decision_note).toBe("Clearly AI-generated");
    expect(review.decided_at_round).toBeGreaterThan(0);
    expect(review.confirmed_at_round).toBe(review.decided_at_round);
  });

  test("rejects suggested_origin=OH (must be AA/AG/MX)", () => {
    const fx = _setup();
    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_c2" })]);
    // buildSigningPayload throws on OH — build the tx manually with bad data
    const txBody = {
      tx_type: TX_TYPES.PRESCAN_REVIEW_CONFIRMED,
      timestamp: new Date().toISOString(),
      prev: fx.dag.getRecentPrev(),
      data: {
        review_id: "rv_c2",
        reviewer_tip_id: REVIEWER_1,
        suggested_origin: "OH",
        decision_note: null,
        signature: "dummy",
      },
    };
    txBody.tx_id = computeTxId(txBody);
    fx.commit([txBody]);
    // State unchanged — tx-validator rejected at Layer 2 (format check)
    expect(fx.dag.getPrescanReview("rv_c2").state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
  });

  test("rejects when signed by non-assigned reviewer", () => {
    const fx = _setup();
    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_c3" })]);
    fx.commit([_buildConfirmedTx(fx, {
      review_id: "rv_c3",
      reviewer_tip_id: REVIEWER_2,
      reviewerKp: fx.reviewer2Kp,
    })]);
    expect(fx.dag.getPrescanReview("rv_c3").state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// PRESCAN_REVIEW_RECUSED — reviewer bows out, content goes back to REGISTERED
// for re-trigger on the next round.
// ═══════════════════════════════════════════════════════════════════════════

describe("PRESCAN_REVIEW_RECUSED — reviewer bows out", () => {
  const recusedSchema = require(path.join(SRC, "schemas", "prescan-review-recused"));

  function _buildRecusedTx(fx, opts) {
    const reviewerKp = opts.reviewerKp || fx.reviewer1Kp;
    const reviewerTipId = opts.reviewer_tip_id || REVIEWER_1;
    const payload = recusedSchema.buildSigningPayload({
      review_id: opts.review_id,
      reviewer_tip_id: reviewerTipId,
      recusal_reason: opts.recusal_reason || null,
    });
    const signature = recusedSchema.sign(payload, reviewerKp.privateKey);
    const data = {
      review_id: opts.review_id,
      reviewer_tip_id: reviewerTipId,
      recusal_reason: opts.recusal_reason || null,
      signature,
    };
    const txBody = {
      tx_type: TX_TYPES.PRESCAN_REVIEW_RECUSED,
      timestamp: new Date().toISOString(),
      prev: fx.dag.getRecentPrev(),
      data,
    };
    txBody.tx_id = computeTxId(txBody);
    return txBody;
  }

  test("transitions state to RECUSED and flips content.status back to REGISTERED", () => {
    const fx = _setup();
    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_rec1" })]);
    expect(fx.dag.getPrescanReview("rv_rec1").state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
    expect(fx.dag.getContent(CTID_1).status).toBe(CONTENT_STATUS.PENDING_REVIEW);

    fx.commit([_buildRecusedTx(fx, { review_id: "rv_rec1", recusal_reason: "schedule conflict" })]);
    const review = fx.dag.getPrescanReview("rv_rec1");
    expect(review.state).toBe(PRESCAN_REVIEW_STATES.RECUSED);
    expect(review.decision_note).toBe("schedule conflict");
    expect(fx.dag.getContent(CTID_1).status).toBe(CONTENT_STATUS.REGISTERED);
    // RECUSED is not an "open" state — trigger can re-pick this CTID next round.
    expect(fx.dag.getOpenPrescanReviewByCtid(CTID_1)).toBeNull();
  });

  test("rejects when signed by non-assigned reviewer", () => {
    const fx = _setup();
    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_rec2" })]);
    const tx = _buildRecusedTx(fx, {
      review_id: "rv_rec2",
      reviewer_tip_id: REVIEWER_2,
      reviewerKp: fx.reviewer2Kp,
    });
    fx.commit([tx]);
    expect(fx.dag.getPrescanReview("rv_rec2").state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
  });

  test("rejects recusal after a decision has been made (state=CLOSED_DISMISSED)", () => {
    const fx = _setup();
    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_rec3" })]);
    fx.commit([_buildDismissedTx(fx, { review_id: "rv_rec3" })]);
    expect(fx.dag.getPrescanReview("rv_rec3").state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);

    fx.commit([_buildRecusedTx(fx, { review_id: "rv_rec3" })]);
    expect(fx.dag.getPrescanReview("rv_rec3").state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Phase 2.3 — status transition rewire
// ═══════════════════════════════════════════════════════════════════════════
//
// 1. REGISTER_CONTENT no longer flips status to PENDING_REVIEW on prescan_flagged
//    — registration always lands as REGISTERED (green badge). The amber flip
//    happens only when PRESCAN_REVIEW_TRIGGERED fires at h=48.
// 2. PRESCAN_REVIEW_TRIGGERED flips content.status → PENDING_REVIEW.
// 3. PRESCAN_REVIEW_DISMISSED restores content.status → REGISTERED.
// 4. UPDATE_ORIGIN closes any open review with state=closed_self_correct.

describe("Phase 2.3 — content status transitions", () => {

  test("REGISTER_CONTENT with prescan_flagged=true still lands as REGISTERED", () => {
    const fx = _setup();
    const newCtid = "tip://c/OH-22222222222222-0002";
    const data = {
      ctid: newCtid,
      origin_code: "OH",
      content_hash: "ef".repeat(32),
      signer_tip_id: CREATOR,
      prescan_flagged: true,
      prescan_tier: "high",
      prescan_probability: 0.95,
      override: true,
    };
    // Use nodeKp because CREATOR's public_key was seeded as nodeKp.publicKey
    data.authors = [{ key_mode: "attribution", role: "byline", signed: false,
                      tip_id: CREATOR, tip_id_type: "personal" }];
    data.attribution_mode = "self";
    data.extras = {};
    data.registered_urls = [];
    data.cna_version = contentRegisterSchema.CURRENT_CNA_VERSION;
    const payload = contentRegisterSchema.buildSigningPayload(data, data.content_hash);
    data.signature = contentRegisterSchema.sign(payload, fx.nodeKp.privateKey);
    const txBody = {
      tx_type: TX_TYPES.REGISTER_CONTENT,
      timestamp: new Date().toISOString(),
      prev: fx.dag.getRecentPrev(),
      data,
    };
    txBody.tx_id = computeTxId(txBody);
    const tx = signTransaction(txBody, fx.nodeKp.privateKey);

    fx.commit([tx]);
    const content = fx.dag.getContent(newCtid);
    expect(content).not.toBeNull();
    expect(content.status).toBe(CONTENT_STATUS.REGISTERED);
    expect(content.prescan_flagged).toBe(true);
    expect(content.prescan_tier).toBe("high");
  });

  test("PRESCAN_REVIEW_TRIGGERED flips content.status to PENDING_REVIEW; DISMISSED restores REGISTERED", () => {
    const fx = _setup();
    expect(fx.dag.getContent(CTID_1).status).toBe(CONTENT_STATUS.REGISTERED);

    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_p23_a" })]);
    expect(fx.dag.getContent(CTID_1).status).toBe(CONTENT_STATUS.PENDING_REVIEW);

    fx.commit([_buildDismissedTx(fx, { review_id: "rv_p23_a" })]);
    expect(fx.dag.getContent(CTID_1).status).toBe(CONTENT_STATUS.REGISTERED);
    expect(fx.dag.getPrescanReview("rv_p23_a").state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);
  });

  test("UPDATE_ORIGIN during an open review closes it with state=closed_self_correct", () => {
    const fx = _setup();
    // Re-seed content with a fresh registered_at so the 48h grace window
    // is still open at commit time. Otherwise canUpdateOrigin rejects the
    // tx and the close-review side effect never runs.
    const seeded = fx.dag.getContent(CTID_1);
    fx.dag.saveContent({ ...seeded, registered_at: new Date().toISOString() });

    fx.commit([_buildTriggeredTx(fx, { review_id: "rv_p23_b" })]);
    expect(fx.dag.getPrescanReview("rv_p23_b").state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
    expect(fx.dag.getContent(CTID_1).status).toBe(CONTENT_STATUS.PENDING_REVIEW);

    // Creator submits UPDATE_ORIGIN. CREATOR.public_key was seeded as
    // nodeKp.publicKey, so nodeKp.privateKey produces a valid body sig.
    const body = { author_tip_id: CREATOR, new_origin_code: "AG" };
    const updateData = {
      ctid: CTID_1,
      old_origin_code: "OH",
      new_origin_code: "AG",
      author_tip_id: CREATOR,
      signature: signBody(body, fx.nodeKp.privateKey),
    };
    const updateTx = {
      tx_type: TX_TYPES.UPDATE_ORIGIN,
      timestamp: new Date().toISOString(),
      prev: fx.dag.getRecentPrev(),
      data: updateData,
    };
    updateTx.tx_id = computeTxId(updateTx);

    fx.commit([updateTx]);

    const content = fx.dag.getContent(CTID_1);
    expect(content.origin_code).toBe("AG");
    expect(content.status).toBe(CONTENT_STATUS.REGISTERED);

    const review = fx.dag.getPrescanReview("rv_p23_b");
    expect(review.state).toBe(PRESCAN_REVIEW_STATES.CLOSED_SELF_CORRECT);
    expect(review.decided_at_round).toBeGreaterThan(0);
    expect(fx.dag.getOpenPrescanReviewByCtid(CTID_1)).toBeNull();
  });
});