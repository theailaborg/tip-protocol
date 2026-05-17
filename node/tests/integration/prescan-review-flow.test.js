/**
 * @file tests/integration/prescan-review-flow.test.js
 * @description End-to-end integration of the prescan-review pipeline,
 * driving everything through commit-handler:
 *
 *   1. Content registered (flagged, override=true)
 *      → status lands as REGISTERED (Phase 2.3, no auto-flip)
 *   2. cert.timestamp crosses h=48
 *      → prescan-review-trigger fires PRESCAN_REVIEW_TRIGGERED
 *   3. Commit-handler applies the trigger
 *      → review row state=TRIGGERED + content.status=PENDING_REVIEW
 *   4. Reviewer calls reviewService.confirm
 *      → PRESCAN_REVIEW_CONFIRMED committed, confirmed_at_ms persisted
 *   5. Creator calls reviewService.acceptCorrection within 24h
 *      → batched UPDATE_ORIGIN + SCORE_UPDATE land atomically
 *      → content.origin_code updated, status=REGISTERED
 *      → review state=CLOSED_ACCEPTED_PRIVATE
 *      → creator's score decreased by REVIEWER.ACCEPT_CORRECTION_SCORE_DELTA
 *
 * This test deliberately seeds the initial content row instead of
 * driving REGISTER_CONTENT through commit-handler — content-register
 * has its own integration suite. Everything past h=0 runs through the
 * real commit pipeline: trigger emission, tx validation, state apply,
 * scoring, business rules.
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
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createPrescanReviewTrigger } = require(path.join(SRC, "consensus", "prescan-review-trigger"));
const { createReviewService } = require(path.join(SRC, "services", "review-service"));
const confirmedSchema = require(path.join(SRC, "schemas", "prescan-review-confirmed"));
const {
  TX_TYPES, PRESCAN_REVIEW_STATES, CONTENT_STATUS,
} = require(path.join(SHARED, "constants"));
const { CONTENT_GRACE, REVIEWER } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/n1";
const VP_ID = "tip://vp/v1";
const CREATOR = "tip://id/US-cccccccccccccccc";
const REVIEWER_TIP = "tip://id/US-1111aaaa1111aaaa";
const CTID = "tip://c/OH-11111111111111-0001";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const creatorKp = generateMLDSAKeypair();
  const reviewerKp = generateMLDSAKeypair();

  dag.saveNode({
    node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
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
    tip_id: REVIEWER_TIP, region: "US",
    public_key: reviewerKp.publicKey, root_public_key: reviewerKp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: true,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("reviewer"),
  });

  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
  };
  const scoring = initScoring(dag, config);

  const seedTs = new Date("2026-02-01T00:00:00.000Z").toISOString();
  dag.setScore(REVIEWER_TIP, 900, 0, seedTs);
  dag.setScore(CREATOR, 700, 0, seedTs);

  // submitted: every tx that ANY pipeline emits — the test then drives
  // commit-handler with these txs in subsequent rounds. The trigger and
  // the review-service share the same submission sink.
  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  const submitBatch = (txs) => { for (const tx of txs) submitted.push(tx); };

  const prescanReviewTrigger = createPrescanReviewTrigger({
    dag, scoring, config, submitTx,
  });
  const commitHandler = createCommitHandler({
    dag, scoring, config, prescanReviewTrigger, nodeId: NODE_ID,
  });
  const reviewService = createReviewService({
    dag, scoring, submitTx, submitBatch, config,
  });

  let round = 0;
  function commit(txs, certTimestamp) {
    round++;
    commitHandler.commitOrderedTxs(txs, round, { certTimestamp });
  }

  function seedContent(registeredAtMs) {
    dag.saveContent({
      ctid: CTID, origin_code: "OH",
      content_hash: "ab".repeat(32), perceptual_hash: null,
      author_tip_id: CREATOR, signer_tip_id: CREATOR,
      authors: [{ tip_id: CREATOR, key_mode: "attribution", role: "byline", signed: false, tip_id_type: "personal" }],
      attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
      status: CONTENT_STATUS.REGISTERED,
      prescan_flagged: true, prescan_probability: 0.95, prescan_tier: "high",
      override: true,
      registered_at: new Date(registeredAtMs).toISOString(),
      registered_urls: [], tx_id: shake256(`c:${CTID}:${registeredAtMs}`),
    });
  }

  return {
    dag, scoring, commit, submitted, seedContent, reviewService,
    nodeKp, creatorKp, reviewerKp,
  };
}

describe("prescan-review end-to-end flow", () => {

  test("register flagged → h=48 trigger → reviewer confirm → creator accept-correction", () => {
    const fx = _setup();

    // ── Step 1: content registered. Phase 2.3: status lands as
    // REGISTERED, NOT PENDING_REVIEW.
    // canUpdateOrigin uses Date.now() (wall clock) at API call; cert
    // timestamps drive the consensus-time checks. Anchor the timeline to
    // a point shortly before real now so wall-clock and simulated time
    // agree across the whole flow.
    const registeredAtMs = Date.now() - CONTENT_GRACE.FLAGGED_MS - 5 * 60_000;
    fx.seedContent(registeredAtMs);
    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.REGISTERED);

    // ── Step 2: tick commit-handler past h=48. Phase 2.5 trigger
    // emits a PRESCAN_REVIEW_TRIGGERED via submitTx.
    const triggerTs = registeredAtMs + CONTENT_GRACE.FLAGGED_MS + 1000;
    fx.commit([], triggerTs);

    const triggeredTx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_TRIGGERED);
    expect(triggeredTx).toBeDefined();
    expect(triggeredTx.data.ctid).toBe(CTID);
    expect(triggeredTx.data.creator_tip_id).toBe(CREATOR);
    expect(triggeredTx.data.assigned_reviewer_tip_id).toBe(REVIEWER_TIP);

    // ── Step 3: commit the trigger tx. Phase 2.3 flips content.status
    // to PENDING_REVIEW; review row lands as TRIGGERED.
    fx.submitted.length = 0;
    fx.commit([triggeredTx], triggerTs);

    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.PENDING_REVIEW);
    const review = fx.dag.getOpenPrescanReviewByCtid(CTID);
    expect(review.state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
    expect(review.assigned_reviewer).toBe(REVIEWER_TIP);
    const reviewId = review.review_id;

    // ── Step 4: reviewer confirms. Service builds + submits the
    // PRESCAN_REVIEW_CONFIRMED tx; commit-handler persists state,
    // confirmed_at_ms = cert.ts.
    const confirmPayload = confirmedSchema.buildSigningPayload({
      review_id: reviewId, reviewer_tip_id: REVIEWER_TIP,
      suggested_origin: "AG", decision_note: "clearly AI",
    });
    const confirmSig = confirmedSchema.sign(confirmPayload, fx.reviewerKp.privateKey);
    fx.reviewService.confirm(reviewId, {
      reviewer_tip_id: REVIEWER_TIP, suggested_origin: "AG",
      decision_note: "clearly AI", signature: confirmSig,
    });
    const confirmTx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_CONFIRMED);
    expect(confirmTx).toBeDefined();

    fx.submitted.length = 0;
    const confirmedAtMs = triggerTs + 3600000;
    fx.commit([confirmTx], confirmedAtMs);

    const reviewAfterConfirm = fx.dag.getPrescanReview(reviewId);
    expect(reviewAfterConfirm.state).toBe(PRESCAN_REVIEW_STATES.CONFIRMED);
    expect(reviewAfterConfirm.confirmed_at_ms).toBe(confirmedAtMs);
    expect(reviewAfterConfirm.suggested_origin).toBe("AG");
    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.PENDING_REVIEW);

    // ── Step 5: creator accepts the correction inside the 24h window.
    // Service emits UPDATE_ORIGIN + SCORE_UPDATE batch. Commit-handler
    // applies origin change, flips review to CLOSED_ACCEPTED_PRIVATE,
    // updates the score.
    const scoreBefore = fx.scoring.getScore(CREATOR).score;

    const updateSig = signBody(
      { author_tip_id: CREATOR, new_origin_code: "AG" },
      fx.creatorKp.privateKey,
    );
    fx.reviewService.acceptCorrection(reviewId, {
      author_tip_id: CREATOR, signature: updateSig,
    });
    const updateTx = fx.submitted.find(t => t.tx_type === TX_TYPES.UPDATE_ORIGIN);
    const scoreTx = fx.submitted.find(t => t.tx_type === TX_TYPES.SCORE_UPDATE);
    expect(updateTx).toBeDefined();
    expect(scoreTx).toBeDefined();
    expect(scoreTx.data.related_tx_id).toBe(updateTx.tx_id);

    fx.submitted.length = 0;
    const acceptAtMs = confirmedAtMs + 3600000;
    fx.commit([updateTx, scoreTx], acceptAtMs);

    const finalContent = fx.dag.getContent(CTID);
    const finalReview = fx.dag.getPrescanReview(reviewId);
    const finalScore = fx.scoring.getScore(CREATOR).score;

    expect(finalContent.origin_code).toBe("AG");
    expect(finalContent.status).toBe(CONTENT_STATUS.REGISTERED);
    expect(finalReview.state).toBe(PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE);
    expect(finalScore).toBe(scoreBefore + REVIEWER.ACCEPT_CORRECTION_SCORE_DELTA);
  });

  test("register flagged → h=48 trigger → reviewer dismisses → green badge restored", () => {
    const fx = _setup();

    // canUpdateOrigin uses Date.now() (wall clock) at API call; cert
    // timestamps drive the consensus-time checks. Anchor the timeline to
    // a point shortly before real now so wall-clock and simulated time
    // agree across the whole flow.
    const registeredAtMs = Date.now() - CONTENT_GRACE.FLAGGED_MS - 5 * 60_000;
    fx.seedContent(registeredAtMs);

    const triggerTs = registeredAtMs + CONTENT_GRACE.FLAGGED_MS + 1000;
    fx.commit([], triggerTs);
    const triggeredTx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_TRIGGERED);

    fx.submitted.length = 0;
    fx.commit([triggeredTx], triggerTs);
    const reviewId = fx.dag.getOpenPrescanReviewByCtid(CTID).review_id;
    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.PENDING_REVIEW);

    // Reviewer dismisses ("AI was wrong"). Phase 2.3 restores
    // content.status to REGISTERED on commit. No score effect.
    const dismissedSchema = require(path.join(SRC, "schemas", "prescan-review-dismissed"));
    const payload = dismissedSchema.buildSigningPayload({
      review_id: reviewId, reviewer_tip_id: REVIEWER_TIP, decision_note: "human voice",
    });
    const signature = dismissedSchema.sign(payload, fx.reviewerKp.privateKey);
    fx.reviewService.dismiss(reviewId, {
      reviewer_tip_id: REVIEWER_TIP, decision_note: "human voice", signature,
    });
    const dismissTx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_DISMISSED);

    const scoreBefore = fx.scoring.getScore(CREATOR).score;
    fx.submitted.length = 0;
    fx.commit([dismissTx], triggerTs + 3600000);

    const finalReview = fx.dag.getPrescanReview(reviewId);
    expect(finalReview.state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);
    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.REGISTERED);
    // No score effect on dismiss — reviewer agreed creator was right.
    expect(fx.scoring.getScore(CREATOR).score).toBe(scoreBefore);
  });

  test("register flagged → creator self-corrects EARLY (h<48) → trigger never fires, no review row", () => {
    const fx = _setup();

    // Content registered just minutes ago — still well inside the 48h
    // creator self-correction window.
    const registeredAtMs = Date.now() - 30 * 60_000; // 30 minutes old
    fx.seedContent(registeredAtMs);

    // Creator updates the origin. Phase 1: 48h grace for flagged
    // content lets this through without penalty.
    const updateSig = signBody(
      { author_tip_id: CREATOR, new_origin_code: "AG" },
      fx.creatorKp.privateKey,
    );
    // No review row exists yet, so we drive UPDATE_ORIGIN directly via
    // a constructed tx (no review-service path for early self-correct;
    // that's the content-service /update-origin endpoint's job).
    const { withTxId } = require(path.join(SRC, "services", "helpers"));
    const updateTx = withTxId({
      tx_type: TX_TYPES.UPDATE_ORIGIN,
      timestamp: new Date().toISOString(),
      prev: fx.dag.getRecentPrev(),
      data: {
        ctid: CTID,
        old_origin_code: "OH",
        new_origin_code: "AG",
        author_tip_id: CREATOR,
        signature: updateSig,
      },
    });

    fx.submitted.length = 0;
    fx.commit([updateTx], Date.now());

    // Content origin updated, status stays REGISTERED (green badge).
    expect(fx.dag.getContent(CTID).origin_code).toBe("AG");
    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.REGISTERED);
    // No review row was ever created — there's nothing for the trigger
    // to find now that content origin is AG (the trigger filter requires
    // prescan_tier in (high, critical) + override; content still matches
    // but age is < 48h, so trigger does NOT fire).
    expect(fx.dag.getOpenPrescanReviewByCtid(CTID)).toBeNull();

    // Tick past h=48 to be sure — trigger still must NOT fire because
    // an UPDATE_ORIGIN already landed (the SQL filter excludes content
    // whose status would still match; but more importantly, a second
    // UPDATE_ORIGIN is rejected by canUpdateOrigin's "already updated"
    // guard — and the content's status is now REGISTERED with the new
    // origin AG, no longer flagged in a way that requires review). The
    // open-review-exclusion in getContentsNeedingReview prevents any
    // duplicate trigger even if the filter were lenient.
    fx.submitted.length = 0;
    fx.commit([], registeredAtMs + CONTENT_GRACE.FLAGGED_MS + 1000);
    const triggered = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_TRIGGERED);
    expect(triggered).toBeUndefined();
  });

  test("register flagged → trigger fires → creator self-corrects BEFORE reviewer decides → review closes with CLOSED_SELF_CORRECT", () => {
    const fx = _setup();

    const registeredAtMs = Date.now() - CONTENT_GRACE.FLAGGED_MS - 5 * 60_000;
    fx.seedContent(registeredAtMs);

    // Trigger fires + lands. Review now in TRIGGERED, content
    // status=PENDING_REVIEW. Reviewer has NOT decided yet.
    const triggerTs = registeredAtMs + CONTENT_GRACE.FLAGGED_MS + 1000;
    fx.commit([], triggerTs);
    const triggeredTx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_TRIGGERED);
    fx.submitted.length = 0;
    fx.commit([triggeredTx], triggerTs);
    const reviewId = fx.dag.getOpenPrescanReviewByCtid(CTID).review_id;
    expect(fx.dag.getPrescanReview(reviewId).state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);

    // Creator beats the reviewer to it — submits UPDATE_ORIGIN while
    // the review is still in TRIGGERED. canUpdateOrigin allows this
    // (content.status === PENDING_REVIEW is permitted; no open
    // CONFIRMED review yet, so the from-registration grace still
    // applies and we're inside the 48h window because triggerTs is
    // ~5min past h=48 — still inside 48h grace? Actually past it.
    // The path that lets this through: PENDING_REVIEW is allowed by
    // the status guard; the trigger doesn't FALSE-positive on grace
    // because the open review's CONFIRMED branch hasn't activated).
    // Phase 2.3: commit-handler.UPDATE_ORIGIN apply flips the open
    // TRIGGERED review to CLOSED_SELF_CORRECT.
    const updateSig = signBody(
      { author_tip_id: CREATOR, new_origin_code: "AG" },
      fx.creatorKp.privateKey,
    );
    const { withTxId } = require(path.join(SRC, "services", "helpers"));
    const updateTx = withTxId({
      tx_type: TX_TYPES.UPDATE_ORIGIN,
      timestamp: new Date().toISOString(),
      prev: fx.dag.getRecentPrev(),
      data: {
        ctid: CTID,
        old_origin_code: "OH",
        new_origin_code: "AG",
        author_tip_id: CREATOR,
        signature: updateSig,
      },
    });
    fx.submitted.length = 0;
    fx.commit([updateTx], triggerTs + 60_000);

    const finalReview = fx.dag.getPrescanReview(reviewId);
    expect(finalReview.state).toBe(PRESCAN_REVIEW_STATES.CLOSED_SELF_CORRECT);
    expect(fx.dag.getContent(CTID).origin_code).toBe("AG");
    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.REGISTERED);
  });

  test("register flagged → reviewer confirm → creator does nothing → h=R+24 auto-escalates to CONTENT_DISPUTED", () => {
    const fx = _setup();

    // canUpdateOrigin uses Date.now() (wall clock) at API call; cert
    // timestamps drive the consensus-time checks. Anchor the timeline to
    // a point shortly before real now so wall-clock and simulated time
    // agree across the whole flow.
    const registeredAtMs = Date.now() - CONTENT_GRACE.FLAGGED_MS - 5 * 60_000;
    fx.seedContent(registeredAtMs);

    // Drive: trigger → confirm → wait past 24h.
    const triggerTs = registeredAtMs + CONTENT_GRACE.FLAGGED_MS + 1000;
    fx.commit([], triggerTs);
    const triggeredTx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_TRIGGERED);
    fx.submitted.length = 0;
    fx.commit([triggeredTx], triggerTs);
    const reviewId = fx.dag.getOpenPrescanReviewByCtid(CTID).review_id;

    const confirmPayload = confirmedSchema.buildSigningPayload({
      review_id: reviewId, reviewer_tip_id: REVIEWER_TIP, suggested_origin: "AG",
    });
    const confirmSig = confirmedSchema.sign(confirmPayload, fx.reviewerKp.privateKey);
    fx.reviewService.confirm(reviewId, {
      reviewer_tip_id: REVIEWER_TIP, suggested_origin: "AG", signature: confirmSig,
    });
    const confirmTx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_CONFIRMED);

    fx.submitted.length = 0;
    const confirmedAtMs = triggerTs + 3600000;
    fx.commit([confirmTx], confirmedAtMs);

    // Tick past R+24h. The trigger should emit a node-signed
    // auto-cascade CONTENT_DISPUTED.
    fx.submitted.length = 0;
    const escalateAtMs = confirmedAtMs + REVIEWER.CREATOR_DECISION_WINDOW_MS + 1000;
    fx.commit([], escalateAtMs);

    const escalateTx = fx.submitted.find(t => t.tx_type === TX_TYPES.CONTENT_DISPUTED);
    expect(escalateTx).toBeDefined();
    expect(escalateTx.data.auto).toBe(true);
    expect(escalateTx.data.reason).toBe("creator_decision_window_expired");
    expect(escalateTx.data.source_review_id).toBe(reviewId);

    // Commit the escalation tx. Phase 2.5: review state flips to
    // ESCALATED_TO_DISPUTE; content.status → DISPUTED.
    fx.submitted.length = 0;
    fx.commit([escalateTx], escalateAtMs);

    const finalReview = fx.dag.getPrescanReview(reviewId);
    expect(finalReview.state).toBe(PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE);
    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.DISPUTED);
  });
});
