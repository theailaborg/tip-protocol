/**
 * @file tests/consensus/prescan-review-auto-recuse.test.js
 * @description Reviewer-SLA auto-recuse end-to-end through the
 * prescan-review-trigger module + commit-handler.
 *
 *   1. PRESCAN_REVIEW_TRIGGERED apply persists triggered_at_ms from
 *      cert.ts (mirrors confirmed_at_ms).
 *   2. getReviewsNeedingAutoRecuse(cert.ts) returns TRIGGERED reviews
 *      older than REVIEWER.AUTO_RECUSE_AGE_MS; younger ones are
 *      excluded.
 *   3. Trigger emits a node-signed PRESCAN_REVIEW_RECUSED tx with
 *      data.auto=true + data.node_id + recusal_reason="sla_expired".
 *      Schema verifyTx accepts it (no reviewer_tip_id needed for the
 *      auto path).
 *   4. Commit-handler apply flips review.state to RECUSED and
 *      content.status back to REGISTERED — same path as a manual
 *      recuse — so the next round's _emitDueReviews re-picks the
 *      content and emits a fresh PRESCAN_REVIEW_TRIGGERED.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const {
  initCrypto, generateMLDSAKeypair, shake256, computeTxId, signTransaction,
} = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createPrescanReviewTrigger } = require(path.join(SRC, "consensus", "prescan-review-trigger"));
const {
  TX_TYPES, PRESCAN_REVIEW_STATES, CONTENT_STATUS,
} = require(path.join(SHARED, "constants"));
const { CONTENT_GRACE, REVIEWER } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/n1";
const VP_ID = "tip://vp/v1";
const CREATOR = "tip://id/US-cccccccccccccccc";
const REVIEWER_1 = "tip://id/US-1111aaaa1111aaaa";
const CTID = "tip://c/OH-11111111111111-0001";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
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
    tip_id: CREATOR, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: false,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("creator"),
  });
  dag.saveIdentity({
    tip_id: REVIEWER_1, region: "US",
    public_key: reviewerKp.publicKey, root_public_key: reviewerKp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: true,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256("reviewer1"),
  });

  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID,
    nodePrivateKey: nodeKp.privateKey,
  };
  const scoring = initScoring(dag, config);
  dag.setScore(REVIEWER_1, 900, 0, new Date().toISOString());

  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };

  const prescanReviewTrigger = createPrescanReviewTrigger({
    dag, scoring, config, submitTx,
  });
  const commitHandler = createCommitHandler({
    dag, scoring, config, prescanReviewTrigger, nodeId: NODE_ID,
  });

  let round = 0;
  function commit(txs, certTimestamp) {
    round++;
    commitHandler.commitOrderedTxs(txs, round, { certTimestamp });
  }

  function seedFlaggedContent(registeredAtMs) {
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

  return { dag, scoring, commit, submitted, prescanReviewTrigger, seedFlaggedContent };
}

describe("PRESCAN_REVIEW_TRIGGERED — triggered_at_ms persistence", () => {

  test("commit-handler sets triggered_at_ms from cert.ts", () => {
    const fx = _setup();
    const registeredAtMs = Date.now() - CONTENT_GRACE.FLAGGED_MS - 5 * 60_000;
    fx.seedFlaggedContent(registeredAtMs);

    const triggerCertMs = registeredAtMs + CONTENT_GRACE.FLAGGED_MS + 1000;
    fx.commit([], triggerCertMs);
    const triggeredTx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_TRIGGERED);
    expect(triggeredTx).toBeDefined();

    fx.submitted.length = 0;
    fx.commit([triggeredTx], triggerCertMs);
    const review = fx.dag.getOpenPrescanReviewByCtid(CTID);
    expect(review.state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
    expect(review.triggered_at_ms).toBe(triggerCertMs);
  });
});

describe("dag.getReviewsNeedingAutoRecuse", () => {

  test("returns TRIGGERED reviews older than REVIEWER.AUTO_RECUSE_AGE_MS; excludes fresh", () => {
    const fx = _setup();
    const nowMs = Date.parse("2026-03-01T00:00:00.000Z");
    const oldMs = nowMs - REVIEWER.AUTO_RECUSE_AGE_MS - 60_000;
    const freshMs = nowMs - 60_000;

    fx.dag.savePrescanReview({
      review_id: "rv_old", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: oldMs,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });
    fx.dag.savePrescanReview({
      review_id: "rv_fresh", ctid: "tip://c/OH-22222222222222-0002", creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 2, triggered_at_ms: freshMs,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });

    const due = fx.dag.getReviewsNeedingAutoRecuse(nowMs);
    expect(due.map(r => r.review_id)).toEqual(["rv_old"]);
  });

  test("excludes non-TRIGGERED reviews (decided / recused / etc.)", () => {
    const fx = _setup();
    const nowMs = Date.parse("2026-03-01T00:00:00.000Z");
    const oldMs = nowMs - REVIEWER.AUTO_RECUSE_AGE_MS - 60_000;

    fx.dag.savePrescanReview({
      review_id: "rv_dismissed", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: oldMs,
      state: PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
    });
    expect(fx.dag.getReviewsNeedingAutoRecuse(nowMs)).toEqual([]);
  });
});

describe("prescan-review-trigger — SLA auto-recuse", () => {

  test("emits node-signed PRESCAN_REVIEW_RECUSED once SLA elapses", () => {
    const fx = _setup();
    const nowMs = Date.parse("2026-03-01T00:00:00.000Z");
    const oldMs = nowMs - REVIEWER.AUTO_RECUSE_AGE_MS - 60_000;
    fx.dag.savePrescanReview({
      review_id: "rv_recuse_me", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: oldMs,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });

    fx.prescanReviewTrigger.checkPending(nowMs, 1);

    const tx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_RECUSED);
    expect(tx).toBeDefined();
    expect(tx.data.auto).toBe(true);
    expect(tx.data.node_id).toBe(NODE_ID);
    expect(tx.data.review_id).toBe("rv_recuse_me");
    expect(tx.data.recusal_reason).toBe("sla_expired");
    // Node-signed, so no data.signature / data.reviewer_tip_id.
    expect(tx.data.reviewer_tip_id).toBeUndefined();
    expect(tx.data.signature).toBeUndefined();
    expect(typeof tx.signature).toBe("string");
  });

  test("does NOT emit before SLA", () => {
    const fx = _setup();
    const nowMs = Date.parse("2026-03-01T00:00:00.000Z");
    fx.dag.savePrescanReview({
      review_id: "rv_fresh", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: nowMs - 60_000,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });
    fx.prescanReviewTrigger.checkPending(nowMs, 1);
    expect(fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_RECUSED)).toBeUndefined();
  });

  test("commit-handler applies auto-recuse → review=RECUSED, content.status=REGISTERED", () => {
    const fx = _setup();
    // Seed an old TRIGGERED review with content row backing it
    const baseMs = Date.now() - REVIEWER.AUTO_RECUSE_AGE_MS - 60_000;
    fx.seedFlaggedContent(baseMs - CONTENT_GRACE.FLAGGED_MS);
    fx.dag.updateContentStatus(CTID, CONTENT_STATUS.PENDING_REVIEW);
    fx.dag.savePrescanReview({
      review_id: "rv_apply", ctid: CTID, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1,
      triggered_at_round: 1, triggered_at_ms: baseMs,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });

    const nowMs = Date.now();
    fx.prescanReviewTrigger.checkPending(nowMs, 1);
    const tx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_RECUSED);
    expect(tx).toBeDefined();

    fx.submitted.length = 0;
    fx.commit([tx], nowMs);

    const finalReview = fx.dag.getPrescanReview("rv_apply");
    expect(finalReview.state).toBe(PRESCAN_REVIEW_STATES.RECUSED);
    expect(finalReview.decision_note).toBe("sla_expired");
    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.REGISTERED);
    expect(fx.dag.getOpenPrescanReviewByCtid(CTID)).toBeNull();
  });
});
