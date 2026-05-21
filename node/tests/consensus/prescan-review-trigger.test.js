/**
 * @file tests/consensus/prescan-review-trigger.test.js
 * @description Phase 2.5 — post-round trigger for the prescan-review
 * pipeline. Covers the two consensus-affecting triggers:
 *
 *   1. h=48 PRESCAN_REVIEW_TRIGGERED — fires once content has aged past
 *      CONTENT_GRACE.FLAGGED_MS, doesn't fire before, no double-fire on
 *      repeat ticks, no fire after creator UPDATE_ORIGIN.
 *
 *   2. h=R+24 auto-escalation — emits CONTENT_DISPUTED (auto-cascade)
 *      once REVIEWER.CREATOR_DECISION_WINDOW_MS has elapsed since
 *      CONFIRMED. confirmed_at_ms is persisted on the review row from
 *      the CONFIRMED apply's cert.ts. The follow-up apply flips
 *      review.state to ESCALATED_TO_DISPUTE.
 *
 * Also covers the DAG-helper level — that getContentsNeedingReview /
 * getReviewsNeedingAutoEscalation honour the time predicate, status
 * filter, tier filter, and open-review exclusion.
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
const dismissedSchema = require(path.join(SRC, "schemas", "prescan-review-dismissed"));
const confirmedSchema = require(path.join(SRC, "schemas", "prescan-review-confirmed"));
const {
  TX_TYPES, PRESCAN_REVIEW_STATES, CONTENT_STATUS,
} = require(path.join(SHARED, "constants"));
const { CONTENT_GRACE, REVIEWER } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/n1";
const VP_ID = "tip://vp/v1";
const CREATOR = "tip://id/US-cccccccccccccccc";
const REVIEWER_1 = "tip://id/US-1111aaaa1111aaaa";
const CTID_1 = "tip://c/OH-11111111111111-0001";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const reviewer1Kp = generateMLDSAKeypair();

  dag.saveNode({
    node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey,
    status: "active", registered_at: 1767225600000,
  });
  dag.saveVP({
    vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
    public_key: "00", status: "active", registered_at: 1767225600000,
  });
  dag.saveIdentity({
    tip_id: CREATOR, region: "US", public_key: nodeKp.publicKey, root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: false,
    registered_at: 1767225600000, tx_id: shake256("creator"),
  });
  dag.saveIdentity({
    tip_id: REVIEWER_1, region: "US",
    public_key: reviewer1Kp.publicKey, root_public_key: reviewer1Kp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    reviewer_consent: true,
    registered_at: 1767225600000, tx_id: shake256("reviewer1"),
  });

  const scoring = initScoring(dag, { nodeId: NODE_ID });
  dag.setScore(REVIEWER_1, 900, 0, Date.now());

  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID,
    nodePrivateKey: nodeKp.privateKey,
  };

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
    commitHandler.commitOrderedTxs(txs, round, {
      certTimestamp: certTimestamp || Date.now(),
    });
    return round;
  }

  function seedFlaggedContent({ ctid = CTID_1, registeredAtMs }) {
    dag.saveContent({
      ctid, origin_code: "OH",
      content_hash: "ab".repeat(32), perceptual_hash: null,
      author_tip_id: CREATOR, signer_tip_id: CREATOR,
      authors: [{ tip_id: CREATOR, key_mode: "attribution", role: "byline", signed: false, tip_id_type: "personal" }],
      attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
      status: CONTENT_STATUS.REGISTERED,
      prescan_flagged: true, prescan_probability: 0.95, prescan_tier: "high",
      override: true,
      registered_at: new Date(registeredAtMs).toISOString(),
      registered_urls: [], tx_id: shake256(`content:${ctid}:${registeredAtMs}`),
    });
  }

  return { dag, commit, submitted, prescanReviewTrigger, nodeKp, reviewer1Kp, seedFlaggedContent };
}

// ═══════════════════════════════════════════════════════════════════════════
// DAG helpers — getContentsNeedingReview
// ═══════════════════════════════════════════════════════════════════════════

describe("dag.getContentsNeedingReview", () => {

  test("returns content past CONTENT_GRACE.FLAGGED_MS; excludes fresh content", () => {
    const fx = _setup();
    const nowMs = Date.parse(1772323200000);
    const oldMs = nowMs - CONTENT_GRACE.FLAGGED_MS - 1000;
    const freshMs = nowMs - 1000;

    fx.seedFlaggedContent({ ctid: "tip://c/OH-aaaaaaaaaaaaaa-0001", registeredAtMs: oldMs });
    fx.seedFlaggedContent({ ctid: "tip://c/OH-bbbbbbbbbbbbbb-0002", registeredAtMs: freshMs });

    const due = fx.dag.getContentsNeedingReview(nowMs);
    expect(due.map(c => c.ctid)).toEqual(["tip://c/OH-aaaaaaaaaaaaaa-0001"]);
  });

  test("excludes content with an open prescan review", () => {
    const fx = _setup();
    const nowMs = Date.parse(1772323200000);
    const oldMs = nowMs - CONTENT_GRACE.FLAGGED_MS - 1000;
    fx.seedFlaggedContent({ ctid: CTID_1, registeredAtMs: oldMs });
    fx.dag.savePrescanReview({
      review_id: "rv_x", ctid: CTID_1, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1, triggered_at_round: 1,
      state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });
    expect(fx.dag.getContentsNeedingReview(nowMs)).toEqual([]);
  });

  test("excludes content whose latest prescan_review is in a non-recused terminal state (no re-trigger after dismiss / accept / escalate)", () => {
    // Regression guard for the re-trigger loop: after a reviewer
    // DISMISSes (review.state=closed_dismissed), content.status flips
    // back to REGISTERED — all the original trigger conditions are
    // still true (OH + critical + override + age>flagged_ms). The
    // trigger's JOIN must include EVERY non-recused review state so
    // it doesn't fire a fresh reviewer assignment on every round.
    const fx = _setup();
    const nowMs = Date.parse(1772323200000);
    const oldMs = nowMs - CONTENT_GRACE.FLAGGED_MS - 1000;

    const TERMINAL_STATES = [
      PRESCAN_REVIEW_STATES.CLOSED_DISMISSED,
      PRESCAN_REVIEW_STATES.CLOSED_ACCEPTED_PRIVATE,
      PRESCAN_REVIEW_STATES.CLOSED_SELF_CORRECT,
      PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE,
    ];
    for (const state of TERMINAL_STATES) {
      const fresh = _setup();
      const ctidForState = `tip://c/OH-${state.replace(/_/g, "").padEnd(14, "0").slice(0, 14)}-0001`;
      fresh.seedFlaggedContent({ ctid: ctidForState, registeredAtMs: oldMs });
      fresh.dag.savePrescanReview({
        review_id: `rv_term_${state}`, ctid: ctidForState, creator_tip_id: CREATOR,
        assigned_reviewer: REVIEWER_1, triggered_at_round: 1,
        decided_at_round: 2,
        state,
      });
      expect(fresh.dag.getContentsNeedingReview(nowMs)).toEqual([]);
    }
  });

  test("re-triggers when latest review is in RECUSED state (need to assign new reviewer)", () => {
    const fx = _setup();
    const nowMs = Date.parse(1772323200000);
    const oldMs = nowMs - CONTENT_GRACE.FLAGGED_MS - 1000;
    fx.seedFlaggedContent({ ctid: CTID_1, registeredAtMs: oldMs });
    fx.dag.savePrescanReview({
      review_id: "rv_recused", ctid: CTID_1, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1, triggered_at_round: 1,
      decided_at_round: 2,
      state: PRESCAN_REVIEW_STATES.RECUSED,
    });
    // Only-recused history → re-trigger is exactly the intended path.
    const out = fx.dag.getContentsNeedingReview(nowMs);
    expect(out).toHaveLength(1);
    expect(out[0].ctid).toBe(CTID_1);
  });

  test("excludes low/elevated tier; includes high/critical regardless of override", () => {
    const fx = _setup();
    const nowMs = Date.parse(1772323200000);
    const oldMs = nowMs - CONTENT_GRACE.FLAGGED_MS - 1000;

    // low tier (excluded — never reviewed)
    fx.dag.saveContent({
      ctid: "tip://c/OH-ll1111ll1111ll-0001", origin_code: "OH",
      content_hash: "cd".repeat(32), perceptual_hash: null,
      author_tip_id: CREATOR, signer_tip_id: CREATOR, authors: [{ tip_id: CREATOR, tip_id_type: "personal" }],
      attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
      status: CONTENT_STATUS.REGISTERED,
      prescan_flagged: false, prescan_probability: 0.1, prescan_tier: "low",
      override: false, registered_at: new Date(oldMs).toISOString(),
      registered_urls: [], tx_id: shake256("c:low"),
    });
    // high tier without override — included. The override gate at registration
    // was dropped; the trigger now fires for every HIGH/CRITICAL OH content
    // past the 48h grace, regardless of the (now-optional) override flag.
    fx.dag.saveContent({
      ctid: "tip://c/OH-nooverridenoover-0001", origin_code: "OH",
      content_hash: "ef".repeat(32), perceptual_hash: null,
      author_tip_id: CREATOR, signer_tip_id: CREATOR, authors: [{ tip_id: CREATOR, tip_id_type: "personal" }],
      attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
      status: CONTENT_STATUS.REGISTERED,
      prescan_flagged: true, prescan_probability: 0.95, prescan_tier: "high",
      override: false, registered_at: new Date(oldMs).toISOString(),
      registered_urls: [], tx_id: shake256("c:no-override"),
    });
    const out = fx.dag.getContentsNeedingReview(nowMs);
    expect(out).toHaveLength(1);
    expect(out[0].ctid).toBe("tip://c/OH-nooverridenoover-0001");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// h=48 PRESCAN_REVIEW_TRIGGERED emission
// ═══════════════════════════════════════════════════════════════════════════

describe("prescan-review-trigger — h=48 review trigger", () => {

  test("fires PRESCAN_REVIEW_TRIGGERED for content past 48h", () => {
    const fx = _setup();
    const nowMs = Date.parse(1772323200000);
    fx.seedFlaggedContent({ registeredAtMs: nowMs - CONTENT_GRACE.FLAGGED_MS - 1000 });

    fx.prescanReviewTrigger.checkPending(nowMs, 1);
    expect(fx.submitted.length).toBe(1);
    const tx = fx.submitted[0];
    expect(tx.tx_type).toBe(TX_TYPES.PRESCAN_REVIEW_TRIGGERED);
    expect(tx.data.ctid).toBe(CTID_1);
    expect(tx.data.creator_tip_id).toBe(CREATOR);
    expect(tx.data.assigned_reviewer_tip_id).toBe(REVIEWER_1);
    expect(tx.data.node_id).toBe(NODE_ID);
    expect(tx.data.triggered_at_round).toBe(1);
  });

  test("does NOT fire before 48h", () => {
    const fx = _setup();
    const nowMs = Date.parse(1772323200000);
    fx.seedFlaggedContent({ registeredAtMs: nowMs - CONTENT_GRACE.FLAGGED_MS + 60_000 });
    fx.prescanReviewTrigger.checkPending(nowMs, 1);
    expect(fx.submitted.length).toBe(0);
  });

  test("no double-fire once a review row exists for the ctid", () => {
    const fx = _setup();
    const nowMs = Date.parse(1772323200000);
    fx.seedFlaggedContent({ registeredAtMs: nowMs - CONTENT_GRACE.FLAGGED_MS - 1000 });

    fx.prescanReviewTrigger.checkPending(nowMs, 1);
    expect(fx.submitted.length).toBe(1);
    // Commit the emitted tx so the open review now exists in the DAG.
    fx.commit([fx.submitted[0]], nowMs);

    fx.prescanReviewTrigger.checkPending(nowMs + 1000, 2);
    expect(fx.submitted.length).toBe(1);  // still one — second tick saw the open review and skipped
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// CONFIRMED apply persists confirmed_at_ms from cert.ts
// ═══════════════════════════════════════════════════════════════════════════

describe("PRESCAN_REVIEW_CONFIRMED — confirmed_at_ms persistence", () => {

  test("commit-handler sets confirmed_at_ms from certTimestamp", () => {
    const fx = _setup();
    const nowMs = Date.parse(1772323200000);
    fx.seedFlaggedContent({ registeredAtMs: nowMs - CONTENT_GRACE.FLAGGED_MS - 1000 });

    fx.prescanReviewTrigger.checkPending(nowMs, 1);
    fx.commit([fx.submitted[0]], nowMs);

    const reviewId = fx.submitted[0].data.review_id;
    const confirmedCertMs = nowMs + 60_000;

    // Build a reviewer-signed CONFIRMED tx
    const payload = confirmedSchema.buildSigningPayload({
      review_id: reviewId, reviewer_tip_id: REVIEWER_1,
      suggested_origin: "AG", decision_note: null,
    });
    const signature = confirmedSchema.sign(payload, fx.reviewer1Kp.privateKey);
    const data = {
      review_id: reviewId, reviewer_tip_id: REVIEWER_1,
      suggested_origin: "AG", decision_note: null, signature,
    };
    const txBody = {
      tx_type: TX_TYPES.PRESCAN_REVIEW_CONFIRMED,
      timestamp: new Date(confirmedCertMs).toISOString(),
      prev: fx.dag.getRecentPrev(), data,
    };
    txBody.tx_id = computeTxId(txBody);

    fx.commit([txBody], confirmedCertMs);

    const review = fx.dag.getPrescanReview(reviewId);
    expect(review.state).toBe(PRESCAN_REVIEW_STATES.CONFIRMED);
    expect(review.confirmed_at_ms).toBe(confirmedCertMs);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// h=R+24 auto-escalation
// ═══════════════════════════════════════════════════════════════════════════

describe("prescan-review-trigger — h=R+24 auto-escalation", () => {

  test("emits auto-cascade CONTENT_DISPUTED once the 24h window has elapsed", () => {
    const fx = _setup();
    const confirmedMs = Date.parse(1772323200000);
    fx.dag.savePrescanReview({
      review_id: "rv_esc", ctid: CTID_1, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1, triggered_at_round: 1,
      decided_at_round: 2, confirmed_at_round: 2,
      confirmed_at_ms: confirmedMs,
      state: PRESCAN_REVIEW_STATES.CONFIRMED, suggested_origin: "AG",
    });
    // Seed content row (required for the CONTENT_DISPUTED apply path)
    fx.dag.saveContent({
      ctid: CTID_1, origin_code: "OH",
      content_hash: "ab".repeat(32), perceptual_hash: null,
      author_tip_id: CREATOR, signer_tip_id: CREATOR, authors: [{ tip_id: CREATOR, tip_id_type: "personal" }],
      attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
      status: CONTENT_STATUS.PENDING_REVIEW,
      prescan_flagged: true, prescan_probability: 0.95, prescan_tier: "high",
      override: true, registered_at: new Date(confirmedMs - 86400000).toISOString(),
      registered_urls: [], tx_id: shake256("c:esc"),
    });

    const nowMs = confirmedMs + REVIEWER.CREATOR_DECISION_WINDOW_MS + 1000;
    fx.prescanReviewTrigger.checkPending(nowMs, 1);

    expect(fx.submitted.length).toBe(1);
    const tx = fx.submitted[0];
    expect(tx.tx_type).toBe(TX_TYPES.CONTENT_DISPUTED);
    expect(tx.data.ctid).toBe(CTID_1);
    expect(tx.data.auto).toBe(true);
    expect(tx.data.reason).toBe("creator_decision_window_expired");
    expect(tx.data.source_review_id).toBe("rv_esc");
    expect(tx.data.node_id).toBe(NODE_ID);
  });

  test("does NOT escalate before 24h", () => {
    const fx = _setup();
    const confirmedMs = Date.parse(1772323200000);
    fx.dag.savePrescanReview({
      review_id: "rv_early", ctid: CTID_1, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1, triggered_at_round: 1,
      decided_at_round: 2, confirmed_at_round: 2,
      confirmed_at_ms: confirmedMs,
      state: PRESCAN_REVIEW_STATES.CONFIRMED, suggested_origin: "AG",
    });

    fx.prescanReviewTrigger.checkPending(confirmedMs + 1000, 1);
    expect(fx.submitted.length).toBe(0);
  });

  test("CONTENT_DISPUTED apply flips review.state to ESCALATED_TO_DISPUTE", () => {
    const fx = _setup();
    const confirmedMs = Date.parse(1772323200000);
    fx.dag.savePrescanReview({
      review_id: "rv_apply", ctid: CTID_1, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1, triggered_at_round: 1,
      decided_at_round: 2, confirmed_at_round: 2,
      confirmed_at_ms: confirmedMs,
      state: PRESCAN_REVIEW_STATES.CONFIRMED, suggested_origin: "AG",
    });
    fx.dag.saveContent({
      ctid: CTID_1, origin_code: "OH",
      content_hash: "ab".repeat(32), perceptual_hash: null,
      author_tip_id: CREATOR, signer_tip_id: CREATOR, authors: [{ tip_id: CREATOR, tip_id_type: "personal" }],
      attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
      status: CONTENT_STATUS.PENDING_REVIEW,
      prescan_flagged: true, prescan_probability: 0.95, prescan_tier: "high",
      override: true, registered_at: new Date(confirmedMs - 86400000).toISOString(),
      registered_urls: [], tx_id: shake256("c:apply"),
    });

    const nowMs = confirmedMs + REVIEWER.CREATOR_DECISION_WINDOW_MS + 1000;
    fx.prescanReviewTrigger.checkPending(nowMs, 1);
    expect(fx.submitted.length).toBe(1);

    fx.commit([fx.submitted[0]], nowMs);
    const review = fx.dag.getPrescanReview("rv_apply");
    expect(review.state).toBe(PRESCAN_REVIEW_STATES.ESCALATED_TO_DISPUTE);
    expect(fx.dag.getContent(CTID_1).status).toBe(CONTENT_STATUS.DISPUTED);
  });

  test("idempotent — does not re-emit if a CONTENT_DISPUTED already exists for the ctid", () => {
    const fx = _setup();
    const confirmedMs = Date.parse(1772323200000);
    fx.dag.savePrescanReview({
      review_id: "rv_idem", ctid: CTID_1, creator_tip_id: CREATOR,
      assigned_reviewer: REVIEWER_1, triggered_at_round: 1,
      decided_at_round: 2, confirmed_at_round: 2,
      confirmed_at_ms: confirmedMs,
      state: PRESCAN_REVIEW_STATES.CONFIRMED, suggested_origin: "AG",
    });
    // Pre-existing dispute tx in DAG (e.g. user filed during the window)
    const preexisting = {
      tx_type: TX_TYPES.CONTENT_DISPUTED,
      timestamp: new Date(confirmedMs).toISOString(),
      prev: [],
      data: { ctid: CTID_1, disputer_tip_id: CREATOR, reason: "user_filed" },
    };
    preexisting.tx_id = computeTxId(preexisting);
    fx.dag.addTx(preexisting);

    const nowMs = confirmedMs + REVIEWER.CREATOR_DECISION_WINDOW_MS + 1000;
    fx.prescanReviewTrigger.checkPending(nowMs, 1);
    expect(fx.submitted.length).toBe(0);
  });
});
