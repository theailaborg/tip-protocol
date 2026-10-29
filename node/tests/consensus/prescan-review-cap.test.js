/**
 * @file tests/consensus/prescan-review-cap.test.js
 * @description Stage-1 review no-show cap. After PRESCAN_REVIEW_CAP.MAX_NO_SHOWS
 * SLA recusals on one post the trigger stops reassigning it and emits a
 * node-signed auto PRESCAN_REVIEW_CONFIRMED that opens the creator's
 * decision window; the existing auto-escalation then closes the case.
 * Epoch-gated: before activation the loop behaves exactly as before.
 * Runs on the memory store and on SQLite.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256 } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createPrescanReviewTrigger, _deriveAutoReviewId } = require(path.join(SRC, "consensus", "prescan-review-trigger"));
const confirmedSchema = require(path.join(SRC, "schemas", "prescan-review-confirmed"));
const {
  TX_TYPES, PRESCAN_REVIEW_STATES, CONTENT_STATUS, RECUSAL_REASONS, PRESCAN_REVIEW_CAP,
} = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { CONTENT_GRACE, REVIEWER } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/n1";
const VP_ID = "tip://vp/v1";
const CREATOR = "tip://id/US-cccccccccccccccc";
const REVIEWER_1 = "tip://id/US-1111aaaa1111aaaa";
const CTID = "tip://c/OH-11111111111111-0001";
const ACTIVATION = 1_800_000_000_000;
const T0 = ACTIVATION - 30 * 24 * 3600 * 1000;   // content registered well before activation
// Keys must already be valid at the emitted tx's wall-clock timestamp.
const REG = 1767225600000;                       // 2026-01-01

const tmpDirs = [];
afterAll(() => { for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true }); });

function _setup({ sqlite = false, activationMs = ACTIVATION } = {}) {
  let dbPath = ":memory:";
  if (sqlite) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-review-cap-"));
    tmpDirs.push(dir);
    dbPath = path.join(dir, "dag.db");
  }
  const dag = initDAG({ dbPath });
  const nodeKp = generateMLDSAKeypair();
  const reviewerKp = generateMLDSAKeypair();

  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: REG });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: REG });
  dag.saveIdentity({
    tip_id: CREATOR, region: "US", public_key: "00", root_public_key: "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", reviewer_consent: false,
    registered_at: REG, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: CREATOR }),
  });
  dag.saveIdentity({
    tip_id: REVIEWER_1, region: "US", public_key: reviewerKp.publicKey, root_public_key: reviewerKp.publicKey,
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", reviewer_consent: true,
    registered_at: REG, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: REVIEWER_1 }),
  });

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, prescanReviewCapActivationMs: activationMs };
  const scoring = initScoring(dag, config);
  dag.setScore(REVIEWER_1, 900, 0, REG);

  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  const prescanReviewTrigger = createPrescanReviewTrigger({ dag, scoring, config, submitTx });
  const commitHandler = createCommitHandler({ dag, scoring, config, prescanReviewTrigger, nodeId: NODE_ID });

  let round = 100;
  function commit(txs, certTimestamp) {
    round++;
    return commitHandler.commitOrderedTxs(txs, round, { certTimestamp });
  }

  dag.saveContent({
    ctid: CTID, origin_code: "OH", content_hash: "ab".repeat(32),
    author_tip_id: CREATOR, signer_tip_id: CREATOR,
    authors: [{ tip_id: CREATOR, key_mode: "attribution", role: "byline", signed: false, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
    status: CONTENT_STATUS.REGISTERED,
    prescan_flagged: true, prescan_probability: 0.99, prescan_tier: "critical",
    prescan_status: "completed", prescan_completed_at: T0, override: true,
    registered_at: T0, registered_urls: [], tx_id: shake256(`c:${CTID}`),
  });

  // n SLA recusals already on the post, as the mainnet loop leaves them.
  // Each under a different (long gone) reviewer so REVIEWER_1 stays eligible.
  function seedNoShows(n) {
    for (let i = 0; i < n; i++) {
      dag.savePrescanReview({
        review_id: `pr_noshow_${i}`, ctid: CTID, creator_tip_id: CREATOR, assigned_reviewer: `tip://id/US-${String(i).padStart(16, "0")}`,
        triggered_at_round: 10 + i, triggered_at_ms: T0 + i * 1000, decided_at_round: 11 + i,
        state: PRESCAN_REVIEW_STATES.RECUSED, decision_note: RECUSAL_REASONS.SLA_EXPIRED,
      });
    }
  }

  return { dag, commit, submitted, prescanReviewTrigger, seedNoShows, config, currentRound: () => round };
}

describe.each([["memory", false], ["sqlite", true]])("review no-show cap (%s store)", (_label, sqlite) => {

  test("below the cap the post is reassigned as before", () => {
    const fx = _setup({ sqlite });
    fx.seedNoShows(PRESCAN_REVIEW_CAP.MAX_NO_SHOWS - 1);
    fx.prescanReviewTrigger.checkPending(ACTIVATION + 1000, 200);
    expect(fx.submitted.map(t => t.tx_type)).toEqual([TX_TYPES.PRESCAN_REVIEW_TRIGGERED]);
  });

  test("before activation the cap does nothing, even past the count", () => {
    const fx = _setup({ sqlite });
    fx.seedNoShows(PRESCAN_REVIEW_CAP.MAX_NO_SHOWS + 10);
    fx.prescanReviewTrigger.checkPending(ACTIVATION - 1, 200);
    expect(fx.submitted.map(t => t.tx_type)).toEqual([TX_TYPES.PRESCAN_REVIEW_TRIGGERED]);
  });

  test("at the cap the node emits an auto-confirm instead of another assignment", () => {
    const fx = _setup({ sqlite });
    fx.seedNoShows(PRESCAN_REVIEW_CAP.MAX_NO_SHOWS);
    fx.prescanReviewTrigger.checkPending(ACTIVATION, 200);
    expect(fx.submitted).toHaveLength(1);
    const tx = fx.submitted[0];
    expect(tx.tx_type).toBe(TX_TYPES.PRESCAN_REVIEW_CONFIRMED);
    expect(tx.data).toMatchObject({
      auto: true, node_id: NODE_ID, ctid: CTID, creator_tip_id: CREATOR,
      suggested_origin: PRESCAN_REVIEW_CAP.AUTO_SUGGESTED_ORIGIN,
      decision_note: PRESCAN_REVIEW_CAP.AUTO_DECISION_NOTE,
      review_id: _deriveAutoReviewId(CTID, 200),
    });
    expect(tx.data.reviewer_tip_id).toBeUndefined();
    expect(typeof tx.signature).toBe("string");
    expect(confirmedSchema.verifyTx(tx, fx.dag)).toEqual({ ok: true });
  });

  test("history counts: a post far past the cap closes on the first tick after activation", () => {
    const fx = _setup({ sqlite });
    fx.seedNoShows(47);
    fx.prescanReviewTrigger.checkPending(ACTIVATION + 5000, 300);
    expect(fx.submitted.map(t => t.tx_type)).toEqual([TX_TYPES.PRESCAN_REVIEW_CONFIRMED]);
  });

  test("commit applies the auto-confirm: confirmed review with no reviewer, content pending, no re-trigger", () => {
    const fx = _setup({ sqlite });
    fx.seedNoShows(PRESCAN_REVIEW_CAP.MAX_NO_SHOWS);
    fx.prescanReviewTrigger.checkPending(ACTIVATION, 200);
    const tx = fx.submitted[0];
    fx.submitted.length = 0;

    const certTs = ACTIVATION + 60_000;
    fx.commit([tx], certTs);

    const review = fx.dag.getPrescanReview(tx.data.review_id);
    expect(review).toMatchObject({
      ctid: CTID, state: PRESCAN_REVIEW_STATES.CONFIRMED, assigned_reviewer: null,
      creator_tip_id: CREATOR, suggested_origin: PRESCAN_REVIEW_CAP.AUTO_SUGGESTED_ORIGIN,
      decision_note: PRESCAN_REVIEW_CAP.AUTO_DECISION_NOTE,
    });
    expect(review.confirmed_at_ms).toBe(certTs);
    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.PENDING_REVIEW);
    expect(fx.dag.getOpenPrescanReviewByCtid(CTID).review_id).toBe(tx.data.review_id);

    // The post is no longer a review candidate: the next tick assigns nobody.
    fx.prescanReviewTrigger.checkPending(certTs + 1000, 201);
    expect(fx.submitted.filter(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_TRIGGERED)).toEqual([]);
    expect(fx.submitted.filter(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_CONFIRMED)).toEqual([]);
  });

  test("the creator window then escalates to a dispute like a reviewer confirm would", () => {
    const fx = _setup({ sqlite });
    fx.seedNoShows(PRESCAN_REVIEW_CAP.MAX_NO_SHOWS);
    fx.prescanReviewTrigger.checkPending(ACTIVATION, 200);
    const confirmTx = fx.submitted[0];
    fx.submitted.length = 0;
    const certTs = ACTIVATION + 60_000;
    fx.commit([confirmTx], certTs);

    fx.prescanReviewTrigger.checkPending(certTs + REVIEWER.CREATOR_DECISION_WINDOW_MS + 1000, 300);
    const dispute = fx.submitted.find(t => t.tx_type === TX_TYPES.CONTENT_DISPUTED);
    expect(dispute).toBeDefined();
    expect(dispute.data).toMatchObject({
      auto: true, ctid: CTID, source_review_id: confirmTx.data.review_id,
      reason: "creator_decision_window_expired", suggested_origin: PRESCAN_REVIEW_CAP.AUTO_SUGGESTED_ORIGIN,
    });
  });

  test("commit rejects an auto-confirm before activation, below the cap, or while a review is open", () => {
    const fx = _setup({ sqlite });
    fx.seedNoShows(PRESCAN_REVIEW_CAP.MAX_NO_SHOWS);
    fx.prescanReviewTrigger.checkPending(ACTIVATION, 200);
    const tx = fx.submitted[0];
    fx.submitted.length = 0;

    // Before activation: a byzantine node emitting early is refused.
    let res = fx.commit([tx], ACTIVATION - 1);
    expect(fx.dag.getPrescanReview(tx.data.review_id)).toBeNull();
    expect(res && res.rejected ? res.rejected.length : 1).toBeGreaterThan(0);

    // Below the cap: same tx against a post with fewer no-shows.
    const fx2 = _setup({ sqlite });
    fx2.seedNoShows(PRESCAN_REVIEW_CAP.MAX_NO_SHOWS - 1);
    expect(confirmedSchema.verifyTx(tx, fx2.dag)).toMatchObject({ ok: false, code: "no_show_cap_not_reached" });

    // Open review: a reviewer is already assigned.
    const fx3 = _setup({ sqlite });
    fx3.seedNoShows(PRESCAN_REVIEW_CAP.MAX_NO_SHOWS);
    fx3.dag.savePrescanReview({
      review_id: "pr_open", ctid: CTID, creator_tip_id: CREATOR, assigned_reviewer: REVIEWER_1,
      triggered_at_round: 50, triggered_at_ms: ACTIVATION, state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });
    fx3.dag.updateContentStatus(CTID, CONTENT_STATUS.PENDING_REVIEW);
    expect(confirmedSchema.verifyTx(tx, fx3.dag)).toMatchObject({ ok: false, code: "content_not_reviewable" });
    fx3.dag.updateContentStatus(CTID, CONTENT_STATUS.REGISTERED);
    expect(confirmedSchema.verifyTx(tx, fx3.dag)).toMatchObject({ ok: false, code: "review_open" });
  });

  test("a reviewer-signed confirm is unaffected by the cap rules", () => {
    const fx = _setup({ sqlite });
    fx.dag.savePrescanReview({
      review_id: "pr_manual", ctid: CTID, creator_tip_id: CREATOR, assigned_reviewer: REVIEWER_1,
      triggered_at_round: 50, triggered_at_ms: ACTIVATION, state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });
    const tx = { tx_type: TX_TYPES.PRESCAN_REVIEW_CONFIRMED, data: { review_id: "pr_manual", reviewer_tip_id: REVIEWER_1, suggested_origin: "AG" } };
    expect(confirmedSchema.verifyTx(tx, fx.dag)).toEqual({ ok: true });
  });
});
