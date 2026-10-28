/**
 * @file tests/consensus/prescan-review-claim.test.js
 * @description Review desk: a roster member of the genesis organization with
 * role reviewer takes over an open review (PRESCAN_REVIEW_CLAIMED). The open
 * slot closes as claimed_over without a no-show, the claimer gets a fresh
 * triggered slot, and nobody can claim a post they signed or authored.
 * Epoch-gated with the no-show cap. Runs on the memory store and on SQLite.
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

const { initCrypto, generateMLDSAKeypair, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { getGenesisOrg } = require(path.join(SRC, "genesis"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createPrescanReviewTrigger, _deriveClaimReviewId } = require(path.join(SRC, "consensus", "prescan-review-trigger"));
const { createReviewService } = require(path.join(SRC, "services", "review-service"));
const { getReviewerNoShowCount } = require(path.join(SRC, "reviewer-selection"));
const claimedSchema = require(path.join(SRC, "schemas", "prescan-review-claimed"));
const dismissedSchema = require(path.join(SRC, "schemas", "prescan-review-dismissed"));
const {
  TX_TYPES, PRESCAN_REVIEW_STATES, CONTENT_STATUS, RECUSAL_REASONS, ORG_MEMBER_STATUS,
} = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { REVIEWER } = require(path.join(SHARED, "protocol-constants"));

beforeAll(async () => { await initCrypto(); });

const NODE_ID = "tip://node/n1";
const VP_ID = "tip://vp/v1";
const DESK_ORG = getGenesisOrg();
const OTHER_ORG = "tip://id/US-0000000000000aaa";
const CREATOR = "tip://id/US-cccccccccccccccc";
const VOLUNTEER = "tip://id/US-1111aaaa1111aaaa";
const DESK = "tip://id/US-2222bbbb2222bbbb";
const AUTHOR_MEMBER = "tip://id/US-3333cccc3333cccc";
const OTHER_REVIEWER = "tip://id/US-4444dddd4444dddd";
const CTID = "tip://c/OH-11111111111111-0001";
const ORG_CTID = "tip://c/OH-22222222222222-0002";
// In the past: tx timestamps after it must not be in the future at commit.
const ACTIVATION = 1_790_000_000_000;
const T0 = ACTIVATION - 30 * 24 * 3600 * 1000;
const REG = 1767225600000;
const OPEN_ID = "pr_open";

const tmpDirs = [];
afterAll(() => { for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true }); });

function _setup({ sqlite = false, activationMs = ACTIVATION, keys: sharedKeys = null } = {}) {
  let dbPath = ":memory:";
  if (sqlite) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-review-claim-"));
    tmpDirs.push(dir);
    dbPath = path.join(dir, "dag.db");
  }
  const dag = initDAG({ dbPath });
  const nodeKp = generateMLDSAKeypair();
  const keys = sharedKeys || {};

  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: REG });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: REG });
  function identity(tipId, { type = "personal", consent = false } = {}) {
    const kp = keys[tipId] || generateMLDSAKeypair();
    keys[tipId] = kp;
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: kp.publicKey, tip_id_type: type,
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", reviewer_consent: consent,
      registered_at: REG, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
    });
  }
  identity(DESK_ORG, { type: "organization" });
  identity(OTHER_ORG, { type: "organization" });
  identity(CREATOR);
  identity(VOLUNTEER, { consent: true });
  identity(DESK);
  identity(AUTHOR_MEMBER);
  identity(OTHER_REVIEWER);

  function member(org, tipId, role) {
    dag.saveOrgMember({
      invite_tx_id: shake256(`inv:${org}:${tipId}`), org_tip_id: org, member_tip_id: tipId, role,
      status: ORG_MEMBER_STATUS.ACTIVE, invited_at: REG, invited_claim: REG, accepted_at: REG,
      add_tx_id: shake256(`add:${org}:${tipId}`), removed_at: null, remove_tx_id: null, removed_by: null,
    });
  }
  member(DESK_ORG, DESK, "reviewer");
  member(DESK_ORG, AUTHOR_MEMBER, "author");
  member(OTHER_ORG, OTHER_REVIEWER, "reviewer");

  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, prescanReviewCapActivationMs: activationMs };
  const scoring = initScoring(dag, config);
  dag.setScore(VOLUNTEER, 900, 0, REG);

  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  const prescanReviewTrigger = createPrescanReviewTrigger({ dag, scoring, config, submitTx });
  const commitHandler = createCommitHandler({ dag, scoring, config, prescanReviewTrigger, nodeId: NODE_ID });
  const reviewService = createReviewService({ dag, scoring, submitTx, config });

  let round = 100;
  function commit(txs, certTimestamp) {
    round++;
    return { res: commitHandler.commitOrderedTxs(txs, round, { certTimestamp }), round };
  }

  function content(ctid, author, authors) {
    dag.saveContent({
      ctid, origin_code: "OH", content_hash: shake256(`h:${ctid}`),
      author_tip_id: author, signer_tip_id: author,
      authors: authors || [{ tip_id: author, key_mode: "attribution", role: "byline", signed: false, tip_id_type: "personal" }],
      attribution_mode: "self", extras: {}, cna_version: "CNA-2.2",
      status: CONTENT_STATUS.PENDING_REVIEW,
      prescan_flagged: true, prescan_probability: 0.99, prescan_tier: "critical",
      prescan_status: "completed", prescan_completed_at: T0, override: true,
      registered_at: T0, registered_urls: [], tx_id: shake256(`c:${ctid}`),
    });
  }
  function openReview(ctid, { reviewId = OPEN_ID, creator = CREATOR, reviewer = VOLUNTEER } = {}) {
    dag.savePrescanReview({
      review_id: reviewId, ctid, creator_tip_id: creator, assigned_reviewer: reviewer,
      triggered_at_round: 50, triggered_at_ms: ACTIVATION - 3600_000, state: PRESCAN_REVIEW_STATES.TRIGGERED,
    });
  }
  content(CTID, CREATOR);
  openReview(CTID);

  function claimTx(claimer, { reviewId = OPEN_ID, timestamp = ACTIVATION + 1000, extra = {} } = {}) {
    const fields = { review_id: reviewId, reviewer_tip_id: claimer };
    const signature = claimedSchema.sign(claimedSchema.buildSigningPayload(fields), keys[claimer].privateKey);
    const review = dag.getPrescanReview(reviewId);
    const tx = {
      tx_type: TX_TYPES.PRESCAN_REVIEW_CLAIMED, timestamp, prev: [],
      data: { ...fields, creator_tip_id: review.creator_tip_id, previous_reviewer_tip_id: review.assigned_reviewer, ...extra },
      signature,
    };
    tx.prev = dag.prevFor(tx.tx_type, tx.data);
    tx.tx_id = computeTxId(tx);
    return tx;
  }
  function pickupTx(claimer, ctid, { timestamp = ACTIVATION + 1000, extra = {} } = {}) {
    const fields = { ctid, reviewer_tip_id: claimer };
    const signature = claimedSchema.sign(claimedSchema.buildSigningPayload(fields), keys[claimer].privateKey);
    const tx = {
      tx_type: TX_TYPES.PRESCAN_REVIEW_CLAIMED, timestamp, prev: [],
      data: { ...fields, creator_tip_id: dag.getContent(ctid).author_tip_id, ...extra },
      signature,
    };
    tx.prev = dag.prevFor(tx.tx_type, tx.data);
    tx.tx_id = computeTxId(tx);
    return tx;
  }
  // A flagged post past the creator window that the empty pool never assigned.
  function waiting(ctid, author = CREATOR, { completedAt = T0, authors } = {}) {
    content(ctid, author, authors);
    dag.saveContent({ ...dag.getContent(ctid), status: CONTENT_STATUS.REGISTERED, prescan_completed_at: completedAt });
  }
  function dismissTx(reviewer, { reviewId = OPEN_ID, timestamp = ACTIVATION + 1000 } = {}) {
    const fields = { review_id: reviewId, reviewer_tip_id: reviewer, decision_note: null };
    const signature = dismissedSchema.sign(dismissedSchema.buildSigningPayload(fields), keys[reviewer].privateKey);
    const tx = { tx_type: TX_TYPES.PRESCAN_REVIEW_DISMISSED, timestamp, prev: [], data: { ...fields }, signature };
    tx.prev = dag.prevFor(tx.tx_type, tx.data);
    tx.tx_id = computeTxId(tx);
    return tx;
  }

  return { dag, commit, submitted, prescanReviewTrigger, reviewService, keys, content, openReview, claimTx, pickupTx, waiting, dismissTx };
}

describe.each([["memory", false], ["sqlite", true]])("review desk claim (%s store)", (_label, sqlite) => {

  test("a desk reviewer takes over: old slot claimed_over, claimer's slot opens at the cert time", () => {
    const fx = _setup({ sqlite });
    const certTs = ACTIVATION + 60_000;
    const { res, round } = fx.commit([fx.claimTx(DESK)], certTs);
    expect(res.committed).toBe(1);

    const old = fx.dag.getPrescanReview(OPEN_ID);
    expect(old).toMatchObject({ state: PRESCAN_REVIEW_STATES.CLAIMED_OVER, assigned_reviewer: VOLUNTEER, decided_at_round: round });
    const open = fx.dag.getOpenPrescanReviewByCtid(CTID);
    expect(open).toMatchObject({
      review_id: _deriveClaimReviewId(CTID, round), assigned_reviewer: DESK, creator_tip_id: CREATOR,
      state: PRESCAN_REVIEW_STATES.TRIGGERED, triggered_at_round: round,
    });
    expect(open.triggered_at_ms).toBe(certTs);
    expect(fx.dag.getContent(CTID).status).toBe(CONTENT_STATUS.PENDING_REVIEW);
  });

  test("the replaced reviewer gets no no-show and the trigger assigns nobody else", () => {
    const fx = _setup({ sqlite });
    const before = getReviewerNoShowCount(fx.dag, VOLUNTEER);
    const certTs = ACTIVATION + 60_000;
    fx.commit([fx.claimTx(DESK)], certTs);
    expect(getReviewerNoShowCount(fx.dag, VOLUNTEER)).toBe(before);
    fx.prescanReviewTrigger.checkPending(certTs + 1000, 500);
    expect(fx.submitted.filter(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_TRIGGERED)).toEqual([]);
  });

  test("the claimer's SLA runs from the claim, and a claimer no-show re-opens the post to the pool", () => {
    const fx = _setup({ sqlite });
    const certTs = ACTIVATION + 60_000;
    fx.commit([fx.claimTx(DESK)], certTs);
    expect(fx.dag.getReviewsNeedingAutoRecuse(certTs + REVIEWER.AUTO_RECUSE_AGE_MS - 1)).toEqual([]);
    expect(fx.dag.getReviewsNeedingAutoRecuse(certTs + REVIEWER.AUTO_RECUSE_AGE_MS).map(r => r.assigned_reviewer)).toEqual([DESK]);

    const recuseAt = certTs + REVIEWER.AUTO_RECUSE_AGE_MS;
    fx.prescanReviewTrigger.checkPending(recuseAt, 600);
    const recuse = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_RECUSED);
    expect(recuse.data).toMatchObject({ auto: true, reviewer_tip_id: DESK, recusal_reason: RECUSAL_REASONS.SLA_EXPIRED });
    fx.submitted.length = 0;
    fx.commit([recuse], recuseAt + 1000);

    // claimed_over must not block the next assignment.
    fx.prescanReviewTrigger.checkPending(recuseAt + 2000, 601);
    expect(fx.submitted.map(t => t.tx_type)).toContain(TX_TYPES.PRESCAN_REVIEW_TRIGGERED);
  });

  test("a claimed-over assignment neither counts as a no-show nor fills the no-show window", () => {
    const fx = _setup({ sqlite });
    for (let i = 0; i < REVIEWER.NOSHOW_SAMPLE_SIZE; i++) {
      fx.dag.savePrescanReview({
        review_id: `pr_claimed_${i}`, ctid: CTID, creator_tip_id: CREATOR, assigned_reviewer: VOLUNTEER,
        triggered_at_round: 10 + i, triggered_at_ms: T0 + i, decided_at_round: 11 + i, state: PRESCAN_REVIEW_STATES.CLAIMED_OVER,
      });
    }
    fx.dag.savePrescanReview({
      review_id: "pr_late_noshow", ctid: CTID, creator_tip_id: CREATOR, assigned_reviewer: VOLUNTEER,
      triggered_at_round: 5, triggered_at_ms: T0 - 1000, decided_at_round: 6,
      state: PRESCAN_REVIEW_STATES.RECUSED, decision_note: RECUSAL_REASONS.SLA_EXPIRED,
    });
    expect(getReviewerNoShowCount(fx.dag, VOLUNTEER)).toBe(1);
  });

  test("rejected before the activation", () => {
    const fx = _setup({ sqlite });
    const { res } = fx.commit([fx.claimTx(DESK, { timestamp: ACTIVATION - 5000 })], ACTIVATION - 1);
    expect(res.committed).toBe(0);
    expect(fx.dag.getPrescanReview(OPEN_ID).state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);
  });

  test("only the genesis org's reviewer role is the desk", () => {
    const fx = _setup({ sqlite });
    expect(claimedSchema.verifyTx(fx.claimTx(AUTHOR_MEMBER), fx.dag)).toMatchObject({ ok: false, code: "not_desk_member" });
    expect(claimedSchema.verifyTx(fx.claimTx(OTHER_REVIEWER), fx.dag)).toMatchObject({ ok: false, code: "not_desk_member" });
    expect(claimedSchema.verifyTx(fx.claimTx(CREATOR), fx.dag)).toMatchObject({ ok: false, code: "not_desk_member" });
    const { res } = fx.commit([fx.claimTx(OTHER_REVIEWER)], ACTIVATION + 60_000);
    expect(res.committed).toBe(0);
  });

  test("a removed desk member can no longer claim", () => {
    const fx = _setup({ sqlite });
    const row = fx.dag.getOrgMembersByOrg(DESK_ORG).find(r => r.member_tip_id === DESK);
    fx.dag.saveOrgMember({ ...row, status: ORG_MEMBER_STATUS.REMOVED, removed_at: REG + 1, remove_tx_id: shake256("rm"), removed_by: DESK_ORG });
    expect(claimedSchema.verifyTx(fx.claimTx(DESK), fx.dag)).toMatchObject({ ok: false, code: "not_desk_member" });
  });

  test("nobody claims a post they signed or are listed on as an author", () => {
    const fx = _setup({ sqlite });
    fx.content("tip://c/OH-33333333333333-0003", DESK);
    fx.openReview("tip://c/OH-33333333333333-0003", { reviewId: "pr_own", creator: DESK });
    expect(claimedSchema.verifyTx(fx.claimTx(DESK, { reviewId: "pr_own" }), fx.dag)).toMatchObject({ ok: false, code: "own_content" });

    fx.content("tip://c/OH-44444444444444-0004", CREATOR, [
      { tip_id: CREATOR, key_mode: "attribution", role: "byline", signed: false, tip_id_type: "personal" },
      { tip_id: DESK, key_mode: "attribution", role: "contributor", signed: false, tip_id_type: "personal" },
    ]);
    fx.openReview("tip://c/OH-44444444444444-0004", { reviewId: "pr_coauthor" });
    expect(claimedSchema.verifyTx(fx.claimTx(DESK, { reviewId: "pr_coauthor" }), fx.dag)).toMatchObject({ ok: false, code: "own_content" });
  });

  test("a desk reviewer may claim a post by the genesis org itself", () => {
    const fx = _setup({ sqlite });
    fx.content(ORG_CTID, DESK_ORG, [{ tip_id: DESK_ORG, key_mode: "attribution", role: "contributor", signed: false, tip_id_type: "organization" }]);
    fx.openReview(ORG_CTID, { reviewId: "pr_org", creator: DESK_ORG });
    const { res } = fx.commit([fx.claimTx(DESK, { reviewId: "pr_org" })], ACTIVATION + 60_000);
    expect(res.committed).toBe(1);
    expect(fx.dag.getOpenPrescanReviewByCtid(ORG_CTID).assigned_reviewer).toBe(DESK);
  });

  test("only an open triggered review can be claimed, and not by its own assignee", () => {
    const fx = _setup({ sqlite });
    fx.dag.savePrescanReview({ ...fx.dag.getPrescanReview(OPEN_ID), state: PRESCAN_REVIEW_STATES.CONFIRMED, confirmed_at_ms: ACTIVATION });
    expect(claimedSchema.verifyTx(fx.claimTx(DESK), fx.dag)).toMatchObject({ ok: false, code: "review_state_invalid" });

    const fx2 = _setup({ sqlite });
    fx2.openReview(CTID, { reviewId: "pr_mine", reviewer: DESK });
    expect(claimedSchema.verifyTx(fx2.claimTx(DESK, { reviewId: "pr_mine" }), fx2.dag)).toMatchObject({ ok: false, code: "already_assigned" });
  });

  test("context fields must name the claimed review", () => {
    const fx = _setup({ sqlite });
    const tx = fx.claimTx(DESK, { extra: { previous_reviewer_tip_id: OTHER_REVIEWER } });
    expect(claimedSchema.verifyTx(tx, fx.dag)).toMatchObject({ ok: false, code: "claim_context_mismatch" });
  });

  test("a claim and the assignee's decision in one batch: the first wins", () => {
    const fx = _setup({ sqlite });
    const { res } = fx.commit([fx.dismissTx(VOLUNTEER), fx.claimTx(DESK)], ACTIVATION + 60_000);
    expect(res.committed).toBe(1);
    expect(fx.dag.getPrescanReview(OPEN_ID).state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);
    expect(fx.dag.getOpenPrescanReviewByCtid(CTID)).toBeNull();
  });

  test("pickup: a desk reviewer takes a flagged post the empty pool never assigned", () => {
    const fx = _setup({ sqlite });
    const W = "tip://c/OH-55555555555555-0005";
    fx.waiting(W);
    const certTs = ACTIVATION + 60_000;
    const { res, round } = fx.commit([fx.pickupTx(DESK, W)], certTs);
    expect(res.committed).toBe(1);
    const open = fx.dag.getOpenPrescanReviewByCtid(W);
    expect(open).toMatchObject({
      review_id: _deriveClaimReviewId(W, round), assigned_reviewer: DESK, creator_tip_id: CREATOR,
      state: PRESCAN_REVIEW_STATES.TRIGGERED, triggered_at_round: round,
    });
    expect(open.triggered_at_ms).toBe(certTs);
    expect(fx.dag.getContent(W).status).toBe(CONTENT_STATUS.PENDING_REVIEW);
    // The automatic trigger leaves it alone now.
    fx.prescanReviewTrigger.checkPending(certTs + 1000, 900);
    expect(fx.submitted.filter(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_TRIGGERED && t.data.ctid === W)).toEqual([]);
  });

  test("pickup follows the trigger's rule: not inside the creator window, not unflagged, not already in review", () => {
    const fx = _setup({ sqlite });
    const certTs = ACTIVATION + 60_000;
    const fresh = "tip://c/OH-66666666666666-0006";
    fx.waiting(fresh, CREATOR, { completedAt: certTs - 1000 });
    expect(claimedSchema.verifyTx(fx.pickupTx(DESK, fresh), fx.dag, { nowMs: certTs })).toMatchObject({ ok: false, code: "not_waiting_for_review" });

    const low = "tip://c/OH-77777777777777-0007";
    fx.waiting(low);
    fx.dag.saveContent({ ...fx.dag.getContent(low), prescan_tier: "low" });
    expect(claimedSchema.verifyTx(fx.pickupTx(DESK, low), fx.dag, { nowMs: certTs })).toMatchObject({ ok: false, code: "not_waiting_for_review" });

    // CTID already has an open review: take it over by review_id instead.
    expect(claimedSchema.verifyTx(fx.pickupTx(DESK, CTID), fx.dag, { nowMs: certTs })).toMatchObject({ ok: false, code: "not_waiting_for_review" });
  });

  test("pickup keeps the desk-only and own-post rules", () => {
    const fx = _setup({ sqlite });
    const certTs = ACTIVATION + 60_000;
    const W = "tip://c/OH-88888888888888-0008";
    fx.waiting(W);
    expect(claimedSchema.verifyTx(fx.pickupTx(OTHER_REVIEWER, W), fx.dag, { nowMs: certTs })).toMatchObject({ ok: false, code: "not_desk_member" });
    const mine = "tip://c/OH-99999999999999-0009";
    fx.waiting(mine, DESK);
    expect(claimedSchema.verifyTx(fx.pickupTx(DESK, mine), fx.dag, { nowMs: certTs })).toMatchObject({ ok: false, code: "own_content" });
    const org = "tip://c/OH-aaaaaaaaaaaaaa-000a";
    fx.waiting(org, DESK_ORG, { authors: [{ tip_id: DESK_ORG, key_mode: "attribution", role: "contributor", signed: false, tip_id_type: "organization" }] });
    expect(claimedSchema.verifyTx(fx.pickupTx(DESK, org), fx.dag, { nowMs: certTs })).toEqual({ ok: true });
  });

  test("pickup is rejected before the activation and names exactly one target", () => {
    const fx = _setup({ sqlite });
    const W = "tip://c/OH-bbbbbbbbbbbbbb-000b";
    fx.waiting(W);
    const { res } = fx.commit([fx.pickupTx(DESK, W, { timestamp: ACTIVATION - 5000 })], ACTIVATION - 1);
    expect(res.committed).toBe(0);
    expect(fx.dag.getContent(W).status).toBe(CONTENT_STATUS.REGISTERED);
    expect(() => claimedSchema.buildSigningPayload({ ctid: W, review_id: OPEN_ID, reviewer_tip_id: DESK })).toThrow(expect.objectContaining({ code: "claim_target_invalid" }));
    expect(claimedSchema.verifyTx(fx.pickupTx(DESK, W, { extra: { creator_tip_id: OTHER_ORG } }), fx.dag, { nowMs: ACTIVATION + 60_000 })).toMatchObject({ ok: false, code: "claim_context_mismatch" });
  });

  test("two desk pickups of one post in a batch: the first wins", () => {
    const fx = _setup({ sqlite });
    const second = "tip://id/US-5555eeee5555eeee";
    const W = "tip://c/OH-cccccccccccccc-000c";
    fx.waiting(W);
    fx.dag.saveIdentity({ ...fx.dag.getIdentity(DESK), tip_id: second, public_key: fx.keys[DESK].publicKey, root_public_key: fx.keys[DESK].publicKey, tx_id: shake256("second") });
    fx.keys[second] = fx.keys[DESK];
    fx.dag.saveOrgMember({
      invite_tx_id: shake256("inv2"), org_tip_id: DESK_ORG, member_tip_id: second, role: "reviewer",
      status: ORG_MEMBER_STATUS.ACTIVE, invited_at: REG, invited_claim: REG, accepted_at: REG,
      add_tx_id: shake256("add2"), removed_at: null, remove_tx_id: null, removed_by: null,
    });
    const { res } = fx.commit([fx.pickupTx(DESK, W), fx.pickupTx(second, W)], ACTIVATION + 60_000);
    expect(res.committed).toBe(1);
    expect(fx.dag.getOpenPrescanReviewByCtid(W).assigned_reviewer).toBe(DESK);
  });

  test("replaying the same claim leaves identical state", () => {
    const a = _setup({ sqlite });
    const b = _setup({ sqlite, keys: a.keys });
    const tx = a.claimTx(DESK);
    a.commit([tx], ACTIVATION + 60_000);
    b.commit([{ ...tx, data: { ...tx.data } }], ACTIVATION + 60_000);
    const strip = rs => rs.map(r => ({ ...r })).sort((x, y) => (x.review_id < y.review_id ? -1 : 1));
    expect(strip(b.dag.getPrescanReviewsByCtid(CTID))).toEqual(strip(a.dag.getPrescanReviewsByCtid(CTID)));
  });
});

describe("review desk API", () => {
  beforeEach(() => { jest.useFakeTimers({ doNotFake: ["nextTick", "setImmediate"] }); });
  afterEach(() => { jest.useRealTimers(); });

  test("claim builds a valid tx once active and refuses before", () => {
    const fx = _setup();
    const fields = { review_id: OPEN_ID, reviewer_tip_id: DESK };
    const signature = claimedSchema.sign(claimedSchema.buildSigningPayload(fields), fx.keys[DESK].privateKey);

    jest.setSystemTime(ACTIVATION - 1000);
    expect(() => fx.reviewService.claim(OPEN_ID, { ...fields, signature })).toThrow(expect.objectContaining({ code: "review_desk_inactive" }));

    jest.setSystemTime(ACTIVATION + 1000);
    const out = fx.reviewService.claim(OPEN_ID, { ...fields, signature });
    expect(out).toMatchObject({ review_id: OPEN_ID, confirmation: "proposed" });
    const tx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_CLAIMED);
    expect(tx.data).toMatchObject({ review_id: OPEN_ID, reviewer_tip_id: DESK, creator_tip_id: CREATOR, previous_reviewer_tip_id: VOLUNTEER });
    expect(tx.data.ctid).toBeUndefined();
    expect(claimedSchema.verifyTx(tx, fx.dag)).toEqual({ ok: true });
  });

  test("claim refuses a bad signature", () => {
    const fx = _setup();
    jest.setSystemTime(ACTIVATION + 1000);
    const fields = { review_id: OPEN_ID, reviewer_tip_id: DESK };
    const signature = claimedSchema.sign(claimedSchema.buildSigningPayload(fields), fx.keys[CREATOR].privateKey);
    expect(() => fx.reviewService.claim(OPEN_ID, { ...fields, signature })).toThrow(expect.objectContaining({ code: "signature_invalid" }));
  });

  test("pickup through the API, and waiting posts in the open list", () => {
    const fx = _setup();
    const W = "tip://c/OH-dddddddddddddd-000d";
    fx.waiting(W);
    jest.setSystemTime(ACTIVATION + 1000);
    const list = fx.reviewService.listOpenReviews({ reviewer_tip_id: DESK });
    expect(list.waiting_for_reviewer.find(r => r.ctid === W)).toMatchObject({ review_id: null, assigned_reviewer: null, claimable: true, not_claimable_reason: null });

    const fields = { ctid: W, reviewer_tip_id: DESK };
    const signature = claimedSchema.sign(claimedSchema.buildSigningPayload(fields), fx.keys[DESK].privateKey);
    const out = fx.reviewService.claim(null, { ...fields, signature });
    expect(out).toMatchObject({ review_id: null, ctid: W, confirmation: "proposed" });
    const tx = fx.submitted.find(t => t.tx_type === TX_TYPES.PRESCAN_REVIEW_CLAIMED);
    expect(tx.data).toEqual({ ctid: W, reviewer_tip_id: DESK, creator_tip_id: CREATOR });
    expect(claimedSchema.verifyTx(tx, fx.dag, { nowMs: ACTIVATION + 1000 })).toEqual({ ok: true });
  });

  test("open list shows idle time and, per person, what they may claim", () => {
    const fx = _setup();
    fx.content(ORG_CTID, DESK_ORG, [{ tip_id: DESK_ORG, key_mode: "attribution", role: "contributor", signed: false, tip_id_type: "organization" }]);
    fx.openReview(ORG_CTID, { reviewId: "pr_org", creator: DESK_ORG, reviewer: DESK });
    jest.setSystemTime(ACTIVATION + 1000);

    const all = fx.reviewService.listOpenReviews({});
    expect(all).toMatchObject({ desk_active: true, count: 2 });
    expect(all.reviews.find(r => r.review_id === OPEN_ID)).toMatchObject({ ctid: CTID, prescan_tier: "critical", assigned_reviewer: VOLUNTEER, idle_ms: 3600_000 + 1000 });
    expect(all.reviews[0].claimable).toBeUndefined();

    const mine = fx.reviewService.listOpenReviews({ reviewer_tip_id: DESK });
    expect(mine.reviews.find(r => r.review_id === OPEN_ID)).toMatchObject({ claimable: true, not_claimable_reason: null });
    expect(mine.reviews.find(r => r.review_id === "pr_org")).toMatchObject({ claimable: false, not_claimable_reason: "already_assigned" });

    const outsider = fx.reviewService.listOpenReviews({ reviewer_tip_id: OTHER_REVIEWER });
    expect(outsider.reviews.every(r => r.claimable === false && r.not_claimable_reason === "not_desk_member")).toBe(true);
  });
});
