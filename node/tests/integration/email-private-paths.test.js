/**
 * @file tests/integration/email-private-paths.test.js
 * @description Every path that can act on a content record, run on an email
 * record and on an ordinary post side by side. Each goes through the API
 * service and through consensus (a tx sent straight to commit), after the
 * activation, before it, and backdated across it. Only the email is refused;
 * the post behaves as it always did.
 *
 *   links      update registered URLs
 *   verify     CONTENT_VERIFIED
 *   dispute    user-filed, node-filed (auto-escalation, creator fast-forward)
 *   review     flagged verdict, trigger, desk list, desk claim, confirm
 *   allowed    origin change, retract, dismiss of a review already running
 *
 * Registration itself (links, hash-only, credit) is in email-private-record.test.js.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");
const { nowMs } = require(path.join(SHARED, "time"));

// Activation an hour ago, read once at module load: real time is after it, and
// "before" is a past time, so no tx is ever stamped in the future.
const GATE = nowMs() - 60 * 60 * 1000;
const BEFORE = GATE - 10 * 60 * 1000;
const T0 = GATE - 60 * 86400000;
const _envBefore = { TIP_EMAIL_PRIVATE_ACTIVATION_MS: process.env.TIP_EMAIL_PRIVATE_ACTIVATION_MS };
process.env.TIP_EMAIL_PRIVATE_ACTIVATION_MS = String(GATE);

const { initCrypto, generateMLDSAKeypair, shake256, computeTxId, signBody, signTransaction } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, CONTENT_STATUS, PRESCAN_REVIEW_STATES, ORG_MEMBER_STATUS, DISPUTE_REASON } = require(path.join(SHARED, "constants"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { getGenesisOrg } = require(path.join(SRC, "genesis"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const { createPrescanReviewTrigger } = require(path.join(SRC, "consensus", "prescan-review-trigger"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { createDisputeService } = require(path.join(SRC, "services", "dispute-service"));
const { createReviewService } = require(path.join(SRC, "services", "review-service"));
const { createPrescanJobs } = require(path.join(SRC, "services", "prescan-jobs"));
const { createPrescanWorker } = require(path.join(SRC, "workers", "prescan-worker"));
const { TX_SIGNATURE_REGISTRY } = require(path.join(SRC, "schemas", "_registry"));
const claimedSchema = require(path.join(SRC, "schemas", "prescan-review-claimed"));
const confirmedSchema = require(path.join(SRC, "schemas", "prescan-review-confirmed"));
const dismissedSchema = require(path.join(SRC, "schemas", "prescan-review-dismissed"));
const rules = require(path.join(SRC, "validators", "business-rules"));
const contentSchema = require(path.join(SRC, "schemas", "content-register"));

const NODE_ID = "tip://node/n_paths";
const VP_ID = "tip://vp/v1";
const DESK_ORG = getGenesisOrg();
const CREATOR = "tip://id/US-c1c1c1c1c1c1c1c1";
const OTHER = "tip://id/US-d2d2d2d2d2d2d2d2";
const VOLUNTEER = "tip://id/US-e3e3e3e3e3e3e3e3";
const DESK = "tip://id/US-f4f4f4f4f4f4f4f4";
const REG = 1767225600000;

beforeAll(async () => { await initCrypto(); });
afterAll(() => {
  for (const [k, v] of Object.entries(_envBefore)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

// Runs fn with the API clock at `ms`.
function at(ms, fn) {
  const spy = jest.spyOn(Date, "now").mockReturnValue(ms);
  try { return fn(); } finally { spy.mockRestore(); }
}

async function atAsync(ms, fn) {
  const spy = jest.spyOn(Date, "now").mockReturnValue(ms);
  try { return await fn(); } finally { spy.mockRestore(); }
}

// One URL and one review id per record: a URL binds to one record only.
const urlFor = (ctid) => `https://example.com/p/${shake256(ctid).slice(0, 12)}`;
const reviewIdFor = (ctid) => `pr_${shake256(ctid).slice(0, 16)}`;

function retime(tx, timestamp) {
  const out = { ...tx, timestamp };
  delete out.tx_id;
  out.tx_id = computeTxId(out);
  return out;
}

function setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  const keys = {};
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: REG });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: REG });
  for (const [tipId, type, consent] of [[DESK_ORG, "organization", false], [CREATOR, "personal", false], [OTHER, "personal", false], [VOLUNTEER, "personal", true], [DESK, "personal", false]]) {
    keys[tipId] = generateMLDSAKeypair();
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: keys[tipId].publicKey, root_public_key: keys[tipId].publicKey, tip_id_type: type,
      vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active", reviewer_consent: consent,
      registered_at: REG, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
    });
  }
  dag.saveOrgMember({
    invite_tx_id: shake256(`inv:${DESK}`), org_tip_id: DESK_ORG, member_tip_id: DESK, role: "reviewer",
    status: ORG_MEMBER_STATUS.ACTIVE, invited_at: REG, invited_claim: REG, accepted_at: REG,
    add_tx_id: shake256(`add:${DESK}`), removed_at: null, remove_tx_id: null, removed_by: null,
  });
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey, prescanReviewCapActivationMs: T0 };
  const scoring = initScoring(dag, config);
  for (const tipId of [CREATOR, OTHER, VOLUNTEER, DESK]) dag.setScore(tipId, 900, 0, REG);

  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); };
  const submitBatch = (txs) => { submitted.push(...txs); };
  const trigger = createPrescanReviewTrigger({ dag, scoring, config, submitTx });
  const commitHandler = createCommitHandler({ dag, scoring, config, prescanReviewTrigger: trigger, nodeId: NODE_ID });
  const contentService = createContentService({ dag, scoring, config, submitTx });
  const disputeDetailsService = {
    persistEvidence: ({ payload }) => ({ evidence_hash: payload.hash, idempotent: false }),
    discardEvidence: jest.fn(),
  };
  const disputeService = createDisputeService({ dag, scoring, config, submitTx, submitBatch, disputeDetailsService });
  const reviewService = createReviewService({ dag, scoring, submitTx, submitBatch, config });
  const prescanJobs = createPrescanJobs({ dag, now: nowMs });
  const classifier = {
    prescan: jest.fn(async () => ({
      flagged: true, probability: 0.97, modalities_analyzed: ["text"],
      modality_results: [{ modality: "text", probability: 0.97, weight: 1, provider: "ensemble", features_used: [], reasoning: null, processing_ms: 1, error: null }],
      provider_used: "ensemble", classifier_version: "2.0.0", processing_ms: 1, note: null,
    })),
    stage1: async () => ({}), providers: async () => ({}), health: async () => ({}),
  };
  const worker = createPrescanWorker({
    dag, jobs: prescanJobs, classifierClient: classifier, submitTx, config,
    log: { info: () => {}, warn: () => {}, error: () => {} }, now: nowMs,
  });

  let round = 1000;
  // Committed count for one tx, judged at `cert`.
  const commits = (tx, cert = nowMs()) => commitHandler.commitOrderedTxs([tx], ++round, { certTimestamp: cert }).committed;

  let n = 0;
  // An email record and an ordinary post, identical but for the marker.
  function pair({ flagged = false, status = CONTENT_STATUS.REGISTERED, prescan = "completed", registeredAt = T0 } = {}) {
    n += 1;
    const out = {};
    for (const [kind, extras] of [["email", { email: { v: 1 } }], ["post", {}]]) {
      const ctid = `tip://c/OH-${kind === "email" ? "e" : "a"}${String(n).padStart(13, "0")}-0001`;
      dag.saveContent({
        ctid, origin_code: "OH", content_hash: shake256(`h:${ctid}`), author_tip_id: CREATOR, signer_tip_id: CREATOR,
        authors: [{ tip_id: CREATOR, key_mode: "attribution", role: "byline", signed: false, tip_id_type: "personal" }],
        attribution_mode: "self", extras, cna_version: "CNA-2.2", status,
        prescan_flagged: flagged, prescan_probability: flagged ? 0.99 : 0.5, prescan_tier: flagged ? "critical" : "low",
        prescan_status: prescan, prescan_completed_at: prescan === "completed" ? registeredAt : null, override: false,
        registered_at: registeredAt, registered_urls: [], tx_id: shake256(`c:${ctid}`),
      });
      out[kind] = ctid;
    }
    return out;
  }

  const sign = (fields, tipId) => signBody(fields, keys[tipId].privateKey);
  const bodies = {
    urls: (ctid) => ({ author_tip_id: CREATOR, registered_urls: [urlFor(ctid)], signature: sign({ author_tip_id: CREATOR, ctid, registered_urls: [urlFor(ctid)] }, CREATOR) }),
    verify: (ctid) => ({ verifier_tip_id: OTHER, verdict: "ORIGIN_CONFIRMED", signature: sign({ verifier_tip_id: OTHER, ctid, verdict: "ORIGIN_CONFIRMED" }, OTHER) }),
    dispute: (ctid) => {
      const fields = { disputer_tip_id: OTHER, reason: DISPUTE_REASON.ORIGIN_MISMATCH, ctid, claimed_origin: "AG", evidence_hash: shake256(`ev:${ctid}`) };
      const contract = TX_SIGNATURE_REGISTRY[TX_TYPES.CONTENT_DISPUTED].getSignatureContract({ data: fields });
      return { ...fields, evidence: { payload: { hash: fields.evidence_hash }, signature: "00" }, signature: sign(contract.buildSigningPayload(fields), OTHER) };
    },
    pickup: (ctid) => {
      const fields = { ctid, reviewer_tip_id: DESK };
      return { ...fields, signature: claimedSchema.sign(claimedSchema.buildSigningPayload(fields), keys[DESK].privateKey) };
    },
    confirm: (reviewId) => {
      const fields = { review_id: reviewId, reviewer_tip_id: VOLUNTEER, suggested_origin: "AG", decision_note: null };
      return { ...fields, signature: confirmedSchema.sign(confirmedSchema.buildSigningPayload(fields), keys[VOLUNTEER].privateKey) };
    },
    escalate: (reviewId, ctid) => ({ author_tip_id: CREATOR, ctid, signature: sign({ author_tip_id: CREATOR, ctid, review_id: reviewId }, CREATOR) }),
  };

  function review(ctid, { state = PRESCAN_REVIEW_STATES.TRIGGERED, confirmedAt = null } = {}) {
    const reviewId = reviewIdFor(ctid);
    dag.savePrescanReview({
      review_id: reviewId, ctid, creator_tip_id: CREATOR, assigned_reviewer: VOLUNTEER,
      triggered_at_round: 1, triggered_at_ms: nowMs() - 1000, state,
      ...(confirmedAt ? { confirmed_at_ms: confirmedAt, suggested_origin: "AG", decided_at_round: 2 } : {}),
    });
    dag.saveContent({ ...dag.getContent(ctid), status: CONTENT_STATUS.PENDING_REVIEW });
    return reviewId;
  }

  function nodeTx(tx_type, data, timestamp = nowMs()) {
    const body = { tx_type, timestamp, data: { ...data, node_id: NODE_ID } };
    body.tx_id = computeTxId(body);
    return signTransaction(body, nodeKp.privateKey);
  }

  // A REGISTER_CONTENT built by hand and sent straight to consensus, past every API check.
  function registerTx({ extras, tag, timestamp }) {
    const data = {
      ctid: `tip://c/OH-${shake256(tag).slice(0, 14)}-0009`, origin_code: "OH", content_hash: shake256(tag),
      signer_tip_id: CREATOR, registered_urls: [urlFor(tag)], attribution_mode: "self", extras,
      authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: CREATOR, tip_id_type: "personal" }],
      cna_version: contentSchema.CURRENT_CNA_VERSION,
    };
    data.signature = contentSchema.sign(contentSchema.buildSigningPayload(data, data.content_hash), keys[CREATOR].privateKey);
    const tx = { tx_type: TX_TYPES.REGISTER_CONTENT, timestamp, prev: dag.getRecentPrev(), data, signature: data.signature };
    tx.tx_id = computeTxId(tx);
    return tx;
  }

  function dismissTx(reviewId) {
    const fields = { review_id: reviewId, reviewer_tip_id: VOLUNTEER, decision_note: null };
    const tx = { tx_type: TX_TYPES.PRESCAN_REVIEW_DISMISSED, timestamp: nowMs(), prev: [], data: { ...fields }, signature: dismissedSchema.sign(dismissedSchema.buildSigningPayload(fields), keys[VOLUNTEER].privateKey) };
    tx.prev = dag.prevFor(tx.tx_type, tx.data);
    tx.tx_id = computeTxId(tx);
    return tx;
  }

  const last = (type) => submitted.filter((t) => t.tx_type === type).pop();
  return { dag, keys, commits, pair, bodies, review, nodeTx, registerTx, dismissTx, submitted, last, contentService, disputeService, reviewService, trigger, prescanJobs, worker, classifier };
}

// The API refusal, as the HTTP layer sees it.
function refusal(fn) {
  try { fn(); } catch (e) { return e.code || e.error || e.message; }
  return null;
}

describe("links: a registration that carries them", () => {
  test("commit: an email with links stamped before the activation but certified after is dropped; certified before, it commits; a post always commits", () => {
    const fx = setup();
    expect(fx.commits(fx.registerTx({ extras: { email: { v: 1 } }, tag: "backdated-email", timestamp: BEFORE }))).toBe(0);
    expect(fx.commits(fx.registerTx({ extras: { email: { v: 1 } }, tag: "old-email", timestamp: BEFORE }), BEFORE + 1000)).toBe(1);
    expect(fx.commits(fx.registerTx({ extras: {}, tag: "post", timestamp: BEFORE }))).toBe(1);
  });
});

describe("links: update registered URLs", () => {
  test("API: refused for the email, the post's URLs update", () => {
    const fx = setup();
    const { email, post } = fx.pair();
    expect(refusal(() => fx.contentService.updateRegisteredUrls(email, fx.bodies.urls(email)))).toBe("email_no_links");
    expect(refusal(() => fx.contentService.updateRegisteredUrls(post, fx.bodies.urls(post)))).toBeNull();
    expect(fx.last(TX_TYPES.UPDATE_REGISTERED_URLS).data.ctid).toBe(post);
  });

  test("commit: dropped for the email (also backdated), committed for the post and before the activation", () => {
    const fx = setup();
    const { email, post } = fx.pair();
    const tx = at(BEFORE, () => { fx.contentService.updateRegisteredUrls(email, fx.bodies.urls(email)); return fx.last(TX_TYPES.UPDATE_REGISTERED_URLS); });
    expect(fx.commits(retime(tx, nowMs()))).toBe(0);
    expect(fx.commits(tx)).toBe(0); // stamped before the activation, certified after
    expect(fx.dag.getContent(email).registered_urls).toEqual([]);
    expect(fx.commits(tx, BEFORE + 1000)).toBe(1); // older nodes agree: no fork
    fx.contentService.updateRegisteredUrls(post, fx.bodies.urls(post));
    expect(fx.commits(fx.last(TX_TYPES.UPDATE_REGISTERED_URLS))).toBe(1);
    expect(fx.dag.getContent(post).registered_urls).toEqual([urlFor(post)]);
  });
});

describe("verify", () => {
  test("API: refused for the email, the post is verified", () => {
    const fx = setup();
    const { email, post } = fx.pair();
    expect(refusal(() => fx.contentService.verify(email, fx.bodies.verify(email)))).toBe("email_not_verifiable");
    expect(refusal(() => fx.contentService.verify(post, fx.bodies.verify(post)))).toBeNull();
    expect(fx.last(TX_TYPES.CONTENT_VERIFIED).data.ctid).toBe(post);
  });

  test("commit: dropped for the email (also backdated), committed for the post and before the activation", () => {
    const fx = setup();
    const { email, post } = fx.pair();
    const tx = at(BEFORE, () => { fx.contentService.verify(email, fx.bodies.verify(email)); return fx.last(TX_TYPES.CONTENT_VERIFIED); });
    expect(fx.commits(retime(tx, nowMs()))).toBe(0);
    expect(fx.commits(tx)).toBe(0);
    expect(fx.commits(tx, BEFORE + 1000)).toBe(1);
    fx.contentService.verify(post, fx.bodies.verify(post));
    expect(fx.commits(fx.last(TX_TYPES.CONTENT_VERIFIED))).toBe(1);
  });
});

describe("dispute filed by a person", () => {
  test("API: refused for the email before anything is kept, the post's dispute is filed", () => {
    const fx = setup();
    const { email, post } = fx.pair();
    expect(refusal(() => fx.disputeService.fileDispute(email, fx.bodies.dispute(email)))).toBe("email_not_disputable");
    expect(fx.submitted.filter((t) => t.tx_type === TX_TYPES.CONTENT_DISPUTED)).toHaveLength(0);
    expect(refusal(() => fx.disputeService.fileDispute(post, fx.bodies.dispute(post)))).toBeNull();
    expect(fx.last(TX_TYPES.CONTENT_DISPUTED).data.ctid).toBe(post);
  });

  test("commit: dropped for the email (also backdated), committed for the post and before the activation", () => {
    const fx = setup();
    const { email, post } = fx.pair();
    const tx = at(BEFORE, () => { fx.disputeService.fileDispute(email, fx.bodies.dispute(email)); return fx.last(TX_TYPES.CONTENT_DISPUTED); });
    expect(fx.commits(retime(tx, nowMs()))).toBe(0);
    expect(fx.commits(tx)).toBe(0);
    expect(fx.dag.getContent(email).status).toBe(CONTENT_STATUS.REGISTERED);
    expect(fx.commits(tx, BEFORE + 1000)).toBe(1);
    fx.disputeService.fileDispute(post, fx.bodies.dispute(post));
    expect(fx.commits(fx.last(TX_TYPES.CONTENT_DISPUTED))).toBe(1);
    expect(fx.dag.getContent(post).status).toBe(CONTENT_STATUS.DISPUTED);
  });
});

describe("dispute filed by a node", () => {
  const autoDispute = (fx, ctid, timestamp) => fx.nodeTx(TX_TYPES.CONTENT_DISPUTED, {
    ctid, reason: "creator_decision_window_expired", auto: true, source_review_id: null, author_tip_id: CREATOR, suggested_origin: "AG",
  }, timestamp);

  test("commit: an auto dispute is dropped for the email (also backdated), committed for the post and before the activation", () => {
    const fx = setup();
    const { email, post } = fx.pair();
    expect(fx.commits(autoDispute(fx, email))).toBe(0);
    expect(fx.commits(autoDispute(fx, email, BEFORE))).toBe(0);
    expect(fx.commits(autoDispute(fx, post))).toBe(1);
    const old = setup();
    const p = old.pair();
    expect(old.commits(autoDispute(old, p.email, BEFORE), BEFORE + 1000)).toBe(1);
  });

  test("the review trigger never auto-escalates the email; it still escalates the post", () => {
    const fx = setup();
    const { email, post } = fx.pair({ flagged: true });
    const expired = nowMs() - 3 * 86400000;
    fx.review(email, { state: PRESCAN_REVIEW_STATES.CONFIRMED, confirmedAt: expired });
    fx.review(post, { state: PRESCAN_REVIEW_STATES.CONFIRMED, confirmedAt: expired });
    fx.trigger.checkPending(nowMs(), 5000);
    const disputes = fx.submitted.filter((t) => t.tx_type === TX_TYPES.CONTENT_DISPUTED).map((t) => t.data.ctid);
    expect(disputes).toEqual([post]);
  });

  test("API: the creator cannot fast-forward a review of the email to a dispute; the post's creator can", () => {
    const fx = setup();
    const { email, post } = fx.pair({ flagged: true });
    const er = fx.review(email, { state: PRESCAN_REVIEW_STATES.CONFIRMED, confirmedAt: nowMs() - 1000 });
    const pr = fx.review(post, { state: PRESCAN_REVIEW_STATES.CONFIRMED, confirmedAt: nowMs() - 1000 });
    expect(refusal(() => fx.reviewService.dispute(er, fx.bodies.escalate(er, email)))).toBe("email_not_disputable");
    expect(refusal(() => fx.reviewService.dispute(pr, fx.bodies.escalate(pr, post)))).toBeNull();
    expect(fx.last(TX_TYPES.CONTENT_DISPUTED).data).toMatchObject({ ctid: post, auto: true });
  });
});

describe("review", () => {
  test("a flagged verdict (an older node that still classified the email) is dropped; the email's skipped verdict and the post's flag commit", async () => {
    const fx = setup();
    const { email, post } = fx.pair({ prescan: "pending" });
    const job = (ctid, extra = {}) => fx.prescanJobs.enqueue({ ctid, payload: { text: "the words", origin_code: "OH", signer_tip_id: CREATOR, content_type: "text", ...extra } });
    job(email);
    await fx.worker.tick();
    const flaggedEmail = fx.last(TX_TYPES.PRESCAN_COMPLETED);
    expect(flaggedEmail.data).toMatchObject({ ctid: email, flagged: true });
    expect(fx.commits(flaggedEmail)).toBe(0);
    expect(fx.dag.getContent(email).prescan_status).toBe("pending");

    const again = setup();
    const p = again.pair({ prescan: "pending" });
    again.prescanJobs.enqueue({ ctid: p.email, payload: { text: "", email: true, origin_code: "OH", signer_tip_id: CREATOR, content_type: "text" } });
    await again.worker.tick();
    expect(again.commits(again.last(TX_TYPES.PRESCAN_COMPLETED))).toBe(1);
    expect(again.dag.getContent(p.email).prescan_status).toBe("completed");
    expect(!!again.dag.getContent(p.email).prescan_flagged).toBe(false);

    job(post);
    await fx.worker.tick();
    expect(fx.commits(fx.last(TX_TYPES.PRESCAN_COMPLETED))).toBe(1);
    expect(!!fx.dag.getContent(post).prescan_flagged).toBe(true);
  });

  test("before the activation a flagged email verdict still commits (no fork)", async () => {
    const fx = setup();
    const { email } = fx.pair({ prescan: "pending" });
    fx.prescanJobs.enqueue({ ctid: email, payload: { text: "the words", origin_code: "OH", signer_tip_id: CREATOR, content_type: "text" } });
    await atAsync(BEFORE, () => fx.worker.tick());
    const tx = fx.last(TX_TYPES.PRESCAN_COMPLETED);
    expect(tx.data).toMatchObject({ ctid: email, flagged: true });
    expect(fx.commits(tx, BEFORE + 1000)).toBe(1);
  });

  test("the trigger never opens a review of a flagged email; it opens the post's", () => {
    const fx = setup();
    const { email, post } = fx.pair({ flagged: true });
    fx.trigger.checkPending(nowMs(), 6000);
    const opened = fx.submitted.filter((t) => t.tx_type === TX_TYPES.PRESCAN_REVIEW_TRIGGERED).map((t) => t.data.ctid);
    expect(opened).toEqual([post]);
    expect(opened).not.toContain(email);
  });

  test("commit: a review trigger is dropped for the email (also backdated), committed for the post and before the activation", () => {
    const fx = setup();
    const { email, post } = fx.pair({ flagged: true });
    const triggerTx = (ctid, timestamp) => fx.nodeTx(TX_TYPES.PRESCAN_REVIEW_TRIGGERED, {
      review_id: `t_${reviewIdFor(ctid)}`, ctid, creator_tip_id: CREATOR, assigned_reviewer_tip_id: VOLUNTEER, triggered_at_round: 1,
    }, timestamp);
    expect(fx.commits(triggerTx(email))).toBe(0);
    expect(fx.commits(triggerTx(email, BEFORE))).toBe(0);
    expect(fx.dag.getOpenPrescanReviewByCtid(email)).toBeNull();
    expect(fx.commits(triggerTx(post))).toBe(1);
    expect(fx.commits(triggerTx(email, BEFORE), BEFORE + 1000)).toBe(1);
  });

  test("the review desk lists the post waiting, never the email", () => {
    const fx = setup();
    const { email, post } = fx.pair({ flagged: true });
    const desk = fx.reviewService.listOpenReviews({});
    const waiting = desk.waiting_for_reviewer.map((r) => r.ctid);
    expect(waiting).toContain(post);
    expect(waiting).not.toContain(email);
  });

  test("API and commit: a desk claim of the email is refused, the post is claimed", () => {
    const fx = setup();
    const { email, post } = fx.pair({ flagged: true });
    expect(refusal(() => fx.reviewService.claim(null, fx.bodies.pickup(email)))).toBe("email_not_reviewable");
    const claim = at(BEFORE, () => { fx.reviewService.claim(null, fx.bodies.pickup(email)); return fx.last(TX_TYPES.PRESCAN_REVIEW_CLAIMED); });
    expect(fx.commits(claim)).toBe(0);
    expect(fx.commits(claim, BEFORE + 1000)).toBe(1);
    expect(refusal(() => fx.reviewService.claim(null, fx.bodies.pickup(post)))).toBeNull();
    expect(fx.commits(fx.last(TX_TYPES.PRESCAN_REVIEW_CLAIMED))).toBe(1);
  });

  test("API and commit: a review already running on the email cannot be confirmed, only dismissed; the post's can be confirmed", () => {
    const fx = setup();
    const { email, post } = fx.pair({ flagged: true });
    const er = fx.review(email);
    const pr = fx.review(post);
    expect(refusal(() => fx.reviewService.confirm(er, fx.bodies.confirm(er)))).toBe("email_not_reviewable");
    const confirmEmail = at(BEFORE, () => { fx.reviewService.confirm(er, fx.bodies.confirm(er)); return fx.last(TX_TYPES.PRESCAN_REVIEW_CONFIRMED); });
    expect(fx.commits(retime(confirmEmail, nowMs()))).toBe(0);
    expect(fx.dag.getPrescanReview(er).state).toBe(PRESCAN_REVIEW_STATES.TRIGGERED);

    expect(fx.commits(fx.dismissTx(er))).toBe(1);
    expect(fx.dag.getPrescanReview(er).state).toBe(PRESCAN_REVIEW_STATES.CLOSED_DISMISSED);
    expect(fx.dag.getContent(email).status).toBe(CONTENT_STATUS.REGISTERED);

    expect(refusal(() => fx.reviewService.confirm(pr, fx.bodies.confirm(pr)))).toBeNull();
    expect(fx.commits(fx.last(TX_TYPES.PRESCAN_REVIEW_CONFIRMED))).toBe(1);
    expect(fx.dag.getPrescanReview(pr).state).toBe(PRESCAN_REVIEW_STATES.CONFIRMED);
  });
});

describe("still allowed on an email record: the sender's own actions", () => {
  test("changing the declared origin and retracting get the same answer as for the post", () => {
    const fx = setup();
    const { email, post } = fx.pair({ registeredAt: nowMs() - 60_000 });
    const now = nowMs();
    for (const ctid of [email, post]) {
      expect(rules.canUpdateOrigin(fx.dag, { ctid, author_tip_id: CREATOR, new_origin_code: "AA" }, { now })).toEqual({ valid: true });
      expect(rules.canRetract(fx.dag, { ctid, author_tip_id: CREATOR })).toEqual({ valid: true });
    }
  });
});
