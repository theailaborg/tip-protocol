/**
 * @file tests/scoring/registration-credit.test.js
 * @description Author reward for registering content: capped +1 per
 * REGISTER_CONTENT, reversed on a dispute upheld against the author.
 *
 * Wiring:
 *   - content-service.register emits a paired SCORE_UPDATE (reason
 *     `reg_credit:<ctid>`, delta = REGISTER_CREDIT.BASE) clamped by the
 *     smallest remaining headroom of per-day / per-month / lifetime-total.
 *   - jury.buildAdjudicationBatch reverses that credit (`reg_credit_rev:<ctid>`)
 *     on an UPHELD verdict, once, only if it was awarded.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256, tipNormalize, computeTxId } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, REGISTER_CREDIT, ORIGIN, VOTE, VERDICT, CONTENT_STATUS, TX_REJECTION_REASON } = require(path.join(SHARED, "constants"));
const { DISPUTE, JURY, APPEAL } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { buildAdjudicationBatch, buildAppealBatch } = require(path.join(SRC, "jury"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const schema = require(path.join(SRC, "schemas", "content-register"));

beforeAll(async () => { await initCrypto(); });

const VP_ID = "tip://vp/v1";
const NODE_ID = "tip://node/n1";
const CTID = "tip://c/OH-aaaaaaaaaaaaaa-1111";

function _setup() {
  const dag = initDAG({ dbPath: ":memory:" });
  const nodeKp = generateMLDSAKeypair();
  dag.saveNode({ node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey, status: "active", registered_at: 1767225600000 });
  dag.saveVP({ vp_id: VP_ID, name: "VP", jurisdiction: "US", jurisdiction_tier: "green", public_key: "00", status: "active", registered_at: 1767225600000 });
  const config = {
    nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey,
    mediaLimits: { max_text_bytes: 1_000_000, max_image_bytes: 0, max_video_bytes: 0, max_audio_bytes: 0 },
  };
  const scoring = initScoring(dag, config);
  const submitted = [];
  const submitTx = (tx) => { submitted.push(tx); dag.addTx(tx); };
  const contentService = createContentService({ dag, scoring, config, submitTx });
  return { dag, scoring, config, contentService, submitted };
}

function _seedIdentity(dag, tipId, kp, score = 750) {
  dag.saveIdentity({
    tip_id: tipId, region: "US", public_key: kp ? kp.publicKey : "00", root_public_key: kp ? kp.publicKey : "00",
    vp_id: VP_ID, verification_tier: "T1", founding: false, status: "active",
    registered_at: 1767225600000, tx_id: seedAnchorTx(dag, "REGISTER_IDENTITY", { tip_id: tipId }),
  });
  dag.setScore(tipId, score, 0, 1767225600000);
}

function _body(tipId, privKey, content) {
  const contentHashFull = shake256(tipNormalize(content));
  const fields = {
    origin_code: "OH", registered_urls: [`https://example.com/${shake256(content).slice(0, 8)}`], extras: {},
    authors: [{ key_mode: "attribution", role: "byline", signed: false, tip_id: tipId, tip_id_type: "personal" }],
    signer_tip_id: tipId, attribution_mode: "self",
  };
  const payload = schema.buildSigningPayload(fields, contentHashFull);
  return { ...fields, cna_version: schema.CURRENT_CNA_VERSION, content, content_type: "text", signature: schema.sign(payload, privKey) };
}

const regCredits = (submitted, tipId) => submitted.filter(t =>
  t.tx_type === TX_TYPES.SCORE_UPDATE && t.data.tip_id === tipId
  && String(t.data.reason).startsWith(REGISTER_CREDIT.AWARD_REASON_PREFIX));

// ─── Award + caps (driven through the real register() path) ─────────────────

describe("registration credit — award on REGISTER_CONTENT", () => {
  test("register emits a +1 reg_credit SCORE_UPDATE to the author", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("reg-author-1").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    const out = await fx.contentService.register(_body(tipId, kp.privateKey, "first post"));
    const credits = regCredits(fx.submitted, tipId);
    expect(credits).toHaveLength(1);
    expect(credits[0].data.delta).toBe(REGISTER_CREDIT.BASE);
    expect(credits[0].data.ctid).toBe(out.ctid);
    expect(credits[0].data.reason).toBe(`${REGISTER_CREDIT.AWARD_REASON_PREFIX}${out.ctid}`);
  });

  test("per-day cap clamps: the (PER_DAY+1)-th same-day registration earns nothing", async () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("reg-author-day").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp);

    for (let i = 0; i < REGISTER_CREDIT.PER_DAY + 1; i++) {
      await fx.contentService.register(_body(tipId, kp.privateKey, `post ${i}`));
    }
    const awardedTotal = regCredits(fx.submitted, tipId).reduce((s, t) => s + t.data.delta, 0);
    expect(awardedTotal).toBe(REGISTER_CREDIT.PER_DAY);
    expect(regCredits(fx.submitted, tipId)).toHaveLength(REGISTER_CREDIT.PER_DAY);
  });

  test("cap is per-author (another author's registrations don't consume your headroom)", async () => {
    const fx = _setup();
    const a = generateMLDSAKeypair(); const aTip = `tip://id/US-${shake256("reg-a").slice(0, 16)}`;
    const b = generateMLDSAKeypair(); const bTip = `tip://id/US-${shake256("reg-b").slice(0, 16)}`;
    _seedIdentity(fx.dag, aTip, a); _seedIdentity(fx.dag, bTip, b);

    await fx.contentService.register(_body(aTip, a.privateKey, "a-one"));
    await fx.contentService.register(_body(bTip, b.privateKey, "b-one"));
    expect(regCredits(fx.submitted, aTip)).toHaveLength(1);
    expect(regCredits(fx.submitted, bTip)).toHaveLength(1);
  });
});

// ─── Commit-time cap (the burst race the emitter cannot see) ────────────────
// The emitter reads only committed SCORE_UPDATEs, so a burst of registrations
// races past the caps before its own credits commit (this is how a load test
// pushed one author to 16 same-day credits with PER_DAY=3). The commit-handler
// re-checks the cap deterministically against committed + in-batch credits.

describe("registration credit: commit-time cap under burst", () => {
  // A committed-and-past same-UTC-day base (post reg_credit activation) so the
  // txs clear the validator's not-in-the-future guard. The cap gate itself is
  // driven by config.regCreditCapActivationMs, not by this timestamp.
  const SAME_DAY = REGISTER_CREDIT.ACTIVATION_MS + 3_600_000;
  const N = REGISTER_CREDIT.PER_DAY + 5;

  // A burst of N distinct-ctid reg_credits for one author, all in the same UTC
  // day. Distinct ctids so the (tip_id, ctid, reason) dedup does not collapse
  // them; they are genuinely separate credits, as under real load.
  function _burst(scoring, config, tipId) {
    return Array.from({ length: N }, (_, i) => scoring.buildScoreUpdateTx({
      tipId, delta: REGISTER_CREDIT.BASE,
      reason: `${REGISTER_CREDIT.AWARD_REASON_PREFIX}tip://c/OH-burst${i}-1111`,
      ctid: `tip://c/OH-burst${i}-1111`, relatedTxId: null,
      timestamp: SAME_DAY + i, config,
    }));
  }

  test("a same-day burst is clamped to PER_DAY; the rest drop with the cap reason", () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("reg-burst").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp, 500);
    // regCreditCapActivationMs: 0 -> cap enforced for these (past) timestamps.
    const handler = createCommitHandler({ dag: fx.dag, scoring: fx.scoring, config: { ...fx.config, regCreditCapActivationMs: 0 } });

    const txs = _burst(fx.scoring, fx.config, tipId);
    const res = handler.commitOrderedTxs(txs, 100);

    expect(res.committed).toBe(REGISTER_CREDIT.PER_DAY);
    expect(res.dropped).toBe(N - REGISTER_CREDIT.PER_DAY);
    const droppedReasons = txs.map(t => fx.dag.getTxRejection(t.tx_id)).filter(Boolean).map(r => r.reason);
    expect(droppedReasons).toHaveLength(N - REGISTER_CREDIT.PER_DAY);
    expect(droppedReasons.every(r => r === TX_REJECTION_REASON.REG_CREDIT_CAP_REACHED)).toBe(true);
    expect(fx.scoring.getScore(tipId).score).toBe(500 + REGISTER_CREDIT.PER_DAY);
  });

  test("cap gate is inert before activation (no fork during the rolling upgrade)", () => {
    const fx = _setup();
    const kp = generateMLDSAKeypair();
    const tipId = `tip://id/US-${shake256("reg-burst-inert").slice(0, 16)}`;
    _seedIdentity(fx.dag, tipId, kp, 500);
    // Default activation (future constant) -> these past timestamps are pre-gate.
    const handler = createCommitHandler({ dag: fx.dag, scoring: fx.scoring, config: fx.config });

    const txs = _burst(fx.scoring, fx.config, tipId);
    const res = handler.commitOrderedTxs(txs, 100);

    // Before the gate the check does not run: pre-fix behavior, all admitted.
    expect(res.committed).toBe(N);
    expect(res.dropped).toBe(0);
  });
});

// ─── Clawback (driven through the real jury adjudication path) ───────────────

function _addTx(dag, body) {
  const tx = { ...body };
  if (!tx.prev) tx.prev = [];
  tx.tx_id = computeTxId(tx);
  dag.addTx(tx);
  return tx;
}

function _seedDisputeFixture(dag) {
  const authorTipId = "tip://id/author";
  const disputerTipId = "tip://id/disputer";
  _seedIdentity(dag, authorTipId, null, 600);
  _seedIdentity(dag, disputerTipId, null, 800);
  dag.saveContent({
    ctid: CTID, origin_code: ORIGIN.OH, content_hash: "00",
    author_tip_id: authorTipId, status: CONTENT_STATUS.DISPUTED, registered_at: 1767225600000, tx_id: "00",
  });
  const disputeTx = _addTx(dag, {
    tx_type: TX_TYPES.CONTENT_DISPUTED, timestamp: 1775001600000,
    data: {
      ctid: CTID, disputer_tip_id: disputerTipId, reason: "origin_mismatch",
      claimed_origin: ORIGIN.AG, declared_origin: ORIGIN.OH, author_tip_id: authorTipId,
      pre_dispute_status: CONTENT_STATUS.REGISTERED, stake: DISPUTE.DISPUTER_STAKE,
    },
  });
  const summons = [];
  const jurors = [];
  for (let i = 0; i < 7; i++) {
    const j = `tip://id/juror-${i}`;
    _seedIdentity(dag, j, null, 750);
    jurors.push(j);
    summons.push(_addTx(dag, {
      tx_type: TX_TYPES.JURY_SUMMONS,
      timestamp: `2026-04-01T00:00:0${i % 10}.${(100 + i).toString().padStart(3, "0")}Z`,
      data: {
        ctid: CTID, dispute_tx_id: disputeTx.tx_id, juror_tip_id: j,
        stake: JURY.JUROR_STAKE, seed: shake256("seed"), identity_count: 7,
        commit_deadline: 1893456000000, reveal_deadline: 1893456000000,
      },
    }));
  }
  return { authorTipId, disputerTipId, jurors, summons };
}

function _buildReveals(jurors, votes) {
  return jurors.slice(0, votes.length).map((j, i) => ({
    tx_id: shake256(`reveal-${i}-${votes[i]}`),
    tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: 1775088000000,
    data: { ctid: CTID, juror_tip_id: j, vote: votes[i], salt: shake256(`s${i}`), confirmed_origin: ORIGIN.AG },
  }));
}

const UPHELD_VOTES = [VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MISMATCH, VOTE.MATCH, VOTE.MATCH];
const DISMISS_VOTES = [VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MATCH, VOTE.MISMATCH, VOTE.MISMATCH];

function _seedRegCredit(dag, scoring, config, tipId, ctid, delta = REGISTER_CREDIT.BASE) {
  dag.addTx(scoring.buildScoreUpdateTx({
    tipId, delta, reason: `${REGISTER_CREDIT.AWARD_REASON_PREFIX}${ctid}`, ctid, relatedTxId: null, timestamp: 1775001600000, config,
  }));
}

const reversals = (txs) => txs.filter(t => String(t.data?.reason || "").startsWith(REGISTER_CREDIT.REVERSAL_REASON_PREFIX));
const restores = (txs) => txs.filter(t => String(t.data?.reason || "").startsWith(REGISTER_CREDIT.RESTORE_REASON_PREFIX));

const EXPERTS = ["tip://id/expert-0", "tip://id/expert-1", "tip://id/expert-2"];

function _expertSummons(dag, experts) {
  return experts.map((e, i) => _addTx(dag, {
    tx_type: TX_TYPES.JURY_SUMMONS,
    timestamp: `2026-04-05T00:00:0${i}.000Z`,
    data: {
      ctid: CTID, juror_tip_id: e, is_appeal: true, stake: JURY.JUROR_STAKE,
      commit_deadline: 1893456000000, reveal_deadline: 1893456000000,
      seed: shake256("expert-seed"), identity_count: experts.length,
    },
  }));
}

function _expertReveals(experts, vote) {
  return experts.map((e, i) => ({
    tx_id: shake256(`exr-${i}-${vote}`),
    tx_type: TX_TYPES.JURY_VOTE_REVEAL, timestamp: 1775433600000,
    data: { ctid: CTID, juror_tip_id: e, vote, salt: shake256(`es${i}`), confirmed_origin: ORIGIN.AG, is_appeal: true },
  }));
}

// Seed a Stage-2 ADJUDICATION_RESULT (+ its reg_credit reclaim on UPHELD) and an
// APPEAL_FILED, so buildAppealBatch has a prior verdict to reconcile against.
function _seedStage2AndAppeal(dag, scoring, config, ids, stage2Verdict) {
  const adj = _addTx(dag, {
    tx_type: TX_TYPES.ADJUDICATION_RESULT, timestamp: 1775090000000,
    data: {
      ctid: CTID, verdict: stage2Verdict, declared_origin: ORIGIN.OH,
      confirmed_origin: stage2Verdict === VERDICT.UPHELD ? ORIGIN.AG : null,
      author_tip_id: ids.authorTipId, disputer_tip_id: ids.disputerTipId,
      author_score_delta: stage2Verdict === VERDICT.UPHELD ? -100 : 0,
      pre_dispute_status: CONTENT_STATUS.REGISTERED,
    },
  });
  if (stage2Verdict === VERDICT.UPHELD) {
    dag.addTx(scoring.buildScoreUpdateTx({
      tipId: ids.authorTipId, delta: -REGISTER_CREDIT.BASE,
      reason: `${REGISTER_CREDIT.REVERSAL_REASON_PREFIX}${CTID}`,
      ctid: CTID, relatedTxId: adj.tx_id, timestamp: 1775090000000, config,
    }));
  }
  _addTx(dag, {
    tx_type: TX_TYPES.APPEAL_FILED, timestamp: 1775095000000,
    data: {
      ctid: CTID,
      appellant_tip_id: stage2Verdict === VERDICT.UPHELD ? ids.authorTipId : ids.disputerTipId,
      stage2_verdict: stage2Verdict, stake: APPEAL.APPELLANT_STAKE,
    },
  });
}

describe("registration credit — clawback on dispute upheld", () => {
  test("UPHELD reverses the author's registration credit exactly once (-1)", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    _seedRegCredit(fx.dag, fx.scoring, fx.config, ids.authorTipId, CTID);

    const out = buildAdjudicationBatch(CTID, _buildReveals(ids.jurors, UPHELD_VOTES), ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);

    const rev = reversals(out.txs);
    expect(rev).toHaveLength(1);
    expect(rev[0].data.tip_id).toBe(ids.authorTipId);
    expect(rev[0].data.delta).toBe(-REGISTER_CREDIT.BASE);
    expect(rev[0].data.ctid).toBe(CTID);
  });

  test("no reversal when the content was never credited", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    const out = buildAdjudicationBatch(CTID, _buildReveals(ids.jurors, UPHELD_VOTES), ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.UPHELD);
    expect(reversals(out.txs)).toHaveLength(0);
  });

  test("no reversal on DISMISSED (author keeps the credit)", () => {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    _seedRegCredit(fx.dag, fx.scoring, fx.config, ids.authorTipId, CTID);
    const out = buildAdjudicationBatch(CTID, _buildReveals(ids.jurors, DISMISS_VOTES), ids.summons, fx.dag, fx.scoring, fx.config);
    expect(out.verdict).toBe(VERDICT.DISMISSED);
    expect(reversals(out.txs)).toHaveLength(0);
  });
});

describe("registration credit — appeal reconciliation (overturn)", () => {
  function _appeal(stage2Verdict, expertVote) {
    const fx = _setup();
    const ids = _seedDisputeFixture(fx.dag);
    _seedRegCredit(fx.dag, fx.scoring, fx.config, ids.authorTipId, CTID);
    _seedStage2AndAppeal(fx.dag, fx.scoring, fx.config, ids, stage2Verdict);
    for (const e of EXPERTS) _seedIdentity(fx.dag, e, null, 900);
    const summons = _expertSummons(fx.dag, EXPERTS);
    const out = buildAppealBatch(CTID, _expertReveals(EXPERTS, expertVote), summons, fx.dag, fx.scoring, fx.config);
    return { ids, out };
  }

  test("overturn UPHELD->DISMISSED restores the author's +1", () => {
    const { ids, out } = _appeal(VERDICT.UPHELD, VOTE.MATCH);
    expect(out.verdict).toBe(VERDICT.DISMISSED);
    expect(out.overturned).toBe(true);
    const r = restores(out.txs);
    expect(r).toHaveLength(1);
    expect(r[0].data.tip_id).toBe(ids.authorTipId);
    expect(r[0].data.delta).toBe(REGISTER_CREDIT.BASE);
    expect(reversals(out.txs)).toHaveLength(0);
  });

  test("overturn DISMISSED->UPHELD claws back the author's +1", () => {
    const { ids, out } = _appeal(VERDICT.DISMISSED, VOTE.MISMATCH);
    expect(out.verdict).toBe(VERDICT.UPHELD);
    expect(out.overturned).toBe(true);
    const rev = reversals(out.txs);
    expect(rev).toHaveLength(1);
    expect(rev[0].data.tip_id).toBe(ids.authorTipId);
    expect(rev[0].data.delta).toBe(-REGISTER_CREDIT.BASE);
    expect(restores(out.txs)).toHaveLength(0);
  });

  test("confirm UPHELD->UPHELD does not double-reclaim (already reversed at Stage 2)", () => {
    const { out } = _appeal(VERDICT.UPHELD, VOTE.MISMATCH);
    expect(out.verdict).toBe(VERDICT.UPHELD);
    expect(reversals(out.txs)).toHaveLength(0);
    expect(restores(out.txs)).toHaveLength(0);
  });

  test("confirm DISMISSED->DISMISSED leaves the +1 untouched", () => {
    const { out } = _appeal(VERDICT.DISMISSED, VOTE.MATCH);
    expect(out.verdict).toBe(VERDICT.DISMISSED);
    expect(reversals(out.txs)).toHaveLength(0);
    expect(restores(out.txs)).toHaveLength(0);
  });
});
