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
const { TX_TYPES, REGISTER_CREDIT, ORIGIN, VOTE, VERDICT, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { DISPUTE, JURY } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { seedAnchorTx } = require(path.join(__dirname, "..", "helpers", "seed-anchor-tx"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createContentService } = require(path.join(SRC, "services", "content-service"));
const { buildAdjudicationBatch } = require(path.join(SRC, "jury"));
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
