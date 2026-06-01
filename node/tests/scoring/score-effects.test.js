/**
 * @file tests/scoring/score-effects.test.js
 * @description Cross-path consistency tests for the unified score-effect
 * function. The whole point of `src/score-effects.js` is that
 * commit-handler (writes the scores table) and computeScore (read-only
 * replay for the history endpoint) produce byte-identical results from
 * the same tx history. If they ever diverge, this file fails loudly.
 *
 * The live federation observed in 2026-04 had a 24K+ byzantine canary
 * tick because computeScore double-counted social_attested registrations
 * (set score=550 absolute AND applied a +50 delta → 600). N1+N2 had
 * crossed their 12h recompute window and stored 610; N3 hadn't and
 * stored 560 (the commit-handler value). state_merkle_root diverged.
 * These tests guard against that class.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, computeTxId, generateMLDSAKeypair, signTransaction, signBody } = require(SHARED + "/crypto");
const { TX_TYPES } = require(SHARED + "/constants");
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCommitHandler } = require(path.join(SRC, "consensus", "commit-handler"));
const registerIdentitySchema = require(path.join(SRC, "schemas", "register-identity"));
const { applyScoreEffect, scoreTargetTipId, initialState, adjudicationDelta } = require(path.join(SRC, "score-effects"));
const { SCORE, SCORE_EVENTS } = require(SHARED + "/protocol-constants");

beforeAll(async () => { await initCrypto(); });

// ─── Pure-function unit tests ───────────────────────────────────────────────

describe("score-effects.applyScoreEffect — pure-function correctness", () => {
  test("REGISTER_IDENTITY → score.initial_identity (= 500), delta 0", () => {
    const tx = { tx_type: TX_TYPES.REGISTER_IDENTITY, data: { tip_id: "tip://id/x" } };
    const next = applyScoreEffect(tx, initialState());
    expect(next.score).toBe(500);
    expect(next.delta).toBe(0);
  });

  test("REGISTER_IDENTITY with social_attested=true → still 500 (legacy +50 boolean removed; per-account linking is #11)", () => {
    const tx = { tx_type: TX_TYPES.REGISTER_IDENTITY, data: { tip_id: "tip://id/x", social_attested: true } };
    const next = applyScoreEffect(tx, initialState());
    expect(next.score).toBe(500);
    expect(next.delta).toBe(0);
  });

  test("CONTENT_VERIFIED is score-neutral inline — paired SCORE_UPDATE owns the delta (single-channel rule)", () => {
    const tx = { tx_type: TX_TYPES.CONTENT_VERIFIED, data: { author_tip_id: "tip://id/x", weighted_delta: 3, ctid: "tip://content/y" } };
    const next = applyScoreEffect(tx, { score: 600, offense_count: 0, frozen: false });
    // Score does NOT move from CONTENT_VERIFIED itself — content-service.verify
    // emits a paired SCORE_UPDATE in the same atomic batch and that one carries
    // the +N delta. scoreTargetTipId returns null for CONTENT_VERIFIED so the
    // commit-handler skips the read-and-write cycle entirely.
    expect(scoreTargetTipId(tx)).toBeNull();
    expect(next.score).toBe(600);
    expect(next.delta).toBe(0);
  });

  test("SCORE_UPDATE applies tx.data.delta to current score", () => {
    const tx = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: 10, reason: "clean_record_bonus" } };
    const next = applyScoreEffect(tx, { score: 550, offense_count: 0, frozen: false });
    expect(next.score).toBe(560);
  });

  test("CONTENT_RETRACTED is score-neutral inline — paired SCORE_UPDATE owns the retraction delta", () => {
    const tx = { tx_type: TX_TYPES.CONTENT_RETRACTED, data: { author_tip_id: "tip://id/x", ctid: "tip://content/y" } };
    const next = applyScoreEffect(tx, { score: 600, offense_count: 0, frozen: false });
    // content-service.retract emits a paired SCORE_UPDATE for the
    // -RETRACTION_PENALTY delta in the same batch. The CONTENT_RETRACTED
    // tx itself records the retraction event; it does not touch the score.
    expect(scoreTargetTipId(tx)).toBeNull();
    expect(next.score).toBe(600);
    expect(next.delta).toBe(0);
  });

  test("REVOKE_VOLUNTARY freezes — positive deltas are zeroed afterwards", () => {
    const revoke = { tx_type: TX_TYPES.REVOKE_VOLUNTARY, data: { tip_id: "tip://id/x" } };
    const after = applyScoreEffect(revoke, { score: 600, offense_count: 0, frozen: false });
    expect(after.frozen).toBe(true);

    // A subsequent positive SCORE_UPDATE on the frozen state should not raise the score.
    const bonus = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: 50, reason: "bonus" } };
    const next = applyScoreEffect(bonus, after);
    expect(next.score).toBe(600);  // delta zeroed by freeze rule
  });

  test("ADJUDICATION_RESULT UPHELD bumps offense_count; score delta lives on a paired SCORE_UPDATE", () => {
    const tx = {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      data: {
        ctid: "tip://content/y", verdict: "UPHELD",
        author_tip_id: "tip://id/x", author_score_delta: -100,
      },
    };
    // Targets the author so commit-handler walks applyScoreEffect for
    // the offense increment. RESULT-owns-offense / SCORE_UPDATE-owns-delta:
    // jury.buildAdjudicationBatch emits the -100 as a separate SCORE_UPDATE
    // in the same batch; this test asserts the RESULT tx itself only flips
    // the offense counter.
    expect(scoreTargetTipId(tx)).toBe("tip://id/x");
    const next = applyScoreEffect(tx, { score: 700, offense_count: 0, frozen: false });
    expect(next.score).toBe(700);
    expect(next.delta).toBe(0);
    expect(next.offense_count).toBe(1);
  });

  test("ADJUDICATION_RESULT DISMISSED is score-neutral (no target, no delta)", () => {
    const tx = {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      data: {
        ctid: "tip://content/y", verdict: "DISMISSED",
        author_tip_id: "tip://id/x", author_score_delta: 0,
      },
    };
    expect(scoreTargetTipId(tx)).toBeNull();
  });

  test("APPEAL_RESULT overturning a Stage-2 UPHELD decrements offense_count", () => {
    const tx = {
      tx_type: TX_TYPES.APPEAL_RESULT,
      data: { ctid: "tip://content/y", overturned: true, stage2_verdict: "UPHELD" },
    };
    expect(scoreTargetTipId(tx)).toBeNull();
    // applyScoreEffect still walked, but no score row write because target is null;
    // computeScore uses the side-channel offense_count update.
    const next = applyScoreEffect(tx, { score: 600, offense_count: 1, frozen: false });
    expect(next.offense_count).toBe(0);
  });

  test("REGISTER_CONTENT, JURY_*, AI_CLASSIFIER_RESULT — no score effect (target null)", () => {
    for (const tx_type of [
      TX_TYPES.REGISTER_CONTENT, TX_TYPES.JURY_SUMMONS, TX_TYPES.JURY_VOTE_COMMIT,
      TX_TYPES.JURY_VOTE_REVEAL, TX_TYPES.AI_CLASSIFIER_RESULT, TX_TYPES.APPEAL_FILED,
    ]) {
      expect(scoreTargetTipId({ tx_type, data: {} })).toBeNull();
    }
  });

  test("initialState() seeds score = score.initial_identity, offense_count 0, frozen false", () => {
    const s = initialState();
    expect(s.score).toBe(SCORE.INITIAL_IDENTITY);
    expect(s.offense_count).toBe(0);
    expect(s.frozen).toBe(false);
  });

  test("clamp: positive delta past MAX_TOTAL caps at SCORE.MAX_TOTAL", () => {
    const tx = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: 9999, reason: "huge bonus" } };
    const next = applyScoreEffect(tx, { score: SCORE.MAX_TOTAL - 5, offense_count: 0, frozen: false });
    expect(next.score).toBe(SCORE.MAX_TOTAL);
  });

  test("clamp: negative delta past zero floors at 0", () => {
    const tx = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: -9999, reason: "huge penalty" } };
    const next = applyScoreEffect(tx, { score: 100, offense_count: 0, frozen: false });
    expect(next.score).toBe(0);
  });

  test("REVOKE_VP freezes the identity (score unchanged)", () => {
    const tx = { tx_type: TX_TYPES.REVOKE_VP, data: { tip_id: "tip://id/x" } };
    const next = applyScoreEffect(tx, { score: 700, offense_count: 0, frozen: false });
    expect(next.frozen).toBe(true);
    expect(next.score).toBe(700);
  });

  test("REVOKE_DECEASED freezes the identity (score unchanged)", () => {
    const tx = { tx_type: TX_TYPES.REVOKE_DECEASED, data: { tip_id: "tip://id/x" } };
    const next = applyScoreEffect(tx, { score: 700, offense_count: 0, frozen: false });
    expect(next.frozen).toBe(true);
    expect(next.score).toBe(700);
  });

  test("REVOKE_DEVICE freezes inline; the device-compromise penalty rides a paired SCORE_UPDATE", () => {
    // Single-channel rule: the REVOKE_* path flips `frozen` (a state flag,
    // not a score delta), and the `-DEVICE_COMPROMISE_PENDING` penalty —
    // when that flow lands — must arrive as a paired SCORE_UPDATE
    // emitted alongside REVOKE_DEVICE in the same batch (no live emission
    // point yet). score-effects.applyScoreEffect itself does not subtract
    // the penalty inline.
    const tx = { tx_type: TX_TYPES.REVOKE_DEVICE, data: { tip_id: "tip://id/x" } };
    const next = applyScoreEffect(tx, { score: 700, offense_count: 0, frozen: false });
    expect(next.frozen).toBe(true);
    expect(next.score).toBe(700);
    expect(next.delta).toBe(0);
  });

  test("frozen state — penalty (negative delta) still lands; positive delta zeroed", () => {
    // Single-channel: every score delta arrives as a SCORE_UPDATE, so the
    // freeze invariant is exercised through SCORE_UPDATEs rather than
    // CONTENT_VERIFIED / CONTENT_RETRACTED (which no longer apply inline
    // deltas — the paired SCORE_UPDATE is what carries the number).
    const revoke = applyScoreEffect(
      { tx_type: TX_TYPES.REVOKE_VOLUNTARY, data: { tip_id: "tip://id/x" } },
      { score: 700, offense_count: 0, frozen: false },
    );

    // Positive delta zeroed.
    const bonus = applyScoreEffect(
      { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: 3, reason: "Content verified" } },
      revoke,
    );
    expect(bonus.score).toBe(700);

    // Negative delta still applies (penalties survive freeze).
    const retract = applyScoreEffect(
      { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "tip://id/x", delta: SCORE_EVENTS.CONTENT_RETRACTION.delta, reason: "Content retracted" } },
      revoke,
    );
    expect(retract.score).toBe(700 + SCORE_EVENTS.CONTENT_RETRACTION.delta);
    expect(retract.frozen).toBe(true);
  });

  test("ADJUDICATION_RESULT UPHELD with delta=0 still targets author (offense_count bump fires regardless of delta)", () => {
    // Under the single-channel architecture, score deltas live on a paired
    // SCORE_UPDATE — author_score_delta on the RESULT tx is informational
    // metadata. UPHELD with author_tip_id always routes to the author so
    // applyScoreEffect can bump offense_count, even when the score-delta
    // metadata is zero.
    const tx = {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      data: { ctid: "tip://content/y", verdict: "UPHELD", author_tip_id: "tip://id/x", author_score_delta: 0 },
    };
    expect(scoreTargetTipId(tx)).toBe("tip://id/x");
    const next = applyScoreEffect(tx, { score: 700, offense_count: 0, frozen: false });
    expect(next.score).toBe(700);
    expect(next.offense_count).toBe(1);
  });

  test("ADJUDICATION_RESULT UPHELD with positive author_score_delta — score still doesn't move (delta lives on paired SCORE_UPDATE)", () => {
    // Defensive: a positive author_score_delta is a malformed verdict tx
    // (penalties only). Under the single-channel rule the RESULT tx never
    // mutates the score regardless of sign, so the only effect is the
    // offense_count bump from UPHELD. If a positive delta ever does need
    // to land, it must come through a SCORE_UPDATE in the same batch.
    const tx = {
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      data: { ctid: "tip://content/y", verdict: "UPHELD", author_tip_id: "tip://id/x", author_score_delta: 50 },
    };
    expect(scoreTargetTipId(tx)).toBe("tip://id/x");
    const next = applyScoreEffect(tx, { score: 700, offense_count: 0, frozen: false });
    expect(next.score).toBe(700);
    expect(next.delta).toBe(0);
    expect(next.offense_count).toBe(1);
  });

  test("LINK_PLATFORM → scoreTargetTipId returns tip_id", () => {
    const tx = { tx_type: TX_TYPES.LINK_PLATFORM, data: { tip_id: "tip://id/IN-abc", platform: "youtube", handle: "@ch" } };
    expect(scoreTargetTipId(tx)).toBe("tip://id/IN-abc");
  });

  test("LINK_PLATFORM → applyScoreEffect has delta=0 (SCORE_UPDATE paired tx owns the +5)", () => {
    const tx = { tx_type: TX_TYPES.LINK_PLATFORM, data: { tip_id: "tip://id/IN-abc", platform: "youtube", handle: "@ch" } };
    const next = applyScoreEffect(tx, initialState());
    expect(next.delta).toBe(0);
    expect(next.score).toBe(500);
    expect(next.reason).toBe("Social account linked");
  });
});

// ─── adjudicationDelta — offense-tier table coverage ──────────────────────
// Same input → same output across every node; protects the asymmetric
// penalty structure from accidental edits.

describe("adjudicationDelta — offense-tier penalty table", () => {
  test("DISMISSED / CONSERVATIVE_LABEL / unknown verdict → 0", () => {
    expect(adjudicationDelta({ verdict: "DISMISSED" }, 0)).toBe(0);
    expect(adjudicationDelta({ verdict: "CONSERVATIVE_LABEL" }, 5)).toBe(0);
    expect(adjudicationDelta({ verdict: "BANANA" }, 0)).toBe(0);
  });

  test("OH declared, AG confirmed: 1st = -100, 2nd = -200, 3rd+ = -300", () => {
    const data = { verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AG" };
    expect(adjudicationDelta(data, 0)).toBe(SCORE_EVENTS.OH_CONFIRMED_AG_1ST.delta);
    expect(adjudicationDelta(data, 1)).toBe(SCORE_EVENTS.OH_CONFIRMED_AG_2ND.delta);
    expect(adjudicationDelta(data, 2)).toBe(SCORE_EVENTS.OH_CONFIRMED_AG_3RD.delta);
    expect(adjudicationDelta(data, 5)).toBe(SCORE_EVENTS.OH_CONFIRMED_AG_3RD.delta);
  });

  test("OH declared, AA confirmed: 1st = -40, 2nd = -80, 3rd+ = -120 (per-pair ladder)", () => {
    const data = { verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AA" };
    expect(adjudicationDelta(data, 0)).toBe(SCORE_EVENTS.OH_CONFIRMED_AA_1ST.delta);
    expect(adjudicationDelta(data, 1)).toBe(SCORE_EVENTS.OH_CONFIRMED_AA_2ND.delta);
    expect(adjudicationDelta(data, 2)).toBe(SCORE_EVENTS.OH_CONFIRMED_AA_3RD.delta);
    expect(adjudicationDelta(data, 5)).toBe(SCORE_EVENTS.OH_CONFIRMED_AA_3RD.delta);
  });

  test("AA declared, AG confirmed: 1st = -25, 2nd = -50, 3rd+ = -75 (per-pair ladder)", () => {
    const data = { verdict: "UPHELD", declared_origin: "AA", confirmed_origin: "AG" };
    expect(adjudicationDelta(data, 0)).toBe(SCORE_EVENTS.AA_CONFIRMED_AG_1ST.delta);
    expect(adjudicationDelta(data, 1)).toBe(SCORE_EVENTS.AA_CONFIRMED_AG_2ND.delta);
    expect(adjudicationDelta(data, 2)).toBe(SCORE_EVENTS.AA_CONFIRMED_AG_3RD.delta);
    expect(adjudicationDelta(data, 5)).toBe(SCORE_EVENTS.AA_CONFIRMED_AG_3RD.delta);
  });

  test("FACTUAL_FALSEHOOD: minor (default) = -75, major = -300", () => {
    expect(adjudicationDelta({ verdict: "UPHELD", type: "FACTUAL_FALSEHOOD" }, 0))
      .toBe(SCORE_EVENTS.FACTUAL_FALSEHOOD_MINOR.delta);
    expect(adjudicationDelta({ verdict: "UPHELD", type: "FACTUAL_FALSEHOOD", severity: "major" }, 0))
      .toBe(SCORE_EVENTS.FACTUAL_FALSEHOOD_MAJOR.delta);
  });

  test("UPHELD with unrecognised origin pair (e.g. AA→AA) → 0", () => {
    const data = { verdict: "UPHELD", declared_origin: "AA", confirmed_origin: "AA" };
    expect(adjudicationDelta(data, 0)).toBe(0);
  });

  // ─── Per-pair escalation: numeric pin + anti-regression ─────────────────
  //
  // Locks in the exact genesis values so a silent change to the `penalties`
  // block (or a regression back to the old universal `MISMATCH_2ND_OFFENSE`
  // ladder) trips here instead of corrupting scores in prod. The constants
  // are read from genesis at runtime — these assertions check the actually-
  // wired values, not aliased lookups.
  test("per-pair penalties — exact numeric values from genesis", () => {
    // OH→AG ladder
    expect(adjudicationDelta({ verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AG" }, 0)).toBe(-100);
    expect(adjudicationDelta({ verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AG" }, 1)).toBe(-200);
    expect(adjudicationDelta({ verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AG" }, 2)).toBe(-300);
    // OH→AA ladder — per-pair: 1× / 2× / 3× of -40
    expect(adjudicationDelta({ verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AA" }, 0)).toBe(-40);
    expect(adjudicationDelta({ verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AA" }, 1)).toBe(-80);
    expect(adjudicationDelta({ verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AA" }, 2)).toBe(-120);
    // AA→AG ladder — per-pair: 1× / 2× / 3× of -25
    expect(adjudicationDelta({ verdict: "UPHELD", declared_origin: "AA", confirmed_origin: "AG" }, 0)).toBe(-25);
    expect(adjudicationDelta({ verdict: "UPHELD", declared_origin: "AA", confirmed_origin: "AG" }, 1)).toBe(-50);
    expect(adjudicationDelta({ verdict: "UPHELD", declared_origin: "AA", confirmed_origin: "AG" }, 2)).toBe(-75);
  });

  test("per-pair escalation preserves severity scaling at 2nd offense (anti-regression)", () => {
    // The bug we fixed: 2nd-offense AA→AG, OH→AA, and OH→AG all returned -200
    // because they all bound to `oh_as_ag[1]`. After the fix, they must be
    // distinct values that preserve the 1st-offense severity ordering.
    const ohAg2nd = adjudicationDelta({ verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AG" }, 1);
    const ohAa2nd = adjudicationDelta({ verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AA" }, 1);
    const aaAg2nd = adjudicationDelta({ verdict: "UPHELD", declared_origin: "AA", confirmed_origin: "AG" }, 1);

    expect(ohAg2nd).not.toBe(ohAa2nd);
    expect(ohAg2nd).not.toBe(aaAg2nd);
    expect(ohAa2nd).not.toBe(aaAg2nd);
    // Severity ordering: OH→AG (worst) < OH→AA < AA→AG (mildest)
    expect(ohAg2nd).toBeLessThan(ohAa2nd);
    expect(ohAa2nd).toBeLessThan(aaAg2nd);
  });

  test("per-pair escalation preserves severity scaling at 3rd offense", () => {
    const ohAg3rd = adjudicationDelta({ verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AG" }, 2);
    const ohAa3rd = adjudicationDelta({ verdict: "UPHELD", declared_origin: "OH", confirmed_origin: "AA" }, 2);
    const aaAg3rd = adjudicationDelta({ verdict: "UPHELD", declared_origin: "AA", confirmed_origin: "AG" }, 2);

    expect(ohAg3rd).toBeLessThan(ohAa3rd);
    expect(ohAa3rd).toBeLessThan(aaAg3rd);
  });

  test("offense ladder is monotonic within each pair (later offense ≤ earlier)", () => {
    for (const [d, c] of [["OH", "AG"], ["OH", "AA"], ["AA", "AG"]]) {
      const first = adjudicationDelta({ verdict: "UPHELD", declared_origin: d, confirmed_origin: c }, 0);
      const second = adjudicationDelta({ verdict: "UPHELD", declared_origin: d, confirmed_origin: c }, 1);
      const third = adjudicationDelta({ verdict: "UPHELD", declared_origin: d, confirmed_origin: c }, 2);
      expect(second).toBeLessThanOrEqual(first);
      expect(third).toBeLessThanOrEqual(second);
    }
  });
});

// ─── Cross-path consistency ────────────────────────────────────────────────
// commit-handler (sole writer to scores table) MUST produce the same final
// score as scoring.computeScore (read-only replay). Same input → same output.

describe("commit-handler vs computeScore — same final score for any tx history", () => {
  function _makeFx() {
    const dag = initDAG({ dbPath: ":memory:" });
    // Real keypairs so commit-handler's signature verifier accepts the
    // synthetic txs we hand it. VP signs REGISTER_IDENTITY; node signs
    // SCORE_UPDATE.
    const vpKp = generateMLDSAKeypair();
    const nodeKp = generateMLDSAKeypair();
    dag.saveNode({
      node_id: "tip://node/n1", name: "n1", public_key: nodeKp.publicKey,
      status: "active", registered_at: 1767225600000,
    });
    dag.saveVP({
      vp_id: "tip://vp/v1", name: "VP", jurisdiction: "US", jurisdiction_tier: "green",
      public_key: vpKp.publicKey, root_public_key: "00", status: "active",
      registered_at: 1767225600000, tx_id: shake256("vp:v1"),
    });
    const config = {
      nodeId: "tip://node/n1", nodeRegisteredId: "tip://node/n1",
      nodePrivateKey: nodeKp.privateKey,
    };
    const scoring = initScoring(dag, config);
    const handler = createCommitHandler({ dag, scoring });
    return { dag, scoring, handler, vpKp, nodeKp, config };
  }

  let _idCounter = 0;
  function _registerIdentityTx(fx, { social_attested = false, timestamp }) {
    // tx-validator requires `tip://id/[REGION]-[16hex]` format and a
    // decimal dedup_hash. Hand-craft both so the synthetic tx clears
    // schema validation.
    const hex = (_idCounter++).toString(16).padStart(16, "0");
    const tip_id = `tip://id/US-${hex}`;
    const dedup_hash = String(BigInt("0x" + shake256(`dedup:${tip_id}`).slice(0, 32)));
    const zk_proof = { pi_a: ["1"], pi_b: [["1"]], pi_c: ["1"], protocol: "groth16", curve: "bn128" };
    const sigBody = {
      region: "US", public_key: "00", dedup_hash, zk_proof,
      verification_tier: "T1", vp_id: "tip://vp/v1", social_attested,
    };
    const canonicalPayload = registerIdentitySchema.buildSigningPayload(sigBody);
    const vp_signature = registerIdentitySchema.sign(canonicalPayload, fx.vpKp.privateKey);
    const txBody = {
      tx_type: TX_TYPES.REGISTER_IDENTITY, timestamp,
      prev: fx.dag.getRecentPrev(),
      data: {
        tip_id, root_public_key: "00", founding: false,
        vp_signature,
        // Mirror canonical payload fields onto tx.data so commit-handler
        // can replay buildSigningPayload(d) deterministically.
        creator_name: canonicalPayload.creator_name,
        dedup_hash: canonicalPayload.dedup_hash,
        public_key: canonicalPayload.public_key,
        region: canonicalPayload.region,
        social_attested: canonicalPayload.social_attested,
        tip_id_type: canonicalPayload.tip_id_type,
        verification_tier: canonicalPayload.verification_tier,
        vp_id: canonicalPayload.vp_id,
        zk_proof: canonicalPayload.zk_proof,
      },
    };
    txBody.tx_id = computeTxId(txBody);
    txBody.signature = vp_signature;
    return { tx: txBody, tip_id };
  }

  function _scoreUpdateTx(fx, { tip_id, delta, reason, timestamp, ctid = null }) {
    const txBody = {
      tx_type: TX_TYPES.SCORE_UPDATE, timestamp, prev: fx.dag.getRecentPrev(),
      data: { tip_id, delta, reason, ctid, node_id: "tip://node/n1" },
    };
    txBody.tx_id = computeTxId(txBody);
    return signTransaction(txBody, fx.nodeKp.privateKey);
  }

  test("social_attested REGISTER_IDENTITY: commit-handler.setScore = computeScore = 500 (post-spec, no +50 bonus)", () => {
    const fx = _makeFx();
    const { tx, tip_id } = _registerIdentityTx(fx, { social_attested: true, timestamp: 1777420800000 });
    const r = fx.handler.commitOrderedTxs([tx], 100);
    expect(r.committed).toBe(1);

    const cached = fx.dag.getScore(tip_id);
    const replayed = fx.scoring.computeScore(tip_id);
    expect(cached.score).toBe(500);
    expect(replayed.score).toBe(500);
  });

  test("non-attested REGISTER_IDENTITY: both paths = 500", () => {
    const fx = _makeFx();
    const { tx, tip_id } = _registerIdentityTx(fx, { social_attested: false, timestamp: 1777420800000 });
    fx.handler.commitOrderedTxs([tx], 100);

    expect(fx.dag.getScore(tip_id).score).toBe(500);
    expect(fx.scoring.computeScore(tip_id).score).toBe(500);
  });

  test("REGISTER_IDENTITY + clean_record_bonus: both paths = 510 (regression for live divergence)", () => {
    const fx = _makeFx();
    const { tx: reg, tip_id } = _registerIdentityTx(fx, {
      social_attested: true, timestamp: 1777420800000,
    });
    fx.handler.commitOrderedTxs([reg], 100);
    const bonus = _scoreUpdateTx(fx, {
      tip_id, delta: 10, reason: "clean_record_bonus",
      timestamp: 1777420801000,
    });
    fx.handler.commitOrderedTxs([bonus], 101);

    const cached = fx.dag.getScore(tip_id);
    const replayed = fx.scoring.computeScore(tip_id);

    // Live-divergence regression. Pre-fix N1+N2 ran recomputeAll which
    // double-counted REGISTER_IDENTITY (set 550 absolute + 50 delta) and
    // wrote 610 to the scores table. N3 (no recompute yet) wrote the
    // commit-handler value, which after the spec migration is 500 + 10.
    // Both paths must now agree on the spec-aligned value.
    expect(cached.score).toBe(510);
    expect(replayed.score).toBe(510);
    expect(cached.score).toBe(replayed.score);
  });

  test("CONTENT_VERIFIED + paired SCORE_UPDATE — both paths reflect the +3 immediately (#38 gap closed)", () => {
    const fx = _makeFx();
    const { tx: author, tip_id: authorId } = _registerIdentityTx(fx, {
      social_attested: false, timestamp: 1777420800000,
    });
    fx.handler.commitOrderedTxs([author], 100);
    expect(fx.dag.getScore(authorId).score).toBe(500);

    // Single-channel rule: CONTENT_VERIFIED owns the verification record;
    // the score delta lives on a paired SCORE_UPDATE in the same atomic
    // batch (content-service.verify emits both). Applying both txs is what
    // realises the +3 — CONTENT_VERIFIED alone is intentionally a no-op
    // for the score row.
    const verify = {
      tx_type: TX_TYPES.CONTENT_VERIFIED,
      timestamp: 1777420860000,
      prev: fx.dag.getRecentPrev(),
      data: {
        ctid: "tip://content/x", verifier_tip_id: "tip://id/verifier",
        author_tip_id: authorId, weighted_delta: 3,
      },
    };
    verify.tx_id = computeTxId(verify);
    verify.signature = "00";
    fx.dag.addTx({ ...verify });

    // CONTENT_VERIFIED alone leaves the score at 500 (single-channel).
    expect(fx.scoring.computeScore(authorId).score).toBe(500);

    // The paired SCORE_UPDATE carries the +3.
    const scoreUpdate = _scoreUpdateTx(fx, {
      tip_id: authorId, delta: 3,
      reason: `Content verified (tip://content/x)`,
      timestamp: 1777420860001,
    });
    fx.handler.commitOrderedTxs([scoreUpdate], 101);

    // Both the live mirror and the replay must now agree on 503.
    expect(fx.dag.getScore(authorId).score).toBe(503);
    expect(fx.scoring.computeScore(authorId).score).toBe(503);
  });
});
