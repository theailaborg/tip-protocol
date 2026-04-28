/**
 * @file tests/consensus/verdict-trigger.test.js
 * @description Unit tests for the post-round verdict-trigger module.
 *
 * Coverage:
 *   - Heap update on JURY_SUMMONS commit (push), idempotent on duplicate
 *     summonses for the same (ctid, stage).
 *   - Heap update on ADJUDICATION_RESULT / APPEAL_RESULT / APPEAL_FILED
 *     commit (drops resolved entry).
 *   - Boot rehydration scans the DAG for unresolved disputes.
 *   - `checkPending(certTimestamp)` doesn't fire when nothing has crossed
 *     the deadline.
 *   - `checkPending` does fire when a deadline has crossed, building
 *     the right batch type (jury vs appeal) via the jury builders and
 *     submitting via the injected `submitBatch`.
 *   - Idempotency guard: skips entries whose ctid already has a result.
 *   - Mempool errors from submitBatch are non-fatal (next round retries).
 *
 * Tests use a real in-memory DAG + real scoring + real jury builders so
 * the integration is meaningful. `submitBatch` is captured as a spy.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, signTransaction, computeTxId, shake256 } = require(path.join(SHARED, "crypto"));
const { TX_TYPES, VERDICT, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { DISPUTE, JURY } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const jury = require(path.join(SRC, "jury"));
const { createVerdictTrigger } = require(path.join(SRC, "consensus", "verdict-trigger"));

beforeAll(async () => {
  await initCrypto();
});

// ═══════════════════════════════════════════════════════════════════════════
// Fixture — minimal DAG with one dispute: content + dispute tx + 3 summons.
// All txs are real (signed, verified-able), so the trigger sees authentic
// state when it queries the DAG.
// ═══════════════════════════════════════════════════════════════════════════
// Default juror count — pull from genesis-loaded JURY.QUORUM so the
// fixture stays aligned with whatever the protocol's quorum threshold
// is set to. Tests that want to exercise the BELOW-quorum code path
// (NO_QUORUM auto-escalation) can pass `jurorCount: JURY.QUORUM - 1`
// and tests that want a strict (ctid, stage) dedup case can pass any
// number ≥ 2.
function _setup({ revealDeadline = "2026-04-15T00:00:00.000Z", isAppeal = false, withReveals = false, jurorCount = JURY.QUORUM } = {}) {
  const dag = initDAG({ dbPath: ":memory:" });

  const nodeKp = generateMLDSAKeypair();
  const NODE_ID = "tip://node/n1";
  dag.saveNode({
    node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey,
    status: "active", registered_at: "2026-01-01T00:00:00.000Z",
  });
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);

  const ctid = "tip://content/test-1";
  const authorTipId = "tip://id/author";
  const disputerTipId = "tip://id/disputer";
  // Default 5 jurors to satisfy JURY.QUORUM=5; tests can override.
  const jurorTipIds = Array.from({ length: jurorCount }, (_, i) => `tip://id/juror${i}`);

  const identityKeys = {};
  for (const tipId of [authorTipId, disputerTipId, ...jurorTipIds]) {
    const kp = generateMLDSAKeypair();
    identityKeys[tipId] = kp;
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: "00",
      vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active",
      registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`id:${tipId}`),
    });
    dag.setScore(tipId, 750, 0);
  }

  dag.saveContent({
    ctid, origin_code: "OH", content_hash: shake256("c1"),
    author_tip_id: authorTipId, status: CONTENT_STATUS.DISPUTED,
    registered_at: "2026-01-01T00:00:00.000Z", tx_id: shake256(`content:${ctid}`),
  });

  // Helper: sign a node-auto tx with prev pulled from current DAG.
  function signNodeTx(txBody) {
    txBody.prev = txBody.prev && txBody.prev.length ? txBody.prev : dag.getRecentPrev();
    txBody.data.node_id = NODE_ID;
    txBody.tx_id = computeTxId(txBody);
    return signTransaction(txBody, nodeKp.privateKey);
  }

  const disputeTx = signNodeTx({
    tx_type: TX_TYPES.CONTENT_DISPUTED,
    timestamp: "2026-01-01T00:00:00.000Z",
    prev: [],
    data: {
      ctid, disputer_tip_id: disputerTipId, reason: "origin_mismatch",
      claimed_origin: "AG", declared_origin: "OH",
      author_tip_id: authorTipId, pre_dispute_status: CONTENT_STATUS.REGISTERED,
      stake: DISPUTE.DISPUTER_STAKE,
    },
  });
  dag.addTx(disputeTx);

  // Summons for each juror — all share the same reveal_deadline.
  for (const jurorTipId of jurorTipIds) {
    const summons = signNodeTx({
      tx_type: TX_TYPES.JURY_SUMMONS,
      timestamp: "2026-01-01T00:00:00.000Z",
      prev: [],
      data: {
        ctid, dispute_tx_id: disputeTx.tx_id, juror_tip_id: jurorTipId,
        commit_deadline: "2026-01-02T00:00:00.000Z",
        reveal_deadline: revealDeadline,
        is_appeal: isAppeal,
      },
    });
    dag.addTx(summons);
  }

  // Optionally seed reveals so verdict can compute a real outcome.
  if (withReveals) {
    const { signBody } = require(path.join(SHARED, "crypto"));
    for (const jurorTipId of jurorTipIds) {
      const kp = identityKeys[jurorTipId];
      const signedFields = { juror_tip_id: jurorTipId, vote: "MISMATCH", salt: "s", confirmed_origin: "AG" };
      const data = { ...signedFields, ctid, is_appeal: isAppeal };
      data.signature = signBody(signedFields, kp.privateKey);
      const revealTx = signNodeTx({
        tx_type: TX_TYPES.JURY_VOTE_REVEAL,
        timestamp: "2026-04-10T00:00:00.000Z",  // before reveal_deadline
        prev: [],
        data,
      });
      dag.addTx(revealTx);
    }
  }

  // Capture submitBatch calls for assertions.
  const submitted = [];
  const submitBatch = (txs) => { submitted.push(txs); };

  const trigger = createVerdictTrigger({ dag, jury, scoring, config, submitBatch });

  return { dag, scoring, config, trigger, ctid, authorTipId, disputerTipId, jurorTipIds, submitted, signNodeTx };
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Heap maintenance via onTxCommitted
// ═══════════════════════════════════════════════════════════════════════════
describe("verdict-trigger: heap maintenance via onTxCommitted", () => {
  test("first JURY_SUMMONS for a (ctid, stage) pushes a heap entry", () => {
    const fx = _setup();
    const summons = fx.dag.getTxsByType(TX_TYPES.JURY_SUMMONS)[0];
    fx.trigger.onTxCommitted(summons);
    expect(fx.trigger.size()).toBe(1);
    const entry = fx.trigger.pending()[0];
    expect(entry.ctid).toBe(fx.ctid);
    expect(entry.stage).toBe("jury");
    expect(entry.deadline).toBe(new Date("2026-04-15T00:00:00.000Z").getTime());
  });

  test("subsequent JURY_SUMMONS for SAME (ctid, stage) does NOT add duplicate entry", () => {
    // Multiple summonses for the same dispute (one per juror) — the
    // trigger should dedup them into a single heap entry keyed on
    // (ctid, stage). Use the protocol's JURY.QUORUM so the fixture
    // size matches what real disputes produce.
    const fx = _setup();
    const summonses = fx.dag.getTxsByType(TX_TYPES.JURY_SUMMONS);
    expect(summonses.length).toBe(JURY.QUORUM);
    for (const s of summonses) fx.trigger.onTxCommitted(s);
    expect(fx.trigger.size()).toBe(1);  // dedup on (ctid, stage)
  });

  test("JURY_SUMMONS for DIFFERENT stages (jury + appeal) add separate entries", () => {
    const fxJury = _setup({ revealDeadline: "2026-04-15T00:00:00.000Z", isAppeal: false });
    const fxAppeal = _setup({ revealDeadline: "2026-05-01T00:00:00.000Z", isAppeal: true });

    // Push jury summons + appeal summons (with same ctid in this test) into one trigger.
    const trigger = fxJury.trigger;
    const jurySummons = fxJury.dag.getTxsByType(TX_TYPES.JURY_SUMMONS)[0];
    const appealSummons = fxAppeal.dag.getTxsByType(TX_TYPES.JURY_SUMMONS)[0];

    trigger.onTxCommitted(jurySummons);
    trigger.onTxCommitted(appealSummons);

    expect(trigger.size()).toBe(2);
    const stages = new Set(trigger.pending().map(e => e.stage));
    expect(stages.has("jury")).toBe(true);
    expect(stages.has("appeal")).toBe(true);
  });

  test("ADJUDICATION_RESULT commit drops the matching jury entry", () => {
    const fx = _setup();
    const summons = fx.dag.getTxsByType(TX_TYPES.JURY_SUMMONS)[0];
    fx.trigger.onTxCommitted(summons);
    expect(fx.trigger.size()).toBe(1);

    const adj = { tx_type: TX_TYPES.ADJUDICATION_RESULT, data: { ctid: fx.ctid, verdict: VERDICT.UPHELD } };
    fx.trigger.onTxCommitted(adj);
    expect(fx.trigger.size()).toBe(0);
  });

  test("APPEAL_FILED commit drops the matching jury entry (jury stage superseded)", () => {
    const fx = _setup();
    fx.trigger.onTxCommitted(fx.dag.getTxsByType(TX_TYPES.JURY_SUMMONS)[0]);
    expect(fx.trigger.size()).toBe(1);

    const appeal = { tx_type: TX_TYPES.APPEAL_FILED, data: { ctid: fx.ctid } };
    fx.trigger.onTxCommitted(appeal);
    expect(fx.trigger.size()).toBe(0);
  });

  test("APPEAL_RESULT commit drops the matching appeal entry", () => {
    const fx = _setup({ isAppeal: true });
    fx.trigger.onTxCommitted(fx.dag.getTxsByType(TX_TYPES.JURY_SUMMONS)[0]);
    expect(fx.trigger.size()).toBe(1);

    const appResult = { tx_type: TX_TYPES.APPEAL_RESULT, data: { ctid: fx.ctid, verdict: VERDICT.DISMISSED } };
    fx.trigger.onTxCommitted(appResult);
    expect(fx.trigger.size()).toBe(0);
  });

  test("ignores tx types it doesn't care about", () => {
    const fx = _setup();
    // No rehydrate — heap starts empty, nothing should populate it.
    const irrelevant = { tx_type: TX_TYPES.SCORE_UPDATE, data: { tip_id: "x", delta: 1, reason: "noise" } };
    fx.trigger.onTxCommitted(irrelevant);
    expect(fx.trigger.size()).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Boot rehydration
// ═══════════════════════════════════════════════════════════════════════════
describe("verdict-trigger: boot rehydration", () => {
  test("rehydrate scans pending JURY_SUMMONS and pushes heap entries", () => {
    const fx = _setup();
    // Trigger created in fixture but heap is empty until first activity.
    expect(fx.trigger.size()).toBe(0);
    fx.trigger.rehydrate();
    expect(fx.trigger.size()).toBe(1);
    expect(fx.trigger.pending()[0].ctid).toBe(fx.ctid);
  });

  test("rehydrate skips disputes that already have an ADJUDICATION_RESULT", () => {
    const fx = _setup();
    // Plant a synthetic resolved-result so rehydrate sees the dispute as
    // closed. Use addTx with a real signature path to avoid validator
    // tripping — easier to fake via direct dag.saveTx, but we use addTx
    // for realism.
    const adj = fx.signNodeTx({
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: "2026-04-15T00:00:01.000Z",
      prev: [],
      data: {
        ctid: fx.ctid, verdict: VERDICT.DISMISSED, declared_origin: "OH",
        confirmed_origin: null, author_tip_id: fx.authorTipId, author_score_delta: 0,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
        match_count: 1, mismatch_count: 0, abstain_count: 0,
        juror_votes: [],
      },
    });
    fx.dag.addTx(adj);

    fx.trigger.rehydrate();
    expect(fx.trigger.size()).toBe(0);
  });

  test("rehydrate skips jury entries that already have an APPEAL_FILED", () => {
    const fx = _setup();
    const appeal = fx.signNodeTx({
      tx_type: TX_TYPES.APPEAL_FILED,
      timestamp: "2026-04-15T00:00:01.000Z",
      prev: [],
      data: { ctid: fx.ctid, appellant_tip_id: fx.disputerTipId, stage2_verdict: VERDICT.UPHELD, stake: 0 },
    });
    fx.dag.addTx(appeal);

    fx.trigger.rehydrate();
    expect(fx.trigger.size()).toBe(0);
  });

  test("rehydrate is idempotent — second call doesn't duplicate", () => {
    const fx = _setup();
    fx.trigger.rehydrate();
    fx.trigger.rehydrate();
    expect(fx.trigger.size()).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. checkPending — the post-round trigger
// ═══════════════════════════════════════════════════════════════════════════
describe("verdict-trigger: checkPending (post-round)", () => {
  test("noop when heap is empty (no rehydrate, no commits)", () => {
    const fx = _setup();
    // No rehydrate, no commits → heap is empty → checkPending shouldn't
    // submit anything regardless of cert.timestamp.
    fx.trigger.checkPending(new Date("2030-01-01T00:00:00.000Z").getTime());
    expect(fx.submitted.length).toBe(0);
  });

  test("noop when cert.timestamp is below the smallest deadline", () => {
    const fx = _setup({ revealDeadline: "2026-04-15T00:00:00.000Z" });
    fx.trigger.rehydrate();
    fx.trigger.checkPending(new Date("2026-04-10T00:00:00.000Z").getTime());
    expect(fx.submitted.length).toBe(0);
    expect(fx.trigger.size()).toBe(1);
  });

  test("fires verdict batch when cert.timestamp crosses the deadline", () => {
    const fx = _setup({ revealDeadline: "2026-04-15T00:00:00.000Z", withReveals: true });
    fx.trigger.rehydrate();

    fx.trigger.checkPending(new Date("2026-04-15T00:00:01.000Z").getTime());

    expect(fx.submitted.length).toBe(1);
    const batch = fx.submitted[0];
    expect(Array.isArray(batch)).toBe(true);
    expect(batch.length).toBeGreaterThan(0);
    // First tx in a jury verdict batch is ADJUDICATION_RESULT.
    expect(batch[0].tx_type).toBe(TX_TYPES.ADJUDICATION_RESULT);
    expect(batch[0].data.ctid).toBe(fx.ctid);
    // Heap entry consumed.
    expect(fx.trigger.size()).toBe(0);
  });

  test("fires APPEAL_RESULT batch for appeal-stage entries", () => {
    const fx = _setup({ revealDeadline: "2026-04-15T00:00:00.000Z", isAppeal: true, withReveals: true });

    // Need a Stage 2 ADJUDICATION_RESULT and APPEAL_FILED in the DAG so
    // buildAppealBatch has the prior context to compute the reversal.
    const adj = fx.signNodeTx({
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: "2026-04-12T00:00:00.000Z",
      prev: [],
      data: {
        ctid: fx.ctid, verdict: VERDICT.UPHELD,
        declared_origin: "OH", confirmed_origin: "AG",
        author_tip_id: fx.authorTipId, author_score_delta: -50,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
        match_count: 0, mismatch_count: 3, abstain_count: 0,
        juror_votes: [],
      },
    });
    fx.dag.addTx(adj);
    const appealFiled = fx.signNodeTx({
      tx_type: TX_TYPES.APPEAL_FILED,
      timestamp: "2026-04-13T00:00:00.000Z",
      prev: [],
      data: {
        ctid: fx.ctid, appellant_tip_id: fx.authorTipId,
        stage2_verdict: VERDICT.UPHELD, stake: 0,
      },
    });
    fx.dag.addTx(appealFiled);

    fx.trigger.rehydrate();
    fx.trigger.checkPending(new Date("2026-04-15T00:00:01.000Z").getTime());

    expect(fx.submitted.length).toBe(1);
    const batch = fx.submitted[0];
    expect(batch[0].tx_type).toBe(TX_TYPES.APPEAL_RESULT);
    expect(batch[0].data.ctid).toBe(fx.ctid);
  });

  test("idempotency — skips ctid that already has ADJUDICATION_RESULT in DAG", () => {
    const fx = _setup({ revealDeadline: "2026-04-15T00:00:00.000Z", withReveals: true });
    fx.trigger.rehydrate();

    // Plant a verdict in the DAG before checkPending fires.
    const adj = fx.signNodeTx({
      tx_type: TX_TYPES.ADJUDICATION_RESULT,
      timestamp: "2026-04-15T00:00:01.000Z",
      prev: [],
      data: {
        ctid: fx.ctid, verdict: VERDICT.DISMISSED, declared_origin: "OH",
        confirmed_origin: null, author_tip_id: fx.authorTipId, author_score_delta: 0,
        pre_dispute_status: CONTENT_STATUS.REGISTERED,
        match_count: 3, mismatch_count: 0, abstain_count: 0, juror_votes: [],
      },
    });
    fx.dag.addTx(adj);

    fx.trigger.checkPending(new Date("2026-04-15T00:00:02.000Z").getTime());
    expect(fx.submitted.length).toBe(0);  // skipped — already resolved
  });

  test("submitBatch errors are non-fatal — heap entry still consumed; next round retries via rehydrate", () => {
    const fx = _setup({ revealDeadline: "2026-04-15T00:00:00.000Z", withReveals: true });
    fx.trigger.rehydrate();

    // Replace submitBatch with one that throws (simulates mempool full).
    let attempts = 0;
    const throwingTrigger = createVerdictTrigger({
      dag: fx.dag, jury, scoring: fx.scoring, config: fx.config,
      submitBatch: () => { attempts++; throw new Error("mempool full"); },
    });
    throwingTrigger.rehydrate();

    expect(() =>
      throwingTrigger.checkPending(new Date("2026-04-15T00:00:01.000Z").getTime())
    ).not.toThrow();
    expect(attempts).toBe(1);  // we DID try
    expect(throwingTrigger.size()).toBe(0);  // entry popped (won't retry until next rehydrate)
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Defensive — invalid input handling
// ═══════════════════════════════════════════════════════════════════════════
describe("verdict-trigger: defensive input handling", () => {
  test("missing dependency makes checkPending a no-op", () => {
    const fx = _setup();
    const trigger = createVerdictTrigger({ dag: fx.dag, /* no jury, scoring, submitBatch */ });
    trigger.rehydrate();
    expect(trigger.size()).toBe(1);  // heap still populated
    trigger.checkPending(new Date("2030-01-01T00:00:00.000Z").getTime());
    // No submitBatch was called, but no error either. Heap untouched
    // because the function short-circuited before popping.
    expect(trigger.size()).toBe(1);
  });

  test("invalid certTimestamp is a no-op", () => {
    const fx = _setup();
    fx.trigger.rehydrate();
    fx.trigger.checkPending(0);
    fx.trigger.checkPending(NaN);
    fx.trigger.checkPending(-5);
    expect(fx.submitted.length).toBe(0);
    expect(fx.trigger.size()).toBe(1);
  });

  test("missing dag throws at construction", () => {
    expect(() => createVerdictTrigger({})).toThrow(/dag required/);
  });
});
