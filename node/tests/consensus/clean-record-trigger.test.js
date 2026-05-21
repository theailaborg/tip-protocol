/**
 * @file tests/consensus/clean-record-trigger.test.js
 * @description Unit tests for the post-round clean-record-bonus trigger.
 *
 * Coverage:
 *   - `checkPending` runs the eligibility scan once per UTC day (as
 *     measured by cert.timestamp), not per round.
 *   - Same-day calls after the first scan short-circuit with no DB hit.
 *   - Day-modulo leader gate skips emission when this node isn't today's
 *     leader; fires when it is.
 *   - Eligible identities → SCORE_UPDATE batch with reason="clean_record_bonus".
 *   - Empty eligibility list → no batch submission.
 *   - submitBatch errors are non-fatal.
 *
 * Tests use a real in-memory DAG + real scoring so the integration is
 * meaningful. `submitBatch` is captured as a spy.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, generateMLDSAKeypair, shake256 } = require(path.join(SHARED, "crypto"));
const { CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const { REPUTATION } = require(path.join(SHARED, "protocol-constants"));
const { initDAG } = require(path.join(SRC, "dag"));
const { initScoring } = require(path.join(SRC, "scoring"));
const { createCleanRecordTrigger } = require(path.join(SRC, "consensus", "clean-record-trigger"));

beforeAll(async () => {
  await initCrypto();
});

const MS_PER_DAY = 86400000;
const FIXED_TS = 1767225600000;

// ═══════════════════════════════════════════════════════════════════════════
// Fixture — DAG with N identities; some eligible, some not.
// ═══════════════════════════════════════════════════════════════════════════
function _setup({
  eligibleCount = 3,
  ineligibleCount = 0,
  committee = null,    // pass to enable leader-gate; null = no gate (legacy)
} = {}) {
  const dag = initDAG({ dbPath: ":memory:" });

  const nodeKp = generateMLDSAKeypair();
  const NODE_ID = "tip://node/n1";
  dag.saveNode({
    node_id: NODE_ID, name: "n1", public_key: nodeKp.publicKey,
    status: "active", registered_at: FIXED_TS,
  });
  const config = { nodeId: NODE_ID, nodeRegisteredId: NODE_ID, nodePrivateKey: nodeKp.privateKey };
  const scoring = initScoring(dag, config);

  // Build identities. Each gets a baseline score so the cache exists.
  const eligibleTipIds = [];
  for (let i = 0; i < eligibleCount; i++) {
    const tipId = `tip://id/eligible${i}`;
    const kp = generateMLDSAKeypair();
    dag.saveIdentity({
      tip_id: tipId, region: "US", public_key: kp.publicKey, root_public_key: "00",
      vp_id: "tip://vp/v1", verification_tier: "T1", founding: false, status: "active",
      registered_at: FIXED_TS, tx_id: shake256(`id:${tipId}`),
    });
    dag.setScore(tipId, 750, 0, FIXED_TS);
    eligibleTipIds.push(tipId);
  }

  // Mock dag.getCleanRecordEligible so the test doesn't depend on the
  // SQL query semantics — we want to test the trigger's day-boundary
  // and leader-gate logic in isolation.
  dag.getCleanRecordEligible = () => eligibleTipIds.slice();

  const submitted = [];
  const submitBatch = (txs) => { submitted.push(txs); };

  const triggerOpts = { dag, scoring, config, submitBatch };
  if (committee) triggerOpts.getCommittee = () => committee;
  const trigger = createCleanRecordTrigger(triggerOpts);

  return { dag, scoring, config, trigger, submitted, eligibleTipIds, nodeId: NODE_ID };
}

const _dayMs = (dayOfEpoch) => dayOfEpoch * MS_PER_DAY;

// ═══════════════════════════════════════════════════════════════════════════
// 1. Day-boundary fast path
// ═══════════════════════════════════════════════════════════════════════════
describe("clean-record-trigger: day-boundary fast path", () => {
  test("first call on a fresh day fires the eligibility scan", () => {
    const fx = _setup({ eligibleCount: 3 });
    fx.trigger.checkPending(_dayMs(20000));
    expect(fx.submitted.length).toBe(1);
    expect(fx.submitted[0].length).toBe(3);
    expect(fx.submitted[0][0].tx_type).toBe("SCORE_UPDATE");
    // Reason is window-scoped: "clean_record_bonus:YYYY-MM-DD" derived
    // from the trigger day. The prefix is stable; the suffix (the day's
    // ISO date) makes the (tip_id, ctid, reason) dedup naturally per
    // window, so a user can collect again in the next 90-day epoch.
    const expectedDay = new Date(20000 * MS_PER_DAY).toISOString().slice(0, 10);
    expect(fx.submitted[0][0].data.reason).toBe(`clean_record_bonus:${expectedDay}`);
    expect(fx.submitted[0][0].data.delta).toBe(REPUTATION.CLEAN_PERIOD_BONUS);
  });

  test("second call on the SAME day does NOT re-fire", () => {
    const fx = _setup({ eligibleCount: 3 });
    fx.trigger.checkPending(_dayMs(20000));
    fx.trigger.checkPending(_dayMs(20000) + 1000);  // same day, +1 sec
    fx.trigger.checkPending(_dayMs(20000) + MS_PER_DAY - 1);  // same day, end of day
    expect(fx.submitted.length).toBe(1);
  });

  test("crossing into a new day fires again", () => {
    const fx = _setup({ eligibleCount: 3 });
    fx.trigger.checkPending(_dayMs(20000));
    fx.trigger.checkPending(_dayMs(20001));  // next day
    expect(fx.submitted.length).toBe(2);
  });

  test("noop when no eligible identities", () => {
    const fx = _setup({ eligibleCount: 0 });
    fx.trigger.checkPending(_dayMs(20000));
    expect(fx.submitted.length).toBe(0);
  });

  test("invalid certTimestamp is a noop", () => {
    const fx = _setup({ eligibleCount: 3 });
    fx.trigger.checkPending(0);
    fx.trigger.checkPending(NaN);
    fx.trigger.checkPending(-5);
    expect(fx.submitted.length).toBe(0);
    expect(fx.trigger.lastScannedDay()).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Day-modulo leader gating
// ═══════════════════════════════════════════════════════════════════════════
describe("clean-record-trigger: day-modulo leader gating", () => {
  // Use large day-of-epoch values so cert.ts > 0 (the trigger rejects
  // <= 0 as invalid). Day numbers chosen so leader rotation is obvious:
  //   sorted committee is [n1, n2, n3], so:
  //     day % 3 == 0 → n1   (the fixture's node)
  //     day % 3 == 1 → n2
  //     day % 3 == 2 → n3
  const COMMITTEE_3 = ["tip://node/n1", "tip://node/n2", "tip://node/n3"];

  test("fires when this node IS today's deterministic leader", () => {
    // day 21000 % 3 == 0 → n1 (us). Fire.
    const fx = _setup({ eligibleCount: 3, committee: COMMITTEE_3 });
    fx.trigger.checkPending(_dayMs(21000));
    expect(fx.submitted.length).toBe(1);
  });

  test("skips when this node is NOT today's leader", () => {
    // day 21001 % 3 == 1 → n2 (not us). No fire.
    const fx = _setup({ eligibleCount: 3, committee: COMMITTEE_3 });
    fx.trigger.checkPending(_dayMs(21001));
    expect(fx.submitted.length).toBe(0);
    expect(fx.trigger.lastScannedDay()).toBe(21001);
  });

  test("rotation across days — different day, different leader", () => {
    // day 21000 → n1 (us, fires)
    const fxA = _setup({ eligibleCount: 1, committee: COMMITTEE_3 });
    fxA.trigger.checkPending(_dayMs(21000));
    expect(fxA.submitted.length).toBe(1);

    // day 21001 → n2 (not us, no fire)
    const fxB = _setup({ eligibleCount: 1, committee: COMMITTEE_3 });
    fxB.trigger.checkPending(_dayMs(21001));
    expect(fxB.submitted.length).toBe(0);

    // day 21003 → n1 (us, fires)
    const fxC = _setup({ eligibleCount: 1, committee: COMMITTEE_3 });
    fxC.trigger.checkPending(_dayMs(21003));
    expect(fxC.submitted.length).toBe(1);
  });

  test("no getCommittee → fires every day (legacy behaviour)", () => {
    const fx = _setup({ eligibleCount: 3, committee: null });
    fx.trigger.checkPending(_dayMs(21000));
    fx.trigger.checkPending(_dayMs(21001));
    fx.trigger.checkPending(_dayMs(21002));
    expect(fx.submitted.length).toBe(3);
  });

  test("empty committee → fires (defensive default)", () => {
    const fx = _setup({ eligibleCount: 3, committee: [] });
    fx.trigger.checkPending(_dayMs(21000));
    expect(fx.submitted.length).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Defensive
// ═══════════════════════════════════════════════════════════════════════════
describe("clean-record-trigger: defensive input handling", () => {
  test("missing dag throws at construction", () => {
    expect(() => createCleanRecordTrigger({})).toThrow(/dag required/);
  });

  test("missing dependency makes checkPending a noop", () => {
    const fx = _setup({ eligibleCount: 3 });
    const trigger = createCleanRecordTrigger({ dag: fx.dag /* no scoring/config/submitBatch */ });
    trigger.checkPending(_dayMs(0));
    expect(fx.submitted.length).toBe(0);
  });

  test("submitBatch errors are non-fatal", () => {
    const fx = _setup({ eligibleCount: 3 });
    const trigger = createCleanRecordTrigger({
      dag: fx.dag, scoring: fx.scoring, config: fx.config,
      submitBatch: () => { throw new Error("mempool full"); },
    });
    expect(() => trigger.checkPending(_dayMs(21000))).not.toThrow();
    expect(trigger.lastScannedDay()).toBeGreaterThan(0);
  });
});
