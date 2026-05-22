/**
 * @file tests/dag/clean-record-eligibility.test.js
 * @description Tests for `dag.getCleanRecordEligible(cutoff)` — the
 * eligibility query that decides who receives a clean-record bonus.
 *
 * Drives the query against BOTH stores (SQLite + MemoryStore) since the
 * SQL and JS implementations are independent; a regression in one is
 * silent for the other. Each test case verifies the same predicate on
 * both — if they disagree, the test fails on the second store.
 *
 * Predicate (post-fix):
 *   - identity.status = 'active'
 *   - identity.registered_at <= cutoff   (≥ CLEAN_PERIOD_DAYS old)
 *   - registered ≥1 OH/AA content in last CLEAN_PERIOD_DAYS
 *     (any other tx — jury reveals, score updates — does NOT qualify)
 *   - no UPHELD adjudication in last CLEAN_PERIOD_DAYS
 *   - no prior clean_record_bonus in last CLEAN_PERIOD_DAYS
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../../../shared/time");

const path = require("path");
const os = require("os");
const fs = require("fs");

const SHARED = path.resolve(__dirname, "../../../shared");
const SRC = path.resolve(__dirname, "../../src");

const { initCrypto, shake256, computeTxId } = require(path.join(SHARED, "crypto"));
const { TX_TYPES } = require(path.join(SHARED, "constants"));
const { initDAG } = require(path.join(SRC, "dag"));

beforeAll(async () => {
  await initCrypto();
});

const TIPS = {
  freshUser: "tip://id/fresh-user",         // registered yesterday — should fail
  oldClean: "tip://id/old-clean",           // registered last year, active recently, clean — should pass
  oldDormant: "tip://id/old-dormant",       // registered last year, no recent activity — should fail
  oldDisputed: "tip://id/old-disputed",     // registered last year, has UPHELD adjudication — should fail
  oldRecentlyBonused: "tip://id/old-bonused", // registered last year, already got bonus — should fail
};

// ─── Fixture builders ────────────────────────────────────────────────────────

function _saveIdentity(dag, tipId, registeredAt) {
  dag.saveIdentity({
    tip_id: tipId,
    region: "US",
    public_key: "00",
    root_public_key: "00",
    vp_id: "tip://vp/v1",
    verification_tier: "T1",
    founding: false,
    status: "active",
    registered_at: registeredAt,
    tx_id: shake256(`id:${tipId}`),
  });
}

function _addTx(dag, body) {
  const txBody = { ...body, prev: body.prev || dag.getRecentPrev() };
  txBody.tx_id = computeTxId(txBody);
  txBody.signature = "00";
  dag.addTx(txBody);
  return txBody;
}

function _seedActivity(dag, tipId, timestamp, origin = "OH") {
  // Spec rule: only OH/AA content registration counts as qualifying
  // activity for the clean-record bonus. Other tx types (jury reveals,
  // SCORE_UPDATEs) deliberately don't satisfy the eligibility predicate.
  // Each call gets a unique ctid so the same tipId can register multiple
  // contents without tx_id collisions.
  _addTx(dag, {
    tx_type: TX_TYPES.REGISTER_CONTENT,
    timestamp,
    data: {
      ctid: `tip://c/test-${shake256(`${tipId}:${timestamp}`).slice(0, 14)}`,
      signer_tip_id: tipId,
      origin_code: origin,
      content_hash: shake256(`${tipId}:${timestamp}`),
      node_id: "tip://node/n1",
    },
  });
}

function _seedUpheld(dag, tipId, timestamp) {
  _addTx(dag, {
    tx_type: TX_TYPES.ADJUDICATION_RESULT,
    timestamp,
    data: { ctid: "tip://content/x", verdict: "UPHELD", author_tip_id: tipId, declared_origin: "OH", node_id: "tip://node/n1" },
  });
}

function _seedPriorBonus(dag, tipId, timestamp) {
  _addTx(dag, {
    tx_type: TX_TYPES.SCORE_UPDATE,
    timestamp,
    data: { tip_id: tipId, delta: 10, reason: "clean_record_bonus", node_id: "tip://node/n1" },
  });
}

/**
 * Set up a DAG containing 5 identities, one for each scenario, and run
 * the eligibility query with `cutoff` set to "today minus 90 days".
 * Returns the eligible-tip-id array.
 */
function _populateAndQuery(dag) {
  const NOW = 1806537600000;        // "today" for the test
  const CUTOFF = 1798761600000;     // 90 days before NOW
  const REGISTERED_OLD = 1767225600000;  // > 90 days before cutoff
  const REGISTERED_RECENT = 1806364800000; // 2 days before NOW (way under 90)

  // freshUser: registered too recently → fails registered_at <= cutoff
  _saveIdentity(dag, TIPS.freshUser, REGISTERED_RECENT);
  _seedActivity(dag, TIPS.freshUser, 1806451200000);

  // oldClean: registered long ago, active recently, no UPHELD, no prior bonus
  _saveIdentity(dag, TIPS.oldClean, REGISTERED_OLD);
  _seedActivity(dag, TIPS.oldClean, 1805068800000);

  // oldDormant: registered long ago, NO activity in window → fails
  _saveIdentity(dag, TIPS.oldDormant, REGISTERED_OLD);
  _seedActivity(dag, TIPS.oldDormant, 1780272000000); // before cutoff

  // oldDisputed: registered long ago, recent UPHELD → fails
  _saveIdentity(dag, TIPS.oldDisputed, REGISTERED_OLD);
  _seedActivity(dag, TIPS.oldDisputed, 1805068800000);
  _seedUpheld(dag, TIPS.oldDisputed, 1801440000000);

  // oldRecentlyBonused: registered long ago, already got bonus inside window → fails
  _saveIdentity(dag, TIPS.oldRecentlyBonused, REGISTERED_OLD);
  _seedActivity(dag, TIPS.oldRecentlyBonused, 1805068800000);
  _seedPriorBonus(dag, TIPS.oldRecentlyBonused, 1802649600000);

  void NOW;  // referenced only to document the scenario; CUTOFF is what we pass
  return dag.getCleanRecordEligible(CUTOFF);
}

const SCENARIOS = [
  ["MemoryStore (in-memory)", () => initDAG({ dbPath: ":memory:" })],
  ["SQLiteStore (real DB)", () => {
    const dbPath = path.join(os.tmpdir(), `tip-clean-record-${nowMs()}-${Math.random().toString(36).slice(2)}.db`);
    const dag = initDAG({ dbPath });
    return { dag, _cleanup: () => { try { fs.unlinkSync(dbPath); } catch { /* ignore */ } } };
  }],
];

describe.each(SCENARIOS)("getCleanRecordEligible — %s", (_label, makeStore) => {
  test("filters correctly across all five scenarios", () => {
    const made = makeStore();
    const dag = made.dag || made;
    try {
      const eligible = _populateAndQuery(dag);
      expect(eligible).toEqual([TIPS.oldClean]);
      expect(eligible).not.toContain(TIPS.freshUser);
      expect(eligible).not.toContain(TIPS.oldDormant);
      expect(eligible).not.toContain(TIPS.oldDisputed);
      expect(eligible).not.toContain(TIPS.oldRecentlyBonused);
    } finally {
      if (made._cleanup) made._cleanup();
      if (typeof dag.close === "function") dag.close();
    }
  });

  test("identity registered exactly AT cutoff is eligible (boundary)", () => {
    const made = makeStore();
    const dag = made.dag || made;
    try {
      const CUTOFF = 1798761600000;
      _saveIdentity(dag, "tip://id/edge", CUTOFF);
      _seedActivity(dag, "tip://id/edge", 1801440000000);
      const eligible = dag.getCleanRecordEligible(CUTOFF);
      expect(eligible).toContain("tip://id/edge");
    } finally {
      if (made._cleanup) made._cleanup();
      if (typeof dag.close === "function") dag.close();
    }
  });

  test("identity registered one second after cutoff is NOT eligible", () => {
    const made = makeStore();
    const dag = made.dag || made;
    try {
      const CUTOFF = 1798761600000;
      _saveIdentity(dag, "tip://id/edge", 1798761601000);
      _seedActivity(dag, "tip://id/edge", 1801440000000);
      const eligible = dag.getCleanRecordEligible(CUTOFF);
      expect(eligible).not.toContain("tip://id/edge");
    } finally {
      if (made._cleanup) made._cleanup();
      if (typeof dag.close === "function") dag.close();
    }
  });

  test("revoked (status != 'active') identity is NOT eligible", () => {
    const made = makeStore();
    const dag = made.dag || made;
    try {
      const CUTOFF = 1798761600000;
      _saveIdentity(dag, "tip://id/revoked", 1735689600000);
      _seedActivity(dag, "tip://id/revoked", 1801440000000);
      // Revoke after seeding — directly mark in DAG.
      dag.addRevocation("tip://id/revoked", TX_TYPES.REVOKE_VOLUNTARY, 1802649600000, shake256("rev"));
      const eligible = dag.getCleanRecordEligible(CUTOFF);
      expect(eligible).not.toContain("tip://id/revoked");
    } finally {
      if (made._cleanup) made._cleanup();
      if (typeof dag.close === "function") dag.close();
    }
  });
});
