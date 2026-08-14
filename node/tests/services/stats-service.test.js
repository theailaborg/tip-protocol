/**
 * @file tests/services/stats-service.test.js
 * @description Unit tests for stats-service: nodeSnapshot (GET /stats) and the
 * app-level scoringSnapshot aggregate (GET /stats/scoring). Aggregate-only:
 * tier distribution, score summary, dispute outcomes. No per-identity rows.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const SRC = path.resolve(__dirname, "../../src");
const SHARED = path.resolve(__dirname, "../../../shared");

const { createStatsService } = require(path.join(SRC, "services", "stats-service"));
const { TX_TYPES, CONTENT_STATUS } = require(path.join(SHARED, "constants"));
const PC = require(path.join(SHARED, "protocol-constants"));

// scores chosen to land one identity in each tier (thresholds 850/650/400/200)
const IDENTITIES = [
  { tip_id: "tip://id/US-a", status: "active", score: 900 }, // HIGHLY_TRUSTED
  { tip_id: "tip://id/US-b", status: "active", score: 700 }, // TRUSTED
  { tip_id: "tip://id/US-c", status: "active", score: 500, offense_count: 2 }, // VERIFIED, offenders
  { tip_id: "tip://id/US-d", status: "active", score: 300 }, // CAUTION
  { tip_id: "tip://id/US-e", status: "revoked", score: 100 }, // NOT_TRUSTED, revoked
];

function makeDag(overrides = {}) {
  const scoreMap = new Map(IDENTITIES.map(i => [i.tip_id, { score: i.score, offense_count: i.offense_count || 0 }]));
  const revoked = new Set(IDENTITIES.filter(i => i.status === "revoked").map(i => i.tip_id));
  const txByType = {
    [TX_TYPES.ADJUDICATION_RESULT]: [
      { data: { verdict: "UPHELD" } }, { data: { verdict: "UPHELD" } },
      { data: { verdict: "DISMISSED" } }, { data: { verdict: "NO_QUORUM" } },
      { data: { verdict: "GARBAGE" } }, // unknown verdict ignored
    ],
    [TX_TYPES.CONTENT_DISPUTED]: [{}, {}, {}],
    [TX_TYPES.APPEAL_RESULT]: [{}],
  };
  return {
    getAllIdentities: () => IDENTITIES.map(i => ({ tip_id: i.tip_id, status: i.status })),
    isRevoked: id => revoked.has(id),
    getScore: id => scoreMap.get(id) || null,
    getTxsByType: t => txByType[t] || [],
    contentCount: () => 12,
    getContentByStatus: s => (s === CONTENT_STATUS.DISPUTED ? [{}, {}] : []),
    count: () => 7,
    ...overrides,
  };
}

function makeService(dag = makeDag(), extra = {}) {
  const config = { nodeId: "tip://node/self", nodeRegisteredId: "tip://node/self", nodeType: "full", nodeVersion: "2.0.0" };
  return createStatsService({ dag, config, consensus: { current: null }, network: { current: null }, ...extra });
}

describe("stats-service", () => {
  beforeAll(() => { if (!PC.isInitialized()) PC.init(); });

  describe("nodeSnapshot", () => {
    test("returns node/consensus/dag/memory shape without a consensus or network", () => {
      const snap = makeService().nodeSnapshot();
      expect(snap.node).toMatchObject({ node_id: "tip://node/self", node_type: "full", version: "2.0.0" });
      expect(snap.network).toBeNull();
      expect(snap.consensus).toBeNull();
      expect(snap.dag.tx_count).toBe(7);
      expect(snap.memory_mb).toHaveProperty("rss");
      expect(snap).toHaveProperty("timestamp");
    });
  });

  describe("scoringSnapshot", () => {
    test("buckets every identity into exactly one tier", () => {
      const { identities } = makeService().scoringSnapshot();
      expect(identities.total).toBe(5);
      expect(identities.by_tier).toEqual({
        HIGHLY_TRUSTED: 1, TRUSTED: 1, VERIFIED: 1, CAUTION: 1, NOT_TRUSTED: 1,
      });
      const summed = Object.values(identities.by_tier).reduce((a, b) => a + b, 0);
      expect(summed).toBe(identities.total);
    });

    test("reports revoked, offenders, and score stats", () => {
      const { identities } = makeService().scoringSnapshot();
      expect(identities.revoked).toBe(1);
      expect(identities.with_offenses).toBe(1);
      expect(identities.score).toEqual({ min: 100, max: 900, mean: 500, median: 500 });
    });

    test("counts dispute outcomes and ignores unknown verdicts", () => {
      const { disputes } = makeService().scoringSnapshot();
      expect(disputes.filed_total).toBe(3);
      expect(disputes.appeals_total).toBe(1);
      expect(disputes.resolved).toEqual({ UPHELD: 2, DISMISSED: 1, CONSERVATIVE_LABEL: 0, NO_QUORUM: 1 });
    });

    test("counts content total and open disputes", () => {
      const { content } = makeService().scoringSnapshot();
      expect(content.total).toBe(12);
      expect(content.disputed_open).toBe(2);
    });

    test("falls back to the initial score when an identity has no score record", () => {
      const { identities } = makeService(makeDag({ getScore: () => null })).scoringSnapshot();
      // initial score is 500 (VERIFIED), so all 5 land in VERIFIED
      expect(identities.by_tier.VERIFIED).toBe(5);
      expect(identities.score.min).toBe(500);
      expect(identities.score.max).toBe(500);
    });

    test("empty network yields nulls, not NaN", () => {
      const dag = makeDag({ getAllIdentities: () => [], contentCount: () => 0, getTxsByType: () => [], getContentByStatus: () => [] });
      const { identities } = makeService(dag).scoringSnapshot();
      expect(identities.total).toBe(0);
      expect(identities.score).toEqual({ min: null, max: null, mean: null, median: null });
    });

    test("memoizes within the cache window (recompute not called on second hit)", () => {
      let calls = 0;
      const base = makeDag();
      const dag = { ...base, getAllIdentities: () => { calls++; return base.getAllIdentities(); } };
      const svc = makeService(dag);
      svc.scoringSnapshot();
      svc.scoringSnapshot();
      expect(calls).toBe(1);
    });
  });
});
