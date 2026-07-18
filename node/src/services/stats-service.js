/**
 * @file @tip-protocol/node/src/services/stats-service.js
 * @description Builds the JSON payloads for the /v1/stats endpoints.
 *
 *   nodeSnapshot():     node + network + consensus + dag + memory (GET /stats).
 *                       Cheap live counters; computed per call.
 *   scoringSnapshot():  app-level scoring aggregate (GET /stats/scoring):
 *                        tier distribution, score summary, dispute outcomes.
 *                        Aggregate-only (no per-identity rows) so it stays cheap
 *                        and leaks no account-level data; memoized for
 *                        STATS_SCORING_CACHE_MS so dashboard scrapes don't
 *                        recompute the O(identities) walk on every hit.
 *
 * The route module just calls these and writes the result as JSON, mirroring
 * how metrics-service backs /metrics.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { nowIso, nowMs } = require("../../../shared/time");
const { TX_TYPES, CONTENT_STATUS, STATS_SCORING_CACHE_MS } = require("../../../shared/constants");
const { getTier, SCORE } = require("../../../shared/protocol-constants");

function createStatsService({ dag, config, consensus, network }) {
  let scoringCache = { at: 0, value: null };

  function nodeSnapshot() {
    const net = network?.current;
    const cons = consensus?.current;
    const mem = process.memoryUsage();

    return {
      node: {
        node_id: config.nodeRegisteredId || config.nodeId,
        node_type: config.nodeType,
        version: config.nodeVersion,
        uptime_seconds: Math.floor(process.uptime()),
      },
      network: net ? {
        peer_id: net.peerId,
        peers_connected: net.peerCount(),
        peer_ids: net.peers().map(p => p.toString()),
      } : null,
      consensus: cons ? cons.stats() : null,
      dag: {
        tx_count: (() => { try { return dag.count(); } catch { return null; } })(),
      },
      memory_mb: {
        rss: Math.round(mem.rss / 1048576),
        heap_used: Math.round(mem.heapUsed / 1048576),
        heap_total: Math.round(mem.heapTotal / 1048576),
      },
      timestamp: nowIso(),
    };
  }

  function identitiesSection() {
    const byTier = { HIGHLY_TRUSTED: 0, TRUSTED: 0, VERIFIED: 0, CAUTION: 0, NOT_TRUSTED: 0 };
    const scores = [];
    let revoked = 0;
    let withOffenses = 0;

    for (const idn of dag.getAllIdentities()) {
      if (idn.status === "revoked" || dag.isRevoked(idn.tip_id)) revoked += 1;
      const sc = dag.getScore(idn.tip_id);
      const score = sc && Number.isFinite(sc.score) ? sc.score : SCORE.INITIAL_IDENTITY;
      scores.push(score);
      byTier[getTier(score).name] += 1;
      if (sc && sc.offense_count > 0) withOffenses += 1;
    }

    scores.sort((a, b) => a - b);
    const n = scores.length;
    const median = n ? (n % 2 ? scores[(n - 1) / 2] : Math.round((scores[n / 2 - 1] + scores[n / 2]) / 2)) : null;
    const mean = n ? Math.round(scores.reduce((s, x) => s + x, 0) / n) : null;

    return {
      total: n,
      revoked,
      with_offenses: withOffenses,
      by_tier: byTier,
      score: { min: n ? scores[0] : null, max: n ? scores[n - 1] : null, mean, median },
    };
  }

  function disputesSection() {
    const resolved = { UPHELD: 0, DISMISSED: 0, CONSERVATIVE_LABEL: 0, NO_QUORUM: 0 };
    for (const t of dag.getTxsByType(TX_TYPES.ADJUDICATION_RESULT)) {
      const v = t.data?.verdict;
      if (v && Object.prototype.hasOwnProperty.call(resolved, v)) resolved[v] += 1;
    }
    return {
      filed_total: dag.getTxsByType(TX_TYPES.CONTENT_DISPUTED).length,
      appeals_total: dag.getTxsByType(TX_TYPES.APPEAL_RESULT).length,
      resolved,
    };
  }

  function contentSection() {
    return {
      total: (() => { try { return dag.contentCount(); } catch { return null; } })(),
      disputed_open: dag.getContentByStatus(CONTENT_STATUS.DISPUTED).length,
    };
  }

  function buildScoring() {
    return {
      identities: identitiesSection(),
      content: contentSection(),
      disputes: disputesSection(),
      computed_at: nowIso(),
    };
  }

  function scoringSnapshot() {
    const now = nowMs();
    if (scoringCache.value && now - scoringCache.at < STATS_SCORING_CACHE_MS) return scoringCache.value;
    const value = buildScoring();
    scoringCache = { at: now, value };
    return value;
  }

  return { nodeSnapshot, scoringSnapshot };
}

module.exports = { createStatsService };
