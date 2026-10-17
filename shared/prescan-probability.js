/**
 * @file tip-protocol/shared/prescan-probability.js
 * @description The precision a pre-scan probability carries in consensus.
 *
 * The state root hashes prescan_probability at basis points. A value kept
 * finer than that can be read back differently after a database round-trip
 * (Postgres float4 vs float64 memory) and land on the other side of a
 * rounding edge, so the blend is rounded here once and every later stage
 * (transaction, memory, store, snapshot, hash) holds the same number.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const PROBABILITY_BASIS_POINTS = 10000;

function quantizeProbability(p) {
  return typeof p === "number" && Number.isFinite(p) ? Math.round(p * PROBABILITY_BASIS_POINTS) : 0;
}

function roundProbability(p) {
  return quantizeProbability(p) / PROBABILITY_BASIS_POINTS;
}

module.exports = { PROBABILITY_BASIS_POINTS, quantizeProbability, roundProbability };
