/**
 * @file @tip-protocol/node/src/services/prescan-aggregator.js
 * @description Pure-function aggregator for classifier modality results.
 * Implements the primary-floor + asymmetric-lift algorithm described in
 * my-notes/ASYNC_PRESCAN_ARCHITECTURE.md § Modality weight matrix.
 *
 * Inputs:
 *   - modalityResults: array of per-modality classifier outputs (one entry
 *     per modality the classifier analysed; see CLASSIFIER_API_PROBES.md
 *     for the shape).
 *   - contentType: the resolved primary modality
 *     (text | image | audio | video | multi).
 *
 * Output:
 *   {
 *     probability:      0..1   — final blended probability
 *     overall_degraded: bool   — at least one modality returned a degraded
 *                                signal (error / 0.5 neutral / disagreement)
 *     modality_results: [...]  — enriched per-modality entries with
 *                                applied_weight + degraded flag
 *   }
 *
 * Algorithm:
 *   1. Collapse multi-instance same-modality results by MAX (worst-evidence
 *      wins — three images, one strongly AI = treat as if there's one
 *      strongly-AI image for aggregation purposes).
 *   2. Identify primary modality from contentType (null for "multi").
 *   3. If primary is present and not degraded:
 *        final = primary_prob
 *                + Σ max(0, secondary_prob - primary_prob) × secondary_weight
 *      Degraded secondaries get half-weight (degraded_weight_multiplier).
 *   4. Else (primary missing/degraded, OR contentType="multi"):
 *        fall back to weighted average over present non-degraded modalities.
 *   5. If all modalities are degraded, return 0.5 with overall_degraded=true
 *      (the "no signal" neutral — the worker's retry loop will pick this up).
 *
 * Pure: no IO, no clocks, no DAG access. Fully unit-testable.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { MODALITY_WEIGHTS } = require("../../../shared/protocol-constants");
const { primaryModality } = require("./content-type");

/**
 * A modality result is "degraded" when the classifier couldn't decide
 * reliably. Three independent tells, any of which sets the flag:
 *
 *   - explicit per-modality error
 *   - exact probability 0.5 (the classifier's "no signal" neutral)
 *   - features_used includes "disagreement_override" (multiple providers
 *     disagreed, classifier picked a neutral default)
 */
function isDegraded(m) {
  if (!m || typeof m !== "object") return true;
  if (m.error) return true;
  if (m.probability === 0.5) return true;
  if (Array.isArray(m.features_used) && m.features_used.includes("disagreement_override")) return true;
  return false;
}

/**
 * Collapse multiple results with the same modality by MAX probability.
 * Three image classifier calls → one effective image entry whose
 * probability is the highest of the three.
 *
 * The kept entry is the original max-prob entry, so all per-modality
 * metadata (provider, error, features_used) survives.
 */
function collapseSameModality(results) {
  const byModality = new Map();
  for (const r of results || []) {
    if (!r || !r.modality) continue;
    const prev = byModality.get(r.modality);
    if (!prev || r.probability > prev.probability) byModality.set(r.modality, r);
  }
  return Array.from(byModality.values());
}

/**
 * Traditional weighted average for "multi" or fallback paths.
 * Renormalises by present modality weights so absent modalities don't
 * penalise.
 *
 * Degraded modalities contribute at half-weight (or the genesis
 * multiplier). If every modality is degraded, returns 0.5 (no signal).
 */
function _weightedAverage(results, weights) {
  let num = 0;
  let den = 0;
  for (const r of results) {
    const w = typeof weights[r.modality] === "number" ? weights[r.modality] : 0;
    if (w <= 0) continue;
    const degraded = isDegraded(r);
    const effective = degraded ? w * MODALITY_WEIGHTS.DEGRADED_MULTIPLIER : w;
    num += r.probability * effective;
    den += effective;
  }
  return den > 0 ? num / den : 0.5;
}

/**
 * Aggregate per-modality classifier results into a single probability +
 * overall degraded flag + enriched modality entries.
 *
 * @param {Array}  modalityResults  classifier per-modality output
 * @param {string} contentType      one of valid_content_types
 * @returns {{probability:number, overall_degraded:boolean, modality_results:Array}}
 */
function aggregate(modalityResults, contentType) {
  const collapsed = collapseSameModality(modalityResults);
  const weights = MODALITY_WEIGHTS[contentType] || MODALITY_WEIGHTS.multi;
  const primary = primaryModality(contentType);

  // Enrich each modality with applied_weight + degraded flag for audit.
  const enriched = collapsed.map(m => ({
    modality:          m.modality,
    probability:       m.probability,
    classifier_weight: typeof m.weight === "number" ? m.weight : null,
    applied_weight:    typeof weights[m.modality] === "number" ? weights[m.modality] : 0,
    provider:          m.provider || null,
    error:             m.error || null,
    degraded:          isDegraded(m),
  }));

  // All-degraded short-circuit: no real signal anywhere → neutral 0.5,
  // worker's retry loop will pick this up and re-run later.
  if (enriched.length === 0 || enriched.every(m => m.degraded)) {
    return {
      probability: 0.5,
      overall_degraded: true,
      modality_results: enriched,
    };
  }

  // No primary (contentType="multi" or primary missing/degraded) → fall
  // back to weighted average over present non-degraded modalities.
  const primaryResult = primary ? collapsed.find(m => m.modality === primary) : null;
  const useFallback = primary === null || !primaryResult || isDegraded(primaryResult);

  if (useFallback) {
    const probability = _weightedAverage(collapsed, weights);
    return {
      probability: _clamp01(probability),
      overall_degraded: enriched.some(m => m.degraded),
      modality_results: enriched,
    };
  }

  // Primary-floor + asymmetric lift: secondaries can only RAISE the
  // verdict above primary's probability, never lower it.
  const primaryProb = primaryResult.probability;
  let lift = 0;
  for (const m of collapsed) {
    if (m.modality === primary) continue;
    if (m.probability <= primaryProb) continue;          // only positive contributions
    if (isDegraded(m)) continue;                          // degraded secondaries skipped entirely

    const w = typeof weights[m.modality] === "number" ? weights[m.modality] : 0;
    lift += (m.probability - primaryProb) * w;
  }

  return {
    probability: _clamp01(primaryProb + lift),
    overall_degraded: enriched.some(m => m.degraded),
    modality_results: enriched,
  };
}

function _clamp01(p) {
  if (!Number.isFinite(p)) return 0;
  if (p < 0) return 0;
  if (p > 1) return 1;
  return p;
}

module.exports = {
  aggregate,
  isDegraded,
  collapseSameModality,
};
