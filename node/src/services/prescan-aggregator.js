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
 * Hard-degraded: the classifier produced no usable signal for this
 * modality. Retrying with the same input may yield a different result
 * (transient error, network blip, model warm-up):
 *
 *   - explicit per-modality error
 *   - non-finite probability (NaN / undefined / Infinity — malformed
 *     classifier response; never trust the value, treat as no-signal)
 *   - exact probability 0.5 (the classifier's "no signal" neutral)
 *
 * Worker treats hard-degraded as retry-eligible. If retries exhaust,
 * a fail-open is emitted with overall_degraded=true so downstream
 * sees the placeholder for what it is.
 */
function isHardDegraded(m) {
  if (!m || typeof m !== "object") return true;
  if (m.error) return true;
  if (!Number.isFinite(m.probability)) return true;
  if (m.probability === 0.5) return true;
  return false;
}

/**
 * Degraded: hard-degraded OR soft-degraded.
 *
 * Soft-degraded means the classifier returned an honest low-confidence
 * answer (e.g., `disagreement_override` — providers disagreed or only one
 * fired). The probability is real and worth recording, but downstream
 * consumers should know it's low-confidence. Retrying won't help — same
 * input deterministically yields the same response.
 *
 * Aggregator weights degraded modalities at half-weight in the fallback
 * path (DEGRADED_MULTIPLIER); the worker uses isHardDegraded to decide
 * retries and uses overall_degraded to decide what to record on chain.
 */
function isDegraded(m) {
  if (isHardDegraded(m)) return true;
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
    if (!prev) { byModality.set(r.modality, r); continue; }
    // Treat non-finite probabilities as -Infinity so a leading malformed
    // entry never blocks a later finite reading from winning the slot.
    const prevP = Number.isFinite(prev.probability) ? prev.probability : -Infinity;
    const curP = Number.isFinite(r.probability) ? r.probability : -Infinity;
    if (curP > prevP) byModality.set(r.modality, r);
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
    // Non-finite probability carries no usable signal — skip entirely
    // rather than half-weight it. Half-weighting NaN would contaminate
    // num via NaN × effective = NaN and collapse the verdict.
    if (!Number.isFinite(r.probability)) continue;
    const degraded = isDegraded(r);
    const effective = degraded ? w * MODALITY_WEIGHTS.DEGRADED_MULTIPLIER : w;
    num += r.probability * effective;
    den += effective;
  }
  return den > 0 ? num / den : 0.5;
}

/**
 * Primary-floor + asymmetric lift: anchor on the primary modality's
 * probability and let non-degraded secondaries only LIFT the verdict
 * upward. Secondaries weaker than the primary contribute nothing —
 * encoding the safety bias that clean secondaries can't exonerate a
 * flagged primary modality.
 *
 *   final = primaryProb + Σ max(0, secondary_prob - primaryProb) × secondary_weight
 *
 * Caller is responsible for verifying primaryProb is finite + non-degraded
 * BEFORE invoking — this helper assumes the floor is trustworthy.
 */
function _primaryFloorLift(collapsed, primary, primaryProb, weights) {
  let lift = 0;
  for (const m of collapsed) {
    if (m.modality === primary) continue;
    if (m.probability <= primaryProb) continue;   // only positive contributions
    if (isDegraded(m)) continue;                   // degraded secondaries excluded entirely
    const w = typeof weights[m.modality] === "number" ? weights[m.modality] : 0;
    lift += (m.probability - primaryProb) * w;
  }
  return primaryProb + lift;
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

  // Enrich each modality with applied_weight + degraded flags for audit.
  const enriched = collapsed.map(m => ({
    modality: m.modality,
    probability: m.probability,
    classifier_weight: typeof m.weight === "number" ? m.weight : null,
    applied_weight: typeof weights[m.modality] === "number" ? weights[m.modality] : 0,
    provider: m.provider || null,
    error: m.error || null,
    degraded: isDegraded(m),
    hard_degraded: isHardDegraded(m),
  }));

  const overallDegraded = enriched.some(m => m.degraded);
  const overallHardDegraded = enriched.some(m => m.hard_degraded);

  // All-hard-degraded short-circuit: no usable signal anywhere → neutral
  // 0.5, worker's retry loop picks this up. Soft-only degradation does
  // NOT short-circuit — the classifier's honest low-confidence answer
  // (e.g., disagreement_override) is preserved.
  if (enriched.length === 0 || collapsed.every(m => isHardDegraded(m))) {
    return {
      probability: 0.5,
      overall_degraded: true,
      overall_hard_degraded: true,
      modality_results: enriched,
    };
  }

  // No primary (contentType="multi" or primary missing/degraded) → fall
  // back to weighted average over present modalities (degraded entries
  // contribute at half-weight via DEGRADED_MULTIPLIER).
  const primaryResult = primary ? collapsed.find(m => m.modality === primary) : null;
  const useFallback = primary === null || !primaryResult || isDegraded(primaryResult);

  if (useFallback) {
    const probability = _weightedAverage(collapsed, weights);
    return {
      probability: _clamp01(probability),
      overall_degraded: overallDegraded,
      overall_hard_degraded: overallHardDegraded,
      modality_results: enriched,
    };
  }

  // Primary-floor + asymmetric lift: secondaries can only RAISE the
  // verdict above primary's probability, never lower it.
  const probability = _primaryFloorLift(collapsed, primary, primaryResult.probability, weights);

  return {
    probability: _clamp01(probability),
    overall_degraded: overallDegraded,
    overall_hard_degraded: overallHardDegraded,
    modality_results: enriched,
  };
}

function _clamp01(p) {
  // Non-finite → neutral. "Definitely-human" (0) would be a lie when we
  // simply have no signal; 0.5 matches the per-modality no-signal marker
  // and lets downstream callers see this as the "unknown" case. With
  // isDegraded()'s finite-probability check upstream, this should never
  // fire on a normal flow — it's a defensive last line.
  if (!Number.isFinite(p)) return 0.5;
  if (p < 0) return 0;
  if (p > 1) return 1;
  return p;
}

module.exports = {
  aggregate,
  isDegraded,
  isHardDegraded,
  collapseSameModality,
};
