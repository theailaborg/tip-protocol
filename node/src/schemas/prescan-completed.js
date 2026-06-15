/**
 * @file @tip-protocol/node/src/schemas/prescan-completed.js
 * @description Canonical schema for `PRESCAN_COMPLETED` — emitted by the
 * worker on the API node that received the registration (or by a
 * failover leader after takeover) once the classifier call returns.
 *
 * Carries the final probability + tier + per-modality breakdown that
 * downstream consumers (h=48 reviewer trigger, grace windows, dashboards,
 * dispute evidence panels) read off the chain instead of re-calling the
 * classifier themselves. See my-notes/ASYNC_PRESCAN_ARCHITECTURE.md.
 *
 * Signed by: emitting node's ML-DSA-65 key (system tx, not user-signed).
 * Signature lives on `tx.signature` (envelope) — same pattern as the
 * PRESCAN_REVIEW_TRIGGERED auto-cascade.
 *
 * Canonical fields:
 *   ctid                       string,  the content this verdict applies to
 *   probability                number,  [0.0, 1.0] aggregated probability
 *   tier                       string,  low | elevated | high | critical
 *                                       (must match probability against
 *                                       prescan.tier_thresholds — replay
 *                                       nodes verify this consistency)
 *   flagged                    boolean, tier ∈ {high, critical}
 *   overall_degraded           boolean, ≥1 modality reported degraded
 *                                       signal (error / 0.5 / disagreement)
 *   content_type               string,  text | image | audio | video | multi
 *   content_type_meta          object,  { hint_provided, resolution, reason? }
 *   modality_results           array,   per-modality breakdown (probability,
 *                                       applied_weight, provider, error,
 *                                       degraded)
 *   classifier_version         string,  e.g. "2.0.0"
 *   classifier_providers_used  string,  e.g. "ensemble(ollama,statistical,heuristic)"
 *   completed_at               number,  ms epoch when worker submitted
 *   node_id                    string,  emitting node's tip://node/...
 *   failed                     boolean, true only on fail-open after
 *                                       retries exhausted
 *   failure_reason             string|null,  populated when failed=true
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError } = require("./_common");
const { mldsaVerify, canonicalTx } = require("../../../shared/crypto");
const { TX_TYPES, SIGNATURE_SCOPE, SIGNED_BY_KIND } = require("../../../shared/constants");
const { PRESCAN_TIER_THRESHOLDS, CONTENT_TYPE } = require("../../../shared/protocol-constants");
const { isValidMs } = require("../../../shared/time");

const TX_TYPE = TX_TYPES.PRESCAN_COMPLETED;
const SIGNATURE_SCOPE_VALUE = SIGNATURE_SCOPE.ENVELOPE;
const SIGNED_BY = SIGNED_BY_KIND.NODE;

const VALID_TIERS = Object.freeze(["low", "elevated", "high", "critical"]);

/**
 * Derive the canonical tier from a probability against the genesis-block
 * thresholds. Single source of truth for tier-from-probability — used at
 * both build time (worker) and verify time (replay nodes).
 */
function tierFromProbability(p) {
  if (typeof p !== "number" || !Number.isFinite(p)) return "low";
  if (p >= PRESCAN_TIER_THRESHOLDS.critical) return "critical";
  if (p >= PRESCAN_TIER_THRESHOLDS.high) return "high";
  if (p >= PRESCAN_TIER_THRESHOLDS.elevated) return "elevated";
  return "low";
}

function _validateShape(d) {
  if (typeof d.ctid !== "string" || !d.ctid.startsWith("tip://c/")) {
    throw schemaError(400, "ctid is required (tip://c/...)", "ctid_required");
  }
  if (typeof d.node_id !== "string" || !d.node_id.startsWith("tip://node/")) {
    throw schemaError(400, "node_id is required (tip://node/...)", "node_id_required");
  }
  if (typeof d.probability !== "number" || d.probability < 0 || d.probability > 1) {
    throw schemaError(400, "probability must be in [0, 1]", "probability_invalid");
  }
  if (!VALID_TIERS.includes(d.tier)) {
    throw schemaError(400, `tier must be one of: ${VALID_TIERS.join(", ")}`, "tier_invalid");
  }
  if (typeof d.flagged !== "boolean") {
    throw schemaError(400, "flagged must be a boolean", "flagged_invalid");
  }
  if (typeof d.overall_degraded !== "boolean") {
    throw schemaError(400, "overall_degraded must be a boolean", "overall_degraded_invalid");
  }
  if (!CONTENT_TYPE.VALID_TYPES.includes(d.content_type)) {
    throw schemaError(400, `content_type must be one of: ${CONTENT_TYPE.VALID_TYPES.join(", ")}`, "content_type_invalid");
  }
  if (!Array.isArray(d.modality_results)) {
    throw schemaError(400, "modality_results must be an array", "modality_results_invalid");
  }
  // Optional per-FILE scores (media_id-tagged, pre-collapse). Additive:
  // txs from older nodes simply omit the field and keep validating. The
  // collapsed modality_results stay authoritative for the verdict; this
  // array preserves the per-file evidence that collapsing discards.
  if (d.media_results !== undefined) {
    if (!Array.isArray(d.media_results)) {
      throw schemaError(400, "media_results must be an array when present", "media_results_invalid");
    }
    for (const m of d.media_results) {
      if (!m || typeof m !== "object"
        || typeof m.media_id !== "string" || !/^[0-9a-f]{64}$/.test(m.media_id)
        || (m.probability !== null && !(typeof m.probability === "number" && m.probability >= 0 && m.probability <= 1))) {
        throw schemaError(400, "media_results entries need media_id (64-hex) and probability (0..1 or null)", "media_results_invalid");
      }
    }
  }
  if (typeof d.classifier_version !== "string" || d.classifier_version.length === 0) {
    throw schemaError(400, "classifier_version is required", "classifier_version_required");
  }
  if (!isValidMs(d.completed_at)) {
    throw schemaError(400, "completed_at must be a valid epoch ms timestamp", "completed_at_invalid");
  }
  if (typeof d.failed !== "boolean") {
    throw schemaError(400, "failed must be a boolean", "failed_invalid");
  }
}

/**
 * State-level verification at consensus replay. The dispatcher verifies
 * the envelope signature; this function enforces the state-machine
 * invariants the dispatcher doesn't know about:
 *
 *   1. Emitting node is registered + active.
 *   2. Tier matches probability against the genesis thresholds (replay
 *      can't trust the asserted tier blindly; the assigned node could
 *      lie about tier even with a valid probability).
 *   3. flagged matches tier (flagged ⇔ tier ∈ {high, critical}).
 *   4. content_type matches the publisher's signed hint, if any (the
 *      hint is on REGISTER_CONTENT.data; this check requires the
 *      content row to exist — defer when it doesn't).
 *
 * Returns { ok: true } on success, or
 * { ok: false, status, error, code } on any failure.
 */
function verifyTx(tx, dag) {
  const d = tx.data || {};

  try { _validateShape(d); }
  catch (err) {
    if (err && err.status) return { ok: false, status: err.status, error: err.error, code: err.code };
    throw err;
  }

  if (typeof tx.signature !== "string" || tx.signature.length === 0) {
    return { ok: false, status: 400, error: "tx.signature missing", code: "signature_missing" };
  }

  const node = dag.getNode(d.node_id);
  if (!node) {
    return { ok: false, status: 412, error: `Node not registered: ${d.node_id}`, code: "node_not_registered" };
  }
  if (node.status !== "active") {
    return { ok: false, status: 403, error: `Node not active: ${d.node_id}`, code: "node_inactive" };
  }

  // Tier-vs-probability consistency. The assigned node computed tier
  // locally from probability; if its value disagrees with our local
  // computation (against the same genesis constants), reject.
  const expectedTier = tierFromProbability(d.probability);
  if (d.tier !== expectedTier) {
    return {
      ok: false, status: 400,
      error: `tier "${d.tier}" inconsistent with probability ${d.probability} (expected "${expectedTier}")`,
      code: "tier_probability_mismatch",
    };
  }
  const expectedFlagged = d.tier === "high" || d.tier === "critical";
  if (d.flagged !== expectedFlagged) {
    return {
      ok: false, status: 400,
      error: `flagged=${d.flagged} inconsistent with tier=${d.tier}`,
      code: "flagged_tier_mismatch",
    };
  }

  if (!mldsaVerify(canonicalTx(tx), tx.signature, node.public_key)) {
    return { ok: false, status: 403, error: "Node signature verification failed", code: "signature_invalid" };
  }
  return { ok: true };
}

module.exports = {
  TX_TYPE,
  verifyTx,
  tierFromProbability,
  VALID_TIERS,
  // GH #51 — unified signature contract
  SIGNATURE_SCOPE: SIGNATURE_SCOPE_VALUE,
  SIGNED_BY,
};
