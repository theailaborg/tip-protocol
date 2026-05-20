/**
 * @file @tip-protocol/node/src/schemas/prescan-review-triggered.js
 * @description Canonical schema for `PRESCAN_REVIEW_TRIGGERED` — emitted
 * by the scheduler when HIGH/CRITICAL-flagged content reaches h=48 without
 * creator self-correction. Carries the reviewer assignment.
 *
 * Signed by: the emitting node's ML-DSA-65 key (system tx, not user-signed).
 * Signature lives on `tx.signature` (top-level) not `tx.data.signature` —
 * matches the CONTENT_DISPUTED auto-cascade pattern for node-emitted txs.
 *
 * Canonical fields (alphabetical):
 *   assigned_reviewer_tip_id  string,  the reviewer the scheduler picked
 *   creator_tip_id            string,  the content's author
 *   ctid                      string,  the content under review
 *   node_id                   string,  the emitting node (signer)
 *   review_id                 string,  `pr_<round>_<ctid-short>` deterministic
 *   triggered_at_round        number,  consensus round at emission
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError } = require("./_common");
const { mldsaVerify, canonicalTx } = require("../../../shared/crypto");
const { TX_TYPES } = require("../../../shared/constants");

const TX_TYPE = TX_TYPES.PRESCAN_REVIEW_TRIGGERED;

function _validateShape(d) {
  if (typeof d.review_id !== "string" || d.review_id.length === 0) {
    throw schemaError(400, "review_id is required", "review_id_required");
  }
  if (typeof d.ctid !== "string" || !d.ctid.startsWith("tip://c/")) {
    throw schemaError(400, "ctid is required (tip://c/...)", "ctid_required");
  }
  if (typeof d.creator_tip_id !== "string" || !d.creator_tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "creator_tip_id is required (tip://id/...)", "creator_tip_id_required");
  }
  if (typeof d.assigned_reviewer_tip_id !== "string" || !d.assigned_reviewer_tip_id.startsWith("tip://id/")) {
    throw schemaError(400, "assigned_reviewer_tip_id is required (tip://id/...)", "assigned_reviewer_tip_id_required");
  }
  if (typeof d.node_id !== "string" || !d.node_id.startsWith("tip://node/")) {
    throw schemaError(400, "node_id is required (tip://node/...)", "node_id_required");
  }
  if (!Number.isInteger(d.triggered_at_round) || d.triggered_at_round < 0) {
    throw schemaError(400, "triggered_at_round must be a non-negative integer", "triggered_at_round_invalid");
  }
}

/**
 * Server-side high-level entry. The emitting node signed `canonicalTx(tx)`
 * with its ML-DSA-65 key — same pattern as the CONTENT_DISPUTED auto
 * cascade. Verifies the signer is a registered active node and the
 * signature matches.
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
    return { ok: false, status: 403, error: `Node not active: ${d.node_id} (status: ${node.status})`, code: "node_inactive" };
  }

  if (!mldsaVerify(canonicalTx(tx), tx.signature, node.public_key)) {
    return { ok: false, status: 403, error: "Node signature verification failed", code: "signature_invalid" };
  }
  return { ok: true };
}

module.exports = {
  TX_TYPE,
  verifyTx,
};
