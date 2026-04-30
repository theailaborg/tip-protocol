/**
 * @file @tip-protocol/node/src/consensus/tx-rejection-sink.js
 * @description Shared persist helper for the no-loss `tx_rejections` table.
 *
 * Single source of truth for the row shape every drop site in the
 * codebase writes — mempool admit (`mempool_full`), mempool TTL
 * eviction, commit-handler revalidation, and any future drop site
 * between API admission and committed DAG state.
 *
 * Why centralised:
 *   - Every site stamps the SAME dropper_node_id, the SAME tx body
 *     shape, the SAME error containment (logs, never throws).
 *   - A drift in just one site (e.g. a future caller that forgets to
 *     attach the tx body) silently degrades the outcome endpoint and
 *     replay tooling. Forcing all writers through this factory makes
 *     the schema contract enforceable.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { getLogger } = require("../logger");

const log = getLogger("tip.tx-rejections");

/**
 * Build a `persist(tx, reason, detail, opts?)` function bound to a
 * specific node + dag.
 *
 * @param {Object} options
 * @param {Object} options.dag      DAG (must expose saveTxRejection in
 *                                  production; missing → no-op so unit
 *                                  tests with stub dags don't break).
 * @param {string} [options.nodeId] Stamped onto every row as
 *                                  `dropper_node_id`. Defaults to
 *                                  "unknown" which surfaces misconfig
 *                                  in dashboard queries instead of
 *                                  crashing the drop path.
 * @returns {(tx, reason, detail, opts?) => void}
 *   - tx:     full transaction object (must have tx_id; missing tx_id
 *             is a silent skip — no PK to index).
 *   - reason: a TX_REJECTION_REASON code.
 *   - detail: optional human-readable specifics (the exact message
 *             that will appear in the outcome endpoint response).
 *   - opts.round: optional consensus round, used by drop sites that
 *                 fire inside commit-handler / narwhal.
 */
function createRejectionSink({ dag, nodeId }) {
  const droppingNodeId = nodeId || "unknown";

  return function persist(tx, reason, detail, opts) {
    if (!tx || !tx.tx_id) return;
    if (!dag || typeof dag.saveTxRejection !== "function") return;
    try {
      dag.saveTxRejection({
        tx_id:             tx.tx_id,
        reason,
        reason_detail:     detail || null,
        rejected_at_round: opts && opts.round != null ? opts.round : null,
        dropper_node_id:   droppingNodeId,
        tx_type:           tx.tx_type || null,
        tx_data:           tx,
      });
    } catch (err) {
      // Never let a logging miss block the surrounding flow. The drop
      // already happened; failing to record it is a degraded but
      // non-fatal state.
      log.warn(`tx_rejection persist failed for ${tx.tx_id}: ${err.message}`);
    }
  };
}

module.exports = { createRejectionSink };
