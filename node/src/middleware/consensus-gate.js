/**
 * @file @tip-protocol/node/src/middleware/consensus-gate.js
 * @description 503-on-halted-consensus gate for write endpoints.
 *
 * When the node's consensus is sub-quorum (peers offline / network
 * partition / can't reach quorum after start-up grace period), we
 * refuse new state-changing requests instead of silently piling txs
 * into a mempool that will never commit.
 *
 * Rationale: a decentralized network that can't advance is a halted
 * network, not a working-but-slow one. Accepting writes we know we
 * can't order mis-represents the system's state to clients. Better
 * to return 503 honestly — clients can retry, monitors can page.
 *
 * Applied to: POST / PUT / PATCH / DELETE requests under /v1/ that
 * go through the mempool. Read paths (GET) are unaffected — stale
 * reads from committed state are safe and useful during a halt.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

/**
 * Create the consensus-gate middleware. Reads live state from
 * `consensus.isConsensusHalted()` every request (no caching) — the
 * call is O(1).
 *
 * @param {Object} options
 * @param {Object} options.consensusRef  Consensus ref wrapper ({ current: consensus }).
 *   We read `.current` at request time so the gate picks up the live
 *   orchestrator once it's wired (same late-binding pattern as
 *   services/helpers.js submitTx).
 * @returns {Function} Express middleware
 */
function createConsensusGate({ consensusRef }) {
  return function consensusGate(req, res, next) {
    // Only gate state-changing methods. Idempotent reads stay open so
    // dashboards and health checks can see state during a halt.
    const method = req.method;
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") return next();

    const consensus = consensusRef?.current;
    if (!consensus || typeof consensus.isConsensusHalted !== "function") return next();

    const status = consensus.isConsensusHalted();
    if (!status.halted) return next();

    // Surface the halt to clients with structured metadata so monitoring
    // tools and retry logic can react programmatically, not by parsing
    // error strings.
    res.status(503).json({
      ok: false,
      status: 503,
      error: {
        message: status.message || "Consensus halted — network is sub-quorum, not accepting writes",
        code: "CONSENSUS_HALTED",
        reason: status.reason,
        stale_ms: status.staleMs,
        last_advance_at: status.lastAdvanceAt,
        request_id: req.id || null,
      },
    });
  };
}

module.exports = { createConsensusGate };
