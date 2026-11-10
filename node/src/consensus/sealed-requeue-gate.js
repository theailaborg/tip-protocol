/**
 * @file @tip-protocol/node/src/consensus/sealed-requeue-gate.js
 * @description One activation time for the sealed-but-never-committed requeue.
 *
 * Two sides switch on together:
 *   - commit-handler applies a tx_id at most once per anchor, judged on the
 *     anchor's BFT timestamp, so every node flips at the same consensus point;
 *   - narwhal requeues its own uncommitted txs, judged on local wall-clock, and
 *     only REQUEUE_SKEW_MARGIN_MS after activation, so no requeued copy can ride
 *     an anchor whose BFT time is still before the gate (clock skew between
 *     nodes is far smaller than the margin).
 *
 * TIP_SEALED_REQUEUE_ACTIVATION_MS overrides the mainnet value for test
 * clusters. Read per call so a test can set it after the module loads.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { SEALED_REQUEUE_ACTIVATION_MS } = require("../../../shared/constants");

const REQUEUE_SKEW_MARGIN_MS = 10 * 60 * 1000;

function sealedRequeueGateMs() {
  const env = parseInt(process.env.TIP_SEALED_REQUEUE_ACTIVATION_MS, 10);
  return Number.isFinite(env) ? env : SEALED_REQUEUE_ACTIVATION_MS;
}

/** Commit side: dedup tx_ids inside one anchor from this anchor time on. */
function inAnchorDedupActive(certTimestamp) {
  return Number.isFinite(certTimestamp) && certTimestamp > 0 && certTimestamp >= sealedRequeueGateMs();
}

/** Narwhal side: requeue allowed from this local time on. */
function requeueActive(nowMsValue) {
  return Number.isFinite(nowMsValue) && nowMsValue >= sealedRequeueGateMs() + REQUEUE_SKEW_MARGIN_MS;
}

module.exports = { sealedRequeueGateMs, inAnchorDedupActive, requeueActive, REQUEUE_SKEW_MARGIN_MS };
