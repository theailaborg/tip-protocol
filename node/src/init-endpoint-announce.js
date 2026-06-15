/**
 * @file @tip-protocol/node/src/init-endpoint-announce.js
 * @description One-shot boot reconcile of this node's on-chain
 * api_endpoint. Mirrors the init-prescan-worker pattern — owns the
 * startup orchestration for one subsystem so index.js stays terse.
 *
 * When TIP_API_ENDPOINT is configured and the on-chain nodes row
 * disagrees, emits NODE_ENDPOINT_UPDATED via the governance service
 * (which probe-verifies the URL answers /health as this very node
 * before publishing). Delayed so consensus is up and our own /health
 * is reachable for the ownership probe.
 *
 * Failure is non-fatal — the operator can POST
 * /v1/node/endpoint/announce later; we warn so the mismatch is visible.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { log } = require("./logger");

const ANNOUNCE_DELAY_MS = 15_000;

/**
 * @param {Object} deps
 * @param {Object} deps.dag                 DAG facade.
 * @param {Object} deps.config              Node config (apiEndpoint + nodeRegisteredId).
 * @param {Object} deps.governanceService   createGovernanceService() instance.
 * @returns {{ stop: () => void }}
 */
function initEndpointAnnounce({ dag, config, governanceService }) {
  const noop = { stop() { /* */ } };

  if (!config.apiEndpoint || !config.nodeRegisteredId) return noop;

  async function _reconcile() {
    try {
      const row = dag.getNode(config.nodeRegisteredId);
      if (row && (row.api_endpoint || null) !== config.apiEndpoint) {
        const out = await governanceService.announceConfiguredEndpoint();
        log.notice(`api_endpoint announced on chain: ${out.api_endpoint} (${out.confirmation})`);
      }
    } catch (err) {
      log.warn(`api_endpoint announce failed (retry on next boot or via POST /v1/node/endpoint/announce): ${err?.error || err?.message || err}`);
    }
  }

  const timer = setTimeout(_reconcile, ANNOUNCE_DELAY_MS);
  if (typeof timer.unref === "function") timer.unref();

  return { stop() { clearTimeout(timer); } };
}

module.exports = { initEndpointAnnounce };
