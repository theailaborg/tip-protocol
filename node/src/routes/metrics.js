/**
 * @file @tip-protocol/node/src/routes/metrics.js
 * @description Thin HTTP route for GET /metrics (§29 in issues.md).
 *
 * Mounted at top-level `/metrics` (NOT under `/v1`) per Prometheus scraper
 * convention. The exposition format is built by metrics-service; this file
 * just sets the right content-type and writes the body. The response
 * deliberately does NOT pass through the global `{ok,data}` JSON envelope
 * middleware; Prometheus scrapers reject anything that isn't bare
 * text/plain v0.0.4.
 *
 * 200 OK is returned even when consensus is halted or the consensus module
 * isn't running; operators see the outage via `tip_consensus_halted=1`
 * inside the body, not via an HTTP error code (a 5xx would just make the
 * scrape itself fail and they'd never see the gauge).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const express = require("express");
const crypto = require("crypto");
const { createMetricsService } = require("../services/metrics-service");

// Constant-time bearer check; length mismatch short-circuits via hashing both
// sides so the comparison never leaks token length.
function _bearerOk(header, token) {
  const presented = typeof header === "string" && header.startsWith("Bearer ") ? header.slice(7) : "";
  const a = crypto.createHash("sha256").update(presented).digest();
  const b = crypto.createHash("sha256").update(token).digest();
  return crypto.timingSafeEqual(a, b);
}

function createRouter({ dag, config, consensus, network }) {
  const router = express.Router();
  const metricsService = createMetricsService({ dag, config, consensus, network });

  router.get("/metrics", (req, res) => {
    // TIP_METRICS_TOKEN set -> scrape-only endpoint on the public API port.
    // Unset -> open (dev / private-network deployments).
    if (config.metricsToken && !_bearerOk(req.headers.authorization, config.metricsToken)) {
      return res.status(401).type("text/plain").send("unauthorized");
    }
    res.type("text/plain; version=0.0.4").send(metricsService.buildBody());
  });

  return router;
}

module.exports = { createRouter };
