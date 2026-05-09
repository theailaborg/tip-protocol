/**
 * @file @tip-protocol/node/src/routes/dispute-details.js
 * @description HTTP surface for reading off-chain dispute bodies.
 *
 * URL path is `/v1/evidence/...` — aligned to the user mental model
 * ("attach evidence to a dispute"). The internal table and service are
 * named dispute_details — the URL doesn't need to leak that.
 *
 * Read-only. Bodies are persisted by `dispute-service.fileDispute` when
 * a dispute is filed with an `evidence` block (atomic dispute+body
 * landing — no separate upload endpoint).
 *
 * Endpoints:
 *   GET    /v1/evidence/:hash      fetch a body
 *   HEAD   /v1/evidence/:hash      existence check
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ disputeDetailsService }) {
  const router = express.Router();

  router.get("/evidence/:hash", asyncHandler((req, res) => {
    res.json(disputeDetailsService.getDetails(req.params.hash));
  }));

  router.head("/evidence/:hash", (req, res) => {
    if (disputeDetailsService.hasDetails(req.params.hash)) res.status(200).end();
    else res.status(404).end();
  });

  return router;
}

module.exports = { createRouter };
