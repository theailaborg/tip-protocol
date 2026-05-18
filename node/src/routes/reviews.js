/**
 * @file @tip-protocol/node/src/routes/reviews.js
 * @description Phase 2.6 — reviewer + creator decision endpoints for the
 * prescan-review pipeline.
 *
 *   GET  /v1/reviews/:id                 — read review state
 *   POST /v1/reviews/:id/dismiss         — reviewer dismisses the AI flag
 *   POST /v1/reviews/:id/confirm         — reviewer confirms the AI flag
 *   POST /v1/reviews/:id/accept-correction — creator's Option 1 (private)
 *
 * Body signature verification, state-machine gating, and signed-payload
 * canonicalization all live in the schema modules + business-rules; the
 * route layer is just JSON marshaling.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ reviewService }) {
  const router = express.Router();

  router.get("/reviewers/pool", asyncHandler((req, res) => {
    res.json(reviewService.listReviewerPool());
  }));

  router.get("/reviews/:id", asyncHandler((req, res) => {
    res.json(reviewService.getReview(req.params.id));
  }));

  router.post("/reviews/:id/dismiss", asyncHandler((req, res) => {
    res.status(202).json(reviewService.dismiss(req.params.id, req.body));
  }));

  router.post("/reviews/:id/confirm", asyncHandler((req, res) => {
    res.status(202).json(reviewService.confirm(req.params.id, req.body));
  }));

  router.post("/reviews/:id/recuse", asyncHandler((req, res) => {
    res.status(202).json(reviewService.recuse(req.params.id, req.body));
  }));

  router.post("/reviews/:id/accept-correction", asyncHandler((req, res) => {
    res.status(202).json(reviewService.acceptCorrection(req.params.id, req.body));
  }));

  return router;
}

module.exports = { createRouter };
