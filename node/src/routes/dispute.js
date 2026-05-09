"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ disputeService }) {
  const router = express.Router();

  router.post("/content/:ctid/dispute", asyncHandler((req, res) => {
    res.status(202).json(disputeService.fileDispute(req.params.ctid, req.body));
  }));

  router.post("/content/:ctid/jury/commit", asyncHandler((req, res) => {
    res.status(202).json(disputeService.juryCommit(req.params.ctid, req.body));
  }));

  router.post("/content/:ctid/jury/reveal", asyncHandler((req, res) => {
    res.status(202).json(disputeService.juryReveal(req.params.ctid, req.body));
  }));

  router.get("/content/:ctid/dispute-case", asyncHandler((req, res) => {
    res.json(disputeService.getDisputeCase(req.params.ctid));
  }));

  router.post("/content/:ctid/appeal", asyncHandler((req, res) => {
    res.status(202).json(disputeService.fileAppeal(req.params.ctid, req.body));
  }));

  router.post("/content/:ctid/appeal/commit", asyncHandler((req, res) => {
    res.status(202).json(disputeService.appealCommit(req.params.ctid, req.body));
  }));

  router.post("/content/:ctid/appeal/reveal", asyncHandler((req, res) => {
    res.status(202).json(disputeService.appealReveal(req.params.ctid, req.body));
  }));

  // ── Dispute listing / lookup / timeline ─────────────────────────────────
  // Read-only views over existing tx state. No new tx types — status is
  // projected from the DAG at request time.

  router.get("/disputes", asyncHandler((req, res) => {
    res.json(disputeService.listDisputesForTipId(req.query.tip_id));
  }));

  // Per-user attention feed. Open / unauthenticated by design — see
  // my-notes/USER_DASHBOARD_API.md "Authentication" for the rationale.
  router.get("/users/:tip_id/dashboard", asyncHandler((req, res) => {
    res.json(disputeService.getUserDashboard(req.params.tip_id));
  }));

  // All-time jury / expert history for a user. Paginated.
  // Optional query params: limit, offset, status, role.
  router.get("/users/:tip_id/jury-history", asyncHandler((req, res) => {
    res.json(disputeService.getJuryHistoryForTipId(req.params.tip_id, req.query));
  }));

  router.get("/disputes/:dispute_id/timeline", asyncHandler((req, res) => {
    res.json(disputeService.getDisputeTimeline(req.params.dispute_id));
  }));

  router.get("/disputes/:dispute_id", asyncHandler((req, res) => {
    res.json(disputeService.getDisputeById(req.params.dispute_id));
  }));

  return router;
}

module.exports = { createRouter };
