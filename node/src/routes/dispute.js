"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ disputeService }) {
  const router = express.Router();

  router.post("/v1/content/:ctid/dispute", asyncHandler((req, res) => {
    res.json(disputeService.fileDispute(req.params.ctid, req.body));
  }));

  router.post("/v1/content/:ctid/jury/commit", asyncHandler((req, res) => {
    res.json(disputeService.juryCommit(req.params.ctid, req.body));
  }));

  router.post("/v1/content/:ctid/jury/reveal", asyncHandler((req, res) => {
    res.json(disputeService.juryReveal(req.params.ctid, req.body));
  }));

  router.get("/v1/content/:ctid/dispute-case", asyncHandler((req, res) => {
    res.json(disputeService.getDisputeCase(req.params.ctid));
  }));

  router.post("/v1/content/:ctid/appeal", asyncHandler((req, res) => {
    res.json(disputeService.fileAppeal(req.params.ctid, req.body));
  }));

  router.post("/v1/content/:ctid/appeal/commit", asyncHandler((req, res) => {
    res.json(disputeService.appealCommit(req.params.ctid, req.body));
  }));

  router.post("/v1/content/:ctid/appeal/reveal", asyncHandler((req, res) => {
    res.json(disputeService.appealReveal(req.params.ctid, req.body));
  }));

  return router;
}

module.exports = { createRouter };
