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

  return router;
}

module.exports = { createRouter };
