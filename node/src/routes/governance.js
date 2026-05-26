"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ governanceService }) {
  const router = express.Router();

  router.post("/vp/register", asyncHandler((req, res) => {
    res.status(202).json(governanceService.registerVP(req.body));
  }));

  router.get("/vp/:vpId", asyncHandler((req, res) => {
    res.json(governanceService.resolveVP(req.params.vpId));
  }));

  router.post("/node/register", asyncHandler((req, res) => {
    res.status(202).json(governanceService.registerNode(req.body));
  }));

  // Add a new interest slug to the curated taxonomy. VP-attested:
  // body carries { slug, label, category, approving_vp_id, signature }.
  // Slug uniqueness enforced at commit time; duplicate request 409s.
  router.post("/interests", asyncHandler((req, res) => {
    res.status(202).json(governanceService.addInterest(req.body));
  }));

  // Public — every interest in the taxonomy. Used by FE to render the
  // profile interest checkboxes. Genesis seed + any committed
  // INTEREST_REGISTERED txs. Returns sorted by slug ASC.
  router.get("/interests", asyncHandler((_req, res) => {
    res.json(governanceService.listInterests());
  }));

  return router;
}

module.exports = { createRouter };
