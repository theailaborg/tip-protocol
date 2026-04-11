"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ governanceService }) {
  const router = express.Router();

  router.post("/v1/vp/register", asyncHandler((req, res) => {
    res.status(201).json(governanceService.registerVP(req.body));
  }));

  router.get("/v1/vp/:vpId", asyncHandler((req, res) => {
    res.json(governanceService.resolveVP(req.params.vpId));
  }));

  router.post("/v1/node/register", asyncHandler((req, res) => {
    res.status(201).json(governanceService.registerNode(req.body));
  }));

  return router;
}

module.exports = { createRouter };
