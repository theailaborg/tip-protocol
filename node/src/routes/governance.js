"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ governanceService }) {
  const router = express.Router();

  router.post("/vp/register", asyncHandler((req, res) => {
    res.status(201).json(governanceService.registerVP(req.body));
  }));

  router.get("/vp/:vpId", asyncHandler((req, res) => {
    res.json(governanceService.resolveVP(req.params.vpId));
  }));

  router.post("/node/register", asyncHandler((req, res) => {
    res.status(201).json(governanceService.registerNode(req.body));
  }));

  return router;
}

module.exports = { createRouter };
