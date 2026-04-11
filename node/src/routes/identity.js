"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ identityService }) {
  const router = express.Router();

  router.post("/identity/register", asyncHandler(async (req, res) => {
    const result = await identityService.register(req.body);
    res.status(201).json(result);
  }));

  router.get("/identity/:tipId", asyncHandler((req, res) => {
    res.json(identityService.resolve(req.params.tipId));
  }));

  router.post("/identity/verify-ownership", asyncHandler((req, res) => {
    res.json(identityService.verifyOwnership(req.body));
  }));

  router.get("/identity/:tipId/score", asyncHandler((req, res) => {
    res.json(identityService.getScore(req.params.tipId));
  }));

  router.get("/identity/:tipId/history", asyncHandler((req, res) => {
    res.json(identityService.getHistory(req.params.tipId));
  }));

  return router;
}

module.exports = { createRouter };
