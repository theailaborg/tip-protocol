"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ identityService }) {
  const router = express.Router();

  router.post("/v1/identity/register", asyncHandler(async (req, res) => {
    const result = await identityService.register(req.body);
    res.status(201).json(result);
  }));

  router.get("/v1/identity/:tipId", asyncHandler((req, res) => {
    res.json(identityService.resolve(req.params.tipId));
  }));

  router.post("/v1/identity/verify-ownership", asyncHandler((req, res) => {
    res.json(identityService.verifyOwnership(req.body));
  }));

  router.get("/v1/identity/:tipId/score", asyncHandler((req, res) => {
    res.json(identityService.getScore(req.params.tipId));
  }));

  router.get("/v1/identity/:tipId/history", asyncHandler((req, res) => {
    res.json(identityService.getHistory(req.params.tipId));
  }));

  return router;
}

module.exports = { createRouter };
