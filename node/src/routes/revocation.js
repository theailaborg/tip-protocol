"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ revocationService }) {
  const router = express.Router();

  router.get("/v1/revocations", asyncHandler((req, res) => {
    res.json(revocationService.list(req.query.since));
  }));

  router.post("/v1/revocations", asyncHandler((req, res) => {
    res.status(201).json(revocationService.create(req.body));
  }));

  return router;
}

module.exports = { createRouter };
