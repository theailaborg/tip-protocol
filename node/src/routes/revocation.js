"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ revocationService }) {
  const router = express.Router();

  router.get("/revocations", asyncHandler((req, res) => {
    res.json(revocationService.list(req.query.since));
  }));

  router.post("/revocations", asyncHandler((req, res) => {
    res.status(202).json(revocationService.create(req.body));
  }));

  return router;
}

module.exports = { createRouter };
