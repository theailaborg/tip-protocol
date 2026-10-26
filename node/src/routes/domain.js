"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ domainService }) {
  const router = express.Router();

  router.post("/domain/register", asyncHandler(async (req, res) => {
    res.status(202).json(domainService.register(req.body));
  }));

  router.post("/domain/verify", asyncHandler(async (req, res) => {
    res.status(202).json(await domainService.verify(req.body));
  }));

  router.post("/domain/renew", asyncHandler(async (req, res) => {
    const out = await domainService.renew(req.body);
    res.status(out.renewed ? 202 : 200).json(out);
  }));

  router.get("/domains", asyncHandler((req, res) => {
    res.json(domainService.listByTip(req.query.tip_id));
  }));

  // Permissive matcher — domains contain dots which Express's default path
  // parser would otherwise treat as a separator (e.g. acmenews.com would
  // match :domain="acmenews" and 404 on .com). The (*) wildcard captures
  // the entire remaining path segment verbatim.
  router.get("/domain/:domain([^/]+)", asyncHandler((req, res) => {
    res.json(domainService.get(req.params.domain));
  }));

  return router;
}

module.exports = { createRouter };
