"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ siteService }) {
  const router = express.Router();

  router.post("/site/snapshot", asyncHandler(async (req, res) => {
    res.status(202).json(await siteService.submitSnapshot(req.body));
  }));

  router.get("/site/snapshot/:tx", asyncHandler(async (req, res) => {
    res.json(await siteService.getSnapshot(req.params.tx));
  }));

  // Domains contain dots, which the default param pattern would split on.
  router.get("/site/:domain([^/]+)/snapshots", asyncHandler((req, res) => {
    res.json(siteService.listSnapshots(req.params.domain, req.query));
  }));

  router.get("/site/:domain([^/]+)/page", asyncHandler(async (req, res) => {
    res.json(await siteService.getPage(req.params.domain, req.query));
  }));

  return router;
}

module.exports = { createRouter };
