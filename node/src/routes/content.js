"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ contentService }) {
  const router = express.Router();

  router.post("/v1/content/register", asyncHandler((req, res) => {
    const result = contentService.register(req.body);
    res.status(201).json(result);
  }));

  router.get("/v1/content/:ctid", asyncHandler((req, res) => {
    res.json(contentService.resolve(req.params.ctid));
  }));

  router.post("/v1/content/:ctid/verify", asyncHandler((req, res) => {
    res.json(contentService.verify(req.params.ctid, req.body));
  }));

  router.post("/v1/content/:ctid/update-origin", asyncHandler((req, res) => {
    res.json(contentService.updateOrigin(req.params.ctid, req.body));
  }));

  router.post("/v1/content/:ctid/retract", asyncHandler((req, res) => {
    res.json(contentService.retract(req.params.ctid, req.body));
  }));

  return router;
}

module.exports = { createRouter };
