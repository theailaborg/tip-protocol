"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ contentService }) {
  const router = express.Router();

  router.post("/content/register", asyncHandler((req, res) => {
    const result = contentService.register(req.body);
    res.status(202).json(result);
  }));

  router.get("/content/:ctid", asyncHandler((req, res) => {
    res.json(contentService.resolve(req.params.ctid));
  }));

  // Lightweight async-prescan poll endpoint. Clients hit this after
  // /content/register (which returns 202 with prescan_status="pending")
  // until prescan_status flips to "completed".
  router.get("/content/:ctid/prescan_status", asyncHandler((req, res) => {
    res.json(contentService.getPrescanStatus(req.params.ctid));
  }));

  router.post("/content/:ctid/verify", asyncHandler((req, res) => {
    res.status(202).json(contentService.verify(req.params.ctid, req.body));
  }));

  router.post("/content/:ctid/update-origin", asyncHandler((req, res) => {
    res.status(202).json(contentService.updateOrigin(req.params.ctid, req.body));
  }));

  router.post("/content/:ctid/retract", asyncHandler((req, res) => {
    res.status(202).json(contentService.retract(req.params.ctid, req.body));
  }));

  return router;
}

module.exports = { createRouter };
