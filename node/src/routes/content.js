"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ contentService }) {
  const router = express.Router();

  router.post("/content/register", asyncHandler(async (req, res) => {
    const result = await contentService.register(req.body);
    res.status(202).json(result);
  }));

  // Explorer list — public, cursor-paginated. Filters: author, origin,
  // status, has_media. Slim rows; follow ctid for the full record.
  router.get("/content", asyncHandler((req, res) => {
    res.json(contentService.list(req.query));
  }));

  router.get("/content/:ctid", asyncHandler(async (req, res) => {
    res.json(await contentService.resolve(req.params.ctid));
  }));

  // OG card read — slim, crawler-cacheable projection used by the Open
  // Graph edge functions. Separate path from /content/:ctid so the
  // browser-extension contract is never affected.
  router.get("/content/:ctid/og", asyncHandler((req, res) => {
    res.set("Cache-Control", "public, max-age=300, stale-while-revalidate=600");
    res.json(contentService.resolveForOg(req.params.ctid));
  }));

  // Perceptually-similar content for this ctid: top-N near-duplicates by score,
  // each as a small content card for the FE. Advisory, off-DAG. ?limit (default
  // 5, max 20).
  router.get("/content/:ctid/similar", asyncHandler(async (req, res) => {
    res.json(await contentService.findSimilar(req.params.ctid, { limit: req.query.limit }));
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
