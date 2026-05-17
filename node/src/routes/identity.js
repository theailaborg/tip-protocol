"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ identityService, profileService }) {
  const router = express.Router();

  router.post("/identity/register", asyncHandler(async (req, res) => {
    const result = await identityService.register(req.body);
    res.status(202).json(result);
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

  router.get("/identity/:tipId/activity", asyncHandler((req, res) => {
    res.json(identityService.getActivity(req.params.tipId, req.query));
  }));

  // ── Profile preferences (sparse update via UPDATE_PROFILE tx) ────────
  // Single endpoint covers any user-settable identity field. v1 has one
  // field: reviewer_consent (opt-in to be selected as an adjudicator
  // across review / jury / expert panels). Adding new preferences =
  // extend schemas/update-profile.KNOWN_FIELDS; this endpoint stays
  // unchanged.
  router.get("/identity/:tipId/profile", asyncHandler((req, res) => {
    res.json(profileService.getProfile(req.params.tipId));
  }));

  router.post("/identity/:tipId/profile", asyncHandler((req, res) => {
    res.status(202).json(profileService.updateProfile(req.params.tipId, req.body));
  }));

  return router;
}

module.exports = { createRouter };
