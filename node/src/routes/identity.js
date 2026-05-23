"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");

function createRouter({ identityService, profileService, keyService }) {
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

  // Convenience aliases over the generic /profile POST. The client signs
  // the same canonical UPDATE_PROFILE payload — these routes just pin
  // reviewer_consent so the API reads as the intent ("become a reviewer")
  // rather than as a generic profile mutation.
  router.post("/identity/:tipId/become-reviewer", asyncHandler((req, res) => {
    res.status(202).json(profileService.becomeReviewer(req.params.tipId, req.body));
  }));

  router.post("/identity/:tipId/stop-reviewing", asyncHandler((req, res) => {
    res.status(202).json(profileService.stopReviewing(req.params.tipId, req.body));
  }));

  // ── Key lifecycle (KEY_ROTATED / KEY_RECOVERY) ──────────────────────
  // Rotation: client signs the canonical body with their CURRENT (OLD)
  // private key. The chain closes the OLD entity_keys row and appends
  // the NEW one at effective_at — old signatures still verify because
  // historical lookup is time-anchored on tx.timestamp.
  router.post("/identity/:tipId/keys/rotate", asyncHandler((req, res) => {
    res.status(202).json(keyService.rotateKey({ ...req.body, tip_id: req.params.tipId }));
  }));

  // Recovery: VP signs the canonical body after off-chain re-verification.
  // Same atomic close+append, but the chain trusts the VP attestation
  // because the user has lost possession of the OLD key.
  router.post("/identity/:tipId/keys/recover", asyncHandler((req, res) => {
    res.status(202).json(keyService.recoverKey({ ...req.body, tip_id: req.params.tipId }));
  }));

  return router;
}

module.exports = { createRouter };
