/**
 * @file @tip-protocol/node/src/routes/media.js
 * @description Media upload + reviewer-access HTTP routes.
 *
 *   POST /v1/media/upload                  — author-attested upload, returns media_id
 *   GET  /v1/content/:ctid/media/:idx      — auth-gated reviewer/juror/disputer fetch
 *
 * Upload challenge (signed by uploader):
 *   MEDIA_UPLOAD:{shake256(bytes)}:{mime}:{timestamp}:{signer_tip_id}
 *
 * Access challenge (signed by requester):
 *   MEDIA_ACCESS:{ctid}:{idx}:{timestamp}:{requester_tip_id}
 *
 * Cross-node behaviour: when the local node doesn't hold the bytes
 * (fs-backed federation where the upload originated on a different node),
 * the response carries `available_at_node_id` so the client can resolve
 * its directory and re-issue the same signed request to the origin node.
 * With shared S3 in prod, this branch never executes — every node sees
 * the same bucket.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const express = require("express");
const { asyncHandler } = require("../middleware/error-handler");
const { CONTENT_LIMITS } = require("../../../shared/protocol-constants");

function createRouter({ mediaService }) {
  const router = express.Router();

  // Raw body parser scoped to upload only so the 25MB limit doesn't leak
  // into express.json's 4MB ceiling for the rest of /v1.
  const rawBody = express.raw({
    type: () => true,
    limit: CONTENT_LIMITS.REQUEST_BODY_MAX_BYTES,
  });

  router.post("/media/upload", rawBody, asyncHandler(async (req, res) => {
    const bytes = req.body;
    const mime = req.get("X-Media-Mime") || req.get("Content-Type");
    const signerTip = req.get("X-Signer-TipId");
    const signature = req.get("X-Signer-Signature");
    const tsHeader = req.get("X-Timestamp");
    const timestamp = tsHeader ? parseInt(tsHeader, 10) : NaN;

    const result = await mediaService.upload({
      bytes, mime, signer_tip_id: signerTip, signature, timestamp,
    });
    res.status(201).json(result);
  }));

  // Reviewer / juror / disputer / author fetch path. All authz happens
  // in mediaService.fetchForReviewer (schema check → identity gate →
  // signature verify → policy predicate). Route stays thin.
  router.get("/content/:ctid/media/:idx", asyncHandler(async (req, res) => {
    const requesterTip = req.get("X-Requester-TipId");
    const signature = req.get("X-Signature");
    const tsHeader = req.get("X-Timestamp");
    const timestamp = tsHeader ? parseInt(tsHeader, 10) : NaN;
    const idx = parseInt(req.params.idx, 10);

    const out = await mediaService.fetchForReviewer({
      ctid: req.params.ctid, idx,
      requester_tip_id: requesterTip,
      signature, timestamp,
    });

    if (out.transport === "redirect") {
      // The bytes live on a different node in this fs-backed federation.
      // Client uses its node directory to resolve the URL and re-issues
      // the same signed request there. We deliberately don't return a
      // URL here — node→URL mapping is a directory concern (added once
      // REGISTER_NODE carries an api_endpoint field).
      return res.status(303).json({
        available_at_node_id: out.origin_node_id,
        message: "Media not held by this node; retry against origin",
        code: "media_remote",
      });
    }
    if (out.transport === "presigned") {
      return res.json({
        media_id: out.media_id,
        mime: out.mime,
        presigned_url: out.presigned_url,
        expires_at: out.expires_at,
      });
    }
    // transport === "stream" — fs backend, direct response.
    res.setHeader("Content-Type", out.mime);
    res.setHeader("Content-Length", out.bytes.length);
    res.send(out.bytes);
  }));

  return router;
}

module.exports = { createRouter };
