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
 * Cross-node behaviour: media storage is PER-NODE — each operator runs
 * (and pays for) their own bucket, so bytes live only on the node that
 * received the upload. When this node doesn't hold the bytes, it issues
 * a real 307 to the origin node's on-chain api_endpoint (announced via
 * NODE_ENDPOINT_UPDATED); 307 preserves method + headers, so the signed
 * MEDIA_ACCESS challenge is re-presented there unchanged. When the
 * origin node hasn't announced an endpoint, the response degrades to a
 * 303 JSON carrying `available_at_node_id` for client-side resolution.
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
      // Bytes live on the upload-receiving node (per-node buckets).
      // 307 preserves method + headers, so the requester's signed
      // challenge arrives at the origin node intact and is re-verified
      // there. Falls back to a 303 JSON when the origin node hasn't
      // announced an api_endpoint on chain yet.
      if (out.origin_endpoint) {
        const target = `${out.origin_endpoint}/v1/content/${encodeURIComponent(req.params.ctid)}/media/${idx}`;
        return res.redirect(307, target);
      }
      return res.status(303).json({
        available_at_node_id: out.origin_node_id,
        message: "Media not held by this node; origin has not announced an api_endpoint — resolve manually",
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
