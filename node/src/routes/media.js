/**
 * @file @tip-protocol/node/src/routes/media.js
 * @description Media upload + reviewer-access HTTP routes.
 *
 *   POST /v1/media/upload                  — author-attested single-shot upload
 *   POST /v1/media/upload-init             — start presigned multipart, returns part URLs
 *   GET  /v1/media/upload-status/:session  — resume: uploaded/missing parts + fresh URLs
 *   POST /v1/media/upload-complete/:session— finalize (signed): assemble + re-hash + promote
 *   POST /v1/media/upload-abort/:session   — cancel (signed): abort multipart
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

function createRouter({ mediaService, chunkedUploadService }) {
  const router = express.Router();

  // Streaming upload — NO body parser. The raw request stream flows
  // through media-service.uploadStream (hash + size gauge → tmp file →
  // promote), so node memory stays flat regardless of file size. The
  // per-mime genesis caps are enforced mid-stream; lifting them later
  // (e.g. video in v2) is a genesis change only — transport is ready.
  router.post("/media/upload", asyncHandler(async (req, res) => {
    const mime = req.get("X-Media-Mime") || req.get("Content-Type");
    const signerTip = req.get("X-Signer-TipId");
    const signature = req.get("X-Signer-Signature");
    const tsHeader = req.get("X-Timestamp");
    const timestamp = tsHeader ? parseInt(tsHeader, 10) : NaN;

    try {
      const result = await mediaService.uploadStream({
        stream: req, mime, signer_tip_id: signerTip, signature, timestamp,
      });
      res.status(201).json(result);
    } catch (err) {
      // Rejecting mid-body (size cap, bad signature) leaves unread bytes
      // on the wire — the keep-alive socket can't be reused. Tell the
      // client explicitly so its NEXT request opens a fresh connection
      // instead of dying on the poisoned one.
      if (!res.headersSent) res.setHeader("Connection", "close");
      throw err;
    }
  }));

  // Large-media upload (Phase 1: presigned S3 multipart). Init verifies the
  // signer and returns presigned part URLs; the client PUTs parts DIRECTLY to S3
  // in parallel; complete re-hashes the assembled bytes before promoting.
  router.post("/media/upload-init", express.json(), asyncHandler(async (req, res) => {
    const result = await chunkedUploadService.init({
      mime: req.body.mime,
      size: req.body.size,
      content_hash: req.body.content_hash,
      signer_tip_id: req.body.signer_tip_id,
      signature: req.body.signature,
      timestamp: req.body.timestamp,
      part_size: req.body.part_size,
    });
    res.status(201).json(result);
  }));

  // Resume: which parts S3 already has + fresh presigned URLs for the missing ones.
  router.get("/media/upload-status/:sessionId", asyncHandler(async (req, res) => {
    const result = await chunkedUploadService.status(req.params.sessionId);
    res.status(200).json(result);
  }));

  // Finalize — authenticated (signer signs MEDIA_UPLOAD_COMPLETE:{session}:{ts}:{tip}).
  // Body carries the S3 part ETags; node assembles, re-hashes, verifies, promotes.
  router.post("/media/upload-complete/:sessionId", express.json(), asyncHandler(async (req, res) => {
    const result = await chunkedUploadService.complete(req.params.sessionId, {
      signer_tip_id: req.body.signer_tip_id,
      signature: req.body.signature,
      timestamp: req.body.timestamp,
      parts: req.body.parts,
    });
    res.status(201).json(result);
  }));

  // Cancel an in-flight upload — authenticated (MEDIA_UPLOAD_ABORT:{session}:{ts}:{tip}).
  router.post("/media/upload-abort/:sessionId", express.json(), asyncHandler(async (req, res) => {
    const result = await chunkedUploadService.abort(req.params.sessionId, {
      signer_tip_id: req.body.signer_tip_id,
      signature: req.body.signature,
      timestamp: req.body.timestamp,
    });
    res.status(200).json(result);
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
