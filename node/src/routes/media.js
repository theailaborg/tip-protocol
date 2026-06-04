/**
 * @file @tip-protocol/node/src/routes/media.js
 * @description Media upload + fetch HTTP routes.
 *
 *   POST /v1/media/upload          — author-attested upload, returns media_id
 *   GET  /v1/media/:media_id       — direct stream (fs backend / fallback)
 *   GET  /v1/media/:media_id/head  — metadata only (mime + size)
 *
 * Wire format for POST /v1/media/upload:
 *
 *   Headers:
 *     Content-Type: application/octet-stream
 *     X-Media-Mime:        image/png         (the file's MIME)
 *     X-Signer-TipId:      tip://id/...      (uploader's identity)
 *     X-Signer-Signature:  <hex>             (ml-dsa sig over challenge)
 *     X-Timestamp:         1780500000000     (ms epoch, signed)
 *   Body: raw file bytes (max varies by mime family)
 *
 * Challenge (signed by uploader):
 *   MEDIA_UPLOAD:{shake256(bytes)}:{mime}:{timestamp}:{signer_tip_id}
 *
 * Response 200:
 *   { media_id, content_hash, mime, size, uploaded_at, signer_tip_id }
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

  // Raw body parser, scoped to this route only so the 25MB limit doesn't
  // leak into express.json's 4MB ceiling for the rest of /v1.
  const rawBody = express.raw({
    type: () => true,                      // accept any content-type for the upload route
    limit: CONTENT_LIMITS.REQUEST_BODY_MAX_BYTES,
  });

  router.post("/media/upload", rawBody, asyncHandler(async (req, res) => {
    const bytes      = req.body;           // Buffer from express.raw
    const mime       = req.get("X-Media-Mime") || req.get("Content-Type");
    const signerTip  = req.get("X-Signer-TipId");
    const signature  = req.get("X-Signer-Signature");
    const tsHeader   = req.get("X-Timestamp");
    const timestamp  = tsHeader ? parseInt(tsHeader, 10) : NaN;

    const result = await mediaService.upload({
      bytes, mime, signer_tip_id: signerTip, signature, timestamp,
    });
    res.status(201).json(result);
  }));

  // Direct stream — for the local-fs backend (which has no presigning) and
  // for the reviewer-access path in M4 (when authorization is satisfied,
  // route layer hands off here). The path here is auth-free for M2; the M4
  // patch will add reviewer/dispute eligibility checks.
  router.get("/media/:media_id", asyncHandler(async (req, res) => {
    const got = await mediaService.fetchBytes(req.params.media_id);
    if (!got) {
      return res.status(404).json({ message: "Not found", code: "media_not_found" });
    }
    res.setHeader("Content-Type", got.mime);
    res.setHeader("Content-Length", got.size);
    res.send(got.bytes);
  }));

  router.get("/media/:media_id/head", asyncHandler(async (req, res) => {
    const h = await mediaService.head(req.params.media_id);
    if (!h.exists) {
      return res.status(404).json({ message: "Not found", code: "media_not_found" });
    }
    res.json(h);
  }));

  return router;
}

module.exports = { createRouter };
