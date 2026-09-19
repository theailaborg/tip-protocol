/**
 * @file node/src/routes/prescan-callback.js
 * @description Classifier job callbacks. The body is only a hint: a verified
 * callback wakes the named job so the worker polls the classifier now, and the
 * verdict always comes from that authenticated poll. Mounted ahead of the JSON
 * body parser because the signature covers the raw request bytes.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const crypto = require("crypto");
const express = require("express");

const SIGNATURE_HEADER = "X-TIP-Classifier-Signature";
const SIGNATURE_PREFIX = "hmac-sha256=";
const BODY_LIMIT = "16kb";

function createRouter({ prescanJobs, config }) {
  const router = express.Router();

  function _fail(res, status, code, message) {
    return res.status(status).json({ ok: false, status, error: { message, code } });
  }

  function _signatureValid(secret, raw, header) {
    const value = String(header || "");
    if (!value.startsWith(SIGNATURE_PREFIX)) return false;
    const given = Buffer.from(value.slice(SIGNATURE_PREFIX.length), "utf8");
    const expected = Buffer.from(crypto.createHmac("sha256", secret).update(raw).digest("hex"), "utf8");
    return given.length === expected.length && crypto.timingSafeEqual(given, expected);
  }

  function handleCallback(req, res) {
    const secret = config?.classifierCallbackSecret;
    if (!secret || !prescanJobs) {
      return _fail(res, 404, "callback_disabled", "classifier callbacks are not enabled on this node");
    }
    const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    if (!_signatureValid(secret, raw, req.get(SIGNATURE_HEADER))) {
      return _fail(res, 401, "signature_invalid", `missing or invalid ${SIGNATURE_HEADER}`);
    }
    let body = null;
    try { body = JSON.parse(raw.toString("utf8")); } catch { body = null; }
    const jobId = body && typeof body.job_id === "string" ? body.job_id : "";
    if (!jobId) return _fail(res, 400, "job_id_required", "callback body must carry job_id");
    if (!prescanJobs.wakeByClassifierRef(jobId)) {
      return _fail(res, 404, "job_not_found", "no prescan job waits on this classifier job");
    }
    return res.json({ ok: true, status: 200, data: { job_id: jobId, woken: true } });
  }

  router.post("/prescan/callback", express.raw({ type: () => true, limit: BODY_LIMIT }), handleCallback);
  return router;
}

module.exports = { createRouter };
