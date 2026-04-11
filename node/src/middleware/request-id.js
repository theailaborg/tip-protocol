"use strict";

const crypto = require("crypto");

/**
 * Assigns a unique request ID to every incoming request.
 * - Sets `req.id` for use in application code / logging
 * - Sets `X-Request-ID` response header for client-side correlation
 * - Honors incoming `X-Request-ID` header (e.g. from load balancer)
 */
function requestId(req, res, next) {
  const id = req.headers["x-request-id"] || crypto.randomUUID();
  req.id = id;
  res.setHeader("X-Request-ID", id);
  next();
}

module.exports = { requestId };
