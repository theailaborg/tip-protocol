"use strict";

const { getLogger } = require("../logger");
const log = getLogger("tip.error");

const STATUS_CODES = {
  400: "BAD_REQUEST",
  403: "FORBIDDEN",
  404: "NOT_FOUND",
  409: "CONFLICT",
  429: "RATE_LIMITED",
  500: "INTERNAL_ERROR",
};

/**
 * Global error handler — normalizes ALL error responses to:
 * { ok: false, error: { message, code, status } }
 */
function errorHandler(err, req, res, _next) {
  const requestId = req.id || null;

  if (err.status && err.error) {
    const message = Array.isArray(err.error) ? err.error.join("; ") : err.error;
    res.status(err.status).json({
      ok: false,
      status: err.status,
      error: {
        message,
        code: err.code || STATUS_CODES[err.status] || "ERROR",
        request_id: requestId,
      },
    });
  } else {
    log.error(`[${requestId}] ${req.method} ${req.path} — unhandled error:`, err.message || err);
    if (!res.headersSent) {
      res.status(500).json({
        ok: false,
        status: 500,
        error: {
          message: "Internal server error",
          code: "INTERNAL_ERROR",
          request_id: requestId,
        },
      });
    }
  }
}

/**
 * Async route wrapper — catches all throws and forwards to error handler.
 */
function asyncHandler(fn) {
  return (req, res, next) => {
    try {
      const result = fn(req, res, next);
      if (result && typeof result.catch === "function") {
        result.catch(next);
      }
    } catch (err) {
      next(err);
    }
  };
}

module.exports = { errorHandler, asyncHandler };
