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

  // Express JSON parse error (malformed body)
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({
      ok: false,
      status: 400,
      error: {
        message: "Malformed JSON in request body",
        code: "BAD_REQUEST",
        request_id: requestId,
      },
    });
  }

  // Body-parser size cap (express.json request_body_max_bytes / express.raw media limit).
  // PayloadTooLargeError carries status=413 but no `.error` field, so
  // without this mapping it falls through to the 500 branch.
  if (err.type === "entity.too.large") {
    return res.status(413).json({
      ok: false,
      status: 413,
      error: {
        message: `Request body too large${err.limit ? ` (limit ${err.limit} bytes)` : ""}`,
        code: "file_too_large",
        request_id: requestId,
      },
    });
  }

  if (err.status && err.error) {
    const message = Array.isArray(err.error) ? err.error.join("; ") : err.error;
    const errorBody = {
      message,
      code: err.code || STATUS_CODES[err.status] || "ERROR",
      request_id: requestId,
    };
    // Generic `details` envelope: thrower can attach structured data
    // (e.g. 409 prescan_override_required → details: { tier, probability },
    // 429 rate-limited → details: { retry_after }). Single recognized
    // pass-through key — keeps the error response shape predictable and
    // prevents accidental field leakage from sloppy throws.
    if (err.details && typeof err.details === "object") {
      errorBody.details = err.details;
    }
    res.status(err.status).json({
      ok: false,
      status: err.status,
      error: errorBody,
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
