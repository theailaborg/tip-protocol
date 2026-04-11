"use strict";

/**
 * Request body validation helper.
 * Throws structured error if any required field is missing or invalid.
 *
 * Usage:
 *   validate(body, {
 *     author_tip_id: { required: true },
 *     origin_code:   { required: true, oneOf: ["OH", "AA", "AG", "MX"] },
 *     signature:     { required: true },
 *     score:         { type: "number", min: 0, max: 1000 },
 *   });
 */
function validate(body, schema) {
  if (!body || typeof body !== "object") {
    throw { status: 400, error: "Request body is required" };
  }

  for (const [field, rules] of Object.entries(schema)) {
    const value = body[field];

    if (rules.required && (value === undefined || value === null || value === "")) {
      throw { status: 400, error: `${field} is required` };
    }

    // Skip further checks if not provided and not required
    if (value === undefined || value === null) continue;

    if (rules.type && typeof value !== rules.type) {
      throw { status: 400, error: `${field} must be a ${rules.type}` };
    }

    if (rules.oneOf && !rules.oneOf.includes(value)) {
      throw { status: 400, error: `${field} must be one of: ${rules.oneOf.join(", ")}` };
    }

    if (rules.min !== undefined && value < rules.min) {
      throw { status: 400, error: `${field} must be >= ${rules.min}` };
    }

    if (rules.max !== undefined && value > rules.max) {
      throw { status: 400, error: `${field} must be <= ${rules.max}` };
    }

    if (rules.match && !rules.match.test(value)) {
      throw { status: 400, error: `${field} has invalid format` };
    }
  }
}

module.exports = { validate };
