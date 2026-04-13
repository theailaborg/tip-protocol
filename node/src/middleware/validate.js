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

/**
 * Validate content size against media limits from config.
 * Content type must be provided by the client — node does not detect type.
 * For text: raw content is sent, node hashes and verifies.
 * For media: raw content will be sent (future), node hashes and verifies.
 *
 * @param {string|Buffer} content      Raw content
 * @param {string}        contentType  "video" | "audio" | "image" | "text"
 * @param {Object}        mediaLimits  config.mediaLimits
 */
function validateContentSize(content, contentType, mediaLimits) {
  const bytes = Buffer.byteLength(content);
  const type = contentType || "text";
  const VALID_TYPES = ["video", "audio", "image", "text"];
  if (!VALID_TYPES.includes(type)) {
    throw { status: 400, error: `content_type must be one of: ${VALID_TYPES.join(", ")}` };
  }
  const limitMap = {
    video: mediaLimits.max_video_bytes,
    audio: mediaLimits.max_audio_bytes,
    image: mediaLimits.max_image_bytes,
    text: mediaLimits.max_text_bytes,
  };
  const maxBytes = limitMap[type];
  if (bytes > maxBytes) {
    throw { status: 400, error: `Content exceeds ${type} size limit (${bytes} bytes, max ${maxBytes})` };
  }
}

module.exports = { validate, validateContentSize };
