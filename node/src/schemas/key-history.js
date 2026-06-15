/**
 * @file @tip-protocol/node/src/schemas/key-history.js
 * @description Request validation for GET /v1/identity/:tipId/keys.
 *
 * Public read endpoint: the append-only key chain for one identity, the
 * raw material a client walks to verify rotations from the
 * tip_id-anchored root key (tip_id == shake256(key0)[0:16]) to the key
 * valid at any tx timestamp. Works for revoked identities too — their
 * historical signatures still need verification.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError } = require("./_common");

const TIP_ID_RE = /^tip:\/\/id\/[A-Z]{2}-[0-9a-f]{16}$/;

function validateRequest({ tip_id } = {}) {
  if (typeof tip_id !== "string" || !TIP_ID_RE.test(tip_id)) {
    throw schemaError(400, "tipId must be a tip://id/<REGION>-<16hex> URI", "tip_id_invalid");
  }
}

module.exports = { validateRequest, TIP_ID_RE };
