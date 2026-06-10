/**
 * @file @tip-protocol/node/src/schemas/node-endpoint-update.js
 * @description Validation for NODE_ENDPOINT_UPDATED — a node updating its
 * own public API base URL on chain.
 *
 * Peers use `nodes.api_endpoint` to issue real HTTP redirects when a
 * reviewer requests media bytes that live in a different node's bucket
 * (per-node S3 storage — each operator pays for and serves their own
 * media). The endpoint is operational, owner-controlled data: it is set
 * optionally at NODE_REGISTERED and updated any time afterwards with
 * this tx, signed by the node's OWN registered key (NODE_ENVELOPE
 * contract in schemas/_registry.js). data.node_id is both subject and
 * signer, so self-update is enforced by the signature itself — no
 * council re-attestation for a domain move.
 *
 * `api_endpoint: null` clears the endpoint (node going private /
 * decommissioning its public surface). Peers fall back to the
 * available_at_node_id JSON response.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { schemaError } = require("./_common");

// Origin-only URL: scheme + host + optional port. No path, query, or
// fragment — the redirect builder appends /v1/... itself.
const API_ENDPOINT_RE = /^https?:\/\/[a-z0-9.-]+(:\d{1,5})?$/i;
const NODE_ID_RE = /^tip:\/\/node\/[0-9a-f]{16}$/;

function validateRequest(input) {
  if (!input || typeof input !== "object") {
    throw schemaError(400, "request input is required", "input_invalid");
  }
  if (typeof input.node_id !== "string" || !NODE_ID_RE.test(input.node_id)) {
    throw schemaError(400, "node_id is required (tip://node/<16hex>)", "node_id_required");
  }
  if (input.api_endpoint !== null && (typeof input.api_endpoint !== "string" || !API_ENDPOINT_RE.test(input.api_endpoint))) {
    throw schemaError(400, "api_endpoint must be an origin URL (https://host[:port], no path) or null to clear", "api_endpoint_invalid");
  }
}

module.exports = {
  validateRequest,
  API_ENDPOINT_RE,
  NODE_ID_RE,
};
