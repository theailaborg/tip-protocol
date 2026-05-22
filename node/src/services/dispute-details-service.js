/**
 * @file @tip-protocol/node/src/services/dispute-details-service.js
 * @description Off-chain dispute body store (v0).
 *
 * Holds the disputer-submitted description + structured evidence array,
 * bound by `evidence_hash` to a CONTENT_DISPUTED tx. The hash lives on-chain;
 * the body does NOT — see my-notes/EVIDENCE_OFFCHAIN_STORE.md for the full
 * design and rationale.
 *
 * v0 scope:
 *   - persistEvidence: validate shape, recompute hash, verify signature,
 *     persist. Called from dispute-service.fileDispute when the request
 *     carries an `evidence` block — never exposed as a standalone HTTP
 *     write endpoint, so the dispute and its body land atomically (no
 *     "uploaded body, walked away" orphans).
 *   - getDetails / hasDetails: read-only retrieval for jurors. Local store
 *     only; no peer-fetch (v1 work).
 *
 * Authenticity contract: every byte the server stores has been sig-verified
 * against the disputer's on-chain public key. Reads can re-verify (signature
 * + payload + disputer_tip_id are returned together) so callers never have
 * to trust the node, only the math.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { shake256, canonicalJson, mldsaVerify } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { TX_TYPES } = require("../../../shared/constants");
const { validate } = require("../middleware/validate");
const { getLogger } = require("../logger");

const log = getLogger("tip.dispute-details");

// Validation caps — match what we promised in the spec.
const MAX_DESCRIPTION_CHARS = 2000;
const MAX_EVIDENCE_ITEMS = 10;
const MAX_STATEMENT_BYTES = 4 * 1024;
const MAX_URL_BYTES = 2 * 1024;
const MAX_CTID_CHARS = 256;
const MAX_PAYLOAD_BYTES = 32 * 1024;
const ITEM_DESCRIPTION_MAX_CHARS = 200;

const URL_PATTERN = /^https?:\/\/[^\s]+$/i;
const CTID_PATTERN = /^tip:\/\/c\//;
const HEX_PATTERN = /^[0-9a-f]+$/i;

const EVIDENCE_TYPES = ["url", "ctid", "statement"];

function _byteLen(s) {
  return Buffer.byteLength(s || "", "utf8");
}

function _validatePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw { status: 400, error: "payload must be an object" };
  }

  const { description, evidence } = payload;

  if (typeof description !== "string") throw { status: 400, error: "payload.description must be a string" };
  if (description.length < 1) throw { status: 400, error: "payload.description must be non-empty" };
  if (description.length > MAX_DESCRIPTION_CHARS) {
    throw { status: 400, error: `payload.description exceeds ${MAX_DESCRIPTION_CHARS} chars` };
  }

  // Items array is optional. Clients drop the key entirely when there are
  // no items — empty/null fields must never appear in the signed canonical
  // payload, otherwise the hash diverges from a description-only build.
  if (evidence === undefined) return;

  if (!Array.isArray(evidence)) throw { status: 400, error: "payload.evidence must be an array (or omit the key entirely)" };
  if (evidence.length === 0) throw { status: 400, error: "payload.evidence must be omitted when empty — do not send `evidence: []`" };
  if (evidence.length > MAX_EVIDENCE_ITEMS) {
    throw { status: 400, error: `payload.evidence exceeds ${MAX_EVIDENCE_ITEMS} items` };
  }

  for (let i = 0; i < evidence.length; i++) {
    const item = evidence[i];
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw { status: 400, error: `payload.evidence[${i}] must be an object` };
    }
    if (!EVIDENCE_TYPES.includes(item.type)) {
      throw { status: 400, error: `payload.evidence[${i}].type must be one of: ${EVIDENCE_TYPES.join(", ")}` };
    }
    if (typeof item.content !== "string" || item.content.length === 0) {
      throw { status: 400, error: `payload.evidence[${i}].content must be a non-empty string` };
    }
    if (item.description !== undefined) {
      if (typeof item.description !== "string") {
        throw { status: 400, error: `payload.evidence[${i}].description must be a string` };
      }
      if (item.description.length > ITEM_DESCRIPTION_MAX_CHARS) {
        throw { status: 400, error: `payload.evidence[${i}].description exceeds ${ITEM_DESCRIPTION_MAX_CHARS} chars` };
      }
    }

    switch (item.type) {
      case "url":
        if (!URL_PATTERN.test(item.content)) {
          throw { status: 400, error: `payload.evidence[${i}].content must be a valid http(s) URL` };
        }
        if (_byteLen(item.content) > MAX_URL_BYTES) {
          throw { status: 400, error: `payload.evidence[${i}].content exceeds ${MAX_URL_BYTES} bytes` };
        }
        break;
      case "ctid":
        if (!CTID_PATTERN.test(item.content)) {
          throw { status: 400, error: `payload.evidence[${i}].content must be a tip://c/... CTID` };
        }
        if (item.content.length > MAX_CTID_CHARS) {
          throw { status: 400, error: `payload.evidence[${i}].content exceeds ${MAX_CTID_CHARS} chars` };
        }
        break;
      case "statement":
        if (_byteLen(item.content) > MAX_STATEMENT_BYTES) {
          throw { status: 400, error: `payload.evidence[${i}].content exceeds ${MAX_STATEMENT_BYTES} bytes` };
        }
        break;
    }
  }
}

function createDisputeDetailsService({ dag }) {

  // Internal helper called from dispute-service.fileDispute when the
  // dispute request carries an `evidence` block. Returns the recomputed
  // evidence_hash on success; throws structured errors on validation /
  // signature / collision failures so the surrounding fileDispute call
  // can abort before any tx is built or submitted.
  //
  // Idempotency: re-running with the same payload + same disputer is a
  // silent no-op. Different disputer hitting the same hash → 409.
  function persistEvidence({ disputer_tip_id, payload, signature }) {
    validate(
      { disputer_tip_id, payload, signature },
      {
        disputer_tip_id: { required: true, type: "string", match: /^tip:\/\/id\// },
        payload: { required: true },
        signature: { required: true, type: "string", match: HEX_PATTERN },
      },
    );

    _validatePayload(payload);

    const canonical = canonicalJson(payload);
    const canonicalBytes = _byteLen(canonical);
    if (canonicalBytes > MAX_PAYLOAD_BYTES) {
      throw { status: 400, error: `payload exceeds ${MAX_PAYLOAD_BYTES} bytes (canonical size: ${canonicalBytes})` };
    }
    const evidence_hash = shake256(canonical);

    // Refuse if this hash is already bound to a CONTENT_DISPUTED tx.
    // Mirrors the consensus uniqueness rule in business-rules.canDispute,
    // surfaced earlier so the disputer hits the error before signing/
    // submitting anything else.
    const bound = dag.getTxsByType(TX_TYPES.CONTENT_DISPUTED)
      .find(t => t.data?.evidence_hash === evidence_hash);
    if (bound) {
      throw { status: 409, error: "evidence body already attached to an existing dispute — vary the body to produce a unique hash" };
    }

    const existing = dag.getDisputeDetails(evidence_hash);
    if (existing) {
      if (existing.disputer_tip_id !== disputer_tip_id) {
        throw { status: 409, error: "evidence_hash already uploaded by a different identity" };
      }
      // Idempotent re-persist of an already-saved body by the same disputer.
      return { evidence_hash, size_bytes: canonicalBytes, idempotent: true };
    }

    const disputer = dag.getIdentity(disputer_tip_id);
    if (!disputer) throw { status: 404, error: "disputer_tip_id not found" };
    if (dag.isRevoked && dag.isRevoked(disputer_tip_id)) {
      throw { status: 403, error: "disputer_tip_id is revoked" };
    }

    if (!mldsaVerify(evidence_hash, signature, disputer.public_key)) {
      throw { status: 403, error: "Evidence signature verification failed" };
    }

    dag.saveDisputeDetails({
      evidence_hash,
      disputer_tip_id,
      payload_json: canonical,
      signature,
      local_inserted_at: nowMs(),
    });

    log.info(`Dispute details stored: ${evidence_hash} by ${disputer_tip_id} (${canonicalBytes} bytes)`);

    return { evidence_hash, size_bytes: canonicalBytes, idempotent: false };
  }

  // Compensating delete used by fileDispute if tx submission fails after
  // the body row was written. Safe to call on a non-existent hash.
  function discardEvidence(hash) {
    if (typeof hash !== "string") return false;
    return dag.deleteDisputeDetails(hash);
  }

  // GET /v1/evidence/:hash — return the body if locally held.
  function getDetails(hash) {
    validate({ evidence_hash: hash }, { evidence_hash: { required: true, type: "string", match: HEX_PATTERN } });
    const row = dag.getDisputeDetails(hash.toLowerCase());
    if (!row) throw { status: 404, error: "Dispute details not found" };
    return {
      evidence_hash: row.evidence_hash,
      disputer_tip_id: row.disputer_tip_id,
      payload: JSON.parse(row.payload_json),
      signature: row.signature,
      local_inserted_at: row.local_inserted_at,
    };
  }

  // HEAD /v1/evidence/:hash — cheap existence check (no payload returned).
  function hasDetails(hash) {
    if (typeof hash !== "string" || !HEX_PATTERN.test(hash)) return false;
    return !!dag.hasDisputeDetails(hash.toLowerCase());
  }

  return { persistEvidence, discardEvidence, getDetails, hasDetails };
}

module.exports = { createDisputeDetailsService };
