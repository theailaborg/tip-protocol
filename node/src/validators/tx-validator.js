/**
 * @file @tip-protocol/node/src/validators/tx-validator.js
 * @description Production-grade transaction validator.
 *
 * Every transaction entering the DAG passes through this validator.
 * Invalid transactions are rejected with a detailed error.
 *
 * Validation layers:
 *   1. Schema validation  — required fields, types, value ranges
 *   2. Semantic validation — business rule enforcement
 *   3. Cryptographic validation — signature verification
 *   4. DAG integrity — prev[] references exist and are valid
 *   5. State validation — identity exists, not revoked, etc.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const { mldsaVerify, canonicalTx, verifyTxId } = require("../../../shared/crypto");
const {
  TX_TYPES, TX_TYPE_SET, ORIGIN,
  CNA_VERSIONS, ATTRIBUTION_MODE_VALUES, TIP_ID_TYPE_VALUES,
  DOMAIN_VERIFICATION_METHOD_VALUES, DOMAIN_UNBIND_REASON_VALUES,
} = require("../../../shared/constants");
const { isValidDomain } = require("../schemas/register-domain");

// Validator accepts every tx type from the shared frozen set plus the
// "GENESIS" pseudo-type used only for the genesis bootstrap row, which
// isn't a regular tx and therefore isn't in TX_TYPES.
const KNOWN_TX_TYPES = new Set([...TX_TYPE_SET, "GENESIS"]);

// ─── Validation result helper ─────────────────────────────────────────────────
function pass() { return { valid: true, errors: [] }; }
function fail(...errors) { return { valid: false, errors }; }

// ─── Schema rules per transaction type ────────────────────────────────────────
const SCHEMA = {
  [TX_TYPES.REGISTER_IDENTITY]: {
    required: ["tip_id", "region", "public_key", "vp_id", "verification_tier", "dedup_hash", "zk_proof"],
    types: { tip_id: "string", region: "string", public_key: "string", vp_id: "string", dedup_hash: "string" },
  },
  [TX_TYPES.REGISTER_CONTENT]: {
    // CNA-2.2 wire contract — every field below MUST be on tx.data so
    // commit-handler can replay `buildSigningPayload(d, d.content_hash)`
    // deterministically. Deep validation (authors[] entry shape,
    // attribution_mode enum, registered_urls/extras types) is enforced
    // in validateBusinessRules below. Spec: docs/CONTENT_SIGNING.md.
    required: [
      "ctid", "origin_code", "content_hash", "signer_tip_id", "signature",
      "cna_version", "authors",
    ],
    types: {
      ctid: "string", origin_code: "string", content_hash: "string",
      signer_tip_id: "string", cna_version: "string",
    },
  },
  [TX_TYPES.CONTENT_VERIFIED]: {
    required: ["ctid", "verifier_tip_id", "weighted_delta"],
    types: { ctid: "string", verifier_tip_id: "string" },
  },
  [TX_TYPES.BIND_DOMAIN]: {
    // Wire contract — every field is on tx.data so commit-handler can
    // replay bindDomainSchema.buildSigningPayload(d) deterministically.
    // Deeper checks (domain format, enum values, sig presence/length)
    // live in validateBusinessRules below + schemas/bind-domain.verifyTx.
    required: [
      "binding_state", "claim_signature", "claimed_at", "domain", "method",
      "node_id", "tip_id", "verified_at", "binding_signature",
    ],
    types: {
      binding_state: "string", claim_signature: "string", claimed_at: "string",
      domain: "string", method: "string", node_id: "string", tip_id: "string",
      verified_at: "string", binding_signature: "string",
    },
  },
  [TX_TYPES.UNBIND_DOMAIN]: {
    required: ["domain", "node_id", "reason", "revoked_at", "unbind_signature"],
    types: {
      domain: "string", node_id: "string", reason: "string",
      revoked_at: "string", unbind_signature: "string",
    },
  },
  [TX_TYPES.CONTENT_DISPUTED]: {
    required: ["ctid"],
    types: { ctid: "string" },
  },
  [TX_TYPES.ADJUDICATION_RESULT]: {
    // confirmed_origin is only present for UPHELD verdicts (it's the
    // jury's confirmed actual origin); DISMISSED / CONSERVATIVE_LABEL /
    // NO_QUORUM all leave it null. Don't require it across all verdicts.
    required: ["ctid", "declared_origin", "verdict"],
    types: { ctid: "string", verdict: "string" },
  },
  [TX_TYPES.SCORE_UPDATE]: {
    // `score_after` is no longer required at build-time. With #15, the
    // delta is applied by commit-handler against current cache state at
    // commit time — the producer doesn't (and shouldn't) know what the
    // post-state will be. The cache mutation lives in the SCORE_UPDATE
    // case of `_applyDerivedState`. If `score_after` is present we still
    // sanity-check its range (back-compat with legacy in-line writes).
    required: ["tip_id", "delta", "reason"],
    types: { tip_id: "string", delta: "number", score_after: "number" },
  },
  [TX_TYPES.REVOKE_VOLUNTARY]: {
    required: ["tip_id"],
    types: { tip_id: "string" },
  },
  [TX_TYPES.REVOKE_VP]: {
    required: ["tip_id", "reason_code", "evidence_hash", "issuing_vp_id"],
    types: { tip_id: "string", issuing_vp_id: "string" },
  },
  [TX_TYPES.REVOKE_DECEASED]: {
    required: ["tip_id", "issuing_vp_id"],
    types: { tip_id: "string" },
  },
  [TX_TYPES.REVOKE_DEVICE]: {
    required: ["tip_id"],
    types: { tip_id: "string" },
  },
  [TX_TYPES.VP_REGISTERED]: {
    required: ["vp_id", "name", "jurisdiction_tier", "public_key"],
    types: { vp_id: "string", name: "string" },
  },
  [TX_TYPES.COMMITTEE_ROTATION]: {
    // §4 + #34: chain-of-trust rotation event. Deeper validation
    // (rotation_number monotonic, sigs from previous committee, ≥2f+1
    // quorum) lives in commit-handler — those checks need DAG state
    // and can't run in the structure-only layer here.
    required: ["rotation_number", "effective_round", "new_committee", "payload_hash", "signer_node_ids", "signatures"],
    types: { rotation_number: "number", effective_round: "number", payload_hash: "string" },
  },
};

// ─── Layer 1: Base structure ──────────────────────────────────────────────────
function validateStructure(tx) {
  const errors = [];

  if (!tx || typeof tx !== "object") { return fail("Transaction must be a non-null object"); }
  // (covered by null check above)
  if (!tx.tx_id) errors.push("tx_id is required");
  if (!tx.tx_type) errors.push("tx_type is required");
  if (!tx.timestamp) errors.push("timestamp is required");
  if (!tx.data || typeof tx.data !== "object") errors.push("data must be a non-null object");
  if (!Array.isArray(tx.prev)) errors.push("prev must be an array");

  if (errors.length) return fail(...errors);

  // tx_id: non-empty string; if hex must be 16-64 lowercase hex chars
  if (typeof tx.tx_id !== "string" || tx.tx_id.length < 8) {
    errors.push("tx_id must be a non-empty string (min 8 chars)");
  } else if (!tx.tx_id.startsWith("genesis") && !/^[0-9a-f]{64}$/.test(tx.tx_id)) {
    errors.push(`tx_id must be 64-char lowercase hex (SHAKE-256), got: "${tx.tx_id}"`);
  }

  // Timestamp must be a valid ISO string
  const ts = Date.parse(tx.timestamp);
  if (isNaN(ts)) errors.push(`timestamp is not a valid ISO date: ${tx.timestamp}`);

  // Must not be in the future (allow 60s clock skew)
  if (ts > Date.now() + 60_000) {
    errors.push(`Transaction timestamp is in the future: ${tx.timestamp}`);
  }

  // tx_type must be a known type
  if (!KNOWN_TX_TYPES.has(tx.tx_type)) {
    errors.push(`Unknown tx_type: "${tx.tx_type}". Known types: ${[...KNOWN_TX_TYPES].join(", ")}`);
  }

  return errors.length ? fail(...errors) : pass();
}

// ─── Layer 2: Schema validation ───────────────────────────────────────────────
function validateSchema(tx) {
  const schema = SCHEMA[tx.tx_type];
  if (!schema) return pass(); // No schema defined — allow (e.g. GENESIS)

  const errors = [];

  // Check required fields
  for (const field of schema.required) {
    if (tx.data[field] === undefined || tx.data[field] === null || tx.data[field] === "") {
      errors.push(`Missing required field: data.${field}`);
    }
  }

  // Check types
  for (const [field, expectedType] of Object.entries(schema.types || {})) {
    if (tx.data[field] !== undefined && typeof tx.data[field] !== expectedType) {
      errors.push(`Field data.${field} must be ${expectedType}, got ${typeof tx.data[field]}`);
    }
  }

  return errors.length ? fail(...errors) : pass();
}

// ─── Layer 3: Business rules ──────────────────────────────────────────────────
function validateBusinessRules(tx) {
  const errors = [];
  const d = tx.data;

  switch (tx.tx_type) {

    case TX_TYPES.REGISTER_IDENTITY: {
      // Founding members come only from genesis_ring (seed script), never from API transactions
      if (d.founding === true) {
        errors.push("founding flag cannot be set via transactions — founding members are defined in the genesis block");
      }
      // TIP-ID format: tip://id/[REGION]-[16hex]
      if (d.tip_id && !/^tip:\/\/id\/[A-Z]{2,}-[0-9a-f]{16}$/.test(d.tip_id)) {
        errors.push(`Invalid TIP-ID format: "${d.tip_id}". Expected: tip://id/[REGION]-[16hex]`);
      }
      // Verification tier must be T1–T4
      if (d.verification_tier && !["T1", "T2", "T3", "T4"].includes(d.verification_tier)) {
        errors.push(`Invalid verification_tier: "${d.verification_tier}". Must be T1, T2, T3, or T4`);
      }
      // dedup_hash must be a decimal string (BN128 field element from Poseidon circuit)
      if (d.dedup_hash && !/^\d{1,78}$/.test(d.dedup_hash)) {
        errors.push(`dedup_hash must be a decimal field element string (Poseidon output)`);
      }
      // tip_id_type, if present, must be in the canonical enum
      if (d.tip_id_type !== undefined && !TIP_ID_TYPE_VALUES.includes(d.tip_id_type)) {
        errors.push(`tip_id_type must be one of: ${TIP_ID_TYPE_VALUES.join(", ")}`);
      }
      // zk_proof must be a Groth16 proof object
      if (d.zk_proof !== undefined) {
        if (typeof d.zk_proof !== "object" || Array.isArray(d.zk_proof)) {
          errors.push(`zk_proof must be a Groth16 proof object`);
        } else if (!d.zk_proof.pi_a || !d.zk_proof.pi_b || !d.zk_proof.pi_c) {
          errors.push(`zk_proof must have pi_a, pi_b, pi_c fields`);
        }
      }
      break;
    }

    case TX_TYPES.REGISTER_CONTENT: {
      // CTID format: tip://c/[OH|AA|AG|MX]-[14hex]-[4hex]
      if (d.ctid && !/^tip:\/\/c\/(OH|AA|AG|MX)-[0-9a-f]{14}-[0-9a-f]{4}$/.test(d.ctid)) {
        errors.push(`Invalid CTID format: "${d.ctid}". Expected: tip://c/[ORIGIN]-[14hex]-[4hex]`);
      }
      // Origin code must be valid
      if (d.origin_code && !Object.keys(ORIGIN).includes(d.origin_code)) {
        errors.push(`Invalid origin_code: "${d.origin_code}". Must be OH, AA, AG, or MX`);
      }
      // Content hash must be 64-char hex (full SHAKE-256)
      if (d.content_hash && !/^[0-9a-f]{64}$/.test(d.content_hash)) {
        errors.push(`content_hash must be a 64-char hex string`);
      }
      // CNA version check (docs/CONTENT_SIGNING.md §13). Accept any
      // whitelisted CNA version so historical txs keep verifying after
      // a CNA bump.
      const supportedVersions = CNA_VERSIONS.REGISTER_CONTENT.versions;
      if (d.cna_version && !supportedVersions.includes(d.cna_version)) {
        errors.push(`Unsupported cna_version: "${d.cna_version}". Must be one of: ${supportedVersions.join(", ")}.`);
      }
      // authors[] must be a non-empty array of objects with tip://id/... tip_id
      if (d.authors !== undefined) {
        if (!Array.isArray(d.authors) || d.authors.length === 0) {
          errors.push("authors[] must be a non-empty array");
        } else {
          for (const a of d.authors) {
            if (!a || typeof a !== "object"
              || typeof a.tip_id !== "string"
              || !a.tip_id.startsWith("tip://id/")) {
              errors.push("authors[] entry must be an object with a tip://id/... tip_id");
              break;
            }
          }
        }
      }
      // attribution_mode (optional on tx.data — buildSigningPayload defaults
      // to "self"; if present here it MUST be in the canonical enum).
      if (d.attribution_mode !== undefined
        && !ATTRIBUTION_MODE_VALUES.includes(d.attribution_mode)) {
        errors.push(
          `Invalid attribution_mode: "${d.attribution_mode}". Must be one of: ${ATTRIBUTION_MODE_VALUES.join(", ")}`,
        );
      }
      // registered_urls (optional, default []): must be array of strings if present
      if (d.registered_urls !== undefined) {
        if (!Array.isArray(d.registered_urls)
          || d.registered_urls.some(u => typeof u !== "string")) {
          errors.push("registered_urls must be an array of strings");
        }
      }
      // extras (optional, default {}): must be a plain object if present
      if (d.extras !== undefined
        && (d.extras === null || typeof d.extras !== "object" || Array.isArray(d.extras))) {
        errors.push("extras must be an object (use {} for empty)");
      }
      break;
    }

    case TX_TYPES.SCORE_UPDATE: {
      // Score must be in valid range
      if (d.score_after !== undefined && (d.score_after < 0 || d.score_after > 1000)) {
        errors.push(`score_after must be 0–1000, got ${d.score_after}`);
      }
      break;
    }

    case TX_TYPES.BIND_DOMAIN: {
      if (d.tip_id && !d.tip_id.startsWith("tip://id/")) {
        errors.push(`tip_id must be a tip://id/... string`);
      }
      if (d.node_id && !d.node_id.startsWith("tip://node/")) {
        errors.push(`node_id must be a tip://node/... string`);
      }
      // Same regex normalizeDomain uses at API time. Mirrors the registry
      // pattern (or loopback in dev mode). Without this, a gossiped tx
      // with a garbage `domain` value reaches signature verification
      // before failing with an unhelpful diagnostic.
      if (d.domain && !isValidDomain(d.domain)) {
        errors.push(`domain must be a valid hostname: "${d.domain}"`);
      }
      if (d.method && !DOMAIN_VERIFICATION_METHOD_VALUES.includes(d.method)) {
        errors.push(`method must be one of: ${DOMAIN_VERIFICATION_METHOD_VALUES.join(", ")}`);
      }
      // binding_state on a committed BIND_DOMAIN tx is always "verified".
      // (Locally-computed states pending_verification / verification_failed
      // never reach the DAG.)
      if (d.binding_state && d.binding_state !== "verified") {
        errors.push(`BIND_DOMAIN binding_state must be "verified"`);
      }
      // ISO8601 + logical ordering. The node observes proof at verified_at
      // AFTER the user signed at claimed_at — reversed order indicates
      // either a clock skew exploit or a malformed tx.
      const claimedMs = d.claimed_at ? Date.parse(d.claimed_at) : NaN;
      const verifiedMs = d.verified_at ? Date.parse(d.verified_at) : NaN;
      if (d.claimed_at && Number.isNaN(claimedMs)) {
        errors.push(`claimed_at must be an ISO8601 timestamp`);
      }
      if (d.verified_at && Number.isNaN(verifiedMs)) {
        errors.push(`verified_at must be an ISO8601 timestamp`);
      }
      if (!Number.isNaN(claimedMs) && !Number.isNaN(verifiedMs) && verifiedMs < claimedMs) {
        errors.push(`verified_at must not precede claimed_at`);
      }
      break;
    }

    case TX_TYPES.UNBIND_DOMAIN: {
      if (d.node_id && !d.node_id.startsWith("tip://node/")) {
        errors.push(`node_id must be a tip://node/... string`);
      }
      if (d.domain && !isValidDomain(d.domain)) {
        errors.push(`domain must be a valid hostname: "${d.domain}"`);
      }
      if (d.reason && !DOMAIN_UNBIND_REASON_VALUES.includes(d.reason)) {
        errors.push(`reason must be one of: ${DOMAIN_UNBIND_REASON_VALUES.join(", ")}`);
      }
      if (d.revoked_at && Number.isNaN(Date.parse(d.revoked_at))) {
        errors.push(`revoked_at must be an ISO8601 timestamp`);
      }
      break;
    }

    case TX_TYPES.ADJUDICATION_RESULT: {
      // VERDICT names per shared/constants.js — UPHELD / DISMISSED /
      // CONSERVATIVE_LABEL / NO_QUORUM. The legacy v1 list (CLEARED,
      // OH_CONFIRMED_AG, ...) was inherited from before VERDICT was
      // centralised in shared/constants.js — this validator never fired
      // in production because ADJUDICATION_RESULT was written directly
      // by jury.js without going through commit-handler validation. Now
      // that #13 routes it through consensus, the list must match.
      const validVerdicts = ["UPHELD", "DISMISSED", "CONSERVATIVE_LABEL", "NO_QUORUM", "FACTUAL_FALSEHOOD"];
      if (d.verdict && !validVerdicts.includes(d.verdict)) {
        errors.push(`Invalid verdict: "${d.verdict}". Valid verdicts: ${validVerdicts.join(", ")}`);
      }
      break;
    }

    case TX_TYPES.VP_REGISTERED: {
      const validTiers = ["green", "amber"];
      if (d.jurisdiction_tier && !validTiers.includes(d.jurisdiction_tier)) {
        errors.push(`Invalid jurisdiction_tier: "${d.jurisdiction_tier}". VPs in red-tier jurisdictions cannot be accredited.`);
      }
      // VP-ID format
      if (d.vp_id && !d.vp_id.startsWith("tip://vp/")) {
        errors.push(`VP ID must start with "tip://vp/"`);
      }
      break;
    }
  }

  return errors.length ? fail(...errors) : pass();
}

// ─── Layer 4: Cryptographic validation ────────────────────────────────────────
function validateCryptography(tx, authorPublicKey) {
  // Signature is optional in some internal flows (scheduler, etc.)
  if (!tx.signature || !authorPublicKey) return pass();

  // For SCORE_UPDATE and system transactions, skip sig check
  const skipSigTypes = new Set([
    TX_TYPES.SCORE_UPDATE,
    TX_TYPES.CONTENT_DISPUTED,
    "GENESIS",
  ]);
  if (skipSigTypes.has(tx.tx_type)) return pass();

  try {
    const valid = mldsaVerify(canonicalTx(tx), tx.signature, authorPublicKey);
    return valid ? pass() : fail("Signature verification failed — transaction may have been tampered with");
  } catch (err) {
    return fail(`Cryptographic verification error: ${err.message}`);
  }
}

// ─── Layer 5: DAG integrity ───────────────────────────────────────────────────
// When skipPrevCheck is true, prev-reference existence is not required. Used
// during sync replay: the tx's authenticity is already guaranteed by the BFT
// cert wrapping it, and some non-consensus writers (scheduler, scoring, jury)
// insert txs directly into the DAG without broadcasting them — see issue #13.
function validateDAGIntegrity(tx, dag, skipPrevCheck = false) {
  const errors = [];

  // tx_id must match content — detects any field-level tampering
  if (!verifyTxId(tx)) {
    errors.push(`tx_id does not match transaction content — transaction may have been tampered with`);
  }

  // Only system txs can have empty prev. GENESIS bootstraps the chain;
  // COMMITTEE_ROTATION is a system event — its tamper-evidence is the
  // 2f+1 committee sigs over payload_hash + chain-of-trust walker over
  // committee_history.prev_rotation, NOT user-tx prev refs. Coupling
  // rotation to a specific genesis tx_id breaks across DB-drifted
  // federations where peer DBs disagree on the genesis row.
  if (!tx.prev || tx.prev.length === 0) {
    if (tx.tx_type !== "GENESIS" && tx.tx_type !== TX_TYPES.COMMITTEE_ROTATION) {
      errors.push("Non-system tx must have prev references");
    }
    return errors.length ? { valid: false, errors } : pass();
  }

  // All prev references must exist in DAG (skipped during sync replay)
  if (!skipPrevCheck) {
    for (const prevId of tx.prev) {
      if (!prevId) { errors.push("Empty prev reference"); continue; }
      if (!dag.getTx(prevId)) {
        errors.push(`prev reference not found in DAG: ${prevId}`);
      }
    }
  }

  // Duplicate tx_id check
  if (!tx.tx_id.startsWith("genesis")) {
    const existing = dag.getTx(tx.tx_id);
    if (existing) {
      errors.push(`Duplicate tx_id: ${tx.tx_id} already exists in DAG`);
    }
  }

  return errors.length ? fail(...errors) : pass();
}

// ─── Layer 6: State validation (business state) ───────────────────────────────
function validateState(tx, dag) {
  const errors = [];
  const d = tx.data;

  switch (tx.tx_type) {

    case TX_TYPES.REGISTER_IDENTITY: {
      // TIP-ID must not already exist
      if (d.tip_id && dag.getIdentity(d.tip_id)) {
        errors.push(`TIP-ID already registered: ${d.tip_id}`);
      }
      // VP must exist and be active
      if (d.vp_id) {
        const vp = dag.getVP(d.vp_id);
        if (!vp) {
          errors.push(`VP not found: ${d.vp_id}. Register the VP before issuing identities.`);
        } else if (vp.status !== "active") {
          errors.push(`VP is not active: ${d.vp_id} (status: ${vp.status})`);
        }
      }
      break;
    }

    case TX_TYPES.REGISTER_CONTENT: {
      // Signer must exist on the DAG and not be revoked. Single
      // canonical signing path (CNA-2.2 per docs/CONTENT_SIGNING.md);
      // off-DAG signers are rejected at the API layer with 412
      // signer_not_registered, so a tx reaching this validator with an
      // unknown signer_tip_id indicates a malformed submission.
      if (d.signer_tip_id) {
        const identity = dag.getIdentity(d.signer_tip_id);
        if (!identity) {
          errors.push(`Signer TIP-ID not found: ${d.signer_tip_id}`);
        } else if (dag.isRevoked(d.signer_tip_id)) {
          errors.push(`Signer TIP-ID is revoked and cannot register content: ${d.signer_tip_id}`);
        }
      }
      // CTID must not already exist
      if (d.ctid && dag.getContent(d.ctid)) {
        errors.push(`CTID already registered: ${d.ctid}`);
      }
      break;
    }

    case TX_TYPES.CONTENT_VERIFIED:
    case TX_TYPES.CONTENT_DISPUTED: {
      // Content must exist
      if (d.ctid && !dag.getContent(d.ctid)) {
        errors.push(`Content not found: ${d.ctid}`);
      }
      break;
    }

    case TX_TYPES.REVOKE_VP:
    case TX_TYPES.REVOKE_VOLUNTARY:
    case TX_TYPES.REVOKE_DECEASED:
    case TX_TYPES.REVOKE_DEVICE: {
      // Target identity must exist
      if (d.tip_id && !dag.getIdentity(d.tip_id)) {
        errors.push(`Cannot revoke: TIP-ID not found: ${d.tip_id}`);
      }
      // Cannot double-revoke
      if (d.tip_id && dag.isRevoked(d.tip_id)) {
        errors.push(`TIP-ID is already revoked: ${d.tip_id}`);
      }
      break;
    }
  }

  return errors.length ? fail(...errors) : pass();
}

// ─── Master validator ─────────────────────────────────────────────────────────

/**
 * Validate a transaction through all layers.
 *
 * @param {Object} tx                The transaction to validate
 * @param {Object} dag               The DAG store (for state/integrity checks)
 * @param {Object} [options]
 * @param {string} [options.authorPublicKey]  For signature verification
 * @param {boolean} [options.skipCrypto]      Skip crypto layer (for internal/system txs)
 * @param {boolean} [options.skipState]       Skip state layer (for sync from peers)
 * @param {boolean} [options.skipPrevCheck]   Skip prev-reference existence check (sync replay;
 *                                            chain integrity guaranteed by the BFT cert instead)
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
function validateTransaction(tx, dag, options = {}) {
  const { authorPublicKey, skipCrypto = false, skipState = false, skipPrevCheck = false } = options;

  // Layer 1: Structure
  const structResult = validateStructure(tx);
  if (!structResult.valid) {
    return { valid: false, errors: structResult.errors, layer: "structure" };
  }

  // Layer 2: Schema
  const schemaResult = validateSchema(tx);
  if (!schemaResult.valid) {
    return { valid: false, errors: schemaResult.errors, layer: "schema" };
  }

  // Layer 3: Business rules
  const businessResult = validateBusinessRules(tx);
  if (!businessResult.valid) {
    return { valid: false, errors: businessResult.errors, layer: "business_rules" };
  }

  // Layer 4: Cryptography — removed. Node tx-level signature no longer used.
  // Body signatures (author/VP/verifier) are verified at the API endpoint level.
  // Node auth is at the gossip transport layer (challenge-response).

  // Layer 5: DAG integrity
  const dagResult = validateDAGIntegrity(tx, dag, skipPrevCheck);
  if (!dagResult.valid) {
    return { valid: false, errors: dagResult.errors, layer: "dag_integrity" };
  }

  // Layer 6: State validation (optional skip for peer sync)
  if (!skipState) {
    const stateResult = validateState(tx, dag);
    if (!stateResult.valid) {
      return { valid: false, errors: stateResult.errors, layer: "state" };
    }
  }

  return { valid: true, errors: [], layer: null };
}

module.exports = {
  validateTransaction,
  validateStructure,
  validateSchema,
  validateBusinessRules,
  validateCryptography,
  validateDAGIntegrity,
  validateState,
};
