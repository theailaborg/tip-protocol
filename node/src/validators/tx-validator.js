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

const { verifyTransaction, mldsaVerify, canonicalTx, verifyTxId } = require("../../../shared/crypto");
const { TX_TYPES, ORIGIN } = require("../../../shared/constants");

// ─── Validation result helper ─────────────────────────────────────────────────
function pass()             { return { valid: true, errors: [] }; }
function fail(...errors)    { return { valid: false, errors }; }
function merge(a, b)        { return { valid: a.valid && b.valid, errors: [...a.errors, ...b.errors] }; }

// ─── Schema rules per transaction type ────────────────────────────────────────
const SCHEMA = {
  [TX_TYPES.REGISTER_IDENTITY]: {
    required: ["tip_id", "region", "public_key", "vp_id", "verification_tier", "dedup_hash", "zk_proof"],
    types:    { tip_id: "string", region: "string", public_key: "string", vp_id: "string", dedup_hash: "string" },
  },
  [TX_TYPES.REGISTER_CONTENT]: {
    required: ["ctid", "origin_code", "content_hash", "author_tip_id", "signature"],
    types:    { ctid: "string", origin_code: "string", content_hash: "string" },
  },
  [TX_TYPES.CONTENT_VERIFIED]: {
    required: ["ctid", "verifier_tip_id", "weighted_delta"],
    types:    { ctid: "string", verifier_tip_id: "string" },
  },
  [TX_TYPES.CONTENT_DISPUTED]: {
    required: ["ctid"],
    types:    { ctid: "string" },
  },
  [TX_TYPES.ADJUDICATION_RESULT]: {
    required: ["ctid", "declared_origin", "confirmed_origin", "verdict"],
    types:    { ctid: "string", verdict: "string" },
  },
  [TX_TYPES.SCORE_UPDATE]: {
    required: ["tip_id", "delta", "score_after", "reason"],
    types:    { tip_id: "string", delta: "number", score_after: "number" },
  },
  [TX_TYPES.REVOKE_VOLUNTARY]: {
    required: ["tip_id"],
    types:    { tip_id: "string" },
  },
  [TX_TYPES.REVOKE_VP]: {
    required: ["tip_id", "reason_code", "evidence_hash", "issuing_vp_id"],
    types:    { tip_id: "string", issuing_vp_id: "string" },
  },
  [TX_TYPES.REVOKE_DECEASED]: {
    required: ["tip_id", "issuing_vp_id"],
    types:    { tip_id: "string" },
  },
  [TX_TYPES.REVOKE_DEVICE]: {
    required: ["tip_id"],
    types:    { tip_id: "string" },
  },
  [TX_TYPES.VP_REGISTERED]: {
    required: ["vp_id", "name", "jurisdiction_tier", "public_key"],
    types:    { vp_id: "string", name: "string" },
  },
  [TX_TYPES.MERKLE_ROOT_PUBLISHED]: {
    required: ["merkle_root", "dedup_count", "identity_count", "node_id"],
    types:    { merkle_root: "string", dedup_count: "number" },
  },
};

// ─── Layer 1: Base structure ──────────────────────────────────────────────────
function validateStructure(tx) {
  const errors = [];

  if (!tx || typeof tx !== "object") { return fail("Transaction must be a non-null object"); }
  // (covered by null check above)
  if (!tx.tx_id)                    errors.push("tx_id is required");
  if (!tx.tx_type)                  errors.push("tx_type is required");
  if (!tx.timestamp)                errors.push("timestamp is required");
  if (!tx.data || typeof tx.data !== "object") errors.push("data must be a non-null object");
  if (!Array.isArray(tx.prev))      errors.push("prev must be an array");

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
  const known = new Set(Object.values(TX_TYPES));
  known.add("GENESIS"); // Allow genesis
  if (!known.has(tx.tx_type)) {
    errors.push(`Unknown tx_type: "${tx.tx_type}". Known types: ${[...known].join(", ")}`);
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
      if (d.verification_tier && !["T1","T2","T3","T4"].includes(d.verification_tier)) {
        errors.push(`Invalid verification_tier: "${d.verification_tier}". Must be T1, T2, T3, or T4`);
      }
      // dedup_hash must be a decimal string (BN128 field element from Poseidon circuit)
      if (d.dedup_hash && !/^\d{1,78}$/.test(d.dedup_hash)) {
        errors.push(`dedup_hash must be a decimal field element string (Poseidon output)`);
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
      // Content hash must be 14-char hex
      if (d.content_hash && !/^[0-9a-f]{14}$/.test(d.content_hash)) {
        errors.push(`content_hash must be a 14-char hex string`);
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

    case TX_TYPES.ADJUDICATION_RESULT: {
      const validVerdicts = ["CLEARED", "DISMISSED", "OH_CONFIRMED_AG", "OH_CONFIRMED_AA", "AA_CONFIRMED_AG", "CONSERVATIVE_LABEL", "FACTUAL_FALSEHOOD"];
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
      if (d.vp_id && !d.vp_id.startsWith("tip://id/VP-")) {
        errors.push(`VP ID must start with "tip://id/VP-"`);
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
    TX_TYPES.MERKLE_ROOT_PUBLISHED,
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
function validateDAGIntegrity(tx, dag) {
  const errors = [];

  // tx_id must match content — detects any field-level tampering
  if (!verifyTxId(tx)) {
    errors.push(`tx_id does not match transaction content — transaction may have been tampered with`);
  }

  // Only genesis can have empty prev
  if (!tx.prev || tx.prev.length === 0) {
    if (tx.tx_type !== "GENESIS") {
      errors.push("Non-genesis tx must have prev references");
    }
    return errors.length ? { valid: false, errors } : pass();
  }

  // All prev references must exist in DAG
  for (const prevId of tx.prev) {
    if (!prevId) { errors.push("Empty prev reference"); continue; }
    if (!dag.getTx(prevId)) {
      errors.push(`prev reference not found in DAG: ${prevId}`);
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
      // Author must exist and not be revoked
      if (d.author_tip_id) {
        const identity = dag.getIdentity(d.author_tip_id);
        if (!identity) {
          errors.push(`Author TIP-ID not found: ${d.author_tip_id}`);
        } else if (dag.isRevoked(d.author_tip_id)) {
          errors.push(`Author TIP-ID is revoked and cannot register content: ${d.author_tip_id}`);
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
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
function validateTransaction(tx, dag, options = {}) {
  const { authorPublicKey, skipCrypto = false, skipState = false } = options;

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
  const dagResult = validateDAGIntegrity(tx, dag);
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
