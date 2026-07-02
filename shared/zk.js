/**
 * @file tip-protocol/shared/zk.js
 * @description ZK proof utilities for TIP Protocol deduplication.
 *
 * Uses Groth16 (snarkjs) with a Poseidon(3) circuit to prove identity
 * uniqueness without revealing govId, DOB, or country.
 *
 * CLIENT (SDK):
 *   generateDedupProof(govId, dob, country)
 *     → { dedup_hash, proof }   send both to POST /v1/identity/register
 *
 * SERVER (node):
 *   verifyDedupProof(dedupHash, proof)
 *     → true / false
 *
 * Environment:
 *
 * Prerequisites (run once):
 *   node scripts/zk-setup.js
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * @author    Dinesh Mendhe <chairman@theailab.org>
 */

"use strict";

const path    = require("path");
const fs      = require("fs");
const snarkjs = require("snarkjs");

const CIRCUITS_DIR = path.join(__dirname, "../circuits");

// ─── Load verification key (server-side) ─────────────────────────────────────
let _vKey = null;
function _loadVKey() {
  if (_vKey) return _vKey;
  const vKeyPath = path.join(CIRCUITS_DIR, "vkey.json");
  if (!fs.existsSync(vKeyPath)) {
    throw new Error(
      "ZK verification key not found. Run: node scripts/zk-setup.js"
    );
  }
  _vKey = JSON.parse(fs.readFileSync(vKeyPath, "utf8"));
  return _vKey;
}

// ─── Input encoding ───────────────────────────────────────────────────────────
// All inputs must be BN128 field elements (< 2^254).

/**
 * Encode a government ID to a BN128 field element.
 * Normalise to uppercase alphanumeric, take first 30 bytes, interpret as BigInt.
 * @param {string} govId
 * @returns {string} decimal string
 */
function encodeGovId(govId) {
  const norm  = govId.trim().toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 30);
  const hex   = Buffer.from(norm, "utf8").toString("hex");
  return hex ? BigInt("0x" + hex).toString() : "0";
}

/**
 * Encode a date of birth to a BN128 field element.
 * @param {string} dob  ISO date "YYYY-MM-DD"
 * @returns {string} decimal string  e.g. "19900515"
 */
function encodeDOB(dob) {
  return BigInt(dob.replace(/-/g, "")).toString();
}

/**
 * Encode an ISO-3166-1 alpha-2 country code to a BN128 field element.
 * @param {string} country  e.g. "US"
 * @returns {string} decimal string
 */
function encodeCountry(country) {
  const upper = country.toUpperCase().slice(0, 2).padEnd(2, "A");
  return BigInt(upper.charCodeAt(0) * 256 + upper.charCodeAt(1)).toString();
}

// ─── Client: generate proof ───────────────────────────────────────────────────

/**
 * Generate a Groth16 ZK proof of identity uniqueness.
 *
 * Runs on the user's device / SDK. The govId, dob, country are PRIVATE —
 * they never leave this function. Only { dedup_hash, proof } are sent to server.
 *
 * @param {string} govId     Government ID (passport number, national ID, etc.)
 * @param {string} dob       Date of birth "YYYY-MM-DD"
 * @param {string} country   ISO-3166-1 alpha-2 country code e.g. "US"
 * @returns {Promise<{ dedup_hash: string, proof: object }>}
 */
async function generateDedupProof(govId, dob, country) {
  const wasmPath = path.join(CIRCUITS_DIR, "dedup_js", "dedup.wasm");
  const zkeyPath = path.join(CIRCUITS_DIR, "dedup_final.zkey");

  if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
    throw new Error(
      "ZK circuit artifacts not found. Run: node scripts/zk-setup.js"
    );
  }

  const input = {
    gov_id:  encodeGovId(govId),
    dob:     encodeDOB(dob),
    country: encodeCountry(country),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );

  // TODO [NIST-HASH]: dedup_hash is currently the raw Poseidon field element (decimal
  // string). Poseidon has no NIST certification — this is a compliance gap for
  // government/financial use. When ready, wrap with SHAKE-256 (FIPS 202):
  //
  //   const { shake256 } = require("./crypto");
  //   const dedup_hash = shake256(publicSignals[0]);  // NIST FIPS 202 ✓
  //
  // Also attach publicSignals to the proof so verifyDedupProof() can verify against
  // the raw Poseidon output then recompute SHAKE-256 to confirm it matches.
  // See todo.md → "ZK Proof — NIST-Compliant Dedup Hash" for full change list.
  return {
    dedup_hash: publicSignals[0],  // raw Poseidon output — see TODO [NIST-HASH] above
    proof,
  };
}

// ─── Server: verify proof ─────────────────────────────────────────────────────

/**
 * Verify a Groth16 dedup proof.
 *
 * Runs on the TIP node. Checks that the proof correctly demonstrates
 * knowledge of inputs that Poseidon-hash to dedupHash.
 *
 * @param {string} dedupHash   Poseidon output (decimal string) — as stored in dedup_registry
 * @param {object} proof       The Groth16 proof object { pi_a, pi_b, pi_c, ... }
 * @returns {Promise<boolean>}
 */
async function verifyDedupProof(dedupHash, proof) {
  const vKey = _loadVKey();
  return snarkjs.groth16.verify(vKey, [dedupHash], proof);
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  generateDedupProof,
  verifyDedupProof,
  encodeGovId,
  encodeDOB,
  encodeCountry,
};
