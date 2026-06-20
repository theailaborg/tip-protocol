/**
 * @file scripts/gen-signing-canonical-vectors.js
 * @description Regenerate the golden canonical signed-payload vectors consumed
 * by tests/signing-canonical-vectors.test.js.
 *
 * The CASES below are the source of truth for WHICH (tx_type, sample data) pairs
 * are frozen. Running this script recomputes the canonical bytes from the live
 * recipes and rewrites the fixture. Only run it to (re)freeze after an APPROVED
 * recipe change, then review the JSON diff: a change to the canonical bytes of
 * an EXISTING case is a break in historical-signature verification and must be
 * deliberate (additive field, or a new tx_type), never an accident.
 *
 *   node node/scripts/gen-signing-canonical-vectors.js
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const path = require("path");

const { canonicalJson } = require(path.resolve(__dirname, "../../shared/crypto"));
const { TX_TYPES } = require(path.resolve(__dirname, "../../shared/constants"));
const { TX_SIGNATURE_REGISTRY } = require(path.resolve(__dirname, "../src/schemas/_registry"));

const FIXTURE = path.resolve(__dirname, "../tests/fixtures/signing-canonical-vectors.json");

// [tx_type key in TX_TYPES, case label, sample data].
// required_only / with_optional pairs pin the strip rule (absent optional must
// not appear in the bytes; present optional must).
const CASES = [
  ["CONTENT_VERIFIED", "base", { verifier_tip_id: "tip://id/US-verif", ctid: "ctid-deadbeef", verdict: "OH" }],
  ["UPDATE_ORIGIN", "base", { author_tip_id: "tip://id/US-author", ctid: "ctid-deadbeef", new_origin_code: "AA" }],
  ["CONTENT_RETRACTED", "base", { author_tip_id: "tip://id/US-author", ctid: "ctid-deadbeef" }],
  ["JURY_VOTE_COMMIT", "base", { juror_tip_id: "tip://id/US-juror", commitment: "commit-hash" }],
  ["JURY_VOTE_REVEAL", "required_only", { juror_tip_id: "tip://id/US-juror", vote: "MATCH", salt: "salt-1" }],
  ["JURY_VOTE_REVEAL", "with_optional", { juror_tip_id: "tip://id/US-juror", vote: "MISMATCH", salt: "salt-1", confirmed_origin: "AG" }],
  ["CONTENT_DISPUTED", "required_only", { disputer_tip_id: "tip://id/US-disp", reason: "mislabel" }],
  ["CONTENT_DISPUTED", "with_optional", { disputer_tip_id: "tip://id/US-disp", reason: "mislabel", claimed_origin: "MX", evidence_hash: "ev-hash" }],
  ["APPEAL_FILED", "user", { appellant_tip_id: "tip://id/US-appel", ctid: "ctid-deadbeef" }],
  ["REVOKE_VOLUNTARY", "required_only", { tx_type: "REVOKE_VOLUNTARY", tip_id: "tip://id/US-x", issuing_vp_id: "tip://vp/iss" }],
  ["REVOKE_VOLUNTARY", "with_optional", { tx_type: "REVOKE_VOLUNTARY", tip_id: "tip://id/US-x", issuing_vp_id: "tip://vp/iss", reason_code: "voluntary", evidence_hash: "ev-hash" }],
  ["REVOKE_DEVICE", "base", { tx_type: "REVOKE_DEVICE", tip_id: "tip://id/US-x", issuing_vp_id: "tip://vp/iss" }],
  ["REVOKE_VP", "base", { tx_type: "REVOKE_VP", tip_id: "tip://id/US-x", issuing_vp_id: "tip://vp/iss" }],
  ["REVOKE_DECEASED", "base", { tx_type: "REVOKE_DECEASED", tip_id: "tip://id/US-x", issuing_vp_id: "tip://vp/iss" }],
  ["VP_REGISTERED", "algo_default", { name: "VP1", jurisdiction: "US", jurisdiction_tier: 1, public_key: "pubkey-hex", approving_vp_id: "tip://vp/appr" }],
  ["NODE_REGISTERED", "no_endpoint", { name: "N1", public_key: "pubkey-hex", approving_vp_id: "tip://vp/appr" }],
  ["NODE_REGISTERED", "with_endpoint", { name: "N1", public_key: "pubkey-hex", approving_vp_id: "tip://vp/appr", api_endpoint: "https://n1.example.com" }],
  ["UNBIND_DOMAIN", "base", { domain: "example.com", node_id: "tip://node/n1", reason: "revoked", revoked_at: 1767225600000 }],
];

function buildCanonical(txType, data) {
  const entry = TX_SIGNATURE_REGISTRY[txType];
  if (!entry) throw new Error(`no registry entry for ${txType}`);
  const contract = typeof entry.getSignatureContract === "function"
    ? entry.getSignatureContract({ tx_type: txType, data })
    : entry;
  return canonicalJson(contract.buildSigningPayload(data));
}

function main() {
  const out = {};
  for (const [typeKey, label, data] of CASES) {
    const txType = TX_TYPES[typeKey];
    if (!txType) throw new Error(`unknown TX_TYPES key: ${typeKey}`);
    out[`${typeKey}:${label}`] = { tx_type: txType, data, canonical: buildCanonical(txType, data) };
  }
  fs.writeFileSync(FIXTURE, JSON.stringify(out, null, 2) + "\n");
  process.stdout.write(`wrote ${Object.keys(out).length} vectors to ${path.relative(process.cwd(), FIXTURE)}\n`);
}

main();
