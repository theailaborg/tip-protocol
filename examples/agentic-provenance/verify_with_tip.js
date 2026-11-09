/**
 * Cross-check an evidence bundle written by `python demo.py --export DIR`
 * using TIP's own Node primitives (shared/crypto.js, shared/merkle.js), so the
 * Python records are verified by a second, independent implementation.
 *
 *   npm install                      # at the repository root, once
 *   node examples/agentic-provenance/verify_with_tip.js DIR/valid_edit.json
 *
 * Exit code 0 when every check passes. The tampered bundle written alongside
 * it is expected to FAIL the receipt check.
 *
 * License: TIPCL-1.0 (see LICENSE.txt at the repository root).
 */

"use strict";

const fs = require("fs");
const path = require("path");

const repoRoot = path.resolve(__dirname, "..", "..");
const tip = require(path.join(repoRoot, "shared", "crypto"));
const merkle = require(path.join(repoRoot, "shared", "merkle"));

const recordId = (rec) => tip.shake256(tip.canonicalJson(rec.body));
const signedBy = (rec, keyField) =>
  tip.mldsaVerify(tip.shake256(tip.canonicalJson(rec.body)), rec.sig, rec.body[keyField]);

async function main() {
  const file = process.argv[2];
  if (!file) {
    console.error("usage: node verify_with_tip.js <bundle.json>");
    process.exit(2);
  }
  await tip.initCrypto();
  const b = JSON.parse(fs.readFileSync(file, "utf8"));

  const checks = [];
  checks.push(["agent request signed by the agent key", signedBy(b.request, "agent_key")]);
  for (const d of b.delegations) {
    checks.push([`delegation ${recordId(d).slice(0, 12)} signed by its issuer`, signedBy(d, "issuer_key")]);
  }
  for (const r of b.revocations || []) {
    checks.push([`revocation ${recordId(r).slice(0, 12)} signed by its issuer`, signedBy(r, "issuer_key")]);
  }
  checks.push(["request chain ids match the delegations",
    JSON.stringify(b.request.body.chain) === JSON.stringify(b.delegations.map(recordId))]);
  checks.push(["receipt signed by the site key", signedBy(b.receipt, "site_key")]);
  checks.push(["receipt points at this request", b.receipt.body.request === recordId(b.request)]);
  checks.push(["checkpoint signed by the site key", signedBy(b.checkpoint, "site_key")]);
  checks.push(["receipt included in the checkpointed log (shared/merkle.js)",
    merkle.verifyProof(recordId(b.receipt), b.proof, b.checkpoint.body.root)]);

  let failed = 0;
  for (const [label, ok] of checks) {
    console.log(`${ok ? "PASS" : "FAIL"}  ${label}`);
    if (!ok) failed += 1;
  }

  // Why the action commitment is exact bytes and not the CNA-2 text hash.
  const plus = tip.hashContent("balance=+100");
  const minus = tip.hashContent("balance=-100");
  console.log(`\nCNA-2 hashContent("balance=+100") = ${plus}`);
  console.log(`CNA-2 hashContent("balance=-100") = ${minus}  (${plus === minus ? "same" : "different"})`);

  console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
