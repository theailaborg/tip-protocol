#!/usr/bin/env node
/**
 * End-to-end bootstrap gate smoke test.
 *
 * Run via: docker exec tip-node1 node /app/node/scripts/test-bootstrap-gate.js
 *
 * What it proves:
 *   1. Queries the live PostgreSQL for the real committed round.
 *   2. Calls validateTransaction (the exact path that commitOrderedTxs uses)
 *      with GENESIS, founding VP_REGISTERED, and founding NODE_REGISTERED txs.
 *   3. Confirms all three are rejected with the bootstrap-only error.
 *   4. Confirms a non-founding VP_REGISTERED at round > 1 still passes.
 *   5. Dumps recent tx_rejections rows from the DB so you can see live rejections.
 */
"use strict";

const { nowMs, toIso } = require("../shared/time");

const path = require("path");
// Resolve from the monorepo root whether the script runs from
// scripts/ on the host or from /app in the container.
const REPO   = (() => {
  // container: script is copied to /app/test-bootstrap-gate.js
  // host:      script lives at <repo>/scripts/test-bootstrap-gate.js
  const candidate = path.resolve(__dirname, "..");            // host: <repo>
  const fs = require("fs");
  if (fs.existsSync(path.join(candidate, "shared"))) return candidate;
  return __dirname;                                           // container: /app
})();
const NODE  = path.join(REPO, "node");
const SHARED = path.join(REPO, "shared");

async function main() {
  // ── 1. Init crypto (needed by the validator module) ─────────────────────────
  const { initCrypto } = require(SHARED + "/crypto");
  await initCrypto();
  console.log("✓ crypto initialised");

  // ── 2. Load validator + genesis helpers ─────────────────────────────────────
  const { validateTransaction } = require(NODE + "/src/validators/tx-validator");
  const { getFoundingVP, getGenesisCommittee } = require(NODE + "/src/genesis");
  const { TX_TYPES } = require(SHARED + "/constants");

  const foundingVpId     = getFoundingVP().vp_id;
  const [foundingNodeId] = [...getGenesisCommittee()];
  console.log(`✓ founding VP   : ${foundingVpId}`);
  console.log(`✓ founding node : ${foundingNodeId}`);

  // ── 3. Query live PostgreSQL for the actual committed round ──────────────────
  const { Client } = require("pg");
  const pg = new Client({
    host:     process.env.DB_HOST     || "postgres",
    port:     parseInt(process.env.DB_PORT || "5432"),
    database: process.env.DB_NAME     || "tip_node1",
    user:     process.env.DB_USER     || "tipuser",
    password: process.env.DB_PASSWORD || "Tip_Password_2025",
  });
  await pg.connect();

  const { rows: [{ max_round }] } = await pg.query(
    "SELECT MAX(round) AS max_round FROM certificates"
  );
  const liveRound = Number(max_round) || 0;
  console.log(`✓ live committed round from postgres: ${liveRound}`);

  if (liveRound <= 1) {
    console.error("✗ SKIP — cluster has not advanced past round 1 yet. Try again later.");
    await pg.end();
    process.exit(1);
  }

  // ── 4. Build a dag stub that returns the real round ──────────────────────────
  const dag = { getLatestRound: () => liveRound };

  // ── 5. Run the gate tests ────────────────────────────────────────────────────
  // Layer 1 (validateStructure) requires tx_id to be 64-char lowercase hex.
  // Use a static valid hex so the tx reaches Layer 3 (our gate) where it belongs.
  const HEX64 = "a".repeat(64);

  const tests = [
    {
      label: "GENESIS tx rejected after round 1",
      tx: { tx_type: "GENESIS", tx_id: HEX64, timestamp: nowMs(), data: {}, prev: [] },
      expectValid: false,
      expectMatch: /bootstrap-only/,
    },
    {
      label: "Founding VP_REGISTERED rejected after round 1",
      tx: {
        tx_type: TX_TYPES.VP_REGISTERED,
        tx_id:   HEX64,
        timestamp: nowMs(),
        prev: [],
        data: { vp_id: foundingVpId, name: "replay", jurisdiction_tier: "green", public_key: "aabb" },
      },
      expectValid: false,
      expectMatch: /founding VP/,
    },
    {
      label: "Founding NODE_REGISTERED rejected after round 1",
      tx: {
        tx_type: TX_TYPES.NODE_REGISTERED,
        tx_id:   HEX64,
        timestamp: nowMs(),
        prev: [],
        data: { node_id: foundingNodeId, name: "replay", public_key: "ccdd" },
      },
      expectValid: false,
      expectMatch: /founding node/,
    },
    {
      label: "Non-founding VP_REGISTERED passes the gate (reaches crypto layer)",
      tx: {
        tx_type: TX_TYPES.VP_REGISTERED,
        tx_id:   HEX64,
        timestamp: nowMs(),
        prev: [],
        data: { vp_id: "tip://vp/US-aabbccddeeff0011", name: "New VP", jurisdiction_tier: "green", public_key: "eeff" },
      },
      // Passes bootstrap gate; will fail at crypto/state — that's expected and fine.
      expectValid: false,
      expectLayer: null,           // any layer other than business_rules
      expectNotMatch: /bootstrap-only|founding/,
    },
  ];

  let passed = 0;
  let failed = 0;
  console.log("\n── Gate tests ──────────────────────────────────────────────────────────────");
  for (const t of tests) {
    const r = validateTransaction(t.tx, dag);
    const errors = r.errors || [];
    const validOk    = r.valid === t.expectValid;
    const matchOk    = !t.expectMatch    || errors.some(e => t.expectMatch.test(e));
    const notMatchOk = !t.expectNotMatch || errors.every(e => !t.expectNotMatch.test(e));
    const layerOk    = t.expectLayer !== undefined
      ? r.layer !== "business_rules"     // non-founding VP: gate didn't fire
      : (!t.expectValid ? r.layer === "business_rules" : true);
    const ok = validOk && matchOk && notMatchOk && layerOk;

    if (ok) {
      console.log(`  PASS  ${t.label}`);
      if (r.layer) console.log(`        layer  : ${r.layer}  |  ${errors[0] || ""}`);
      passed++;
    } else {
      console.log(`  FAIL  ${t.label}`);
      console.log(`        valid  : expected=${t.expectValid} got=${r.valid}`);
      console.log(`        layer  : got=${r.layer}`);
      console.log(`        errors : ${JSON.stringify(errors)}`);
      failed++;
    }
  }

  // ── 6. Dump recent tx_rejections for bootstrap-related entries ───────────────
  console.log("\n── Recent tx_rejections (bootstrap-related) ────────────────────────────────");
  const { rows: rejections } = await pg.query(`
    SELECT tx_id, tx_type, reason, reason_detail, rejected_at_ms
    FROM tx_rejections
    WHERE reason_detail ILIKE '%bootstrap%'
       OR reason_detail ILIKE '%founding%'
       OR tx_type = 'GENESIS'
    ORDER BY rejected_at_ms DESC
    LIMIT 10
  `);
  if (rejections.length === 0) {
    console.log("  (none — no bootstrap-type rejections recorded yet; this is expected unless a malicious peer was active)");
  } else {
    rejections.forEach(r => {
      const ts = toIso(Number(r.rejected_at_ms));
      console.log(`  ${ts} | ${r.tx_type} | ${r.reason} | ${r.reason_detail}`);
    });
  }

  await pg.end();

  // ── 7. Final summary ─────────────────────────────────────────────────────────
  console.log(`\n── Result: ${passed} passed, ${failed} failed ──────────────────────────────────`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error("ERROR:", err.message);
  process.exit(1);
});
