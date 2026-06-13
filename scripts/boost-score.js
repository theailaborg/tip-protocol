#!/usr/bin/env node
/**
 * @file scripts/boost-score.js
 * @description DEV-ONLY: Directly SQL-update a TIP-ID's score in all 5
 * postgres DBs so it meets the reviewer.min_score (800) threshold.
 *
 * Uses the same docker exec + psql pattern as seed-temp-users.js.
 * Requires the tip-postgres container to be running.
 *
 * Usage:
 *   node scripts/boost-score.js --tip-id tip://id/IN-2ead91afd880db75 --score 850
 *   node scripts/boost-score.js --tip-id tip://id/IN-2ead91afd880db75 --score 850 --dry-run
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const { execSync } = require("child_process");
const { nowMs } = require("../shared/time");

const NODES_DBS = [
  "tip_node1",
  "tip_node2",
  "tip_node3",
  "tip_node4",
  "tip_node5",
];
const PG_CONTAINER = "tip-postgres";
const PG_USER      = "tipuser";
const PG_PASSWORD  = "Tip_Password_2025";

function parseArgs(argv) {
  const args = { tipId: null, score: 850, dryRun: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if      (a === "--tip-id")  args.tipId  = argv[++i];
    else if (a === "--score")   args.score  = Number(argv[++i]);
    else if (a === "--dry-run") args.dryRun = true;
    else if (a === "--help" || a === "-h") {
      console.log("usage: boost-score.js --tip-id <TIP-ID> [--score N] [--dry-run]");
      console.log("  --tip-id tip://id/...   identity to boost");
      console.log("  --score  N              target score (default 850)");
      console.log("  --dry-run               print SQL without executing");
      process.exit(0);
    }
  }
  if (!args.tipId) { console.error("ERROR: --tip-id is required"); process.exit(1); }
  if (isNaN(args.score) || args.score < 1 || args.score > 1000) {
    console.error("ERROR: --score must be between 1 and 1000"); process.exit(1);
  }
  return args;
}

function runSql(db, sql, dryRun) {
  if (dryRun) {
    console.log(`  [dry-run] DB=${db} SQL: ${sql.trim()}`);
    return true;
  }
  try {
    execSync(
      `docker exec -i -e PGPASSWORD=${PG_PASSWORD} ${PG_CONTAINER} psql -U ${PG_USER} -d ${db} -v ON_ERROR_STOP=1`,
      { input: sql, stdio: ["pipe", "pipe", "pipe"] }
    );
    return true;
  } catch (e) {
    const stderr = e.stderr?.toString() || e.message || "";
    if (/relation "scores" does not exist|database .* does not exist/i.test(stderr)) {
      console.log(`  ⚠  ${db}: table not ready yet — skip`);
      return false;
    }
    console.error(`  ✗  ${db}: ${stderr.split("\n")[0]}`);
    return false;
  }
}

function main() {
  const args = parseArgs(process.argv);
  const now  = nowMs();

  const sql = `
INSERT INTO scores (tip_id, score, offense_count, last_updated)
VALUES ('${args.tipId}', ${args.score}, 0, ${now})
ON CONFLICT (tip_id) DO UPDATE
  SET score = EXCLUDED.score,
      last_updated = EXCLUDED.last_updated;
`;

  console.log(`Boosting score for ${args.tipId} → ${args.score} in ${NODES_DBS.length} DBs`);
  if (args.dryRun) console.log("(dry-run mode — no changes will be made)\n");

  let ok = 0;
  for (const db of NODES_DBS) {
    if (runSql(db, sql, args.dryRun)) {
      if (!args.dryRun) console.log(`  ✓  ${db}`);
      ok++;
    }
  }

  console.log(`\n${ok}/${NODES_DBS.length} DBs updated.`);
  if (!args.dryRun && ok > 0) {
    console.log("\nNOTE: Do NOT restart the nodes — getScore() reads postgres live.");
    console.log("Restarting causes peer snapshot sync which overwrites the score back to 500.");
    console.log("\nVerify immediately:");
    console.log(`  curl -s "http://localhost:4000/v1/reviewers/pool" | python3 -m json.tool`);
    console.log("  (reviewer_consent must also be set — go to http://localhost:5050/settings)");
  }
}

main();
