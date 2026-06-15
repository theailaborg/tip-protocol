#!/usr/bin/env node
/**
 * @file scripts/inject-prescan-review.js
 * @description DEV-ONLY: Backdate a content's `registered_at` timestamp so
 * the prescan-review-trigger fires on the very next consensus round (instead
 * of waiting the 48-hour content_grace.flagged_ms window).
 *
 * How it works
 * ────────────
 * The trigger query is:
 *   SELECT … FROM content WHERE … AND registered_at <= nowMs - FLAGGED_MS
 *
 * By setting registered_at = now - 49h, the content is immediately eligible.
 * The next round (~4-10 s) the trigger emits a real PRESCAN_REVIEW_TRIGGERED
 * tx signed by the node — same as the protocol does after a real 48h wait.
 *
 * Prerequisites
 * ─────────────
 *   1. Content must already be registered (run it through the VP first).
 *   2. The reviewer TIP-ID must have reviewer_consent = true AND score ≥ 800.
 *      • Score: node scripts/boost-score.js --tip-id <id> --score 850
 *      • Consent: http://localhost:5050/settings → "Become a reviewer" toggle
 *   3. Nodes restarted after score boost (docker restart tip-node …)
 *   4. Content must have origin_code=OH and prescan_tier=high or critical.
 *      Register with "override: true" via the VP (or use --force-tier below).
 *
 * Usage
 * ─────
 *   node scripts/inject-prescan-review.js --ctid tip://c/OH-abc123
 *   node scripts/inject-prescan-review.js --ctid tip://c/OH-abc123 --force-tier high
 *   node scripts/inject-prescan-review.js --ctid tip://c/OH-abc123 --dry-run
 *
 * After running, wait 4-10 s then check:
 *   curl -s http://localhost:4000/v1/reviewers/pool | python3 -m json.tool
 *   curl -s http://localhost:4000/v1/identity/<reviewer-tid>/reviews | python3 -m json.tool
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const { execSync } = require("child_process");
const http = require("http");
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

// 49 hours in ms — just past the 48h FLAGGED_MS window
const BACKDATE_MS = 49 * 60 * 60 * 1000;

// ─── CLI ─────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = {
    ctid:       null,
    nodeUrl:    "http://localhost:4000",
    forceTier:  null,   // override prescan_tier if it's "low"
    dryRun:     false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if      (a === "--ctid")        args.ctid       = argv[++i];
    else if (a === "--node-url")    args.nodeUrl     = argv[++i];
    else if (a === "--force-tier")  args.forceTier   = argv[++i];
    else if (a === "--dry-run")     args.dryRun      = true;
    else if (a === "--help" || a === "-h") {
      console.log("usage: inject-prescan-review.js --ctid <CTID> [opts]");
      console.log("  --ctid      tip://c/...    content already in the DAG");
      console.log("  --node-url  URL            node to check pool against (default http://localhost:4000)");
      console.log("  --force-tier high|critical also update prescan_tier (useful if content was registered low)");
      console.log("  --dry-run                  print SQL without executing");
      process.exit(0);
    }
  }
  if (!args.ctid) { console.error("ERROR: --ctid is required"); process.exit(1); }
  return args;
}

// ─── HTTP GET ─────────────────────────────────────────────────────────────────
function httpGet(url) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({
      hostname: u.hostname, port: u.port,
      path: u.pathname + (u.search || ""),
      method: "GET",
      headers: { "Accept": "application/json" },
      timeout: 10000,
    }, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: null }); }
      });
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end();
  });
}

// ─── SQL runner ───────────────────────────────────────────────────────────────
function runSql(db, sql, dryRun) {
  if (dryRun) {
    console.log(`  [dry-run] ${db}:\n${sql.trim()}`);
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
    console.error(`  ✗  ${db}: ${stderr.split("\n")[0]}`);
    return false;
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv);

  // Verify content exists and check its tier
  console.log(`Checking content: ${args.ctid}`);
  const res = await httpGet(`${args.nodeUrl}/v1/content/${encodeURIComponent(args.ctid)}`);
  if (res.status === 404) {
    console.error(`ERROR: Content not found on node. Register it via the VP first.`);
    process.exit(1);
  }
  const content = res.body?.data || res.body;
  const originCode   = content?.origin_code;
  const prescanTier  = content?.prescan_tier || "low";
  const authorTipId  = content?.author_tip_id;

  console.log(`  origin_code:  ${originCode}`);
  console.log(`  prescan_tier: ${prescanTier}`);
  console.log(`  author:       ${authorTipId}`);
  console.log(`  status:       ${content?.status}`);

  if (originCode !== "OH") {
    console.error(`ERROR: prescan reviews only trigger for origin_code=OH content (got: ${originCode}).`);
    process.exit(1);
  }

  const effectiveTier = args.forceTier || prescanTier;
  if (effectiveTier !== "high" && effectiveTier !== "critical") {
    console.error([
      `ERROR: prescan_tier must be "high" or "critical" (got: "${prescanTier}").`,
      `Re-register the content with override=true, or add --force-tier high to this command.`,
    ].join("\n"));
    process.exit(1);
  }

  // Check reviewer pool
  console.log(`\nChecking reviewer pool...`);
  const poolRes = await httpGet(`${args.nodeUrl}/v1/reviewers/pool`);
  const pool = poolRes.body?.data?.pool || [];
  if (pool.length === 0) {
    console.warn([
      `  ⚠  Reviewer pool is empty! The trigger will fire but no reviewer can be assigned.`,
      `     Fix first:`,
      `       1. node scripts/boost-score.js --tip-id <your-tip-id> --score 850`,
      `       2. docker restart tip-node tip-node2 tip-node3 tip-node4 tip-node5`,
      `       3. http://localhost:5050/settings → enable "Become a reviewer"`,
      `       4. Re-run this script`,
    ].join("\n"));
    process.exit(1);
  }
  console.log(`  ✓ ${pool.length} reviewer(s) in pool: ${pool.map(r => r.tip_id).join(", ")}`);

  // Build SQL: backdate registered_at + optionally fix tier
  const backdatedMs = nowMs() - BACKDATE_MS;
  const tierUpdate = args.forceTier
    ? `, prescan_tier = '${args.forceTier}', prescan_flagged = 1`
    : "";

  const ctidEscaped = args.ctid.replace(/'/g, "''");
  const sql = `
UPDATE content
SET registered_at = ${backdatedMs}${tierUpdate}
WHERE tip_ctid = '${ctidEscaped}'
  AND status = 'registered'
  AND origin_code = 'OH';
`;

  console.log(`\nBackdating registered_at by 49 h across ${NODES_DBS.length} DBs...`);
  if (args.dryRun) console.log("(dry-run mode)\n");

  let ok = 0;
  for (const db of NODES_DBS) {
    if (runSql(db, sql, args.dryRun)) {
      if (!args.dryRun) console.log(`  ✓  ${db}`);
      ok++;
    }
  }

  if (args.dryRun) {
    console.log("\n--dry-run: no changes made.");
    return;
  }

  console.log(`\n${ok}/${NODES_DBS.length} DBs updated.`);

  if (ok > 0) {
    console.log([
      ``,
      `✓ Done. The prescan-review-trigger will fire on the next consensus round.`,
      ``,
      `What happens next (automatically, within 4-10 s):`,
      `  • The node emits a PRESCAN_REVIEW_TRIGGERED tx assigned to a reviewer`,
      `  • Content status flips to PENDING_REVIEW`,
      `  • The review appears at GET /v1/identity/<reviewer>/reviews`,
      ``,
      `Check the review pool and wait for the tx:`,
      `  curl -s "${args.nodeUrl}/v1/reviewers/pool" | python3 -m json.tool`,
      ``,
      `Then poll for the review (replace <reviewer-tip-id>):`,
      `  curl -s "${args.nodeUrl}/v1/identity/<reviewer-tip-id>/reviews" | python3 -m json.tool`,
      ``,
      `Act on the review (get the review_id from above):`,
      `  Dismiss → POST ${args.nodeUrl}/v1/reviews/<review_id>/dismiss`,
      `  Confirm → POST ${args.nodeUrl}/v1/reviews/<review_id>/confirm`,
      `  Recuse  → POST ${args.nodeUrl}/v1/reviews/<review_id>/recuse`,
      `  (These require a signed body — use the VP UI at http://localhost:5050/reviewer-history)`,
    ].join("\n"));
  }
}

main().catch(err => {
  console.error("FATAL:", err.message || err);
  process.exit(1);
});
