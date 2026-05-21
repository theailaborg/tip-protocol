#!/usr/bin/env node
/**
 * @file scripts/file-dispute.js
 * @description DEV-ONLY: File a dispute against a CTID on behalf of a temp-user.
 *
 * Filing a dispute:
 *   1. Builds a minimal evidence payload (signed by the disputer's ML-DSA key).
 *   2. Signs the dispute body (disputer_tip_id + reason + claimed_origin + evidence_hash).
 *   3. Submits POST /v1/content/:ctid/dispute.
 *   4. Prints the dispute_tx_id and jury summary.
 *
 * After filing, run drive-jury.js to commit/reveal votes:
 *   node scripts/drive-jury.js --ctid <CTID> --phase COMMIT
 *   node scripts/drive-jury.js --ctid <CTID> --phase REVEAL --watch
 *
 * Signature scheme:
 *   evidence_signature = mldsaSign(shake256(canonicalJson(evidence.payload)), privateKey)
 *                      = signBody(evidence.payload, privateKey)
 *   dispute_signature  = signBody({ disputer_tip_id, reason, claimed_origin?, evidence_hash }, privateKey)
 *
 * Usage:
 *   node scripts/file-dispute.js --ctid tip://c/OH-... --disputer-tip-id tip://id/US-...
 *   node scripts/file-dispute.js --ctid <CTID> --pick-first --claimed-origin AG
 *   node scripts/file-dispute.js --ctid <CTID> --disputer-tip-id <TIP> --dry-run
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const http = require("http");

const {
  initCrypto, shake256, canonicalJson, signBody,
} = require("../shared/crypto");

const REPO_ROOT = path.resolve(__dirname, "..");
const KEYS_DIR = path.join(REPO_ROOT, "genesis-data", "temp-users", "keys");
const LATEST_FILE = path.join(REPO_ROOT, "genesis-data", "temp-users", "temp-users-latest.json");

const VALID_REASONS = ["origin_mismatch"];
const VALID_ORIGINS = ["OH", "AA", "AG", "MX"];

// ─── Colors ──────────────────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", yellow: "\x1b[33m",
};
const ok = (m) => console.log(`${C.green}  ✓${C.reset} ${m}`);
const fail = (m) => console.log(`${C.red}  ✗${C.reset} ${m}`);
const info = (m) => console.log(`${C.cyan}  ℹ${C.reset} ${m}`);
const warn = (m) => console.log(`${C.yellow}  ⚠${C.reset} ${m}`);
const label = (k, v) => console.log(`    ${C.dim}${k.padEnd(26)}${C.reset}${v}`);

// ─── CLI ─────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = {
    ctid: null,
    disputerTipId: null,
    pickFirst: false,
    nodeUrl: "http://localhost:4000",
    reason: "origin_mismatch",
    claimedOrigin: null,       // required for origin_mismatch; defaults to AG
    evidenceNote: null,        // optional free-text note in the evidence payload
    dryRun: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--ctid") args.ctid = argv[++i];
    else if (a === "--disputer-tip-id") args.disputerTipId = argv[++i];
    else if (a === "--pick-first") args.pickFirst = true;
    else if (a === "--node-url") args.nodeUrl = argv[++i];
    else if (a === "--reason") args.reason = argv[++i];
    else if (a === "--claimed-origin") args.claimedOrigin = argv[++i].toUpperCase();
    else if (a === "--evidence-note") args.evidenceNote = argv[++i];
    else if (a === "--dry-run") args.dryRun = true;
    else if (a === "--help" || a === "-h") {
      console.log("usage: file-dispute.js --ctid <CTID> [opts]");
      console.log("  --ctid CTID                 content target (required, e.g. tip://c/OH-...)");
      console.log("  --disputer-tip-id TIP       tip://id/... of the disputer (requires key file)");
      console.log("  --pick-first                 auto-pick the first user in temp-users-latest.json");
      console.log("  --node-url URL               submission target (default http://localhost:4000)");
      console.log("  --reason REASON              origin_mismatch (default; only supported reason)");
      console.log("  --claimed-origin CODE        OH | AA | AG | MX  (default AG; what the content actually is)");
      console.log("  --evidence-note TEXT         free-text note embedded in the evidence payload");
      console.log("  --dry-run                    print plan, do not submit");
      process.exit(0);
    } else throw new Error(`unknown arg: ${a}`);
  }
  if (!args.ctid) throw new Error("--ctid is required");
  if (!VALID_REASONS.includes(args.reason)) throw new Error(`--reason must be one of ${VALID_REASONS.join(", ")}`);
  if (args.claimedOrigin && !VALID_ORIGINS.includes(args.claimedOrigin)) throw new Error(`--claimed-origin must be one of ${VALID_ORIGINS.join(", ")}`);
  if (!args.disputerTipId && !args.pickFirst) throw new Error("--disputer-tip-id or --pick-first is required");
  // Default claimed_origin for origin_mismatch (the "real" AI-generated origin).
  if (args.reason === "origin_mismatch" && !args.claimedOrigin) args.claimedOrigin = "AG";
  return args;
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────
function httpRequest(url, { method = "GET", body = null, timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = body ? JSON.stringify(body) : null;
    const headers = { Accept: "application/json" };
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + (u.search || ""), method, headers, timeout: timeoutMs },
      (res) => {
        let data = ""; res.on("data", c => data += c);
        res.on("end", () => {
          let parsed = null;
          try { parsed = JSON.parse(data); } catch { /* leave null */ }
          resolve({ status: res.statusCode, body: parsed, raw: data });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error(`timeout after ${timeoutMs}ms`)));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function postJson(url, body) {
  return httpRequest(url, { method: "POST", body });
}

async function getJson(url, timeoutMs = 5000) {
  return httpRequest(url, { method: "GET", timeoutMs });
}

// ─── Key loading ──────────────────────────────────────────────────────────────
function loadKeyForTipId(tipId) {
  const m = /^tip:\/\/id\/(.+)$/.exec(tipId);
  if (!m) throw new Error(`unrecognized tip_id format: ${tipId}`);
  const file = path.join(KEYS_DIR, `tip-id-${m[1]}.tip.json`);
  if (!fs.existsSync(file)) return null;
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!parsed.public_key || !parsed.private_key) throw new Error(`malformed key file: ${file}`);
  return { publicKey: parsed.public_key, privateKey: parsed.private_key, name: parsed.name || tipId };
}

function pickFirstUser() {
  if (!fs.existsSync(LATEST_FILE)) throw new Error("temp-users-latest.json not found — run scripts/seed-temp-users.js first");
  const latest = JSON.parse(fs.readFileSync(LATEST_FILE, "utf8"));
  if (!latest.users || latest.users.length === 0) throw new Error("no users in temp-users-latest.json");
  const u = latest.users[0];
  return { tipId: u.tip_id, publicKey: u.public_key, privateKey: u.private_key, name: u.creator_name || u.tip_id };
}

// ─── Evidence building ────────────────────────────────────────────────────────
// The evidence payload is a plain JSON object signed by the disputer.
// Server verifies: mldsaVerify(shake256(canonicalJson(payload)), signature, pubKey).
// That equals signBody(payload, privateKey), so we can use signBody directly.
function buildEvidence({ disputerTipId, ctid, reason, claimedOrigin, note, privateKey }) {
  const payload = {
    type: "dev_script_evidence",
    ctid,
    disputer_tip_id: disputerTipId,
    reason,
    claimed_origin: claimedOrigin || null,
    note: note || `Filed via scripts/file-dispute.js at ${new Date().toISOString()}`,
  };
  const signature = signBody(payload, privateKey);
  // evidence_hash = shake256(canonicalJson(payload)) — precomputed locally
  // so we can include it in the main dispute signature without a round-trip.
  const evidenceHash = shake256(canonicalJson(payload));
  return { payload, signature, evidenceHash };
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv);
  await initCrypto();

  // Load disputer keypair.
  let disputerTipId, privateKey, disputerName;
  if (args.pickFirst) {
    const u = pickFirstUser();
    disputerTipId = u.tipId; privateKey = u.privateKey; disputerName = u.name;
  } else {
    disputerTipId = args.disputerTipId;
    const kp = loadKeyForTipId(disputerTipId);
    if (!kp) throw new Error(`no key file for ${disputerTipId} in ${KEYS_DIR}`);
    privateKey = kp.privateKey; disputerName = kp.name;
  }

  // Fetch content to confirm it exists + show its current status.
  info("Fetching content record…");
  const contentRes = await getJson(`${args.nodeUrl}/v1/content/${encodeURIComponent(args.ctid)}`);
  if (contentRes.status === 404) throw new Error(`Content not found: ${args.ctid}\n  Register it first: node scripts/register-content.js`);
  if (contentRes.status !== 200) throw new Error(`GET /v1/content/${args.ctid} → HTTP ${contentRes.status}`);
  const content = contentRes.body?.data || contentRes.body;

  // Fetch disputer score to sanity-check eligibility (min score = 400).
  const scoreRes = await getJson(`${args.nodeUrl}/v1/identity/${encodeURIComponent(disputerTipId)}/score`);
  const currentScore = scoreRes.body?.data?.score ?? scoreRes.body?.score ?? null;

  console.log(`${C.bold}File Dispute${C.reset}`);
  label("ctid", args.ctid);
  label("declared origin", content.origin_code);
  label("content status", content.status);
  label("prescan_tier", content.prescan_tier || "(not set)");
  label("disputer", `${disputerName} (${disputerTipId})`);
  label("disputer score", currentScore !== null ? String(currentScore) : "(unknown)");
  label("reason", args.reason);
  if (args.claimedOrigin) label("claimed_origin", args.claimedOrigin);
  label("node", args.nodeUrl);
  console.log("");

  if (currentScore !== null && currentScore < 400) {
    warn(`Disputer score ${currentScore} < 400 (min required). Dispute will be rejected.`);
    warn("  Run scripts/seed-temp-users.js to create higher-scored identities.");
    if (!args.dryRun) { process.exitCode = 1; return; }
  }

  // Build evidence (sign evidence payload first so we have the hash).
  const evidence = buildEvidence({
    disputerTipId, ctid: args.ctid, reason: args.reason,
    claimedOrigin: args.claimedOrigin, note: args.evidenceNote, privateKey,
  });

  // Main dispute signature covers: { disputer_tip_id, reason, [claimed_origin], evidence_hash }.
  const sigBody = { disputer_tip_id: disputerTipId, reason: args.reason };
  if (args.claimedOrigin) sigBody.claimed_origin = args.claimedOrigin;
  sigBody.evidence_hash = evidence.evidenceHash;
  const disputeSignature = signBody(sigBody, privateKey);

  const requestBody = {
    disputer_tip_id: disputerTipId,
    reason: args.reason,
    claimed_origin: args.claimedOrigin || undefined,
    signature: disputeSignature,
    evidence: { payload: evidence.payload, signature: evidence.signature },
  };

  if (args.dryRun) {
    info("--dry-run: would submit:");
    console.log(JSON.stringify(requestBody, null, 2));
    label("evidence_hash (computed)", evidence.evidenceHash);
    return;
  }

  // Submit dispute.
  info("Submitting dispute…");
  const r = await postJson(`${args.nodeUrl}/v1/content/${encodeURIComponent(args.ctid)}/dispute`, requestBody);

  if (r.status >= 400) {
    const msg = r.body?.error?.message || r.body?.error || r.raw;
    fail(`HTTP ${r.status}: ${msg}`);
    if (r.body?.error?.code) label("code", r.body.error.code);
    process.exitCode = 1;
    return;
  }

  const d = r.body?.data || r.body || {};
  ok(`Dispute filed successfully`);
  console.log("");
  label("dispute_tx_id", d.dispute_tx_id || "(pending)");
  label("evidence_hash", d.evidence_hash || evidence.evidenceHash);
  label("disputer stake at risk", String(d.stake_at_risk ?? 15));
  label("jurors summoned", String(d.stage2?.count ?? "?") + (d.stage2?.insufficient ? " (INSUFFICIENT — below target)" : ""));
  label("commit_deadline", d.stage2?.commit_deadline || "(unknown)");
  label("reveal_deadline", d.stage2?.reveal_deadline || "(unknown)");
  console.log("");

  const bypass = "  Use TIP_DEV_BYPASS_VOTE_WINDOWS=1 on the node to fire verdict on quorum instead of deadline.";
  console.log(`${C.bold}Next steps:${C.reset}`);
  console.log(`  1. Commit votes (run during commit window):`);
  console.log(`       node scripts/drive-jury.js --ctid ${args.ctid} --phase COMMIT`);
  console.log(`  2. Reveal votes (run during reveal window):`);
  console.log(`       node scripts/drive-jury.js --ctid ${args.ctid} --phase REVEAL --watch`);
  console.log(`  3. Check scores after verdict:`);
  console.log(`       node scripts/scoring-status.js --tip-id ${disputerTipId} --ctid ${args.ctid}`);
  console.log(bypass);
}

main().catch(e => {
  console.error(`\nERROR: ${e.message}`);
  if (e.body) console.error(`  body: ${JSON.stringify(e.body)}`);
  process.exit(1);
}).finally(() => setTimeout(() => process.exit(process.exitCode || 0), 50).unref());
