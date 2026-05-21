#!/usr/bin/env node
/**
 * @file scripts/register-content.js
 * @description DEV-ONLY: Register a piece of content on behalf of a temp-user
 * identity, optionally forcing a HIGH/CRITICAL prescan tier so the content
 * enters the review → dispute → scoring pipeline immediately.
 *
 * Prerequisites:
 *   1. scripts/seed.js         — genesis bootstrap
 *   2. start nodes (quorum healthy)
 *   3. scripts/seed-temp-users.js — temp identities with elevated scores
 *
 * Usage:
 *   node scripts/register-content.js --signer-tip-id tip://id/US-... --content "some text"
 *   node scripts/register-content.js --pick-first --content "some text" --origin OH
 *   node scripts/register-content.js --signer-tip-id tip://id/... --content "text" --origin AA --dry-run
 *
 * Env:
 *   TIP_DEV_FORCE_PRESCAN_TIER=high|critical|random
 *     Must be set on the TARGET NODE (not this script) to override the AI stub.
 *     This script prints a reminder if the variable is not set on the node.
 *
 * Output:
 *   Prints the committed CTID once the content appears on the node.
 *   Exits 0 on success, 1 on error.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const http = require("http");

const {
  initCrypto, shake256, tipNormalize, canonicalJson, signBody,
} = require("../shared/crypto");

const REPO_ROOT = path.resolve(__dirname, "..");
const TEMP_USERS_DIR = path.join(REPO_ROOT, "genesis-data", "temp-users");
const KEYS_DIR = path.join(TEMP_USERS_DIR, "keys");
const LATEST_FILE = path.join(TEMP_USERS_DIR, "temp-users-latest.json");

// CNA-2.2 signing schema constants (mirrors content-register.js to avoid
// pulling in server-side middleware/dag dependencies).
const CNA_VERSION = "CNA-2.2";
const VALID_ORIGINS = ["OH", "AA", "AG", "MX"];
const VALID_ATTRIBUTION_MODES = ["self", "employed", "hosted"];

// ─── Colors ──────────────────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", yellow: "\x1b[33m",
};
const ok = (m) => console.log(`${C.green}  ✓${C.reset} ${m}`);
const err = (m) => console.log(`${C.red}  ✗${C.reset} ${m}`);
const info = (m) => console.log(`${C.cyan}  ℹ${C.reset} ${m}`);
const warn = (m) => console.log(`${C.yellow}  ⚠${C.reset} ${m}`);
const label = (k, v) => console.log(`    ${C.dim}${k.padEnd(26)}${C.reset}${v}`);

// ─── CLI ─────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = {
    signerTipId: null,
    pickFirst: false,
    userIndex: 0,
    nodeUrl: "http://localhost:4000",
    content: null,
    origin: "OH",
    attributionMode: "self",
    registeredUrls: [],
    dryRun: false,
    watchTimeout: 30,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--signer-tip-id") args.signerTipId = argv[++i];
    else if (a === "--pick-first") args.pickFirst = true;
    else if (a === "--user-index") args.userIndex = Number(argv[++i]);
    else if (a === "--node-url") args.nodeUrl = argv[++i];
    else if (a === "--content") args.content = argv[++i];
    else if (a === "--origin") args.origin = argv[++i].toUpperCase();
    else if (a === "--attribution-mode") args.attributionMode = argv[++i];
    else if (a === "--url") args.registeredUrls = args.registeredUrls.concat(argv[++i]);
    else if (a === "--dry-run") args.dryRun = true;
    else if (a === "--watch-timeout") args.watchTimeout = Number(argv[++i]);
    else if (a === "--help" || a === "-h") {
      console.log("usage: register-content.js [opts]");
      console.log("  --signer-tip-id TIP     tip://id/... of the content author (requires key file)");
      console.log("  --pick-first             auto-pick a user in temp-users-latest.json");
      console.log("  --user-index N           which user to pick with --pick-first (0-based, default 0)");
      console.log("  --content TEXT           content body (required)");
      console.log("  --origin CODE            OH | AA | AG | MX  (default OH)");
      console.log("  --attribution-mode MODE  self | employed | hosted  (default self)");
      console.log("  --url URL                registered URL (may repeat for multiple)");
      console.log("  --node-url URL           submission target (default http://localhost:4000)");
      console.log("  --dry-run                print plan without submitting");
      console.log("  --watch-timeout SEC      seconds to wait for tx to land (default 30)");
      console.log("");
      console.log("  Env (set on the TARGET NODE, not this script):");
      console.log("    TIP_DEV_FORCE_PRESCAN_TIER=high|critical|random");
      console.log("      Forces prescan tier so LOW-probability stub content enters the review");
      console.log("      pipeline. Required for testing reviewer/disputer/appeal scoring.");
      process.exit(0);
    } else throw new Error(`unknown arg: ${a}`);
  }

  if (!args.content) throw new Error("--content is required");
  if (!VALID_ORIGINS.includes(args.origin)) throw new Error(`--origin must be one of ${VALID_ORIGINS.join(", ")}`);
  if (!VALID_ATTRIBUTION_MODES.includes(args.attributionMode)) throw new Error(`--attribution-mode must be one of ${VALID_ATTRIBUTION_MODES.join(", ")}`);
  if (!args.signerTipId && !args.pickFirst) throw new Error("--signer-tip-id or --pick-first is required");

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
  const r = await httpRequest(url, { method: "POST", body });
  return r;
}

async function getJson(url, timeoutMs = 5000) {
  return httpRequest(url, { method: "GET", timeoutMs });
}

// ─── Key loading ──────────────────────────────────────────────────────────────
function tipIdToFileName(tipId) {
  // tip://id/US-002ff11f40397f7f → tip-id-US-002ff11f40397f7f.tip.json
  const m = /^tip:\/\/id\/(.+)$/.exec(tipId);
  if (!m) throw new Error(`unrecognized tip_id format: ${tipId}`);
  return `tip-id-${m[1]}.tip.json`;
}

function loadKeyForTipId(tipId) {
  const file = path.join(KEYS_DIR, tipIdToFileName(tipId));
  if (!fs.existsSync(file)) return null;
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!parsed.public_key || !parsed.private_key) throw new Error(`malformed key file: ${file}`);
  return { publicKey: parsed.public_key, privateKey: parsed.private_key, name: parsed.name || tipId };
}

function pickUser(index = 0) {
  if (!fs.existsSync(LATEST_FILE)) throw new Error(`temp-users-latest.json not found — run scripts/seed-temp-users.js first`);
  const latest = JSON.parse(fs.readFileSync(LATEST_FILE, "utf8"));
  if (!latest.users || latest.users.length === 0) throw new Error("no users in temp-users-latest.json");
  const idx = Math.max(0, Math.min(index, latest.users.length - 1));
  const u = latest.users[idx];
  return { tipId: u.tip_id, tipIdType: u.tip_id_type || "personal", publicKey: u.public_key, privateKey: u.private_key, name: u.creator_name || u.tip_id };
}

// ─── Content signing ──────────────────────────────────────────────────────────
// Builds the CNA-2.2 canonical 8-field signing payload.
// Mirrors content-register.buildSigningPayload() without the server-side imports.
function buildCanonicalPayload({ signerTipId, tipIdType, originCode, contentHashFull, attributionMode, registeredUrls }) {
  return {
    attribution_mode: attributionMode,
    authors: [{
      key_mode: "attribution",
      role: "contributor",
      signed: false,
      tip_id: signerTipId,
      tip_id_type: tipIdType,
    }],
    cna_version: CNA_VERSION,
    content_hash: contentHashFull,
    extras: {},
    origin_code: originCode,
    registered_urls: registeredUrls,
    signer_tip_id: signerTipId,
  };
}

// ─── Wait for content on node ─────────────────────────────────────────────────
async function waitForContent(ctid, nodeUrl, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await getJson(`${nodeUrl}/v1/content/${encodeURIComponent(ctid)}`);
      if (r.status === 200) return r.body;
    } catch { /* transient */ }
    await new Promise(r => setTimeout(r, 1000));
  }
  return null;
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv);
  await initCrypto();

  // Load signer identity + keypair.
  let signerTipId, tipIdType, privateKey, signerName;
  if (args.pickFirst) {
    const u = pickUser(args.userIndex);
    signerTipId = u.tipId; tipIdType = u.tipIdType; privateKey = u.privateKey; signerName = u.name;
  } else {
    signerTipId = args.signerTipId;
    const kp = loadKeyForTipId(signerTipId);
    if (!kp) throw new Error(`no key file for ${signerTipId} in ${KEYS_DIR}`);
    privateKey = kp.privateKey; signerName = kp.name;
    // tip_id_type defaults to personal; exact value is in the key file if stored.
    tipIdType = "personal";
  }

  // Compute content hash (CNA-2.2: SHA3-256 of CNA-normalised text).
  const contentHashFull = shake256(tipNormalize(args.content));

  // Build canonical payload and sign.
  const canonicalPayload = buildCanonicalPayload({
    signerTipId, tipIdType, originCode: args.origin,
    contentHashFull, attributionMode: args.attributionMode,
    registeredUrls: args.registeredUrls,
  });
  const signature = signBody(canonicalPayload, privateKey);

  // Request body for POST /v1/content/register.
  const body = {
    signer_tip_id: signerTipId,
    origin_code: args.origin,
    content: args.content,
    signature,
    authors: canonicalPayload.authors,
    attribution_mode: canonicalPayload.attribution_mode,
    registered_urls: canonicalPayload.registered_urls,
    extras: {},
  };

  console.log(`${C.bold}Register Content${C.reset}`);
  label("signer", `${signerName} (${signerTipId})`);
  label("origin", args.origin);
  label("content (preview)", `${args.content.slice(0, 60)}${args.content.length > 60 ? "…" : ""}`);
  label("content_hash (short)", contentHashFull.slice(0, 14) + "…");
  label("node", args.nodeUrl);
  label("cna_version", CNA_VERSION);
  console.log("");

  // Reminder: the prescan tier is controlled by an env var on the TARGET NODE.
  // The AI stub never reaches HIGH/CRITICAL on its own (max probability ~0.45).
  const prescanEnv = process.env.TIP_DEV_FORCE_PRESCAN_TIER;
  if (!prescanEnv) {
    warn("TIP_DEV_FORCE_PRESCAN_TIER is not set on this process.");
    warn("  For content to enter the review pipeline the TARGET NODE must have:");
    warn("    TIP_DEV_FORCE_PRESCAN_TIER=high|critical|random");
    warn("  Without it the AI stub (~0.45 max probability) never reaches HIGH/CRITICAL.");
    warn("  Set it in the node's .env file and restart the node(s), then re-register.");
    console.log("");
  } else {
    info(`TIP_DEV_FORCE_PRESCAN_TIER=${prescanEnv} detected locally.`);
    info("  Verify the same variable is set on the target node process.");
    console.log("");
  }

  if (args.dryRun) {
    info("--dry-run: canonical payload would be signed and submitted as:");
    console.log(JSON.stringify(body, null, 2));
    return;
  }

  // Submit.
  info("Submitting REGISTER_CONTENT tx…");
  const r = await postJson(`${args.nodeUrl}/v1/content/register`, body);

  if (r.status >= 400) {
    const msg = r.body?.error?.message || r.body?.error || r.raw;
    err(`HTTP ${r.status}: ${msg}`);
    if (r.body?.error?.code) label("code", r.body.error.code);
    process.exitCode = 1;
    return;
  }

  const ctid = r.body?.data?.ctid;
  if (!ctid) {
    err(`Unexpected response (no ctid): ${JSON.stringify(r.body).slice(0, 300)}`);
    process.exitCode = 1;
    return;
  }

  ok(`tx proposed — ctid: ${C.bold}${ctid}${C.reset}`);
  label("prescan_tier", r.body?.data?.prescan_tier || "(unknown)");
  label("prescan_flagged", String(r.body?.data?.prescan_flagged ?? "unknown"));
  label("status", r.body?.data?.status || "(unknown)");
  console.log("");

  // Wait for consensus to commit.
  info(`Waiting up to ${args.watchTimeout}s for consensus commit…`);
  const committed = await waitForContent(ctid, args.nodeUrl, args.watchTimeout * 1000);
  if (!committed) {
    warn(`Content not confirmed within ${args.watchTimeout}s — check node logs.`);
    warn("  The tx may still commit. Poll: GET /v1/content/" + encodeURIComponent(ctid));
  } else {
    const d = committed.data || committed;
    ok(`committed — status=${d.status}  prescan_tier=${d.prescan_tier}`);
    console.log("");
    console.log(`${C.bold}CTID:${C.reset} ${ctid}`);
    if (d.prescan_flagged) {
      console.log("");
      console.log(`${C.yellow}Next steps (HIGH/CRITICAL tier):${C.reset}`);
      console.log(`  1. Wait for PRESCAN_REVIEW_TRIGGERED (h=48 BFT-time, or use TIP_DEV_BYPASS_VOTE_WINDOWS=1 on node)`);
      console.log(`  2. Reviewer decides → CONFIRMED auto-escalates to dispute`);
      console.log(`  3. Or file dispute manually:`);
      console.log(`       node scripts/file-dispute.js --ctid ${ctid} --disputer-tip-id <TIP-ID>`);
    } else {
      console.log("");
      console.log("Content registered as LOW/ELEVATED tier — not entering review pipeline.");
      console.log("Set TIP_DEV_FORCE_PRESCAN_TIER=high on the target node and re-register.");
    }
  }
}

main().catch(e => {
  console.error(`\nERROR: ${e.message}`);
  if (e.body) console.error(`  body: ${JSON.stringify(e.body)}`);
  process.exit(1);
}).finally(() => setTimeout(() => process.exit(process.exitCode || 0), 50).unref());
