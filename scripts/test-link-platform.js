#!/usr/bin/env node
/**
 * @file scripts/test-link-platform.js
 * @description End-to-end smoke test for LINK_PLATFORM social account linking.
 *
 * Scenario:
 *   1. Register one TIP identity (via VP-signed REGISTER_IDENTITY)
 *   2. Check initial score (500)
 *   3. Link 6 social platforms one by one — score +5 per platform
 *   4. Link a 7th platform — expect 202 success but score_delta 0 (no bonus beyond cap)
 *   5. Verify final score is 530 (500 + 30, unchanged after 7th)
 *
 * Prerequisites:
 *   - genesis-data/founding-vp-keys.json must exist (from npm run seed:fresh)
 *   - genesis-data/seed-output.json must exist (from npm run seed:fresh)
 *   - Target node must be running and healthy
 *
 * Usage:
 *   node scripts/test-link-platform.js
 *   node scripts/test-link-platform.js --node-url http://localhost:4000
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const fs   = require("fs");
const path = require("path");
const http = require("http");
const crypto = require("crypto");

const { nowMs }                    = require("../shared/time");
const { initCrypto, generateMLDSAKeypair } = require("../shared/crypto");
const registerIdentitySchema       = require("../node/src/schemas/register-identity");
const linkPlatformSchema           = require("../node/src/schemas/link-platform");
const { generateDedupProof }       = require("../shared/zk");

const REPO_ROOT   = path.resolve(__dirname, "..");
const GENESIS_DIR = path.join(REPO_ROOT, "genesis-data");
const VP_KEYS_FILE  = path.join(GENESIS_DIR, "founding-vp-keys.json");
const SEED_OUT_FILE = path.join(GENESIS_DIR, "seed-output.json");

// ─── ANSI colors ─────────────────────────────────────────────────────────────
const T = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m",
  yellow: "\x1b[33m", blue: "\x1b[34m",
};

// ─── Constants ────────────────────────────────────────────────────────────────
const PLATFORMS = ["youtube", "x.com", "instagram", "linkedin", "youtube", "tiktok", "rooverse", "twitter"];
const HANDLES   = {
  youtube: "@testuser_yt", "x.com": "@testuser_xcom", instagram: "@testuser_ig",
  linkedin: "testuser-li", tiktok: "@testuser_tk", rooverse: "testuser_rv", twitter: "testuser_tw",
};
const INITIAL_SCORE = 500;
const BONUS_PER_LINK = 5;
const MAX_LINKS = 6;
const MAX_BONUS = 30;

// ─── CLI args ────────────────────────────────────────────────────────────────
const args = { nodeUrl: "http://localhost:4000" };
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === "--node-url") { args.nodeUrl = process.argv[++i]; }
  else if (process.argv[i] === "--help") {
    console.log("usage: test-link-platform.js [--node-url URL]");
    process.exit(0);
  }
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────
function httpRequest(url, { method = "GET", body = null, timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = body ? JSON.stringify(body) : null;
    const hdrs = { Accept: "application/json" };
    if (payload) {
      hdrs["Content-Type"] = "application/json";
      hdrs["Content-Length"] = Buffer.byteLength(payload);
    }
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + (u.search || ""), method, headers: hdrs, timeout: timeoutMs },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          let parsed = null;
          try { parsed = JSON.parse(data); } catch { /* leave raw */ }
          resolve({ status: res.statusCode, body: parsed, raw: data });
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error(`HTTP timeout after ${timeoutMs}ms: ${url}`)));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const getJson  = (url, ms = 5000) => httpRequest(url, { method: "GET",  timeoutMs: ms });
const postJson = (url, body, ms = 30000) => httpRequest(url, { method: "POST", body, timeoutMs: ms });

async function waitFor(predicate, { intervalMs = 1200, timeoutMs = 90000 } = {}) {
  const deadline = nowMs() + timeoutMs;
  while (nowMs() < deadline) {
    try {
      const v = await predicate();
      if (v !== false && v !== null && v !== undefined) return v;
    } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return null;
}

// ─── Output helpers ───────────────────────────────────────────────────────────
const pass = (m) => console.log(`  ${T.green}✓${T.reset} ${m}`);
const fail = (m) => console.log(`  ${T.red}✗${T.reset} ${T.bold}${m}${T.reset}`);
const info = (m) => console.log(`  ${T.cyan}→${T.reset} ${m}`);
const warn = (m) => console.log(`  ${T.yellow}⚠${T.reset} ${m}`);
const section = (m) => console.log(`\n${T.bold}${T.blue}▸ ${m}${T.reset}`);

// ─── Score helper — uses /history which always returns actual score ───────────
// getScore via /score only includes numeric score when score_display_mode=FULL_PUBLIC.
// getHistory always returns it, so we use that for polling.
// All API responses are wrapped: { ok, status, data: { ... } }
async function fetchScore(nodeUrl, tipId) {
  const r = await getJson(`${nodeUrl}/v1/identity/${encodeURIComponent(tipId)}/history`);
  if (r.status !== 200) throw new Error(`history endpoint ${r.status}: ${r.raw}`);
  return r.body?.data?.score;
}

async function waitForScore(nodeUrl, tipId, expected) {
  const result = await waitFor(async () => {
    const s = await fetchScore(nodeUrl, tipId);
    return s === expected ? s : false;
  }, { intervalMs: 1200, timeoutMs: 90000 });
  return result !== null;
}

// ─── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  const errors = [];

  console.log(`\n${T.bold}${T.cyan}══════════════════════════════════════════════════${T.reset}`);
  console.log(`${T.bold}  LINK_PLATFORM — End-to-End Smoke Test${T.reset}`);
  console.log(`${T.bold}${T.cyan}══════════════════════════════════════════════════${T.reset}`);
  console.log(`  Target : ${args.nodeUrl}`);
  console.log(`  Expect : score ${INITIAL_SCORE} → ${INITIAL_SCORE + MAX_BONUS} after ${MAX_LINKS} links`);

  // ── Pre-flight ──────────────────────────────────────────────────────────────
  section("Pre-flight");

  if (!fs.existsSync(VP_KEYS_FILE))  throw new Error(`founding-vp-keys.json missing — run: npm run seed:fresh`);
  if (!fs.existsSync(SEED_OUT_FILE)) throw new Error(`seed-output.json missing — run: npm run seed:fresh`);
  pass("Genesis files found");

  const health = await getJson(`${args.nodeUrl}/health`, 8000);
  if (health.status !== 200) throw new Error(`Node not healthy (${health.status})`);
  const cs = health.body?.data?.consensus;
  if (cs?.halt?.halted) throw new Error(`Node is halted: ${cs.halt.reason}`);
  pass(`Node healthy  round=${cs?.narwhal?.round ?? "?"}`);

  const vpFile  = JSON.parse(fs.readFileSync(VP_KEYS_FILE, "utf8"));
  const vpEntry = vpFile?.entries?.find((e) => e.tag === "primary-vp");
  if (!vpEntry?.public_key || !vpEntry?.private_key) throw new Error("founding-vp-keys.json missing primary-vp entry");
  const vpKp = { publicKey: vpEntry.public_key, privateKey: vpEntry.private_key };

  const seedOut   = JSON.parse(fs.readFileSync(SEED_OUT_FILE, "utf8"));
  const vpSummary = seedOut?.founding_vps?.find((v) => v.tag === "primary-vp");
  if (!vpSummary?.vp_id) throw new Error("seed-output.json missing founding_vps[primary-vp].vp_id");
  const vpId = vpSummary.vp_id;
  pass(`VP loaded : ${vpId}`);

  // ── Init crypto ─────────────────────────────────────────────────────────────
  section("Crypto init");
  await initCrypto();
  pass("ML-DSA-65 ready");

  // ── Step 1: Register identity ───────────────────────────────────────────────
  section("Step 1  Register test identity");

  const kp     = generateMLDSAKeypair();
  const region = "US";
  const govId  = `LNKTEST-${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
  info("Generating ZK dedup proof…");
  const { dedup_hash, proof: zk_proof } = await generateDedupProof(govId, "1990-01-01", region);

  const idFields = {
    region, public_key: kp.publicKey, dedup_hash, zk_proof,
    verification_tier: "T1", vp_id: vpId, social_attested: false,
    tip_id_type: "personal", creator_name: "LinkPlatformSmokeTest",
  };
  const regPayload = registerIdentitySchema.buildSigningPayload(idFields);
  const regSig     = registerIdentitySchema.sign(regPayload, vpKp.privateKey);

  const regRes = await postJson(`${args.nodeUrl}/v1/identity/register`, { ...idFields, vp_signature: regSig }, 60000);
  if (regRes.status < 200 || regRes.status >= 300) {
    throw new Error(`Registration failed (${regRes.status}): ${JSON.stringify(regRes.body)}`);
  }
  const tipId = regRes.body?.data?.tip_id;
  if (!tipId) throw new Error(`No tip_id in register response: ${JSON.stringify(regRes.body)}`);
  pass(`Registered  tip_id=${tipId}`);

  info("Waiting for identity to commit…");
  const appeared = await waitFor(async () => {
    const r = await getJson(`${args.nodeUrl}/v1/identity/${encodeURIComponent(tipId)}`);
    return r.status === 200;
  });
  if (!appeared) throw new Error("Identity did not appear within 90s");
  pass("Identity committed to DAG");

  // ── Step 2: Initial score ───────────────────────────────────────────────────
  section("Step 2  Initial score");
  const initScore = await fetchScore(args.nodeUrl, tipId);
  console.log(`  Score: ${T.bold}${initScore}${T.reset}  (expected: ${INITIAL_SCORE})`);
  if (initScore === INITIAL_SCORE) {
    pass(`Initial score correct: ${initScore}`);
  } else {
    fail(`Initial score mismatch — got ${initScore}, expected ${INITIAL_SCORE}`);
    errors.push("initial score wrong");
  }

  // ── Steps 3–9: Link all platforms — first 6 earn +5, rest earn 0 ─────────────
  section(`Steps 3–${2 + PLATFORMS.length}  Link ${PLATFORMS.length} social platforms (first ${MAX_LINKS} earn +5 each)`);

  let currentScore    = initScore ?? INITIAL_SCORE;
  let successfulLinks = 0; // tracks committed unique platforms — mirrors server's existing.length
  const linkResults   = [];

  for (let i = 0; i < PLATFORMS.length; i++) {
    const platform      = PLATFORMS[i];
    const handle        = HANDLES[platform];
    const linkedAt      = nowMs();
    // Use successfulLinks (not loop index) so skipped duplicates don't shift the cap boundary
    const bonusRound    = successfulLinks < MAX_LINKS;
    const expectedScore = bonusRound ? currentScore + BONUS_PER_LINK : currentScore;

    console.log(`\n  [${i + 1}/${PLATFORMS.length}] ${T.bold}${platform}${T.reset}  handle="${handle}"  linked=${successfulLinks}  bonus=${bonusRound ? `+${BONUS_PER_LINK}` : "none (cap)"}`);

    const payload = linkPlatformSchema.buildSigningPayload({ tip_id: tipId, platform, handle, linked_at: linkedAt });
    const vpSig   = linkPlatformSchema.sign(payload, vpKp.privateKey);

    const linkRes = await postJson(
      `${args.nodeUrl}/v1/identity/${encodeURIComponent(tipId)}/link-platform`,
      { platform, handle, linked_at: linkedAt, vp_id: vpId, vp_signature: vpSig },
      30000
    );

    if (linkRes.status === 409) {
      const code = linkRes.body?.error?.code;
      if (code === "platform_already_linked") {
        pass(`Duplicate correctly rejected 409 — "${platform}" already linked`);
      } else {
        fail(`409 with unexpected code: ${code}`);
        errors.push(`link ${platform} got 409 code=${code}`);
      }
      // Do NOT increment successfulLinks — duplicate was not accepted
      linkResults.push({ platform, bonusRound, ok: null, status: 409, score: currentScore, duplicate: true });
      continue;
    }

    if (linkRes.status !== 202) {
      fail(`Expected 202, got ${linkRes.status}: ${JSON.stringify(linkRes.body)}`);
      errors.push(`link ${platform} returned ${linkRes.status}`);
      linkResults.push({ platform, bonusRound, ok: false, status: linkRes.status, score: currentScore });
      continue;
    }

    const body = linkRes.body?.data ?? linkRes.body;
    const txId = body?.tx_id;
    info(`Proposed  tx_id=${txId}  score_tx_id=${body?.score_tx_id}  delta=${body?.score_delta}`);

    if (bonusRound) {
      // Expect score to increase by +5 — wait confirms LINK_PLATFORM committed
      info(`Waiting for score → ${expectedScore}…`);
      const reached = await waitForScore(args.nodeUrl, tipId, expectedScore);
      if (reached) {
        pass(`Score: ${currentScore} → ${expectedScore} (+${BONUS_PER_LINK}) ✓`);
        currentScore = expectedScore;
        successfulLinks++;
        linkResults.push({ platform, bonusRound, ok: true, score: currentScore });
      } else {
        const actual = await fetchScore(args.nodeUrl, tipId).catch(() => "?");
        fail(`Score stuck — expected ${expectedScore}, got ${actual} after 90s`);
        errors.push(`${platform} score did not reach ${expectedScore}`);
        currentScore = typeof actual === "number" ? actual : currentScore;
        successfulLinks++;
        linkResults.push({ platform, bonusRound, ok: false, score: currentScore });
      }
    } else {
      // Expect no score change — check response fields
      const deltOk = body?.score_delta === 0;
      const txOk   = body?.score_tx_id === null;
      if (!deltOk) {
        fail(`Expected score_delta 0, got ${body?.score_delta}`);
        errors.push(`${platform} score_delta ${body?.score_delta} ≠ 0`);
      }
      // Wait for LINK_PLATFORM tx to appear in committed activity before proceeding.
      // This prevents the next call from racing against an uncommitted tx count.
      info(`Waiting for no-bonus tx to commit (tx_id=${txId})…`);
      const committed = await waitFor(async () => {
        const r = await getJson(`${args.nodeUrl}/v1/identity/${encodeURIComponent(tipId)}/activity`);
        if (r.status !== 200) return false;
        const items = r.body?.data?.items ?? [];
        return items.some(item => item.tx_id === txId) ? true : false;
      }, { intervalMs: 1200, timeoutMs: 30000 });

      if (!committed) {
        warn(`No-bonus tx not confirmed in activity within 30s`);
      }

      const actualScore = await fetchScore(args.nodeUrl, tipId).catch(() => null);
      if (actualScore !== null && actualScore !== currentScore) {
        fail(`Score changed after no-bonus link — expected ${currentScore}, got ${actualScore}`);
        errors.push(`${platform} score changed unexpectedly to ${actualScore}`);
        currentScore = actualScore;
      } else {
        pass(`Link accepted (202) — no bonus  score_delta=0  score unchanged: ${currentScore} ✓`);
      }
      successfulLinks++;
      linkResults.push({ platform, bonusRound, ok: deltOk && txOk, score: currentScore });
    }
  }

  // ── Final score ──────────────────────────────────────────────────────────────
  section(`Step ${2 + PLATFORMS.length + 1}  Final score verification`);
  const finalScore    = await fetchScore(args.nodeUrl, tipId);
  const expectedFinal = INITIAL_SCORE + MAX_BONUS;
  console.log(`  Final score: ${T.bold}${finalScore}${T.reset}  (expected: ${expectedFinal})`);

  if (finalScore === expectedFinal) {
    pass(`Final score correct: ${INITIAL_SCORE} + ${MAX_BONUS} = ${finalScore}`);
  } else {
    fail(`Final score mismatch — got ${finalScore}, expected ${expectedFinal}`);
    errors.push(`final score ${finalScore} ≠ ${expectedFinal}`);
  }

  // ── Summary ──────────────────────────────────────────────────────────────────
  section("Summary");

  const bonusLinked   = linkResults.filter((r) => r.bonusRound && r.ok === true).length;
  const noBonusLinked = linkResults.filter((r) => !r.bonusRound && r.ok === true).length;
  const duplicates    = linkResults.filter((r) => r.duplicate).length;

  console.log(`\n  ${T.bold}TIP-ID   :${T.reset} ${tipId}`);
  console.log(`  ${T.bold}Platforms:${T.reset} ${bonusLinked} with bonus, ${noBonusLinked} no-bonus, ${duplicates} duplicate(s) rejected`);
  console.log(`\n  ${T.bold}Score progression:${T.reset}`);
  console.log(`    Initial  : ${INITIAL_SCORE}`);
  linkResults.forEach((r, i) => {
    let s, bonus;
    if (r.duplicate) {
      s = `${T.yellow}⊘${T.reset}`;
      bonus = " dup";
    } else {
      s = r.ok ? `${T.green}✓${T.reset}` : `${T.red}✗${T.reset}`;
      bonus = r.bonusRound ? `+${BONUS_PER_LINK}` : " +0";
    }
    console.log(`    [${i + 1}] ${r.platform.padEnd(12)} ${bonus}  → ${String(r.score ?? "?").padStart(4)}  ${s}`);
  });
  console.log(`    Final    : ${finalScore}`);

  if (errors.length === 0) {
    console.log(`\n${T.green}${T.bold}  ✓ ALL CHECKS PASSED${T.reset}\n`);
    process.exit(0);
  } else {
    console.log(`\n${T.red}${T.bold}  ✗ ${errors.length} CHECK(S) FAILED:${T.reset}`);
    errors.forEach((e) => console.log(`    ${T.red}•${T.reset} ${e}`));
    console.log();
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(`\n${T.red}${T.bold}FATAL:${T.reset} ${err.message}`);
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});
