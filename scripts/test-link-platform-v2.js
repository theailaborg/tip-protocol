#!/usr/bin/env node
/**
 * @file scripts/test-link-platform-v2.js
 * @description End-to-end smoke test for LINK_PLATFORM v2 (node-attested, user claim-signed).
 *
 * Flow:
 *   1. Register one TIP identity
 *   2. Check initial score (500)
 *   3. Link 6 platforms — user signs 4-field claim, node attests — score +5 each
 *   4. Link a 7th platform — score_delta should be 0 (cap enforced)
 *   5. Verify final score is 530 (500 + 30)
 *
 * Usage:
 *   node scripts/test-link-platform-v2.js
 *   node scripts/test-link-platform-v2.js --node-url http://localhost:4000
 */

"use strict";

const fs     = require("fs");
const path   = require("path");
const http   = require("http");
const crypto = require("crypto");

const { nowMs }                              = require("../shared/time");
const { initCrypto, generateMLDSAKeypair, mldsaSign, canonicalJson } = require("../shared/crypto");
const registerIdentitySchema                 = require("../node/src/schemas/register-identity");
const registerSocialSchema                   = require("../node/src/schemas/register-social");
const { generateDedupProof }                 = require("../shared/zk");

const REPO_ROOT     = path.resolve(__dirname, "..");
const GENESIS_DIR   = path.join(REPO_ROOT, "genesis-data");
const VP_KEYS_FILE  = path.join(GENESIS_DIR, "founding-vp-keys.json");
const SEED_OUT_FILE = path.join(GENESIS_DIR, "seed-output.json");

const T = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m",
  yellow: "\x1b[33m", blue: "\x1b[34m",
};
const pass    = (m) => console.log(`  ${T.green}✓${T.reset} ${m}`);
const fail    = (m) => console.log(`  ${T.red}✗${T.reset} ${T.bold}${m}${T.reset}`);
const info    = (m) => console.log(`  ${T.cyan}→${T.reset} ${m}`);
const section = (m) => console.log(`\n${T.bold}${T.blue}▸ ${m}${T.reset}`);

const PLATFORMS = [
  { platform: "github",    profileUrl: "https://github.com/testuser-smoke-v2" },
  { platform: "twitter",   profileUrl: "https://x.com/testuser_smoke_v2" },
  { platform: "instagram", profileUrl: "https://instagram.com/testuser_smoke_v2" },
  { platform: "tiktok",    profileUrl: "https://tiktok.com/@testuser_smoke_v2" },
  { platform: "youtube",   profileUrl: "https://youtube.com/@testuser_smoke_v2" },
  { platform: "bluesky",   profileUrl: "https://bsky.app/profile/testuser.smoke.v2" },
  // 7th — should earn 0 bonus (cap hit)
  { platform: "reddit",    profileUrl: "https://reddit.com/user/testuser_smoke_v2" },
];

const INITIAL_SCORE  = 500;
const BONUS_PER_LINK = 5;
const MAX_LINKS      = 6;
const MAX_BONUS      = 30;

const args = { nodeUrl: "http://localhost:4000" };
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === "--node-url") args.nodeUrl = process.argv[++i];
}

function httpRequest(url, { method = "GET", body = null, timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = body ? JSON.stringify(body) : null;
    const hdrs = { Accept: "application/json" };
    if (payload) { hdrs["Content-Type"] = "application/json"; hdrs["Content-Length"] = Buffer.byteLength(payload); }
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
    req.on("timeout", () => req.destroy(new Error(`Timeout: ${url}`)));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const getJson  = (url, ms = 5000) => httpRequest(url, { method: "GET", timeoutMs: ms });
const postJson = (url, body, ms = 30000) => httpRequest(url, { method: "POST", body, timeoutMs: ms });

async function waitFor(fn, { intervalMs = 1200, timeoutMs = 90000 } = {}) {
  const deadline = nowMs() + timeoutMs;
  while (nowMs() < deadline) {
    try { const v = await fn(); if (v !== false && v !== null && v !== undefined) return v; } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return null;
}

async function fetchScore(nodeUrl, tipId) {
  const r = await getJson(`${nodeUrl}/v1/identity/${encodeURIComponent(tipId)}/history`);
  if (r.status !== 200) throw new Error(`history ${r.status}: ${r.raw}`);
  return r.body?.data?.score;
}

async function waitForScore(nodeUrl, tipId, expected) {
  const result = await waitFor(async () => {
    const s = await fetchScore(nodeUrl, tipId);
    return s === expected ? s : false;
  }, { intervalMs: 1200, timeoutMs: 90000 });
  return result !== null;
}

async function main() {
  const errors = [];

  console.log(`\n${T.bold}${T.cyan}══════════════════════════════════════════════════${T.reset}`);
  console.log(`${T.bold}  LINK_PLATFORM v2 — End-to-End Smoke Test${T.reset}`);
  console.log(`${T.bold}${T.cyan}══════════════════════════════════════════════════${T.reset}`);
  console.log(`  Target: ${args.nodeUrl}`);
  console.log(`  Expect: ${INITIAL_SCORE} → ${INITIAL_SCORE + MAX_BONUS} after ${MAX_LINKS} links\n`);

  // ── Pre-flight ────────────────────────────────────────────────────────────────
  section("Pre-flight");
  if (!fs.existsSync(VP_KEYS_FILE))  throw new Error("founding-vp-keys.json missing — run: npm run seed:fresh");
  if (!fs.existsSync(SEED_OUT_FILE)) throw new Error("seed-output.json missing — run: npm run seed:fresh");
  pass("Genesis files found");

  const health = await getJson(`${args.nodeUrl}/health`, 8000);
  if (health.status !== 200) throw new Error(`Node not healthy (${health.status})`);
  const cs = health.body?.data?.consensus;
  if (cs?.halt?.halted) throw new Error(`Node halted: ${cs.halt.reason}`);
  pass(`Node healthy  round=${cs?.narwhal?.round ?? "?"}`);

  const vpFile  = JSON.parse(fs.readFileSync(VP_KEYS_FILE, "utf8"));
  const vpEntry = vpFile?.entries?.find((e) => e.tag === "primary-vp");
  if (!vpEntry?.public_key || !vpEntry?.private_key) throw new Error("founding-vp-keys.json missing primary-vp entry");
  const vpKp = { publicKey: vpEntry.public_key, privateKey: vpEntry.private_key };

  const seedOut   = JSON.parse(fs.readFileSync(SEED_OUT_FILE, "utf8"));
  const vpSummary = seedOut?.founding_vps?.find((v) => v.tag === "primary-vp");
  if (!vpSummary?.vp_id) throw new Error("seed-output.json missing founding_vps[primary-vp].vp_id");
  const vpId = vpSummary.vp_id;
  pass(`VP loaded: ${vpId}`);

  // ── Crypto init ───────────────────────────────────────────────────────────────
  section("Crypto init");
  await initCrypto();
  pass("ML-DSA-65 ready");

  // ── Step 1: Register identity ─────────────────────────────────────────────────
  section("Step 1  Register test identity");

  const userKp  = generateMLDSAKeypair();
  const region  = "US";
  const govId   = `LNKV2TEST-${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
  info("Generating ZK dedup proof…");
  const { dedup_hash, proof: zk_proof } = await generateDedupProof(govId, "1990-01-01", region);

  const idFields = {
    region, public_key: userKp.publicKey, dedup_hash, zk_proof,
    verification_tier: "T1", vp_id: vpId, social_attested: false,
    tip_id_type: "personal", creator_name: "LinkPlatformV2SmokeTest",
  };
  const regPayload = registerIdentitySchema.buildSigningPayload(idFields);
  const regSig     = registerIdentitySchema.sign(regPayload, vpKp.privateKey);

  const regRes = await postJson(`${args.nodeUrl}/v1/identity/register`, { ...idFields, vp_signature: regSig }, 60000);
  if (regRes.status < 200 || regRes.status >= 300) {
    throw new Error(`Registration failed (${regRes.status}): ${JSON.stringify(regRes.body)}`);
  }
  const tipId = regRes.body?.data?.tip_id;
  if (!tipId) throw new Error(`No tip_id in response: ${JSON.stringify(regRes.body)}`);
  pass(`Registered  tip_id=${tipId}`);

  info("Waiting for identity to commit…");
  const appeared = await waitFor(async () => {
    const r = await getJson(`${args.nodeUrl}/v1/identity/${encodeURIComponent(tipId)}`);
    return r.status === 200;
  });
  if (!appeared) throw new Error("Identity did not appear within 90s");
  pass("Identity committed to DAG");

  // ── Step 2: Initial score ─────────────────────────────────────────────────────
  section("Step 2  Initial score");
  const initScore = await fetchScore(args.nodeUrl, tipId);
  console.log(`  Score: ${T.bold}${initScore}${T.reset}  (expected: ${INITIAL_SCORE})`);
  if (initScore === INITIAL_SCORE) {
    pass(`Initial score correct: ${initScore}`);
  } else {
    fail(`Initial score mismatch — got ${initScore}, expected ${INITIAL_SCORE}`);
    errors.push("initial score wrong");
  }

  // ── Steps 3–N: Link platforms (v2 user-claim-signed) ──────────────────────────
  section(`Steps 3–${2 + PLATFORMS.length}  Link ${PLATFORMS.length} platforms (v2 user-signed claim)`);

  let currentScore    = initScore ?? INITIAL_SCORE;
  let successfulLinks = 0;
  const linkResults   = [];

  for (let i = 0; i < PLATFORMS.length; i++) {
    const { platform, profileUrl } = PLATFORMS[i];
    const claimedAt   = nowMs();
    const bonusRound  = successfulLinks < MAX_LINKS;
    const expectedScore = bonusRound ? currentScore + BONUS_PER_LINK : currentScore;

    console.log(`\n  [${i + 1}/${PLATFORMS.length}] ${T.bold}${platform}${T.reset}  linked=${successfulLinks}  bonus=${bonusRound ? `+${BONUS_PER_LINK}` : "none (cap)"}`);

    // User signs 4-field claim payload (alphabetical: claimed_at, platform, profile_url, tip_id)
    const claimPayload   = registerSocialSchema.buildSigningPayload({ claimed_at: claimedAt, platform, profile_url: profileUrl, tip_id: tipId });
    const claimSignature = registerSocialSchema.sign(claimPayload, userKp.privateKey);
    info(`Claim signed. Calling link-platform…`);

    const linkRes = await postJson(
      `${args.nodeUrl}/v1/identity/${encodeURIComponent(tipId)}/link-platform`,
      { platform, profile_url: profileUrl, claim_signature: claimSignature, claimed_at: claimedAt },
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
      linkResults.push({ platform, bonusRound, ok: null, status: 409, score: currentScore, duplicate: true });
      continue;
    }

    if (linkRes.status !== 202) {
      fail(`Expected 202, got ${linkRes.status}: ${JSON.stringify(linkRes.body)}`);
      errors.push(`link ${platform} returned ${linkRes.status}`);
      linkResults.push({ platform, bonusRound, ok: false, status: linkRes.status, score: currentScore });
      continue;
    }

    const body  = linkRes.body?.data ?? linkRes.body;
    const txId  = body?.tx_id;
    info(`Proposed  tx_id=${txId}  score_delta=${body?.score_delta}`);

    if (bonusRound) {
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
        errors.push(`${platform}: score did not reach ${expectedScore} (got ${actual})`);
        currentScore = typeof actual === "number" ? actual : currentScore;
        successfulLinks++;
        linkResults.push({ platform, bonusRound, ok: false, score: currentScore });
      }
    } else {
      const deltOk  = body?.score_delta === 0;
      const txOk    = body?.score_tx_id === null;
      if (!deltOk) {
        fail(`Expected score_delta 0, got ${body?.score_delta}`);
        errors.push(`${platform} score_delta ${body?.score_delta} ≠ 0`);
      }
      info(`Waiting for no-bonus tx to commit (tx_id=${txId})…`);
      await waitFor(async () => {
        const r = await getJson(`${args.nodeUrl}/v1/identity/${encodeURIComponent(tipId)}/activity`);
        if (r.status !== 200) return false;
        return (r.body?.data?.items ?? []).some(item => item.tx_id === txId);
      }, { intervalMs: 1200, timeoutMs: 30000 });

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

  // ── Final score ───────────────────────────────────────────────────────────────
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

  // ── Summary ───────────────────────────────────────────────────────────────────
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
    if (r.duplicate) { s = `${T.yellow}⊘${T.reset}`; bonus = " dup"; }
    else { s = r.ok ? `${T.green}✓${T.reset}` : `${T.red}✗${T.reset}`; bonus = r.bonusRound ? `+${BONUS_PER_LINK}` : " +0"; }
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
