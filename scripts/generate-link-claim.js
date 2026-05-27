#!/usr/bin/env node
/**
 * @file scripts/generate-link-claim.js
 * @description Generate a LINK_PLATFORM claim signature for Postman testing.
 *
 * This tool:
 *   1. Reads your .tip.json backup (DOB-encrypted) and decrypts it, OR
 *      accepts a raw private key hex directly.
 *   2. Signs the register-social claim payload (4-field ML-DSA-65 signature).
 *   3. Outputs the complete JSON body ready to paste into Postman, AND
 *      optionally calls the API directly.
 *
 * Usage:
 *   # From .tip.json backup (DOB-encrypted):
 *   node scripts/generate-link-claim.js \
 *     --tip-json ./my-tip-id.tip.json \
 *     --dob 01011990 \
 *     --platform github \
 *     --profile-url https://github.com/myusername
 *
 *   # From raw private key hex:
 *   node scripts/generate-link-claim.js \
 *     --tip-id "tip://id/US-abcdef1234567890" \
 *     --private-key "abc123..." \
 *     --platform twitter \
 *     --profile-url https://x.com/myhandle
 *
 *   # Call the API directly (uses node-url):
 *   node scripts/generate-link-claim.js \
 *     --tip-json ./my.tip.json --dob 01011990 \
 *     --platform github --profile-url https://github.com/myusername \
 *     --call --node-url http://localhost:4000
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");
const http   = require("http");
const https  = require("https");

const { nowMs }           = require("../shared/time");
const { initCrypto, mldsaSign, canonicalJson } = require("../shared/crypto");
const registerSocialSchema = require("../node/src/schemas/register-social");

// ─── ANSI colors ─────────────────────────────────────────────────────────────
const T = { reset: "\x1b[0m", bold: "\x1b[1m", green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", dim: "\x1b[2m", yellow: "\x1b[33m" };
const ok   = m => console.log(`${T.green}  ✓${T.reset} ${m}`);
const fail = m => console.log(`${T.red}  ✗${T.reset} ${m}`);
const info = m => console.log(`${T.cyan}  ℹ${T.reset} ${m}`);
const lbl  = (k, v) => console.log(`    ${T.dim}${k.padEnd(20)}${T.reset}${v}`);

// ─── CLI args ─────────────────────────────────────────────────────────────────
function getArg(name, fallback = null) {
  const eqHit = process.argv.find(a => a.startsWith(`${name}=`));
  if (eqHit) return eqHit.slice(name.length + 1);
  const idx = process.argv.indexOf(name);
  return idx !== -1 && process.argv[idx + 1] ? process.argv[idx + 1] : fallback;
}
const hasFlag = name => process.argv.includes(name);

const tipJsonFile  = getArg("--tip-json");
const dob          = getArg("--dob");          // MMDDYYYY or MM/DD/YYYY
const rawTipId     = getArg("--tip-id");
const rawPrivKey   = getArg("--private-key");
const platform     = getArg("--platform");
const profileUrl   = getArg("--profile-url");
const nodeUrl      = getArg("--node-url", "http://localhost:4000");
const callApi      = hasFlag("--call");

// ─── Decrypt .tip.json ───────────────────────────────────────────────────────
async function decryptTipJson(filePath, dobRaw) {
  const dobDigits = dobRaw.replace(/\D/g, "");
  if (dobDigits.length !== 8) {
    throw new Error("DOB must be 8 digits: MMDDYYYY (e.g. 01011990 for Jan 1, 1990)");
  }

  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  if (!parsed.encrypted) throw new Error(".tip.json has no 'encrypted' field — may be a different format");
  if (parsed.version !== "tip-key-export-v2") {
    throw new Error(`Unsupported .tip.json version: ${parsed.version}`);
  }

  const combined = Buffer.from(parsed.encrypted, "base64");
  const salt = combined.slice(0, 16);
  const iv   = combined.slice(16, 28);
  const ct   = combined.slice(28);

  // PBKDF2 key derivation (same as frontend: 200000 iterations, SHA-256, AES-256-GCM)
  const keyMaterial = await crypto.webcrypto.subtle.importKey(
    "raw", new TextEncoder().encode(dobDigits), "PBKDF2", false, ["deriveKey"]
  );
  const aesKey = await crypto.webcrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );

  let plaintext;
  try {
    const decrypted = await crypto.webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
    plaintext = new TextDecoder().decode(decrypted);
  } catch {
    throw new Error("Decryption failed — wrong Date of Birth? (format: MMDDYYYY)");
  }

  return {
    tipId:      parsed.tipId,
    publicKey:  parsed.publicKey,
    privateKey: plaintext,
  };
}

// ─── HTTP POST helper ─────────────────────────────────────────────────────────
function postJson(url, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const parsed  = new URL(url);
    const lib     = parsed.protocol === "https:" ? https : http;
    const req = lib.request(
      { hostname: parsed.hostname, port: parsed.port, path: parsed.pathname + (parsed.search || ""),
        method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } },
      res => {
        let data = "";
        res.on("data", c => data += c);
        res.on("end", () => { try { resolve({ status: res.statusCode, body: JSON.parse(data) }); } catch { resolve({ status: res.statusCode, body: data }); } });
      }
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log(`\n${T.bold}  TIP LINK_PLATFORM — Claim Signature Generator${T.reset}\n`);

  if (!platform || !profileUrl) {
    fail("--platform and --profile-url are required");
    console.log(`\nUsage:\n  node scripts/generate-link-claim.js \\\n    --tip-json ./my.tip.json --dob MMDDYYYY \\\n    --platform github --profile-url https://github.com/myusername\n`);
    process.exit(1);
  }

  await initCrypto();
  ok("ML-DSA-65 ready");

  let tipId, privateKey;

  if (tipJsonFile) {
    if (!dob) { fail("--dob MMDDYYYY is required when using --tip-json"); process.exit(1); }
    info(`Decrypting ${tipJsonFile}...`);
    const decrypted = await decryptTipJson(tipJsonFile, dob);
    tipId      = decrypted.tipId;
    privateKey = decrypted.privateKey;
    ok(`Decrypted: ${tipId}`);
  } else if (rawTipId && rawPrivKey) {
    tipId      = rawTipId;
    privateKey = rawPrivKey;
    ok(`Using provided TIP-ID: ${tipId}`);
  } else {
    fail("Provide either --tip-json + --dob, OR --tip-id + --private-key");
    process.exit(1);
  }

  const claimedAt = nowMs();

  // Build the 4-field canonical claim payload (alphabetical order)
  const claimPayload = registerSocialSchema.buildSigningPayload({
    claimed_at:  claimedAt,
    platform:    platform,
    profile_url: profileUrl,
    tip_id:      tipId,
  });

  // Sign with user's ML-DSA-65 private key
  const claimSignature = registerSocialSchema.sign(claimPayload, privateKey);
  ok(`Claim signed — ${claimSignature.length / 2} byte signature`);

  // ── Output ────────────────────────────────────────────────────────────────
  const postBody = {
    platform:        platform,
    profile_url:     profileUrl,
    claim_signature: claimSignature,
    claimed_at:      claimedAt,
  };

  const tipIdEncoded = encodeURIComponent(tipId);
  const endpoint = `POST ${nodeUrl}/v1/identity/${tipIdEncoded}/link-platform`;

  console.log(`\n${"─".repeat(64)}`);
  console.log(`${T.bold}  Postman Request${T.reset}`);
  console.log(`${"─".repeat(64)}`);
  lbl("Method + URL:", endpoint);
  lbl("Content-Type:", "application/json");
  console.log(`\n  Body (paste into Postman → Body → raw → JSON):\n`);
  console.log(JSON.stringify(postBody, null, 2));
  console.log(`\n${"─".repeat(64)}`);
  console.log(`\n  Check score after linking:`);
  lbl("GET", `${nodeUrl}/v1/identity/${tipIdEncoded}/score`);
  console.log("");

  // ── Optionally call the API ───────────────────────────────────────────────
  if (callApi) {
    info(`Calling API: ${endpoint}`);
    const apiUrl = `${nodeUrl}/v1/identity/${tipIdEncoded}/link-platform`;
    const res = await postJson(apiUrl, postBody);
    if (res.status === 202) {
      ok(`API returned 202 — LINK_PLATFORM submitted`);
      const d = res.body?.data ?? res.body;
      if (d?.tx_id)     lbl("tx_id",     d.tx_id);
      if (d?.score_delta !== undefined) lbl("score_delta", d.score_delta);

      // Poll score
      info("Waiting 5s for DAG commit...");
      await new Promise(r => setTimeout(r, 5000));
      const scoreUrl = `${nodeUrl}/v1/identity/${tipIdEncoded}/score`;
      const scoreReq = await new Promise((resolve, reject) => {
        const lib = scoreUrl.startsWith("https") ? https : http;
        lib.get(scoreUrl, res => {
          let d = ""; res.on("data", c => d += c); res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(d) }));
        }).on("error", reject);
      });
      if (scoreReq.status === 200) {
        const s = scoreReq.body?.data ?? scoreReq.body;
        ok(`Score after linking: ${T.bold}${s?.score ?? "?"}${T.reset} (delta: ${d?.score_delta ?? "?"})`);
      }
    } else {
      fail(`API returned ${res.status}: ${JSON.stringify(res.body)}`);
    }
  }
}

main().catch(err => {
  console.error(`\n${T.red}Error:${T.reset} ${err.message || err}`);
  process.exit(1);
});
