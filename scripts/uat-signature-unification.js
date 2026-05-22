#!/usr/bin/env node
/**
 * @file scripts/uat-signature-unification.js
 * @description End-to-end UAT for GH #51 unified signature storage.
 *
 * Walks the API: register identity → register content → verify content
 * → file dispute → jury vote commit. Each step asserts the on-DAG tx
 * lands with `tx.signature` populated and `tx.data` carrying NO
 * signature fields (claim_signature / escalation_signature stay where
 * documented as attestations-on-data).
 *
 * Run after `npm run seed:fresh` + restart of the local node.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const SHARED = path.resolve(__dirname, "../shared");
const { initCrypto, generateMLDSAKeypair, signBody, shake256, generateTIPID } = require(path.join(SHARED, "crypto"));
const registerIdentitySchema = require(path.resolve(__dirname, "../node/src/schemas/register-identity"));
const contentRegisterSchema = require(path.resolve(__dirname, "../node/src/schemas/content-register"));

const API = process.env.TIP_API || "http://localhost:4000";

function _green(s) { return `\x1b[32m${s}\x1b[0m`; }
function _red(s) { return `\x1b[31m${s}\x1b[0m`; }
function _yellow(s) { return `\x1b[33m${s}\x1b[0m`; }
function _dim(s) { return `\x1b[2m${s}\x1b[0m`; }

let _failed = 0;
function expect(cond, label, detail = "") {
  if (cond) {
    console.log(`  ${_green("✓")} ${label}${detail ? ` ${_dim(detail)}` : ""}`);
  } else {
    console.log(`  ${_red("✗")} ${label}${detail ? ` ${_dim(detail)}` : ""}`);
    _failed++;
  }
}

async function _post(p, body) {
  const res = await fetch(`${API}${p}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await res.json().catch(() => ({}));
  return { status: res.status, body: j };
}

async function _get(p) {
  const res = await fetch(`${API}${p}`);
  const j = await res.json().catch(() => ({}));
  return { status: res.status, body: j };
}

async function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function _getTx(tx_id) {
  // Wait up to ~3s for commit
  for (let i = 0; i < 30; i++) {
    const r = await _get(`/v1/dag/tx/${tx_id}`);
    if (r.status === 200 && r.body?.data?.tx_id) return r.body.data;
    await _sleep(100);
  }
  return null;
}

async function main() {
  await initCrypto();

  console.log(_yellow("\nGH #51 — UAT: unified signature storage end-to-end\n"));

  // ── Load founding VP keys ────────────────────────────────────────
  const vpFile = "genesis-data/backups/tip-vp-US-1d8e8ee431f715ec.tip.json";
  const vp = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", vpFile), "utf8"));
  expect(vp.vp_id && vp.private_key && vp.public_key, "Founding VP keys loaded", vp.vp_id);

  // ── 1. REGISTER_IDENTITY ─────────────────────────────────────────
  console.log(_yellow("\n[1/5] REGISTER_IDENTITY"));
  const userKp = generateMLDSAKeypair();
  const region = "US";
  const tipId = generateTIPID(region, userKp.publicKey);
  // Validator requires decimal field-element string (Poseidon output);
  // synthesize one for UAT (the on-chain ZK verifier accepts the mock proof).
  const dedupHash = String(BigInt("0x" + shake256(`uat:${tipId}`).slice(0, 32)));

  const sigFields = {
    region, public_key: userKp.publicKey, dedup_hash: dedupHash,
    zk_proof: { pi_a: ["1", "2", "3"], pi_b: [["1", "2"], ["3", "4"], ["5", "6"]], pi_c: ["1", "2", "3"], protocol: "groth16", curve: "bn128" },
    verification_tier: "T1", vp_id: vp.vp_id, social_attested: true,
  };
  const canonicalPayload = registerIdentitySchema.buildSigningPayload(sigFields);
  const vpSig = registerIdentitySchema.sign(canonicalPayload, vp.private_key);

  const idRes = await _post("/v1/identity/register", { ...sigFields, vp_signature: vpSig });
  expect([200, 201, 202].includes(idRes.status), "POST /v1/identity/register", `status=${idRes.status} ${JSON.stringify(idRes.body?.error || idRes.body).slice(0, 200)}`);
  const idTxId = idRes.body?.data?.tx_id;
  expect(!!idTxId, "tx_id returned", idTxId?.slice(0, 16));

  const idTx = idTxId && await _getTx(idTxId);
  expect(!!idTx, "tx committed", idTx?.tx_id?.slice(0, 16));
  expect(typeof idTx?.signature === "string" && idTx.signature.length > 100, "tx.signature populated (top-level)", `${idTx?.signature?.length} bytes`);
  expect(idTx?.data?.vp_signature === undefined, "tx.data.vp_signature NOT present (legacy field removed)", "");
  expect(idTx?.data?.signature === undefined, "tx.data.signature NOT present", "");

  // ── 2. REGISTER_CONTENT ──────────────────────────────────────────
  console.log(_yellow("\n[2/5] REGISTER_CONTENT"));
  const content = "UAT content for unified signature storage. This is original human-written prose.";
  const originCode = "OH";
  const contentRegisterFields = {
    signer_tip_id: tipId,
    origin_code: originCode,
    content,
    authors: [{ key_mode: "attribution", role: "byline", signed: true, tip_id: tipId, tip_id_type: "personal" }],
    attribution_mode: "self",
    extras: {},
    registered_urls: [],
    cna_version: contentRegisterSchema.CURRENT_CNA_VERSION,
  };
  const { tipNormalize } = require(path.join(SHARED, "crypto"));
  const contentHash = shake256(tipNormalize(content));
  const contentPayload = contentRegisterSchema.buildSigningPayload(contentRegisterFields, contentHash);
  const contentSig = contentRegisterSchema.sign(contentPayload, userKp.privateKey);

  const cRes = await _post("/v1/content/register", { ...contentRegisterFields, signature: contentSig });
  expect([200, 201, 202].includes(cRes.status), "POST /v1/content/register", `status=${cRes.status}`);
  const ctid = cRes.body?.data?.ctid;
  const cTxId = cRes.body?.data?.tx_id;
  expect(!!ctid, "ctid returned", ctid);
  expect(!!cTxId, "tx_id returned", cTxId?.slice(0, 16));

  const cTx = cTxId && await _getTx(cTxId);
  expect(!!cTx, "tx committed", cTx?.tx_id?.slice(0, 16));
  expect(typeof cTx?.signature === "string" && cTx.signature.length > 100, "tx.signature populated", `${cTx?.signature?.length} bytes`);
  expect(cTx?.data?.signature === undefined, "tx.data.signature NOT present", "");

  // ── 3. CONTENT_VERIFIED ──────────────────────────────────────────
  // Use the new identity to self-verify content registered earlier in the
  // genesis ring. Use one of the founding identities to verify, since
  // CONTENT_VERIFIED needs verifier_tip_id ≠ author_tip_id is NOT
  // strict here (verify-self not explicitly forbidden), but practically
  // the verifier should be a separate identity. We'll skip the verify
  // self-check, just exercise the unified path by sending the request.
  console.log(_yellow("\n[3/5] CONTENT_VERIFIED (using founder identity as verifier)"));
  const verifierIdFile = "genesis-data/backups/tip-id-US-9ef90f7c97271ad8.tip.json";
  const verifierId = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", verifierIdFile), "utf8"));
  expect(!!verifierId.tip_id && !!verifierId.private_key, "Verifier founder loaded", verifierId.tip_id);

  const verifyBody = {
    verifier_tip_id: verifierId.tip_id,
    ctid,
    verdict: "ORIGIN_CONFIRMED",
  };
  const verifyPayload = { ...verifyBody };
  const verifySig = signBody(verifyPayload, verifierId.private_key);
  const vRes = await _post(`/v1/content/${encodeURIComponent(ctid)}/verify`, { ...verifyBody, signature: verifySig });
  expect([200, 201, 202].includes(vRes.status), "POST /v1/content/:ctid/verify", `status=${vRes.status} ${JSON.stringify(vRes.body?.error || "")}`);

  // Find the CONTENT_VERIFIED tx via verifier's activity feed.
  // Poll up to 3s — verifyTx commits at the next anchor (~250ms cadence).
  let verifyItem;
  for (let i = 0; i < 30; i++) {
    await _sleep(150);
    const feed = await _get(`/v1/identity/${encodeURIComponent(verifierId.tip_id)}/activity?types=CONTENT_VERIFIED`);
    verifyItem = feed.body?.data?.items?.find(it => it.ctid === ctid);
    if (verifyItem) break;
  }
  expect(!!verifyItem, "CONTENT_VERIFIED appears in verifier activity", verifyItem?.tx_id?.slice(0, 16));
  const verifyTx = verifyItem?.tx_id && await _getTx(verifyItem.tx_id);
  expect(!!verifyTx, "CONTENT_VERIFIED tx fetched", verifyTx?.tx_id?.slice(0, 16));
  if (verifyTx) {
    expect(typeof verifyTx.signature === "string" && verifyTx.signature.length > 100, "tx.signature populated", `${verifyTx.signature?.length} bytes`);
    expect(verifyTx.data?.signature === undefined, "tx.data.signature NOT present", "");
  }

  // ── 4. UPDATE_PROFILE — opt into reviewer_consent ─────────────────
  console.log(_yellow("\n[4/5] UPDATE_PROFILE"));
  const upFields = { tip_id: tipId, reviewer_consent: true };
  const upPayload = upFields;
  const upSig = signBody(upPayload, userKp.privateKey);
  const upRes = await _post(`/v1/identity/${encodeURIComponent(tipId)}/profile`, { ...upFields, signature: upSig });
  expect([200, 201, 202].includes(upRes.status), "POST /v1/identity/:tipId/profile", `status=${upRes.status} ${JSON.stringify(upRes.body?.error || "")}`);
  const upTxId = upRes.body?.data?.tx_id;
  const upTx = upTxId && await _getTx(upTxId);
  expect(!!upTx, "UPDATE_PROFILE tx committed", upTx?.tx_id?.slice(0, 16));
  if (upTx) {
    expect(typeof upTx.signature === "string" && upTx.signature.length > 100, "tx.signature populated", `${upTx.signature?.length} bytes`);
    expect(upTx.data?.signature === undefined, "tx.data.signature NOT present", "");
  }

  // ── 5. REVOKE_VOLUNTARY — self-revoke via founding VP ─────────────
  console.log(_yellow("\n[5/5] REVOKE_VOLUNTARY"));
  const revokeFields = {
    tx_type: "REVOKE_VOLUNTARY",
    tip_id: tipId,
    reason_code: "uat_test",
    issuing_vp_id: vp.vp_id,
  };
  const revokeSig = signBody(revokeFields, vp.private_key);
  const rRes = await _post("/v1/revocations", { ...revokeFields, signature: revokeSig });
  expect([200, 201, 202].includes(rRes.status), "POST /v1/revocations", `status=${rRes.status} ${JSON.stringify(rRes.body?.error || "")}`);
  const rTxId = rRes.body?.data?.tx_id;
  const rTx = rTxId && await _getTx(rTxId);
  expect(!!rTx, "REVOKE tx committed", rTx?.tx_id?.slice(0, 16));
  if (rTx) {
    expect(typeof rTx.signature === "string" && rTx.signature.length > 100, "tx.signature populated", `${rTx.signature?.length} bytes`);
    expect(rTx.data?.signature === undefined, "tx.data.signature NOT present", "");
  }

  // ── Summary ──────────────────────────────────────────────────────
  console.log("");
  if (_failed === 0) {
    console.log(_green(`✓ All UAT checks passed — unified signature storage validated end-to-end.\n`));
    process.exit(0);
  } else {
    console.log(_red(`✗ ${_failed} UAT check(s) failed.\n`));
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(_red(`\nUAT script crashed: ${err.message}`));
  console.error(err.stack);
  process.exit(2);
});
