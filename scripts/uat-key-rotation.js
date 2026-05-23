#!/usr/bin/env node
/**
 * @file scripts/uat-key-rotation.js
 * @description End-to-end UAT for KEY_ROTATED + KEY_RECOVERY (GH #60).
 *
 * Walks both lifecycle flows against a live node + PG:
 *
 *   PHASE 1  Register a fresh identity.
 *   PHASE 2  Rotate the key with the OLD private key signing the
 *            canonical KEY_ROTATED body. After commit:
 *              - tx.signature is populated; no legacy field on tx.data.
 *              - The NEW key signs an arbitrary follow-up action
 *                (update-profile) and the API accepts it.
 *              - The OLD key signing the same follow-up action is
 *                rejected (signature does not verify against the
 *                now-current active key).
 *   PHASE 3  Recover the key via the VP. The user "loses" the rotated
 *            key (we just generate a third keypair); the VP signs the
 *            canonical KEY_RECOVERY body. After commit:
 *              - tx.signature is populated.
 *              - The recovered key signs update-profile and the API
 *                accepts it.
 *              - Neither of the prior two keys can authenticate.
 *
 * Pre-reqs: `npm run seed:fresh` and a fresh PG schema + node started
 * with `ZK_SKIP_VERIFY=true`.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const SHARED = path.resolve(__dirname, "../shared");
const { initCrypto, generateMLDSAKeypair, shake256, generateTIPID, signBody } = require(SHARED + "/crypto");
const { nowMs } = require(SHARED + "/time");
const registerIdentitySchema = require(path.resolve(__dirname, "../node/src/schemas/register-identity"));
const keyRotatedSchema = require(path.resolve(__dirname, "../node/src/schemas/key-rotated"));
const keyRecoverySchema = require(path.resolve(__dirname, "../node/src/schemas/key-recovery"));

const API = process.env.TIP_API || "http://localhost:4000";

function _green(s) { return `\x1b[32m${s}\x1b[0m`; }
function _red(s) { return `\x1b[31m${s}\x1b[0m`; }
function _yellow(s) { return `\x1b[33m${s}\x1b[0m`; }
function _dim(s) { return `\x1b[2m${s}\x1b[0m`; }

let _passed = 0;
let _failed = 0;
function expect(cond, label, detail = "") {
  if (cond) {
    _passed++;
    console.log(`  ${_green("✓")} ${label}${detail ? ` ${_dim(detail)}` : ""}`);
  } else {
    _failed++;
    console.log(`  ${_red("✗")} ${label}${detail ? ` ${_dim(detail)}` : ""}`);
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

async function _getTx(tx_id, { timeoutMs = 4000 } = {}) {
  const start = nowMs();
  while (nowMs() - start < timeoutMs) {
    const r = await _get(`/v1/dag/tx/${tx_id}`);
    if (r.status === 200 && r.body?.data?.tx_id) return r.body.data;
    await _sleep(100);
  }
  return null;
}

function assertUnifiedSig(label, tx) {
  expect(typeof tx?.signature === "string" && tx.signature.length > 100,
    `${label} — tx.signature populated`, tx?.signature ? `${tx.signature.length} bytes` : "missing");
  for (const f of ["signature", "vp_signature", "council_signature"]) {
    expect(tx?.data?.[f] === undefined, `${label} — tx.data.${f} absent`, "");
  }
}

const VP = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../genesis-data/backups/tip-vp-US-1d8e8ee431f715ec.tip.json"), "utf8"));

async function _registerIdentity(label) {
  const kp = generateMLDSAKeypair();
  const region = "US";
  const tipId = generateTIPID(region, kp.publicKey);
  const dedupHash = String(BigInt("0x" + shake256(`uat-key:${tipId}:${label}`).slice(0, 32)));
  const fields = {
    region, public_key: kp.publicKey, dedup_hash: dedupHash,
    zk_proof: { pi_a: ["1", "2", "3"], pi_b: [["1", "2"], ["3", "4"], ["5", "6"]], pi_c: ["1", "2", "3"], protocol: "groth16", curve: "bn128" },
    verification_tier: "T1", vp_id: VP.vp_id, social_attested: true,
  };
  const payload = registerIdentitySchema.buildSigningPayload(fields);
  const vpSig = registerIdentitySchema.sign(payload, VP.private_key);
  const r = await _post("/v1/identity/register", { ...fields, vp_signature: vpSig });
  if (![200, 201, 202].includes(r.status)) {
    throw new Error(`${label} register failed: ${r.status} ${JSON.stringify(r.body)}`);
  }
  // Wait for commit so subsequent ops see the identity.
  for (let i = 0; i < 60; i++) {
    const cr = await _get(`/v1/identity/${encodeURIComponent(r.body.data.tip_id)}`);
    if (cr.status === 200 && cr.body?.data?.tip_id) return { tip_id: r.body.data.tip_id, kp, tx_id: r.body.data.tx_id };
    await _sleep(150);
  }
  throw new Error(`${label} identity did not commit within timeout`);
}

// update-profile is a convenient "any signed user-action" oracle —
// it touches no other side-effects, and the schema's signer-of-record
// is the subject's currently-active key. If a profile POST succeeds
// after a rotation, the chain has actually switched the active key
// for this tip_id (not just stored the new row).
async function _trySignedProfileUpdate(tipId, privateKeyHex, reviewerConsent) {
  const body = { tip_id: tipId, reviewer_consent: reviewerConsent };
  const sig = signBody(body, privateKeyHex);
  return _post(`/v1/identity/${encodeURIComponent(tipId)}/profile`, { ...body, signature: sig });
}

async function main() {
  await initCrypto();
  console.log(_yellow("\nGH #60 — KEY_ROTATED + KEY_RECOVERY end-to-end UAT\n"));

  // ── PHASE 1: register a fresh identity ────────────────────────────
  console.log(_yellow("[Phase 1/3] REGISTER FRESH IDENTITY"));
  const user = await _registerIdentity("rotate-test");
  expect(!!user.tip_id, "Identity registered + committed", user.tip_id);
  const oldKp = user.kp;

  // Sanity: OLD key signs profile update successfully.
  {
    const r = await _trySignedProfileUpdate(user.tip_id, oldKp.privateKey, true);
    expect([200, 201, 202].includes(r.status),
      "Pre-rotation: OLD key authenticates update-profile", `status=${r.status}`);
  }

  // ── PHASE 2: rotate key ───────────────────────────────────────────
  console.log(_yellow("\n[Phase 2/3] KEY_ROTATED"));
  const newKp = generateMLDSAKeypair();
  const oldFingerprint = shake256(oldKp.publicKey).slice(0, 32);
  // effective_at must be >= tx.timestamp set server-side; we send a
  // value far enough in the future to survive transport jitter.
  const effectiveAt1 = nowMs() + 5000;
  const rotateBody = {
    tip_id: user.tip_id,
    new_public_key: newKp.publicKey,
    old_key_fingerprint: oldFingerprint,
    effective_at: effectiveAt1,
    algorithm: "ml-dsa-65",
  };
  const rotatePayload = keyRotatedSchema.buildSigningPayload(rotateBody);
  const rotateSig = keyRotatedSchema.sign(rotatePayload, oldKp.privateKey);
  const rotateRes = await _post(`/v1/identity/${encodeURIComponent(user.tip_id)}/keys/rotate`,
    { ...rotateBody, signature: rotateSig });
  expect([200, 201, 202].includes(rotateRes.status),
    "POST /v1/identity/:tipId/keys/rotate", `status=${rotateRes.status} ${JSON.stringify(rotateRes.body?.error || "")}`);

  if ([200, 201, 202].includes(rotateRes.status)) {
    const rotateTxId = rotateRes.body.data.tx_id;
    const tx = await _getTx(rotateTxId);
    expect(!!tx, "KEY_ROTATED tx committed", tx?.tx_id?.slice(0, 16));
    if (tx) assertUnifiedSig("KEY_ROTATED", tx);

    // Wait past effective_at so the NEW key is active.
    const waitMs = Math.max(0, effectiveAt1 - nowMs()) + 500;
    await _sleep(waitMs);

    // NEW key authenticates.
    {
      const r = await _trySignedProfileUpdate(user.tip_id, newKp.privateKey, false);
      expect([200, 201, 202].includes(r.status),
        "Post-rotation: NEW key authenticates update-profile", `status=${r.status} ${JSON.stringify(r.body?.error || "")}`);
    }

    // OLD key no longer authenticates (signature won't verify against
    // the now-active NEW public key).
    {
      const r = await _trySignedProfileUpdate(user.tip_id, oldKp.privateKey, true);
      expect(r.status === 403 || r.status === 400,
        "Post-rotation: OLD key REJECTED for update-profile", `status=${r.status}`);
    }
  }

  // ── PHASE 3: recover key via VP ───────────────────────────────────
  console.log(_yellow("\n[Phase 3/3] KEY_RECOVERY"));
  // User "loses" the current key. They go back to the VP for off-chain
  // re-verification; the VP attests and the chain installs the new key.
  const recoveredKp = generateMLDSAKeypair();
  const effectiveAt2 = nowMs() + 5000;
  const evidenceHash = shake256(`recovery-evidence:${user.tip_id}:${nowMs()}`);
  const recoverBody = {
    tip_id: user.tip_id,
    vp_id: VP.vp_id,
    new_public_key: recoveredKp.publicKey,
    recovery_evidence_hash: evidenceHash,
    effective_at: effectiveAt2,
    algorithm: "ml-dsa-65",
  };
  const recoverPayload = keyRecoverySchema.buildSigningPayload(recoverBody);
  const recoverSig = keyRecoverySchema.sign(recoverPayload, VP.private_key);
  const recoverRes = await _post(`/v1/identity/${encodeURIComponent(user.tip_id)}/keys/recover`,
    { ...recoverBody, signature: recoverSig });
  expect([200, 201, 202].includes(recoverRes.status),
    "POST /v1/identity/:tipId/keys/recover", `status=${recoverRes.status} ${JSON.stringify(recoverRes.body?.error || "")}`);

  if ([200, 201, 202].includes(recoverRes.status)) {
    const recoverTxId = recoverRes.body.data.tx_id;
    const tx = await _getTx(recoverTxId);
    expect(!!tx, "KEY_RECOVERY tx committed", tx?.tx_id?.slice(0, 16));
    if (tx) assertUnifiedSig("KEY_RECOVERY", tx);

    const waitMs = Math.max(0, effectiveAt2 - nowMs()) + 500;
    await _sleep(waitMs);

    // RECOVERED key authenticates.
    {
      const r = await _trySignedProfileUpdate(user.tip_id, recoveredKp.privateKey, true);
      expect([200, 201, 202].includes(r.status),
        "Post-recovery: RECOVERED key authenticates update-profile", `status=${r.status} ${JSON.stringify(r.body?.error || "")}`);
    }

    // Neither of the previous keys authenticates.
    for (const [label, kp] of [["OLD (pre-rotation)", oldKp], ["ROTATED (pre-recovery)", newKp]]) {
      const r = await _trySignedProfileUpdate(user.tip_id, kp.privateKey, false);
      expect(r.status === 403 || r.status === 400,
        `Post-recovery: ${label} key REJECTED for update-profile`, `status=${r.status}`);
    }
  }

  // ── Summary ───────────────────────────────────────────────────────
  console.log("");
  if (_failed === 0) {
    console.log(_green(`✓ ${_passed} UAT check(s) passed — KEY_ROTATED + KEY_RECOVERY validated end-to-end.\n`));
    process.exit(0);
  } else {
    console.log(_red(`✗ ${_failed} of ${_passed + _failed} UAT check(s) failed.\n`));
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(_red(`\nUAT script crashed: ${err.message}`));
  console.error(err.stack);
  process.exit(2);
});
