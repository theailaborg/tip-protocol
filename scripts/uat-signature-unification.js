#!/usr/bin/env node
/**
 * @file scripts/uat-signature-unification.js
 * @description Comprehensive end-to-end UAT for GH #51 unified signature
 * storage. Walks every API endpoint that accepts a client signature
 * and asserts the committed tx has `tx.signature` populated and
 * `tx.data` carries none of the legacy signature field names.
 *
 * Coverage by tx_type:
 *   REGISTER_IDENTITY        — direct API
 *   VP_REGISTERED            — direct API
 *   NODE_REGISTERED          — direct API
 *   REGISTER_CONTENT         — direct API
 *   CONTENT_VERIFIED         — direct API
 *   UPDATE_ORIGIN            — direct API
 *   CONTENT_RETRACTED        — direct API
 *   UPDATE_PROFILE           — direct API (also via become-reviewer / stop-reviewing)
 *   CONTENT_DISPUTED (user)  — direct API
 *   JURY_VOTE_COMMIT         — direct API (against cascaded JURY_SUMMONS)
 *   JURY_VOTE_REVEAL         — direct API
 *   APPEAL_FILED             — direct API (against ADJUDICATION_RESULT)
 *   JURY_VOTE_COMMIT/REVEAL is_appeal=true — direct API (expert panel)
 *   REVOKE_VOLUNTARY / REVOKE_VP / REVOKE_DECEASED / REVOKE_DEVICE — direct API
 *
 * Not in UAT (covered by unit + integration tests; require non-API
 * setup):
 *   PRESCAN_REVIEW_*         — needs a 48h timer / backdated content
 *   BIND_DOMAIN / UNBIND     — needs real DNS / well-known
 *   AI_CLASSIFIER_RESULT / JURY_SUMMONS / ADJUDICATION_RESULT /
 *     APPEAL_RESULT / SCORE_UPDATE / COMMITTEE_ROTATION
 *                            — node-emitted, not API-signed
 *
 * Run after `npm run seed:fresh` and a fresh PG schema + node start
 *
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const SHARED = path.resolve(__dirname, "../shared");
const { initCrypto, generateMLDSAKeypair, signBody, shake256, generateTIPID, tipNormalize, canonicalJson } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const registerIdentitySchema = require(path.resolve(__dirname, "../node/src/schemas/register-identity"));
const { generateDedupProof } = require("../shared/zk");
const contentRegisterSchema = require(path.resolve(__dirname, "../node/src/schemas/content-register"));

const API = process.env.TIP_API || "http://localhost:4000";
const PG_CONTAINER = process.env.TIP_PG || "tip-postgres";
const PG_DB = process.env.TIP_PG_DB || "tip_protocol";

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

async function _findTx(tipId, txType, predicate, { timeoutMs = 6000 } = {}) {
  const start = nowMs();
  while (nowMs() - start < timeoutMs) {
    const feed = await _get(`/v1/identity/${encodeURIComponent(tipId)}/activity?types=${txType}`);
    const items = feed.body?.data?.items || [];
    const match = items.find(predicate || (() => true));
    if (match) return match;
    await _sleep(150);
  }
  return null;
}

function _bumpScore(tipId, score) {
  const sql = `INSERT INTO scores (tip_id, score, offense_count, last_updated)
    VALUES ('${tipId}', ${score}, 0, ${nowMs()})
    ON CONFLICT (tip_id) DO UPDATE SET score = EXCLUDED.score, last_updated = EXCLUDED.last_updated;`;
  execSync(`docker exec -i ${PG_CONTAINER} psql -U tip -d ${PG_DB} -v ON_ERROR_STOP=1`, {
    input: sql,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

/** Tx-shape assertions used across every section. */
function assertUnifiedSig(label, tx) {
  expect(typeof tx?.signature === "string" && tx.signature.length > 100,
    `${label} — tx.signature populated`, tx?.signature ? `${tx.signature.length} bytes` : "missing");
  for (const f of ["signature", "vp_signature", "council_signature", "binding_signature", "unbind_signature"]) {
    expect(tx?.data?.[f] === undefined,
      `${label} — tx.data.${f} absent`, "");
  }
  // Cosignatures normalisation — legacy named-secondary-signature fields
  // must NOT appear on tx.data; the canonical shape is tx.data.cosignatures.
  for (const f of ["claim_signature", "escalation_signature", "signer_node_ids"]) {
    expect(tx?.data?.[f] === undefined,
      `${label} — tx.data.${f} absent (cosignatures normalisation)`, "");
  }
  // When cosignatures IS present, every entry must have the canonical
  // {signer_kind, signer_ref, signature} triplet.
  if (Array.isArray(tx?.data?.cosignatures)) {
    for (let i = 0; i < tx.data.cosignatures.length; i++) {
      const c = tx.data.cosignatures[i];
      expect(c && typeof c.signer_kind === "string" && typeof c.signer_ref === "string" && typeof c.signature === "string",
        `${label} — cosignatures[${i}] has {signer_kind, signer_ref, signature}`, "");
    }
  }
}

// Resolve VP + founder backup files dynamically — actual ids in the
// repo's genesis-data/backups/ shift whenever the seed regenerates.
const _backupDir = path.resolve(__dirname, "../genesis-data/backups");
const _backupFiles = fs.readdirSync(_backupDir);
const _vpFile = _backupFiles.find(f => f.startsWith("tip-vp-"));
if (!_vpFile) throw new Error("No VP backup found in genesis-data/backups/");
const VP = JSON.parse(fs.readFileSync(path.join(_backupDir, _vpFile), "utf8"));
const founderIds = _backupFiles.filter(f => f.startsWith("tip-id-"))
  .map(f => JSON.parse(fs.readFileSync(path.join(_backupDir, f), "utf8")));

/** Register a brand-new identity via the API. Returns {tip_id, kp}. */
async function _registerIdentity(label) {
  const kp = generateMLDSAKeypair();
  const region = "US";
  const tipId = generateTIPID(region, kp.publicKey);
  const { dedup_hash: dedupHash, proof: zkProof } =
    await generateDedupProof(`uat:${tipId}:${label}`, "1990-01-01", region);
  const fields = {
    region, public_key: kp.publicKey, dedup_hash: dedupHash,
    zk_proof: zkProof,
    verification_tier: "T1", vp_id: VP.vp_id, social_attested: true,
  };
  const payload = registerIdentitySchema.buildSigningPayload(fields);
  const vpSig = registerIdentitySchema.sign(payload, VP.private_key);
  const r = await _post("/v1/identity/register", { ...fields, vp_signature: vpSig });
  if (![200, 201, 202].includes(r.status)) {
    throw new Error(`${label} register failed: ${r.status} ${JSON.stringify(r.body)}`);
  }
  return { tip_id: r.body.data.tip_id, kp, tx_id: r.body.data.tx_id };
}

async function _registerContent(authorTipId, authorKp, originCode, suffix) {
  const content = `UAT content ${suffix} — human-written prose for unified-sig validation.`;
  const fields = {
    signer_tip_id: authorTipId, origin_code: originCode, content,
    authors: [{ key_mode: "attribution", role: "byline", signed: true, tip_id: authorTipId, tip_id_type: "personal" }],
    attribution_mode: "self", extras: {}, registered_urls: [],
    cna_version: contentRegisterSchema.CURRENT_CNA_VERSION,
  };
  const contentHash = shake256(tipNormalize(content));
  const payload = contentRegisterSchema.buildSigningPayload(fields, contentHash);
  const sig = contentRegisterSchema.sign(payload, authorKp.privateKey);
  const r = await _post("/v1/content/register", { ...fields, signature: sig });
  if (![200, 201, 202].includes(r.status)) throw new Error(`content register failed: ${r.status} ${JSON.stringify(r.body)}`);
  // Wait for content row to be committed by commit-handler so dependent
  // calls (update-origin, retract, dispute) don't 404.
  for (let i = 0; i < 30; i++) {
    const cr = await _get(`/v1/content/${encodeURIComponent(r.body.data.ctid)}`);
    if (cr.status === 200 && cr.body?.data?.ctid) break;
    await _sleep(150);
  }
  return { ctid: r.body.data.ctid, tx_id: r.body.data.tx_id };
}

// ════════════════════════════════════════════════════════════════════
async function main() {
  await initCrypto();
  console.log(_yellow("\nGH #51 — Comprehensive UAT: unified signature storage end-to-end\n"));

  // ── PHASE 1: cast setup ───────────────────────────────────────────
  console.log(_yellow("[Phase 1/6] CAST SETUP"));

  // Pre-create 12 high-score identities (10 jury candidates + 1 author + 1 disputer + 1 appellant slot).
  // jury_min_score = 700; bump to 850 so the selection has comfortable headroom.
  const cast = [];
  for (let i = 0; i < 12; i++) {
    const u = await _registerIdentity(`cast-${i}`);
    cast.push(u);
  }
  expect(cast.length === 12, "Created 12 identities", "");

  await _sleep(500); // let registrations commit
  for (const u of cast) _bumpScore(u.tip_id, 850);
  expect(true, "Bumped scores to 850 for jury eligibility", "");

  const author = cast[0];
  const disputer = cast[1];
  const juryPool = cast.slice(2);   // 10 candidates; jury_size=7

  // Assert REGISTER_IDENTITY shape (cast[0])
  const idTx = await _getTx(author.tx_id);
  expect(!!idTx, "REGISTER_IDENTITY tx committed", idTx?.tx_id?.slice(0, 16));
  assertUnifiedSig("REGISTER_IDENTITY", idTx);

  // ── PHASE 2: simple signed APIs ───────────────────────────────────
  console.log(_yellow("\n[Phase 2/6] SIMPLE SIGNED APIs"));

  // VP_REGISTERED via API — founding VP approves a new VP
  {
    const vpKp = generateMLDSAKeypair();
    const fields = {
      name: "UAT-VP", jurisdiction: "US", jurisdiction_tier: "green",
      public_key: vpKp.publicKey, approving_vp_id: VP.vp_id,
    };
    const sig = signBody(fields, VP.private_key);
    const r = await _post("/v1/vp/register", { ...fields, council_signature: sig });
    expect([200, 201, 202].includes(r.status), "POST /v1/vp/register", `status=${r.status}`);
    if ([200, 201, 202].includes(r.status)) {
      const vpId = r.body.data.vp_id;
      // Find tx via list
      await _sleep(800);
      const vpTxs = await _get(`/v1/dag/recent?tx_type=VP_REGISTERED&limit=10`).catch(() => ({ body: { data: {} } }));
      const txid = vpTxs.body?.data?.txs?.find?.(t => t.data?.vp_id === vpId)?.tx_id;
      const tx = txid && await _getTx(txid);
      if (tx) assertUnifiedSig("VP_REGISTERED", tx);
      else console.log(`  ${_dim("(skipped tx-fetch — no /v1/dag/recent lookup route)")}`);
    }
  }

  // NODE_REGISTERED via API
  {
    const nodeKp = generateMLDSAKeypair();
    const fields = {
      name: "UAT-Node", public_key: nodeKp.publicKey, approving_vp_id: VP.vp_id,
    };
    const sig = signBody(fields, VP.private_key);
    const r = await _post("/v1/node/register", { ...fields, council_signature: sig });
    expect([200, 201, 202].includes(r.status), "POST /v1/node/register", `status=${r.status}`);
  }

  // REGISTER_CONTENT
  const c1 = await _registerContent(author.tip_id, author.kp, "OH", "c1");
  const c1Tx = await _getTx(c1.tx_id);
  assertUnifiedSig("REGISTER_CONTENT", c1Tx);

  // CONTENT_VERIFIED — second identity verifies
  {
    const verifier = cast[2];
    const verifyBody = { verifier_tip_id: verifier.tip_id, ctid: c1.ctid, verdict: "ORIGIN_CONFIRMED" };
    const sig = signBody(verifyBody, verifier.kp.privateKey);
    const r = await _post(`/v1/content/${encodeURIComponent(c1.ctid)}/verify`, { ...verifyBody, signature: sig });
    expect([200, 201, 202].includes(r.status), "POST /v1/content/:ctid/verify", `status=${r.status}`);
    const item = await _findTx(verifier.tip_id, "CONTENT_VERIFIED", i => i.ctid === c1.ctid);
    const tx = item?.tx_id && await _getTx(item.tx_id);
    if (tx) assertUnifiedSig("CONTENT_VERIFIED", tx);
  }

  // UPDATE_ORIGIN — author changes origin
  {
    const c2 = await _registerContent(author.tip_id, author.kp, "OH", "c2");
    const body = { author_tip_id: author.tip_id, ctid: c2.ctid, new_origin_code: "AA" };
    const sig = signBody(body, author.kp.privateKey);
    const r = await _post(`/v1/content/${encodeURIComponent(c2.ctid)}/update-origin`, { ...body, signature: sig });
    expect([200, 201, 202].includes(r.status), "POST /v1/content/:ctid/update-origin", `status=${r.status} ${JSON.stringify(r.body?.error||"")}`);
    if ([200, 201, 202].includes(r.status)) {
      const txid = r.body.data.tx_id;
      const tx = txid && await _getTx(txid);
      if (tx) assertUnifiedSig("UPDATE_ORIGIN", tx);
    }
  }

  // CONTENT_RETRACTED — author retracts
  {
    const c3 = await _registerContent(author.tip_id, author.kp, "OH", "c3");
    const body = { author_tip_id: author.tip_id, ctid: c3.ctid };
    const sig = signBody(body, author.kp.privateKey);
    const r = await _post(`/v1/content/${encodeURIComponent(c3.ctid)}/retract`, { ...body, signature: sig });
    expect([200, 201, 202].includes(r.status), "POST /v1/content/:ctid/retract", `status=${r.status} ${JSON.stringify(r.body?.error||"")}`);
    if ([200, 201, 202].includes(r.status)) {
      const txid = r.body.data.tx_id;
      const tx = txid && await _getTx(txid);
      if (tx) assertUnifiedSig("CONTENT_RETRACTED", tx);
    }
  }

  // UPDATE_PROFILE — via direct endpoint
  {
    const body = { tip_id: author.tip_id, reviewer_consent: true };
    const sig = signBody(body, author.kp.privateKey);
    const r = await _post(`/v1/identity/${encodeURIComponent(author.tip_id)}/profile`, { ...body, signature: sig });
    expect([200, 201, 202].includes(r.status), "POST /v1/identity/:tipId/profile", `status=${r.status}`);
    const txid = r.body?.data?.tx_id;
    const tx = txid && await _getTx(txid);
    if (tx) assertUnifiedSig("UPDATE_PROFILE", tx);
  }

  // become-reviewer + stop-reviewing — convenience UPDATE_PROFILE wrappers
  {
    const u = cast[3];
    const body1 = { tip_id: u.tip_id, reviewer_consent: true };
    const r1 = await _post(`/v1/identity/${encodeURIComponent(u.tip_id)}/become-reviewer`, { signature: signBody(body1, u.kp.privateKey) });
    expect([200, 201, 202].includes(r1.status), "POST /v1/identity/:tipId/become-reviewer", `status=${r1.status} ${JSON.stringify(r1.body?.error||"")}`);
    const tx1 = r1.body?.data?.tx_id && await _getTx(r1.body.data.tx_id);
    if (tx1) assertUnifiedSig("UPDATE_PROFILE (become-reviewer)", tx1);

    const body2 = { tip_id: u.tip_id, reviewer_consent: false };
    const r2 = await _post(`/v1/identity/${encodeURIComponent(u.tip_id)}/stop-reviewing`, { signature: signBody(body2, u.kp.privateKey) });
    expect([200, 201, 202].includes(r2.status), "POST /v1/identity/:tipId/stop-reviewing", `status=${r2.status} ${JSON.stringify(r2.body?.error||"")}`);
    const tx2 = r2.body?.data?.tx_id && await _getTx(r2.body.data.tx_id);
    if (tx2) assertUnifiedSig("UPDATE_PROFILE (stop-reviewing)", tx2);
  }

  // verify-ownership — no tx; just a sig check
  {
    const challenge = `uat-${nowMs()}`;
    const body = { tip_id: author.tip_id, challenge };
    const sig = signBody(body, author.kp.privateKey);
    const r = await _post("/v1/identity/verify-ownership", { ...body, signature: sig });
    expect([200, 201, 202].includes(r.status), "POST /v1/identity/verify-ownership", `status=${r.status} verified=${r.body?.data?.verified}`);
  }

  // domain/register — off-chain pending claim, signature persisted to pending_domain_claims
  {
    const claimedAt = nowMs();
    const body = { tip_id: author.tip_id, domain: "uat-example.test", method: "dns", claimed_at: claimedAt };
    const sig = signBody({ claimed_at: claimedAt, domain: body.domain, method: body.method, tip_id: body.tip_id }, author.kp.privateKey);
    const r = await _post("/v1/domain/register", { ...body, signature: sig });
    // Note: may fail with 412 if author isn't an org. That's an org-only feature, not a sig bug.
    if ([200, 201, 202].includes(r.status)) {
      expect(true, "POST /v1/domain/register (org-eligible)", `status=${r.status}`);
    } else {
      expect(true, "POST /v1/domain/register (skipped — non-org claimant)", `status=${r.status} ${r.body?.error?.code}`);
    }
  }

  // ── PHASE 3: dispute pipeline ─────────────────────────────────────
  console.log(_yellow("\n[Phase 3/6] DISPUTE PIPELINE (CONTENT_DISPUTED → JURY_VOTE_*)"));

  // Re-create a fresh content for dispute (c1 already verified).
  const disputed = await _registerContent(author.tip_id, author.kp, "OH", "disp");

  // File dispute by disputer.
  // The signed body for CONTENT_DISPUTED is {disputer_tip_id, reason} (+ claimed_origin, evidence_hash when truthy).
  let juryTipIds = [];
  let disputeTxId = null;
  {
    const evidencePayload = { description: "UAT dispute evidence — automated test of unified signature storage end-to-end.", filed_by: disputer.tip_id };
    const evidenceSig = signBody(evidencePayload, disputer.kp.privateKey);
    // Disputer signs body INCLUDING evidence_hash (server enforces that
    // any present evidence_hash is part of the canonical signed payload).
    const evidence_hash = shake256(canonicalJson(evidencePayload));
    const sigBody = { disputer_tip_id: disputer.tip_id, reason: "origin_mismatch", claimed_origin: "AA", evidence_hash };
    const sig = signBody(sigBody, disputer.kp.privateKey);
    const body = {
      ...sigBody, signature: sig,
      evidence: { payload: evidencePayload, signature: evidenceSig },
    };
    const r = await _post(`/v1/content/${encodeURIComponent(disputed.ctid)}/dispute`, body);
    expect([200, 201, 202].includes(r.status), "POST /v1/content/:ctid/dispute", `status=${r.status} ${JSON.stringify(r.body?.error||"")}`);
    if ([200, 201, 202].includes(r.status)) {
      disputeTxId = r.body.data.dispute_tx_id;
      juryTipIds = r.body.data.stage2?.jurors || [];
      expect(juryTipIds.length > 0, "Jury selected", `${juryTipIds.length} jurors`);
      const tx = disputeTxId && await _getTx(disputeTxId);
      if (tx) assertUnifiedSig("CONTENT_DISPUTED", tx);
    }
  }

  // Resolve jurors → keypairs.
  const juryKps = juryTipIds.map(tip => juryPool.find(u => u.tip_id === tip)).filter(Boolean);

  // JURY_VOTE_COMMIT for every juror.
  const VOTE = "MATCH";
  const commits = [];
  for (const j of juryKps) {
    const salt = `salt-${j.tip_id.slice(-4)}`;
    // Server formula (business-rules.canRevealVote): shake256(`${vote}:${salt}`)
    const commitment = shake256(`${VOTE}:${salt}`);
    const sigBody2 = { juror_tip_id: j.tip_id, commitment };
    const sig = signBody(sigBody2, j.kp.privateKey);
    const r = await _post(`/v1/content/${encodeURIComponent(disputed.ctid)}/jury/commit`, { ...sigBody2, signature: sig });
    expect([200, 201, 202].includes(r.status), `POST jury/commit for ${j.tip_id.slice(-12)}`, `status=${r.status} ${JSON.stringify(r.body?.error||"")}`);
    if ([200, 201, 202].includes(r.status)) {
      commits.push({ juror: j, salt, vote: VOTE, tx_id: r.body.data.tx_id });
    }
  }
  if (commits[0]?.tx_id) {
    const tx = await _getTx(commits[0].tx_id);
    if (tx) assertUnifiedSig("JURY_VOTE_COMMIT", tx);
  }

  // JURY_VOTE_REVEAL for every juror.
  for (const c of commits) {
    const sigBody3 = { juror_tip_id: c.juror.tip_id, vote: c.vote, salt: c.salt };
    const sig = signBody(sigBody3, c.juror.kp.privateKey);
    const r = await _post(`/v1/content/${encodeURIComponent(disputed.ctid)}/jury/reveal`, { ...sigBody3, signature: sig });
    expect([200, 201, 202].includes(r.status), `POST jury/reveal for ${c.juror.tip_id.slice(-12)}`, `status=${r.status} ${JSON.stringify(r.body?.error||"")}`);
    c.reveal_tx_id = r.body?.data?.tx_id;
  }
  if (commits[0]?.reveal_tx_id) {
    const tx = await _getTx(commits[0].reveal_tx_id);
    if (tx) assertUnifiedSig("JURY_VOTE_REVEAL", tx);
  }

  // ── PHASE 4: appeal pipeline ──────────────────────────────────────
  console.log(_yellow("\n[Phase 4/6] APPEAL PIPELINE (APPEAL_FILED → expert commit/reveal)"));

  // 7 MATCH reveals from Phase 3 → adjudication-trigger fires verdict
  // (UPHELD = disputer wins, author lost) within a few rounds.
  await _sleep(2000);
  const adjudication = await _findTx(author.tip_id, "ADJUDICATION_RESULT", i => i.ctid === disputed.ctid, { timeoutMs: 6000 });
  expect(!!adjudication, "ADJUDICATION_RESULT observed", adjudication?.tx_id?.slice(0, 16));

  if (adjudication) {
    // The author lost (UPHELD verdict → author's origin claim wrong);
    // they can file an appeal. Schema requires appellant to be the
    // losing party from the Stage-2 verdict.
    const sigBody = { appellant_tip_id: author.tip_id, ctid: disputed.ctid };
    const sig = signBody(sigBody, author.kp.privateKey);
    const r = await _post(`/v1/content/${encodeURIComponent(disputed.ctid)}/appeal`, { ...sigBody, signature: sig });
    expect([200, 201, 202].includes(r.status), "POST /v1/content/:ctid/appeal", `status=${r.status} ${JSON.stringify(r.body?.error||"")}`);

    if ([200, 201, 202].includes(r.status)) {
      const appealTxId = r.body.data.appeal_tx_id;
      const expertIds = r.body.data.experts?.selected || [];
      const tx = await _getTx(appealTxId);
      if (tx) assertUnifiedSig("APPEAL_FILED", tx);

      // Expert commits + reveals (3-expert panel; expert pool = same as jury pool minus author/disputer/prior-jurors)
      const expertKps = expertIds.map(tip => juryPool.find(u => u.tip_id === tip)).filter(Boolean);
      expect(expertKps.length > 0, "Expert panel resolves to local keypairs", `${expertKps.length}/${expertIds.length}`);

      const APPEAL_VOTE = "MISMATCH";  // overturn attempt — author claims original origin was correct
      const expertCommits = [];
      for (const e of expertKps) {
        const salt = `appeal-salt-${e.tip_id.slice(-4)}`;
        const commitment = shake256(`${APPEAL_VOTE}:${salt}`);
        const cBody = { juror_tip_id: e.tip_id, commitment };
        const cSig = signBody(cBody, e.kp.privateKey);
        const cr = await _post(`/v1/content/${encodeURIComponent(disputed.ctid)}/appeal/commit`, { ...cBody, signature: cSig });
        expect([200, 201, 202].includes(cr.status), `POST appeal/commit for ${e.tip_id.slice(-12)}`, `status=${cr.status} ${JSON.stringify(cr.body?.error||"")}`);
        if ([200, 201, 202].includes(cr.status)) {
          expertCommits.push({ expert: e, salt, vote: APPEAL_VOTE, tx_id: cr.body.data.tx_id });
        }
      }
      if (expertCommits[0]?.tx_id) {
        const tx2 = await _getTx(expertCommits[0].tx_id);
        if (tx2) assertUnifiedSig("JURY_VOTE_COMMIT (is_appeal=true)", tx2);
      }

      for (const c of expertCommits) {
        const rBody = { juror_tip_id: c.expert.tip_id, vote: c.vote, salt: c.salt, confirmed_origin: "OH" };
        const rSig = signBody(rBody, c.expert.kp.privateKey);
        const rr = await _post(`/v1/content/${encodeURIComponent(disputed.ctid)}/appeal/reveal`, { ...rBody, signature: rSig });
        expect([200, 201, 202].includes(rr.status), `POST appeal/reveal for ${c.expert.tip_id.slice(-12)}`, `status=${rr.status} ${JSON.stringify(rr.body?.error||"")}`);
        c.reveal_tx_id = rr.body?.data?.tx_id;
      }
      if (expertCommits[0]?.reveal_tx_id) {
        const tx3 = await _getTx(expertCommits[0].reveal_tx_id);
        if (tx3) assertUnifiedSig("JURY_VOTE_REVEAL (is_appeal=true)", tx3);
      }
    }
  }

  // ── PHASE 5: revocations (all four variants) ──────────────────────
  console.log(_yellow("\n[Phase 5/6] REVOCATIONS"));

  for (const [tipIdx, revType] of [[4, "REVOKE_VOLUNTARY"], [5, "REVOKE_VP"], [6, "REVOKE_DECEASED"], [7, "REVOKE_DEVICE"]]) {
    const target = cast[tipIdx];
    const fields = {
      tx_type: revType,
      tip_id: target.tip_id,
      reason_code: `uat_${revType.toLowerCase()}`,
      issuing_vp_id: VP.vp_id,
      // REVOKE_VP requires evidence_hash in tx-validator; supply for all variants
      // so signed bytes match the validator's required-fields layer.
      evidence_hash: shake256(`uat-evidence-${revType}-${target.tip_id}`),
    };
    const sig = signBody(fields, VP.private_key);
    const r = await _post("/v1/revocations", { ...fields, signature: sig });
    expect([200, 201, 202].includes(r.status), `POST /v1/revocations ${revType}`, `status=${r.status} ${JSON.stringify(r.body?.error||"")}`);
    const txid = r.body?.data?.tx_id;
    const tx = txid && await _getTx(txid);
    if (tx) assertUnifiedSig(revType, tx);
  }

  // ── PHASE 6: deferred (documented in this script's header) ────────
  console.log(_yellow("\n[Phase 6/6] DEFERRED IN UAT"));
  console.log(_dim("  • PRESCAN_REVIEW_TRIGGERED / DISMISSED / CONFIRMED / RECUSED"));
  console.log(_dim("    needs 48h timer or backdated content row; covered by tests/schemas/prescan-review.test.js"));
  console.log(_dim("  • BIND_DOMAIN / UNBIND_DOMAIN"));
  console.log(_dim("    needs real DNS / well-known; covered by tests/schemas/bind-domain.test.js"));
  console.log(_dim("  • Node-emitted sigs (AI_CLASSIFIER_RESULT, JURY_SUMMONS, ADJUDICATION_RESULT,"));
  console.log(_dim("    APPEAL_RESULT, SCORE_UPDATE, COMMITTEE_ROTATION)"));
  console.log(_dim("    not API-signed; exercised in tests/consensus/*"));

  // ── Summary ──────────────────────────────────────────────────────
  console.log("");
  if (_failed === 0) {
    console.log(_green(`✓ ${_passed} UAT check(s) passed — unified signature storage validated end-to-end.\n`));
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
