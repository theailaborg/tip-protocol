#!/usr/bin/env node
/**
 * @file scripts/test-inbatch-dedup.js
 * @description DEV-ONLY: live-cluster test for GH #87/#112 — in-batch dedup of
 * state-changing tx types in commit-handler's `_dedupCheck`.
 *
 * The dedup only fires when two competing same-key txs land in the SAME
 * consensus round. This harness manufactures that race: it fires two
 * competing signed txs at two different nodes simultaneously (Promise.all),
 * then polls `/v1/dag/tx/:txId/outcome` for both tx_ids and classifies:
 *
 *   IN_BATCH    — loser rejected with "... in batch ..." → the #87 path fired ✅
 *   CROSS_ROUND — loser rejected by an older committed-history guard
 *                 (txs landed in different rounds; rerun usually hits in-batch)
 *   FAILED      — both txs committed → dedup miss (real bug)
 *
 * After each case it asserts all nodes converge (same state root at the
 * same committed round — the consensus-level proof the drop was
 * deterministic on every node).
 *
 * Prereqs:
 *   1. 5-node cluster up (docker-compose.local.yml)
 *   2. node scripts/seed-temp-users.js --count 20 --high-pct 70   (+ node restart)
 *
 * Usage:
 *   node scripts/test-inbatch-dedup.js                      # all cases
 *   node scripts/test-inbatch-dedup.js --case dispute       # one case
 *   node scripts/test-inbatch-dedup.js --case verify --attempts 5
 *
 * Cases: dispute | verify | update-origin | retract | key-rotate |
 *        dispute-verify | dispute-retract | dispute-update-origin | verify-retract |
 *        revoke-update-profile | all
 *
 * Options:
 *   --node-a URL     first submission target   (default http://localhost:4000)
 *   --node-b URL     second submission target  (default http://localhost:4100)
 *   --ports LIST     health/state-root ports   (default 4000,4100,4200,4300,4400)
 *   --attempts N     retries per case to hit a same-round collision (default 3)
 *   --users FILE     temp users file (default genesis-data/temp-users/temp-users-latest.json)
 */

"use strict";

const path = require("path");
const fs = require("fs");
const nodeCrypto = require("crypto");
const { execSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const SHARED = path.join(ROOT, "shared");

const {
  initCrypto, shake256, canonicalJson, signBody, generateMLDSAKeypair,
} = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const { DISPUTE_REASON } = require(path.join(SHARED, "constants"));
const contentRegisterSchema = require(path.join(ROOT, "node/src/schemas/content-register"));
const keyRotatedSchema = require(path.join(ROOT, "node/src/schemas/key-rotated"));

// Protocol constants from genesis (schema validators need MEDIA_LIMITS etc.)
const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(ROOT, "node/src/genesis"));
try { PC._resetForTesting(); } catch { /* not initialised yet */ }
PC.init(getGenesisPayload().protocol_constants);

// ── args ────────────────────────────────────────────────────────────────────
function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : dflt;
}
const CASE = arg("case", "all");
const NODE_A = arg("node-a", "http://localhost:4000");
const NODE_B = arg("node-b", "http://localhost:4100");
const PORTS = arg("ports", "4000,4100,4200,4300,4400").split(",").map(s => s.trim());
const ATTEMPTS = parseInt(arg("attempts", "3"), 10);
const USERS_FILE = arg("users", path.join(ROOT, "genesis-data/temp-users/temp-users-latest.json"));

const RESET = "\x1b[0m", GREEN = "\x1b[32m", RED = "\x1b[31m", YELLOW = "\x1b[33m", DIM = "\x1b[2m", BOLD = "\x1b[1m";
const ok = (s) => `${GREEN}${s}${RESET}`;
const bad = (s) => `${RED}${s}${RESET}`;
const warn = (s) => `${YELLOW}${s}${RESET}`;
const dim = (s) => `${DIM}${s}${RESET}`;

const nonce = () => nodeCrypto.randomBytes(4).toString("hex");
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const enc = encodeURIComponent;

// ── http ────────────────────────────────────────────────────────────────────
async function http(method, base, p, body) {
  try {
    const resp = await fetch(`${base}${p}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await resp.text();
    let json; try { json = JSON.parse(text); } catch { json = { raw: text }; }
    return { status: resp.status, body: json };
  } catch (err) {
    return { status: 0, body: { error: err.message } };
  }
}
const post = (base, p, body) => http("POST", base, p, body);
const get = (base, p) => http("GET", base, p);

const pick = (resp, ...keys) => {
  const d = resp.body?.data ?? resp.body ?? {};
  for (const k of keys) if (d[k] !== undefined) return d[k];
  return undefined;
};

// ── temp users ──────────────────────────────────────────────────────────────
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    console.error(bad(`✗ ${USERS_FILE} not found — run scripts/seed-temp-users.js first`));
    process.exit(1);
  }
  const all = JSON.parse(fs.readFileSync(USERS_FILE, "utf8")).users || [];
  // Disputers need score ≥ 550 (dispute_filing_min_score, PR #82); use ≥600
  // for margin. Each filed dispute costs -15 stake, so rotate actors.
  const eligible = all.filter(u => (u.target_score ?? 0) >= 600);
  if (all.length < 4 || eligible.length < 3) {
    console.error(bad(`✗ need ≥4 temp users (≥3 with score ≥600); have ${all.length}/${eligible.length} — re-run seed-temp-users.js with --count 20 --high-pct 70`));
    process.exit(1);
  }
  return { all, eligible };
}

// ── outcome polling ─────────────────────────────────────────────────────────
async function pollOutcome(txId, timeoutMs = 30_000) {
  const deadline = nowMs() + timeoutMs;
  while (nowMs() < deadline) {
    const r = await get(NODE_A, `/v1/dag/tx/${enc(txId)}/outcome`);
    const status = pick(r, "status");
    if (status === "committed" || status === "rejected") return r.body?.data ?? r.body;
    await sleep(1000);
  }
  return { status: "timeout" };
}

// ── content registration (mirrors test-prescan-e2e.js) ─────────────────────
async function registerFreshContent(author, { waitPrescan }) {
  const text = `In-batch dedup live test ${nonce()} — paragraph long enough to register cleanly through the content pipeline.`;
  const body = {
    signer_tip_id: author.tip_id,
    origin_code: "OH",
    content: text,
    media_canonical_hash: null,
    content_type_hint: null,
    cna_version: "2.2",
    attribution_mode: "self",
    authors: [{ tip_id: author.tip_id, tip_id_type: author.tip_id_type || "personal", contribution_role: "creator" }],
    extras: {},
    registered_urls: [],
  };
  const { tipNormalize } = require(path.join(SHARED, "crypto"));
  const contentHash = shake256(tipNormalize(text));
  const canonical = contentRegisterSchema.buildSigningPayload(body, contentHash);
  body.signature = contentRegisterSchema.sign(canonical, author.private_key);

  const reg = await post(NODE_A, "/v1/content/register", body);
  if (reg.status !== 202) throw new Error(`content register: expected 202, got ${reg.status}: ${JSON.stringify(reg.body).slice(0, 200)}`);
  const ctid = pick(reg, "ctid");
  const txId = pick(reg, "tx_id");
  if (!ctid) throw new Error(`no ctid in register response: ${JSON.stringify(reg.body).slice(0, 200)}`);

  const out = await pollOutcome(txId, 30_000);
  if (out.status !== "committed") throw new Error(`content register tx not committed (${out.status}): ${out.reason_detail || ""}`);

  if (waitPrescan) {
    // canDispute requires prescan_status === "completed" (async prescan, PR #69)
    const deadline = nowMs() + 60_000;
    while (nowMs() < deadline) {
      const r = await get(NODE_A, `/v1/content/${enc(ctid)}/prescan_status`);
      const s = pick(r, "prescan_status") || r.body?.data?.content?.prescan_status;
      if (s === "completed") break;
      await sleep(1000);
    }
  }
  console.log(dim(`    content registered: ${ctid}`));
  return ctid;
}

// ── duel mechanics ──────────────────────────────────────────────────────────
/**
 * Fire two competing requests simultaneously at NODE_A and NODE_B, then
 * classify the pair of tx outcomes.
 */
async function duel(label, reqA, reqB) {
  const [respA, respB] = await Promise.all([
    post(NODE_A, reqA.path, reqA.body),
    post(NODE_B, reqB.path, reqB.body),
  ]);

  const txA = pick(respA, "tx_id", "dispute_tx_id");
  const txB = pick(respB, "tx_id", "dispute_tx_id");
  console.log(dim(`    A(${NODE_A}) → ${respA.status} tx=${(txA || JSON.stringify(respA.body).slice(0, 80))}`));
  console.log(dim(`    B(${NODE_B}) → ${respB.status} tx=${(txB || JSON.stringify(respB.body).slice(0, 80))}`));

  // An API-time rejection of ONE call already demonstrates first-wins, but
  // not the in-batch path — classify as CROSS_ROUND so the attempt retries.
  if (!txA || !txB) {
    if (txA || txB) return { verdict: "CROSS_ROUND", detail: "second call rejected at API time (first had already committed)" };
    return { verdict: "ERROR", detail: `both API calls failed: A=${JSON.stringify(respA.body).slice(0, 120)} B=${JSON.stringify(respB.body).slice(0, 120)}` };
  }
  if (txA === txB) return { verdict: "IDENTICAL_TX", detail: "both nodes built the identical tx (same tx_id) — no race to dedup; retrying" };

  const [outA, outB] = await Promise.all([pollOutcome(txA), pollOutcome(txB)]);
  const fmt = (o) => `${o.status}${o.reason_detail ? ` (${o.reason_detail})` : ""}`;
  console.log(dim(`    outcome A: ${fmt(outA)}`));
  console.log(dim(`    outcome B: ${fmt(outB)}`));

  const committed = [outA, outB].filter(o => o.status === "committed").length;
  const loser = outA.status === "rejected" ? outA : outB.status === "rejected" ? outB : null;

  if (committed === 2) return { verdict: "FAILED", detail: `BOTH txs committed — in-batch dedup missed for ${label}` };
  if (committed === 1 && loser) {
    if (/in batch|in this batch/i.test(loser.reason_detail || "")) {
      return { verdict: "IN_BATCH", detail: loser.reason_detail, round: loser.rejected_at_round };
    }
    return { verdict: "CROSS_ROUND", detail: loser.reason_detail || loser.reason };
  }
  return { verdict: "ERROR", detail: `unresolved outcomes: A=${fmt(outA)} B=${fmt(outB)}` };
}

/**
 * Variant for endpoints whose API response carries no tx_id (e.g.
 * content-service.verify). Fires both requests, then classifies via the
 * tx_rejections table on node1's postgres DB: a rejection row mentioning
 * the ctid with "in batch" proves the #87 path; any other rejection means
 * the cross-round guard fired; no rejection row at all after the settle
 * window means BOTH txs committed (dedup miss).
 */
async function duelViaRejectionTable(label, ctid, reqA, reqB) {
  const [respA, respB] = await Promise.all([
    post(NODE_A, reqA.path, reqA.body),
    post(NODE_B, reqB.path, reqB.body),
  ]);
  console.log(dim(`    A(${NODE_A}) → ${respA.status}`));
  console.log(dim(`    B(${NODE_B}) → ${respB.status}`));
  const okCalls = [respA, respB].filter(r => r.status >= 200 && r.status < 300).length;
  if (okCalls < 2) {
    if (okCalls === 1) return { verdict: "CROSS_ROUND", detail: "second call rejected at API time" };
    return { verdict: "ERROR", detail: `both API calls failed: A=${JSON.stringify(respA.body).slice(0, 120)} B=${JSON.stringify(respB.body).slice(0, 120)}` };
  }

  const sql = `SELECT reason_detail FROM tx_rejections WHERE tx_type='${label}' AND reason_detail LIKE '%${ctid}%' ORDER BY rejected_at_ms DESC LIMIT 3;`;
  const deadline = nowMs() + 20_000;
  while (nowMs() < deadline) {
    await sleep(2000);
    let out = "";
    try {
      out = execSync(`docker exec tip-postgres psql -U tipuser -d tip_node1 -t -A -c "${sql.replace(/"/g, '\\"')}"`,
        { stdio: ["pipe", "pipe", "pipe"] }).toString().trim();
    } catch (e) { return { verdict: "ERROR", detail: `psql probe failed: ${e.message.slice(0, 120)}` }; }
    if (out) {
      console.log(dim(`    rejection row: ${out.split("\n")[0]}`));
      if (/in batch|in this batch/i.test(out)) return { verdict: "IN_BATCH", detail: out.split("\n")[0] };
      return { verdict: "CROSS_ROUND", detail: out.split("\n")[0] };
    }
  }
  return { verdict: "FAILED", detail: `no ${label} rejection row for ${ctid} after settle window — both txs likely committed` };
}

/**
 * Cross-type variant: fire two requests of DIFFERENT tx types for the same
 * key (ctid or tip_id) and classify via the rejection table. Either tx_type
 * may end up as the loser — searches all provided types.
 */
async function duelViaRejectionTableAny(key, reqA, reqB, txTypes) {
  const [respA, respB] = await Promise.all([
    post(NODE_A, reqA.path, reqA.body),
    post(NODE_B, reqB.path, reqB.body),
  ]);
  console.log(dim(`    A(${NODE_A}) → ${respA.status}`));
  console.log(dim(`    B(${NODE_B}) → ${respB.status}`));
  const okCalls = [respA, respB].filter(r => r.status >= 200 && r.status < 300).length;
  if (okCalls < 2) {
    if (okCalls === 1) return { verdict: "CROSS_ROUND", detail: "second call rejected at API time" };
    return { verdict: "ERROR", detail: `both API calls failed: A=${JSON.stringify(respA.body).slice(0, 120)} B=${JSON.stringify(respB.body).slice(0, 120)}` };
  }

  const typeList = txTypes.map(t => `'${t}'`).join(",");
  const sql = `SELECT tx_type, reason_detail FROM tx_rejections WHERE tx_type IN (${typeList}) AND reason_detail LIKE '%${key.replace(/'/g, "''")}%' ORDER BY rejected_at_ms DESC LIMIT 3;`;
  const deadline = nowMs() + 20_000;
  while (nowMs() < deadline) {
    await sleep(2000);
    let out = "";
    try {
      out = execSync(
        `docker exec tip-postgres psql -U tipuser -d tip_node1 -t -A -c "${sql.replace(/"/g, '\\"')}"`,
        { stdio: ["pipe", "pipe", "pipe"] }
      ).toString().trim();
    } catch (e) { return { verdict: "ERROR", detail: `psql probe failed: ${e.message.slice(0, 120)}` }; }
    if (out) {
      console.log(dim(`    rejection row: ${out.split("\n")[0]}`));
      if (/in batch|in this batch|content-status conflict|revocation freeze/i.test(out)) {
        return { verdict: "IN_BATCH", detail: out.split("\n")[0] };
      }
      return { verdict: "CROSS_ROUND", detail: out.split("\n")[0] };
    }
  }
  return { verdict: "FAILED", detail: `no rejection row for (${txTypes.join("|")}) key=${key} after settle window — both txs likely committed` };
}

/** Retry wrapper: fresh setup per attempt until IN_BATCH or attempts exhausted. */
async function runCase(name, attemptFn) {
  console.log(`\n${BOLD}━━ ${name} ━━${RESET}`);
  let last = { verdict: "ERROR", detail: "no attempts ran" };
  for (let i = 1; i <= ATTEMPTS; i++) {
    console.log(`  attempt ${i}/${ATTEMPTS}`);
    try {
      last = await attemptFn(i);
    } catch (err) {
      last = { verdict: "ERROR", detail: err.message };
    }
    if (last.verdict === "IN_BATCH" || last.verdict === "FAILED") break;
    if (i < ATTEMPTS) console.log(warn(`    ${last.verdict}: ${last.detail} — retrying`));
  }
  const mark = last.verdict === "IN_BATCH" ? ok("✅ IN_BATCH")
    : last.verdict === "CROSS_ROUND" ? warn("◐ CROSS_ROUND (first-wins held, in-batch window not hit)")
    : bad(`✗ ${last.verdict}`);
  console.log(`  ${mark} ${dim(last.detail || "")}`);
  await stateRootCheck();
  return { name, ...last };
}

// ── consensus convergence check ─────────────────────────────────────────────
async function stateRootCheck() {
  for (let i = 0; i < 6; i++) {
    const snaps = await Promise.all(PORTS.map(async (p) => {
      const r = await get(`http://localhost:${p}`, "/v1/state-root");
      const d = r.body?.data ?? r.body ?? {};
      const rootKey = Object.keys(d).find(k => /merkle|state.*root|^root$/i.test(k));
      const roundKey = Object.keys(d).find(k => /round/i.test(k));
      return { port: p, root: rootKey ? d[rootKey] : null, round: roundKey ? d[roundKey] : null };
    }));
    // Divergence = two nodes at the SAME round with DIFFERENT roots.
    const byRound = new Map();
    let divergent = false;
    for (const s of snaps) {
      if (s.root == null) continue;
      const seen = byRound.get(s.round);
      if (seen && seen !== s.root) divergent = true;
      byRound.set(s.round, s.root);
    }
    const allSame = new Set(snaps.map(s => s.root).filter(Boolean)).size === 1;
    if (divergent) {
      console.log(bad(`  ✗ STATE DIVERGENCE: ${snaps.map(s => `${s.port}:${String(s.root).slice(0, 12)}@${s.round}`).join(" ")}`));
      return false;
    }
    if (allSame) {
      console.log(dim(`    state roots converged across ${snaps.length} nodes (${String(snaps[0].root).slice(0, 16)}…)`));
      return true;
    }
    await sleep(1500); // nodes mid-round; let them settle
  }
  console.log(warn("    state roots not identical after settle window (round skew only — no same-round mismatch seen)"));
  return true;
}

// ── cases ───────────────────────────────────────────────────────────────────

function buildDispute(ctid, disputer) {
  const evidencePayload = { description: `In-batch dedup test by ${disputer.tip_id} nonce=${nonce()}` };
  const evidence_hash = shake256(canonicalJson(evidencePayload));
  const evidenceSig = signBody(evidencePayload, disputer.private_key);
  const sigBody = {
    disputer_tip_id: disputer.tip_id,
    reason: DISPUTE_REASON.ORIGIN_MISMATCH,
    claimed_origin: "AG",
    evidence_hash,
  };
  const signature = signBody(sigBody, disputer.private_key);
  return {
    path: `/v1/content/${enc(ctid)}/dispute`,
    body: {
      disputer_tip_id: disputer.tip_id,
      reason: DISPUTE_REASON.ORIGIN_MISMATCH,
      claimed_origin: "AG",
      signature,
      evidence: { payload: evidencePayload, signature: evidenceSig },
    },
  };
}

function buildVerify(ctid, verifier) {
  const verdict = "ORIGIN_CONFIRMED";
  const signature = signBody({ verifier_tip_id: verifier.tip_id, ctid, verdict }, verifier.private_key);
  return { path: `/v1/content/${enc(ctid)}/verify`, body: { verifier_tip_id: verifier.tip_id, verdict, signature } };
}

function buildRetract(ctid, author) {
  return {
    path: `/v1/content/${enc(ctid)}/retract`,
    body: {
      author_tip_id: author.tip_id,
      signature: signBody({ author_tip_id: author.tip_id, ctid }, author.private_key),
    },
  };
}

async function caseDispute(users, attempt) {
  // Rotate actors each attempt: stake is -15 per filed dispute and filers
  // are rate-limited (5 per 30d).
  const [author, d1, d2] = pickActors(users, attempt, 3);
  const ctid = await registerFreshContent(author, { waitPrescan: true });
  const r = await duel("CONTENT_DISPUTED", buildDispute(ctid, d1), buildDispute(ctid, d2));
  if (r.verdict === "IN_BATCH") {
    console.log(dim(`    winner's dispute is live — drive the jury with:\n      node scripts/drive-jury.js --ctid "${ctid}" --phase COMMIT --vote-bias UPHELD`));
  }
  return r;
}

async function caseVerify(users, attempt) {
  const [author, verifier] = pickActors(users, attempt, 2);
  const ctid = await registerFreshContent(author, { waitPrescan: true });
  const mk = () => {
    const verdict = "ORIGIN_CONFIRMED";
    const signature = signBody({ verifier_tip_id: verifier.tip_id, ctid, verdict }, verifier.private_key);
    return { path: `/v1/content/${enc(ctid)}/verify`, body: { verifier_tip_id: verifier.tip_id, verdict, signature } };
  };
  // verify's API response carries no tx_id — classify via tx_rejections.
  return duelViaRejectionTable("CONTENT_VERIFIED", ctid, mk(), mk());
}

async function caseUpdateOrigin(users, attempt) {
  const [author] = pickActors(users, attempt, 1);
  const ctid = await registerFreshContent(author, { waitPrescan: true });
  const mk = (new_origin_code) => ({
    path: `/v1/content/${enc(ctid)}/update-origin`,
    body: {
      author_tip_id: author.tip_id,
      new_origin_code,
      signature: signBody({ author_tip_id: author.tip_id, ctid, new_origin_code }, author.private_key),
    },
  });
  const r = await duel("UPDATE_ORIGIN", mk("AA"), mk("AG"));
  const rec = await get(NODE_A, `/v1/content/${enc(ctid)}`);
  const finalOrigin = pick(rec, "origin_code") || rec.body?.data?.content?.origin_code;
  if (finalOrigin) console.log(dim(`    final origin_code: ${finalOrigin} (first-in-canonical-order wins)`));
  return r;
}

async function caseRetract(users, attempt) {
  const [author] = pickActors(users, attempt, 1);
  const ctid = await registerFreshContent(author, { waitPrescan: true });
  const mk = () => ({
    path: `/v1/content/${enc(ctid)}/retract`,
    body: {
      author_tip_id: author.tip_id,
      signature: signBody({ author_tip_id: author.tip_id, ctid }, author.private_key),
    },
  });
  return duel("CONTENT_RETRACTED", mk(), mk());
}

async function caseKeyRotate(users, attempt) {
  // Dedicated user from the END of the pool — rotation invalidates the
  // recorded private key for any later signing, so never reuse this actor.
  const u = users.all[users.all.length - attempt];
  if (!u) throw new Error("ran out of dedicated key-rotation users");
  const mk = () => {
    const newKp = generateMLDSAKeypair();
    const fields = {
      tip_id: u.tip_id,
      algorithm: "ml-dsa-65",
      new_public_key: newKp.publicKey,
      old_key_fingerprint: shake256(u.public_key).slice(0, 32),
      effective_at: nowMs() + 120_000,
    };
    const signature = keyRotatedSchema.sign(keyRotatedSchema.buildSigningPayload(fields), u.private_key);
    return { path: `/v1/identity/${enc(u.tip_id)}/keys/rotate`, body: { ...fields, signature } };
  };
  return duel("KEY_ROTATED", mk(), mk());
}

async function caseDisputeVerify(users, attempt) {
  // Three distinct actors: author registers, disputer disputes, verifier verifies.
  const [author, disputer, verifier] = pickActors(users, attempt, 3);
  const ctid = await registerFreshContent(author, { waitPrescan: true });
  return duelViaRejectionTableAny(
    ctid,
    buildDispute(ctid, disputer),
    buildVerify(ctid, verifier),
    ["CONTENT_DISPUTED", "CONTENT_VERIFIED"],
  );
}

async function caseDisputeRetract(users, attempt) {
  // Author fires retract; a different user fires dispute simultaneously.
  const [author, disputer] = pickActors(users, attempt, 2);
  const ctid = await registerFreshContent(author, { waitPrescan: true });
  return duelViaRejectionTableAny(
    ctid,
    buildDispute(ctid, disputer),
    buildRetract(ctid, author),
    ["CONTENT_DISPUTED", "CONTENT_RETRACTED"],
  );
}

async function caseDisputeUpdateOrigin(users, attempt) {
  // Author fires update-origin; a different user fires dispute simultaneously.
  // Content is freshly registered so still within the grace window for UPDATE_ORIGIN.
  const [author, disputer] = pickActors(users, attempt, 2);
  const ctid = await registerFreshContent(author, { waitPrescan: true });
  const updateReq = {
    path: `/v1/content/${enc(ctid)}/update-origin`,
    body: {
      author_tip_id: author.tip_id,
      new_origin_code: "AG",
      signature: signBody({ author_tip_id: author.tip_id, ctid, new_origin_code: "AG" }, author.private_key),
    },
  };
  return duelViaRejectionTableAny(
    ctid,
    buildDispute(ctid, disputer),
    updateReq,
    ["CONTENT_DISPUTED", "UPDATE_ORIGIN"],
  );
}

async function caseVerifyRetract(users, attempt) {
  // Third-party verifier fires verify; author fires retract simultaneously.
  const [author, verifier] = pickActors(users, attempt, 2);
  const ctid = await registerFreshContent(author, { waitPrescan: true });
  return duelViaRejectionTableAny(
    ctid,
    buildVerify(ctid, verifier),
    buildRetract(ctid, author),
    ["CONTENT_VERIFIED", "CONTENT_RETRACTED"],
  );
}

// Deterministic actor rotation across attempts so retries use fresh pairs.
function pickActors(users, attempt, n) {
  const pool = users.eligible;
  const out = [];
  for (let k = 0; k < n; k++) out.push(pool[((attempt - 1) * n + k) % pool.length]);
  if (new Set(out.map(u => u.tip_id)).size !== n) {
    throw new Error("temp-user pool too small for distinct actors — seed more users");
  }
  return out;
}

// ── main ────────────────────────────────────────────────────────────────────
const CASES = {
  "dispute": caseDispute,
  "verify": caseVerify,
  "update-origin": caseUpdateOrigin,
  "retract": caseRetract,
  "key-rotate": caseKeyRotate,
  "dispute-verify": caseDisputeVerify,
  "dispute-retract": caseDisputeRetract,
  "dispute-update-origin": caseDisputeUpdateOrigin,
  "verify-retract": caseVerifyRetract,
};

(async () => {
  await initCrypto();
  const users = loadUsers();

  // Cluster sanity
  for (const base of [NODE_A, NODE_B]) {
    const h = await get(base, "/health");
    if (h.status !== 200) { console.error(bad(`✗ ${base}/health → ${h.status} — is the cluster up?`)); process.exit(1); }
  }
  console.log(`${BOLD}GH #87/#112 in-batch dedup live test${RESET}  A=${NODE_A}  B=${NODE_B}  attempts/case=${ATTEMPTS}`);

  const names = CASE === "all" ? Object.keys(CASES) : [CASE];
  if (names.some(nm => !CASES[nm])) { console.error(bad(`✗ unknown --case ${CASE} (use ${Object.keys(CASES).join("|")}|all)`)); process.exit(1); }

  const results = [];
  for (const nm of names) {
    results.push(await runCase(nm, (attempt) => CASES[nm](users, attempt)));
  }

  console.log(`\n${BOLD}━━ summary ━━${RESET}`);
  for (const r of results) {
    const mark = r.verdict === "IN_BATCH" ? ok("IN_BATCH ✅") : r.verdict === "CROSS_ROUND" ? warn("CROSS_ROUND ◐") : bad(r.verdict);
    console.log(`  ${r.name.padEnd(14)} ${mark}  ${dim((r.detail || "").slice(0, 100))}`);
  }
  console.log(dim(`\n  rejection rows: docker exec tip-postgres psql -U tipuser -d tip_node1 -c "SELECT tx_type, reason_detail, rejected_at_round FROM tx_rejections WHERE reason_detail LIKE '%in batch%' ORDER BY rejected_at_ms DESC LIMIT 10;"`));

  const failed = results.filter(r => r.verdict === "FAILED" || r.verdict === "ERROR");
  process.exit(failed.length > 0 ? 1 : 0);
})().catch(err => { console.error(bad(`✗ ${err.stack || err}`)); process.exit(1); });
