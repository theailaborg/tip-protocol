#!/usr/bin/env node
/**
 * @file scripts/drive-jury.js
 * @description DEV-ONLY: Drive a live dispute through commit → reveal → verdict
 * on behalf of seeded temp jurors.
 *
 * For each juror summoned in a dispute:
 *   - Loads their keypair from genesis-data/temp-users/keys/
 *   - Picks a vote per --vote-bias (default UPHELD-leaning so verdict is decisive)
 *   - Generates a 32-byte salt, computes shake256("vote:salt") commitment
 *   - Phase auto-detects from dispute-case:
 *       * commit window open  → POST jury/commit (caches secrets)
 *       * reveal window open  → POST jury/reveal (replays cached secrets)
 *   - Skips jurors who already committed/revealed (idempotent re-runs OK)
 *
 * Vote/salt secrets are cached to:
 *   genesis-data/temp-users/jury-secrets-<ctid-slug>.json
 *
 * The reveal phase REQUIRES the same cache file the commit phase wrote — if
 * lost, those jurors can never reveal (matches protocol semantics).
 *
 * Usage:
 *   node scripts/drive-jury.js --ctid tip://c/AA-3356172f3297aa-4c0b
 *   node scripts/drive-jury.js --ctid <CTID> --vote-bias MISMATCH
 *   node scripts/drive-jury.js --ctid <CTID> --watch           # poll until verdict
 *   node scripts/drive-jury.js --ctid <CTID> --dry-run         # no network calls
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const { nowMs, nowIso, toIso } = require("../shared/time");

const fs = require("fs");
const path = require("path");
const http = require("http");
const crypto = require("crypto");

const { initCrypto, signBody, shake256 } = require("../shared/crypto");
const { VOTE, JURY_VOTES, ORIGIN_LABELS } = require("../shared/constants");
const ORIGIN_CODES = Object.keys(ORIGIN_LABELS);

const REPO_ROOT = path.resolve(__dirname, "..");
const TEMP_USERS_KEYS_DIR = path.join(REPO_ROOT, "genesis-data", "temp-users", "keys");
const SECRETS_DIR = path.join(REPO_ROOT, "genesis-data", "temp-users");

// ─── CLI ────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = {
    ctid: null,
    nodeUrl: "http://localhost:4000",
    voteBias: "UPHELD",       // UPHELD → mostly MISMATCH, DISMISSED → mostly MATCH, RANDOM → uniform
    confirmedOrigin: null,    // for MISMATCH votes; defaults to the dispute's claimed_origin
    forcePhase: null,         // override auto-detected phase (COMMIT|REVEAL) — needed when validator bypass is on
    appeal: false,            // drive Stage-3 appeal experts via /appeal/{commit,reveal} instead of /jury/...
    watch: false,
    watchTimeoutSec: 30,
    dryRun: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--ctid") args.ctid = argv[++i];
    else if (a === "--node-url") args.nodeUrl = argv[++i];
    else if (a === "--vote-bias") args.voteBias = argv[++i].toUpperCase();
    else if (a === "--confirmed-origin") args.confirmedOrigin = argv[++i];
    else if (a === "--phase") args.forcePhase = argv[++i].toUpperCase();
    else if (a === "--appeal") args.appeal = true;
    else if (a === "--watch") args.watch = true;
    else if (a === "--watch-timeout") args.watchTimeoutSec = Number(argv[++i]);
    else if (a === "--dry-run") args.dryRun = true;
    else if (a === "--help" || a === "-h") {
      console.log("usage: drive-jury.js --ctid <CTID> [opts]");
      console.log("  --ctid CTID              dispute target (required, e.g. tip://c/AA-...)");
      console.log("  --node-url URL           submission target (default http://localhost:4000)");
      console.log("  --vote-bias BIAS         UPHELD | DISMISSED | RANDOM (default UPHELD)");
      console.log("  --confirmed-origin CODE  origin code for MISMATCH votes (default: dispute.claimed_origin)");
      console.log("  --phase COMMIT|REVEAL    force phase (override the wall-clock auto-detect — required when");
      console.log("                           the validator's TIP_DEV_BYPASS_VOTE_WINDOWS is set)");
      console.log("  --appeal                 drive Stage-3 appeal experts (uses /appeal/{commit,reveal})");
      console.log("  --watch                  after reveal, poll dispute-case until verdict lands");
      console.log("  --watch-timeout SEC      max seconds to watch (default 30)");
      console.log("  --dry-run                print plan, do not submit");
      process.exit(0);
    } else throw new Error(`unknown arg: ${a}`);
  }
  if (!args.ctid) throw new Error("--ctid is required");
  if (!["UPHELD", "DISMISSED", "RANDOM"].includes(args.voteBias)) throw new Error("--vote-bias must be UPHELD | DISMISSED | RANDOM");
  if (args.confirmedOrigin && !ORIGIN_CODES.includes(args.confirmedOrigin)) throw new Error(`--confirmed-origin must be one of ${ORIGIN_CODES.join(",")}`);
  if (args.forcePhase && !["COMMIT", "REVEAL"].includes(args.forcePhase)) throw new Error("--phase must be COMMIT or REVEAL");
  return args;
}

// ─── HTTP ───────────────────────────────────────────────────────────────────
function httpRequest(url, { method = "GET", body = null, timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = body ? JSON.stringify(body) : null;
    const headers = { "Accept": "application/json" };
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }
    const req = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname + (u.search || ""),
      method, headers, timeout: timeoutMs,
    }, (res) => {
      let data = ""; res.on("data", c => data += c);
      res.on("end", () => {
        let parsed = null;
        try { parsed = JSON.parse(data); } catch { /* leave null */ }
        resolve({ status: res.statusCode, body: parsed, raw: data });
      });
    });
    req.on("timeout", () => { req.destroy(new Error(`timeout after ${timeoutMs}ms`)); });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function getJson(url) {
  const r = await httpRequest(url, { method: "GET" });
  if (r.status >= 200 && r.status < 300) return r.body;
  const msg = r.body?.error?.message || r.body?.error || `HTTP ${r.status}`;
  const err = new Error(msg); err.status = r.status; err.body = r.body;
  throw err;
}

async function postJson(url, body) {
  const r = await httpRequest(url, { method: "POST", body });
  if (r.status >= 200 && r.status < 300) return { ok: true, body: r.body };
  return { ok: false, status: r.status, body: r.body };
}

// ─── Vote/salt picking ──────────────────────────────────────────────────────
//
// UPHELD bias: jurors vote MISMATCH (= author's declared origin is wrong),
// which produces an UPHELD verdict. The 1-in-7 ABSTAIN keeps the realistic
// "not-everyone-voted-the-same-way" texture for tallying logic. DISMISSED
// bias is the mirror image (mostly MATCH).
function pickVote(bias, idx, total) {
  if (bias === "RANDOM") return JURY_VOTES[Math.floor(Math.random() * JURY_VOTES.length)];
  const oneAbstain = idx === total - 1;        // last juror abstains
  if (bias === "UPHELD") return oneAbstain ? VOTE.ABSTAIN : VOTE.MISMATCH;
  if (bias === "DISMISSED") return oneAbstain ? VOTE.ABSTAIN : VOTE.MATCH;
  return VOTE.MATCH;
}

function randomSalt() {
  return crypto.randomBytes(16).toString("hex");
}

// ─── Key load ───────────────────────────────────────────────────────────────
function juryKeyPath(jurorTipId) {
  // tip://id/US-002ff11f40397f7f → tip-id-US-002ff11f40397f7f.tip.json
  const m = /^tip:\/\/id\/(.+)$/.exec(jurorTipId);
  if (!m) throw new Error(`unrecognized tip_id: ${jurorTipId}`);
  return path.join(TEMP_USERS_KEYS_DIR, `tip-id-${m[1]}.tip.json`);
}

function loadKey(jurorTipId) {
  const p = juryKeyPath(jurorTipId);
  if (!fs.existsSync(p)) return null;            // caller skips with a warning — not all jurors are temp-seeded
  const env = JSON.parse(fs.readFileSync(p, "utf8"));
  if (!env.public_key || !env.private_key) throw new Error(`malformed key file: ${p}`);
  return { publicKey: env.public_key, privateKey: env.private_key, name: env.name };
}

// ─── Secrets cache ──────────────────────────────────────────────────────────
function ctidSlug(ctid) {
  return ctid.replace(/^tip:\/\/c\//, "").replace(/[^A-Za-z0-9_-]/g, "_");
}

function secretsPath(ctid, appeal) {
  return path.join(SECRETS_DIR, `${appeal ? "appeal" : "jury"}-secrets-${ctidSlug(ctid)}.json`);
}

function loadSecrets(ctid, appeal) {
  const p = secretsPath(ctid, appeal);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function writeSecrets(ctid, secrets, appeal) {
  const p = secretsPath(ctid, appeal);
  fs.writeFileSync(p, JSON.stringify(secrets, null, 2));
  return p;
}

// ─── Phase resolution ───────────────────────────────────────────────────────
// The Stage-3 appeal block lives at disputeCase.appeal with `experts`; we
// normalize to a jurors-shaped block so the rest of the script is unchanged.
function pickBlock(disputeCase, appeal) {
  if (appeal) {
    const a = disputeCase.appeal;
    if (!a) throw new Error("dispute-case has no appeal (no appeal filed yet?)");
    return { jurors: a.experts.map(e => ({ ...e, juror_tip_id: e.expert_tip_id })), commit_deadline: a.commit_deadline, reveal_deadline: a.reveal_deadline, total_summoned: a.total_summoned, total_committed: a.total_committed, total_revealed: a.total_revealed };
  }
  const j = disputeCase.jury;
  if (!j) throw new Error("dispute-case has no jury (jury not summoned yet?)");
  return j;
}

function resolvePhase(block, now = nowMs()) {
  const commit = block.commit_deadline;
  const reveal = block.reveal_deadline;
  if (now <= commit) return { phase: "COMMIT", commit, reveal };
  if (now <= reveal) return { phase: "REVEAL", commit, reveal };
  return { phase: "EXPIRED", commit, reveal };
}

// ─── Commit phase ───────────────────────────────────────────────────────────
async function doCommit(args, block) {
  const jurors = block.jurors;
  const routeBase = args.appeal ? "appeal" : "jury";
  const existing = loadSecrets(args.ctid, args.appeal) || { ctid: args.ctid, jurors: {} };

  const planned = jurors.map((j, i) => {
    const cached = existing.jurors[j.juror_tip_id];
    const already = j.status === "committed" || j.status === "revealed";
    const vote = cached?.vote ?? pickVote(args.voteBias, i, jurors.length);
    const salt = cached?.salt ?? randomSalt();
    const commitment = shake256(`${vote}:${salt}`);
    return { ...j, vote, salt, commitment, alreadyOnChain: already };
  });

  console.log(`\nCOMMIT phase — ctid=${args.ctid}`);
  console.log(`  ${jurors.length} jurors total; vote-bias=${args.voteBias}`);
  for (const p of planned) {
    console.log(`    ${p.juror_tip_id} (${p.creator_name}) vote=${p.vote} salt=${p.salt.slice(0, 8)}… commit=${p.commitment.slice(0, 12)}…${p.alreadyOnChain ? "  [SKIP — already committed]" : ""}`);
  }

  if (args.dryRun) { console.log("  --dry-run, no submission"); return; }

  // Persist BEFORE submission so a crash mid-commit doesn't strand secrets.
  const toPersist = { ctid: args.ctid, jurors: { ...existing.jurors } };
  for (const p of planned) toPersist.jurors[p.juror_tip_id] = { vote: p.vote, salt: p.salt, commitment: p.commitment, name: p.creator_name };
  const secretsFile = writeSecrets(args.ctid, toPersist, args.appeal);
  console.log(`  secrets cached → ${path.relative(REPO_ROOT, secretsFile)}`);

  let submitted = 0, skipped = 0, failed = 0;
  for (const p of planned) {
    if (p.alreadyOnChain) { skipped++; continue; }
    const key = loadKey(p.juror_tip_id);
    if (!key) { skipped++; console.log(`    ? ${p.creator_name || p.juror_tip_id} no key file — skipping`); continue; }
    const fields = { juror_tip_id: p.juror_tip_id, commitment: p.commitment };
    const signature = signBody(fields, key.privateKey);
    const url = `${args.nodeUrl}/v1/content/${encodeURIComponent(args.ctid)}/${routeBase}/commit`;
    const r = await postJson(url, { ...fields, signature });
    if (r.ok) { submitted++; console.log(`    ✓ ${p.creator_name} commit accepted (tx_id=${r.body?.data?.tx_id?.slice(0, 12)}…)`); }
    else if (r.status === 409) { skipped++; console.log(`    = ${p.creator_name} already committed (409)`); }
    else { failed++; console.log(`    ✗ ${p.creator_name} commit FAILED: ${r.status} ${r.body?.error?.message || r.body?.error || r.body?.raw}`); }
  }
  console.log(`  result: ${submitted} submitted, ${skipped} skipped, ${failed} failed`);
  if (failed) process.exitCode = 1;
}

// ─── Reveal phase ───────────────────────────────────────────────────────────
async function doReveal(args, block, disputeCase) {
  const secrets = loadSecrets(args.ctid, args.appeal);
  if (!secrets) throw new Error(`no cached secrets for ${args.ctid} — did you run the commit phase first? (expected ${secretsPath(args.ctid, args.appeal)})`);

  const jurors = block.jurors;
  const routeBase = args.appeal ? "appeal" : "jury";
  const claimedOrigin = disputeCase.dispute?.claimed_origin || "AG";
  const confirmedOrigin = args.confirmedOrigin || claimedOrigin;
  if (!ORIGIN_CODES.includes(confirmedOrigin)) throw new Error(`confirmed_origin ${confirmedOrigin} not in ${ORIGIN_CODES.join(",")}`);

  console.log(`\nREVEAL phase — ctid=${args.ctid}`);
  console.log(`  ${jurors.length} jurors total; confirmed_origin (for MISMATCH) = ${confirmedOrigin}`);

  let submitted = 0, skipped = 0, failed = 0, missing = 0;
  for (const j of jurors) {
    const sec = secrets.jurors[j.juror_tip_id];
    if (!sec) { console.log(`    ? ${j.creator_name} no cached secret — cannot reveal`); missing++; continue; }
    if (j.status === "revealed") { console.log(`    = ${j.creator_name} already revealed`); skipped++; continue; }
    if (j.status !== "committed") { console.log(`    - ${j.creator_name} not in committed state (status=${j.status}) — skipping`); skipped++; continue; }

    const key = loadKey(j.juror_tip_id);
    if (!key) { missing++; console.log(`    ? ${j.creator_name || j.juror_tip_id} no key file — cannot reveal`); continue; }
    const isMismatch = sec.vote === VOTE.MISMATCH;
    const fields = isMismatch
      ? { juror_tip_id: j.juror_tip_id, vote: sec.vote, salt: sec.salt, confirmed_origin: confirmedOrigin }
      : { juror_tip_id: j.juror_tip_id, vote: sec.vote, salt: sec.salt };

    if (args.dryRun) {
      console.log(`    DRY ${j.creator_name} would reveal vote=${sec.vote}${isMismatch ? ` confirmed_origin=${confirmedOrigin}` : ""}`);
      continue;
    }

    const signature = signBody(fields, key.privateKey);
    const url = `${args.nodeUrl}/v1/content/${encodeURIComponent(args.ctid)}/${routeBase}/reveal`;
    const r = await postJson(url, { ...fields, signature });
    if (r.ok) { submitted++; console.log(`    ✓ ${j.creator_name} reveal accepted vote=${sec.vote} (tx_id=${r.body?.data?.tx_id?.slice(0, 12)}…)`); }
    else if (r.status === 409) { skipped++; console.log(`    = ${j.creator_name} already revealed (409)`); }
    else { failed++; console.log(`    ✗ ${j.creator_name} reveal FAILED: ${r.status} ${r.body?.error?.message || r.body?.error || r.body?.raw}`); }
  }
  console.log(`  result: ${submitted} submitted, ${skipped} skipped, ${missing} missing-secret, ${failed} failed`);
  if (failed) process.exitCode = 1;
}

// ─── Watch ──────────────────────────────────────────────────────────────────
async function watchVerdict(args) {
  const url = `${args.nodeUrl}/v1/content/${encodeURIComponent(args.ctid)}/dispute-case`;
  const deadline = nowMs() + args.watchTimeoutSec * 1000;
  console.log(`\nWatching for verdict (timeout ${args.watchTimeoutSec}s)…`);
  while (nowMs() < deadline) {
    try {
      const j = await getJson(url);
      const v = args.appeal ? j?.data?.appeal?.verdict : j?.data?.verdict;
      const jc = args.appeal ? j?.data?.appeal : j?.data?.jury;
      const label = v ? (args.appeal ? `${v.verdict}${v.overturned != null ? ` (overturned=${v.overturned})` : ""}` : v.verdict) : null;
      process.stdout.write(`  committed=${jc?.total_committed ?? "?"}/${jc?.total_summoned ?? "?"} revealed=${jc?.total_revealed ?? "?"}${label ? ` verdict=${label}` : ""}\r`);
      if (v) { console.log(`\n  ✓ verdict landed: ${label} (resolved_at=${v.resolved_at})`); return; }
    } catch (e) { /* transient — keep polling */ }
    await new Promise(r => setTimeout(r, 1000));
  }
  console.log("\n  timed out waiting for verdict (verdict-trigger fires post-round when reveal_deadline crosses cert.timestamp)");
}

// ─── Main ───────────────────────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv);
  await initCrypto();

  const url = `${args.nodeUrl}/v1/content/${encodeURIComponent(args.ctid)}/dispute-case`;
  const r = await getJson(url);
  const disputeCase = r?.data || r;
  if (!disputeCase?.jury) throw new Error(`no jury on dispute-case for ${args.ctid} — has the dispute been filed?`);

  const block = pickBlock(disputeCase, args.appeal);
  const auto = resolvePhase(block);
  const phase = args.forcePhase || auto.phase;
  const { commit, reveal } = auto;
  console.log(`Dispute ${args.ctid}${args.appeal ? " (appeal / Stage-3)" : ""}`);
  console.log(`  phase=${phase}${args.forcePhase ? " (forced — wall-clock would say " + auto.phase + ")" : ""}  commit_deadline=${toIso(commit)}  reveal_deadline=${toIso(reveal)}`);
  console.log(`  summoned=${block.total_summoned}  committed=${block.total_committed}  revealed=${block.total_revealed}`);

  if (phase === "COMMIT") {
    await doCommit(args, block);
    console.log(`\nNext step: wait for commit_deadline (${toIso(commit)}), then re-run this script to reveal.`);
  } else if (phase === "REVEAL") {
    await doReveal(args, block, disputeCase);
    if (args.watch) await watchVerdict(args);
    else console.log(`\nNext step: verdict-trigger fires post-round when reveal_deadline (${toIso(reveal)}) crosses cert.timestamp. Use --watch to poll, or query /dispute-case manually.`);
  } else {
    console.log(`\n  windows expired — verdict-trigger should have fired already. Check /dispute-case for the ${args.appeal ? "APPEAL_RESULT" : "ADJUDICATION_RESULT"}.`);
  }
}

main().catch(err => {
  console.error(`\nERROR: ${err.message}`);
  if (err.body) console.error(`  body: ${JSON.stringify(err.body)}`);
  process.exit(1);
}).finally(() => {
  // snarkjs WASM workers (loaded transitively) can hold the loop open;
  // explicit exit ensures clean termination after legitimate completion.
  setTimeout(() => process.exit(process.exitCode || 0), 50).unref();
});
