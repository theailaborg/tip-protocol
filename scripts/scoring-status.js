#!/usr/bin/env node
/**
 * @file scripts/scoring-status.js
 * @description DEV: Show the full scoring lifecycle state for a TIP-ID and/or CTID.
 *
 * Fetches and displays:
 *   - Identity + current score, tier, offense_count
 *   - Score history (SCORE_UPDATE events in chronological order)
 *   - Content record + prescan status (when --ctid is given)
 *   - Dispute case: jury phase, verdicts, appeal, jury composition (when --ctid is given)
 *
 * Useful for validating that scoring transitions are happening correctly
 * as you step through the register → dispute → jury → verdict → appeal flow.
 *
 * Usage:
 *   node scripts/scoring-status.js --tip-id tip://id/US-...
 *   node scripts/scoring-status.js --ctid tip://c/OH-...
 *   node scripts/scoring-status.js --tip-id tip://id/US-... --ctid tip://c/OH-...
 *   node scripts/scoring-status.js --ctid tip://c/OH-... --all-parties
 *
 * Options:
 *   --tip-id TIP        Show identity + score + history for this TIP-ID
 *   --ctid CTID         Show content + dispute case for this CTID
 *   --all-parties       Also fetch scores for author, disputer, and jurors
 *   --node-url URL      Target node (default http://localhost:4000)
 *   --json              Dump raw API responses as JSON (for piping / debugging)
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */

"use strict";

const http = require("http");

// ─── Colors ──────────────────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m",
  yellow: "\x1b[33m", magenta: "\x1b[35m", blue: "\x1b[34m",
};
const section = (title) => console.log(`\n${C.bold}${C.cyan}── ${title} ${C.reset}${"─".repeat(Math.max(0, 54 - title.length))}`);
const row = (k, v, color = "") => console.log(`  ${C.dim}${k.padEnd(28)}${C.reset}${color}${v}${color ? C.reset : ""}`);
const hr = () => console.log(`  ${C.dim}${"─".repeat(60)}${C.reset}`);

// ─── CLI ─────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = {
    tipId: null,
    ctid: null,
    allParties: false,
    nodeUrl: "http://localhost:4000",
    json: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--tip-id") args.tipId = argv[++i];
    else if (a === "--ctid") args.ctid = argv[++i];
    else if (a === "--all-parties") args.allParties = true;
    else if (a === "--node-url") args.nodeUrl = argv[++i];
    else if (a === "--json") args.json = true;
    else if (a === "--help" || a === "-h") {
      console.log("usage: scoring-status.js [opts]");
      console.log("  --tip-id TIP        show identity score + history");
      console.log("  --ctid CTID         show content + dispute case + verdict");
      console.log("  --all-parties       also fetch scores for author/disputer/jurors (requires --ctid)");
      console.log("  --node-url URL      target node (default http://localhost:4000)");
      console.log("  --json              dump raw API responses as JSON");
      process.exit(0);
    } else throw new Error(`unknown arg: ${a}`);
  }
  if (!args.tipId && !args.ctid) throw new Error("--tip-id and/or --ctid is required");
  return args;
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────
function httpGet(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + (u.search || ""), method: "GET", headers: { Accept: "application/json" }, timeout: timeoutMs },
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
    req.end();
  });
}

async function fetchOr(url, fallback = null) {
  try {
    const r = await httpGet(url);
    if (r.status === 200) return r.body?.data || r.body;
    return fallback;
  } catch {
    return fallback;
  }
}

// ─── Score tier label ─────────────────────────────────────────────────────────
function tierLabel(score) {
  if (score === null || score === undefined) return "(unknown)";
  if (score >= 850) return `${C.green}HIGHLY_TRUSTED${C.reset} (≥850)`;
  if (score >= 650) return `${C.green}TRUSTED${C.reset} (≥650)`;
  if (score >= 400) return `${C.cyan}VERIFIED${C.reset} (≥400)`;
  if (score >= 200) return `${C.yellow}CAUTION${C.reset} (≥200)`;
  return `${C.red}NOT_TRUSTED${C.reset} (<200)`;
}

function deltaColor(delta) {
  if (!delta && delta !== 0) return C.dim;
  return Number(delta) >= 0 ? C.green : C.red;
}

function fmtDelta(delta) {
  if (delta === null || delta === undefined) return "";
  return Number(delta) >= 0 ? `+${delta}` : String(delta);
}

// ─── Identity + Score section ─────────────────────────────────────────────────
async function showIdentityScore(tipId, nodeUrl, jsonMode) {
  const [identity, scoreData, history] = await Promise.all([
    fetchOr(`${nodeUrl}/v1/identity/${encodeURIComponent(tipId)}`),
    fetchOr(`${nodeUrl}/v1/identity/${encodeURIComponent(tipId)}/score`),
    fetchOr(`${nodeUrl}/v1/identity/${encodeURIComponent(tipId)}/history`),
  ]);

  if (jsonMode) {
    console.log(JSON.stringify({ identity, score: scoreData, history }, null, 2));
    return;
  }

  if (!identity) {
    console.log(`  ${C.red}✗ Identity not found: ${tipId}${C.reset}`);
    return;
  }

  section(`Identity — ${identity.creator_name || tipId}`);
  row("tip_id", tipId);
  row("tip_id_type", identity.tip_id_type || "personal");
  row("region", identity.region || "(unknown)");
  row("verification_tier", identity.verification_tier || "(unknown)");
  row("registered_at", identity.registered_at || "(unknown)");

  section("Score");
  const score = scoreData?.score ?? null;
  const offenses = scoreData?.offense_count ?? 0;
  const lastUpdated = scoreData?.last_updated || "(no updates yet)";
  row("score", score !== null ? String(score) : "(not found)", score !== null ? C.bold : C.dim);
  row("tier", tierLabel(score));
  row("offense_count", String(offenses), offenses > 0 ? C.red : C.green);
  row("last_updated", lastUpdated);

  // Eligibility summary (thresholds from protocol constants).
  const elig = [];
  if (score !== null) {
    if (score >= 400) elig.push(`${C.green}can dispute${C.reset}`);
    else elig.push(`${C.red}cannot dispute (need ≥400)${C.reset}`);
    if (score >= 700) elig.push(`${C.green}jury-eligible${C.reset}`);
    else elig.push(`${C.dim}below jury threshold (need ≥700)${C.reset}`);
    if (score >= 800) elig.push(`${C.green}reviewer-eligible${C.reset}`);
    else elig.push(`${C.dim}below reviewer threshold (need ≥800)${C.reset}`);
  }
  if (elig.length) row("eligibility", elig.join("  "));

  // Score history (SCORE_UPDATE events).
  const events = Array.isArray(history) ? history
    : Array.isArray(history?.events) ? history.events
    : [];

  if (events.length === 0) {
    section("Score History");
    console.log(`  ${C.dim}No SCORE_UPDATE events found yet.${C.reset}`);
  } else {
    section(`Score History (${events.length} events)`);
    for (const ev of events) {
      const delta = ev.delta ?? ev.data?.delta;
      const reason = ev.reason || ev.data?.reason || "(no reason)";
      const ts = ev.timestamp || ev.data?.timestamp || "";
      const contentRef = ev.ctid || ev.data?.ctid;
      const dc = deltaColor(delta);
      console.log(`  ${C.dim}${ts.slice(0, 19).replace("T", " ")}${C.reset}  ${dc}${fmtDelta(delta).padStart(5)}${C.reset}  ${reason}${contentRef ? `  ${C.dim}(${contentRef.slice(0, 30)})${C.reset}` : ""}`);
    }
  }
}

// ─── Prescan tier badge ───────────────────────────────────────────────────────
function prescanBadge(tier, flagged) {
  if (!tier) return "(not set)";
  const colors = { low: C.green, elevated: C.yellow, high: C.red, critical: C.red + C.bold };
  return `${colors[tier] || ""}${tier.toUpperCase()}${C.reset}${flagged ? ` ${C.red}[FLAGGED]${C.reset}` : ""}`;
}

// ─── Content + Dispute section ────────────────────────────────────────────────
async function showContent(ctid, nodeUrl, allParties, jsonMode) {
  const [content, disputeCase] = await Promise.all([
    fetchOr(`${nodeUrl}/v1/content/${encodeURIComponent(ctid)}`),
    fetchOr(`${nodeUrl}/v1/content/${encodeURIComponent(ctid)}/dispute-case`),
  ]);

  if (jsonMode) {
    console.log(JSON.stringify({ content, disputeCase }, null, 2));
    return;
  }

  if (!content) {
    console.log(`  ${C.red}✗ Content not found: ${ctid}${C.reset}`);
    return;
  }

  section("Content");
  row("ctid", ctid);
  row("origin_code", content.origin_code);
  row("status", content.status || "(unknown)", content.status === "disputed" ? C.red : content.status === "verified" ? C.green : "");
  row("prescan_tier", prescanBadge(content.prescan_tier, content.prescan_flagged));
  row("prescan_probability", content.prescan_probability !== undefined ? content.prescan_probability.toFixed(3) : "(unknown)");
  row("author_tip_id", content.author_tip_id || "(unknown)");
  row("registered_at", content.registered_at || "(unknown)");

  if (!disputeCase || !disputeCase.dispute) {
    section("Dispute");
    console.log(`  ${C.dim}No dispute on record for this CTID.${C.reset}`);
    console.log(`  ${C.dim}File one: node scripts/file-dispute.js --ctid ${ctid} --disputer-tip-id <TIP>${C.reset}`);
    return;
  }

  const dc = disputeCase;
  section("Dispute");
  row("dispute_tx_id", (dc.dispute?.tx_id || "(unknown)").slice(0, 20) + "…");
  row("disputer_tip_id", dc.dispute?.disputer_tip_id || "(unknown)");
  row("reason", dc.dispute?.reason || "(unknown)");
  row("claimed_origin", dc.dispute?.claimed_origin || "(none)");
  row("declared_origin", dc.dispute?.declared_origin || "(none)");
  row("dispute status", dc.dispute?.status || "(unknown)");
  row("filed_at", dc.dispute?.filed_at || "(unknown)");

  // Stage-2 jury.
  const jury = dc.jury;
  if (jury) {
    section("Stage-2 Jury");
    row("commit_deadline", jury.commit_deadline || "(unknown)");
    row("reveal_deadline", jury.reveal_deadline || "(unknown)");
    row("summoned", String(jury.total_summoned ?? "?"));
    row("committed", String(jury.total_committed ?? "?"));
    row("revealed", String(jury.total_revealed ?? "?"));

    // Phase
    const now = Date.now();
    const commitMs = jury.commit_deadline ? new Date(jury.commit_deadline).getTime() : null;
    const revealMs = jury.reveal_deadline ? new Date(jury.reveal_deadline).getTime() : null;
    let phase;
    if (dc.verdict) phase = "CONCLUDED";
    else if (commitMs && now <= commitMs) phase = "COMMIT_WINDOW";
    else if (revealMs && now <= revealMs) phase = "REVEAL_WINDOW";
    else phase = "EXPIRED (awaiting verdict trigger)";
    const phaseColor = phase === "COMMIT_WINDOW" ? C.cyan : phase === "REVEAL_WINDOW" ? C.yellow : phase === "CONCLUDED" ? C.green : C.red;
    row("current phase", `${phaseColor}${phase}${C.reset}`);

    // Juror list.
    if (Array.isArray(jury.jurors) && jury.jurors.length > 0) {
      hr();
      console.log(`  ${C.dim}Jurors:${C.reset}`);
      for (const j of jury.jurors) {
        const statusColor = j.status === "revealed" ? C.green : j.status === "committed" ? C.cyan : C.dim;
        const stake = j.stake !== undefined ? ` stake=${j.stake}` : "";
        console.log(`    ${statusColor}${(j.status || "pending").padEnd(10)}${C.reset}  ${j.juror_tip_id}${stake}`);
      }
    }
  }

  // Stage-2 verdict.
  if (dc.verdict) {
    section("Stage-2 Verdict");
    const v = dc.verdict;
    const vColor = v.verdict === "UPHELD" ? C.red : v.verdict === "DISMISSED" ? C.green : C.yellow;
    row("verdict", `${vColor}${C.bold}${v.verdict}${C.reset}`);
    row("resolved_at", v.resolved_at || "(unknown)");
    if (v.confirmed_origin) row("confirmed_origin", v.confirmed_origin);
    if (v.score_summary) {
      hr();
      console.log(`  ${C.dim}Score effects:${C.reset}`);
      for (const [party, delta] of Object.entries(v.score_summary)) {
        const dc2 = deltaColor(delta);
        console.log(`    ${party.padEnd(30)} ${dc2}${fmtDelta(delta)}${C.reset}`);
      }
    }
  }

  // Appeal.
  const appeal = dc.appeal;
  if (appeal) {
    section("Stage-3 Appeal");
    row("appellant", appeal.appellant_tip_id || "(unknown)");
    row("commit_deadline", appeal.commit_deadline || "(unknown)");
    row("reveal_deadline", appeal.reveal_deadline || "(unknown)");
    row("experts summoned", String(appeal.total_summoned ?? "?"));
    row("committed", String(appeal.total_committed ?? "?"));
    row("revealed", String(appeal.total_revealed ?? "?"));

    if (dc.appeal_verdict) {
      const av = dc.appeal_verdict;
      const avColor = av.verdict === "UPHELD" ? C.red : av.verdict === "DISMISSED" ? C.green : C.yellow;
      row("appeal verdict", `${avColor}${C.bold}${av.verdict}${C.reset}  overturned=${av.overturned}`);
      row("resolved_at", av.resolved_at || "(unknown)");
    } else {
      const now = Date.now();
      const aCommitMs = appeal.commit_deadline ? new Date(appeal.commit_deadline).getTime() : null;
      const aRevealMs = appeal.reveal_deadline ? new Date(appeal.reveal_deadline).getTime() : null;
      let aPhase;
      if (aCommitMs && now <= aCommitMs) aPhase = "COMMIT_WINDOW";
      else if (aRevealMs && now <= aRevealMs) aPhase = "REVEAL_WINDOW";
      else aPhase = "EXPIRED (awaiting verdict trigger)";
      const aphColor = aPhase === "COMMIT_WINDOW" ? C.cyan : aPhase === "REVEAL_WINDOW" ? C.yellow : C.red;
      row("appeal phase", `${aphColor}${aPhase}${C.reset}`);
      console.log(`  ${C.dim}Drive appeal: node scripts/drive-jury.js --ctid ${ctid} --appeal --phase COMMIT${C.reset}`);
    }
  }

  // All-parties score snapshot.
  if (allParties) {
    const parties = new Set();
    if (content.author_tip_id) parties.add({ label: "author", tipId: content.author_tip_id });
    if (dc.dispute?.disputer_tip_id) parties.add({ label: "disputer", tipId: dc.dispute.disputer_tip_id });
    if (dc.jury?.jurors) {
      for (const j of dc.jury.jurors) parties.add({ label: "juror", tipId: j.juror_tip_id });
    }
    if (dc.appeal?.experts) {
      for (const e of dc.appeal.experts) parties.add({ label: "expert", tipId: e.expert_tip_id });
    }

    if (parties.size > 0) {
      section("Party Scores (snapshot)");
      const results = await Promise.all([...parties].map(async (p) => {
        const s = await fetchOr(`${nodeUrl}/v1/identity/${encodeURIComponent(p.tipId)}/score`);
        return { ...p, score: s?.score ?? null, offenses: s?.offense_count ?? 0 };
      }));
      for (const p of results) {
        const dc2 = p.score !== null
          ? (p.score >= 700 ? C.green : p.score >= 400 ? C.cyan : C.red)
          : C.dim;
        console.log(`  ${C.dim}${p.label.padEnd(10)}${C.reset} ${dc2}${String(p.score ?? "?").padStart(4)}${C.reset}  offenses=${p.offenses}  ${p.tipId}`);
      }
    }
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv);

  if (!args.json) {
    console.log(`${C.bold}TIP Scoring Status${C.reset}  ${C.dim}node: ${args.nodeUrl}${C.reset}`);
  }

  if (args.tipId) {
    await showIdentityScore(args.tipId, args.nodeUrl, args.json);
  }
  if (args.ctid) {
    await showContent(args.ctid, args.nodeUrl, args.allParties, args.json);
  }

  if (!args.json) console.log("");
}

main().catch(e => {
  console.error(`\nERROR: ${e.message}`);
  process.exit(1);
}).finally(() => setTimeout(() => process.exit(process.exitCode || 0), 50).unref());
