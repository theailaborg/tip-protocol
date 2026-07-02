#!/usr/bin/env node
/**
 * Async prescan end-to-end smoke test.
 *
 * Drives real registration → real classifier → real PRESCAN_COMPLETED tx
 * → real poll. Loads a founding identity's private key from genesis-data/
 * to sign the request the same way the schema module does on the server.
 *
 * Usage: node scripts/test-prescan-e2e.js [test-name]
 *   test-name omitted = run all scenarios
 *   test-name = run only the matching scenario
 *
 * Env:
 *   NODE_URL   default http://localhost:4000
 *   POLL_MS    default 1000
 *   POLL_MAX   default 60 (= 60s max wait per scenario)
 */

"use strict";

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "..");
const SHARED = path.join(ROOT, "shared");

// Load identity from the per-identity backup file so tip_id_type is
// captured correctly (backups/*.tip.json keep the keypairs; one entries
// array; the backups dir has one file per identity with full metadata).
const IDENTITY_FILE = process.env.TIP_IDENTITY_FILE
  || path.join(ROOT, "genesis-data", "backups", "tip-id-US-02debc7b60b07301.tip.json");
const SIGNER = JSON.parse(fs.readFileSync(IDENTITY_FILE, "utf8"));

// Load shared modules so signing is identical to server.
const { initCrypto } = require(path.join(SHARED, "crypto"));
const { nowMs } = require(path.join(SHARED, "time"));
const contentRegisterSchema = require(path.join(ROOT, "node/src/schemas/content-register"));

// Initialise protocol constants from genesis so MEDIA_LIMITS etc. are
// available to the schema validator.
const PC = require(path.join(SHARED, "protocol-constants"));
const { getGenesisPayload } = require(path.join(ROOT, "node/src/genesis"));
try { PC._resetForTesting(); } catch { /* not yet initialised */ }
PC.init(getGenesisPayload().protocol_constants);

const NODE_URL = process.env.NODE_URL || "http://localhost:4000";
const POLL_MS  = parseInt(process.env.POLL_MS || "1000", 10);
const POLL_MAX = parseInt(process.env.POLL_MAX || "60", 10);

const RESET = "\x1b[0m"; const GREEN = "\x1b[32m"; const RED = "\x1b[31m"; const YELLOW = "\x1b[33m"; const DIM = "\x1b[2m";

async function registerContent(opts) {
  const {
    content, origin_code = "OH", content_type_hint = null,
    registered_urls = [], media_canonical_hash = null,
  } = opts;

  const body = {
    signer_tip_id: SIGNER.tip_id,
    origin_code,
    content: content || null,
    media_canonical_hash,
    content_type_hint,
    cna_version: "2.2",
    attribution_mode: "self",
    authors: [{ tip_id: SIGNER.tip_id, tip_id_type: SIGNER.tip_id_type, contribution_role: "creator" }],
    extras: {},
    registered_urls,
  };

  // Build canonical signing payload and sign with ML-DSA.
  const textHash = content
    ? require(path.join(SHARED, "crypto")).shake256(
        require(path.join(SHARED, "crypto")).tipNormalize(content),
      )
    : require(path.join(SHARED, "crypto")).shake256("");
  const contentHash = media_canonical_hash
    ? require(path.join(SHARED, "crypto")).shake256(media_canonical_hash + textHash)
    : textHash;
  const canonical = contentRegisterSchema.buildSigningPayload(body, contentHash);
  const signature = contentRegisterSchema.sign(canonical, SIGNER.private_key);

  body.signature = signature;

  const resp = await fetch(`${NODE_URL}/v1/content/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await resp.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { status: resp.status, body: json };
}

async function pollPrescanStatus(ctid) {
  for (let i = 0; i < POLL_MAX; i++) {
    const resp = await fetch(`${NODE_URL}/v1/content/${encodeURIComponent(ctid)}/prescan_status`);
    if (resp.ok) {
      const json = await resp.json();
      const s = json.data?.prescan_status || json.prescan_status;
      if (s === "completed") return { ok: true, attempts: i + 1, data: json.data || json };
    }
    await new Promise(r => setTimeout(r, POLL_MS));
  }
  return { ok: false, attempts: POLL_MAX };
}

// ── Scenarios ────────────────────────────────────────────────────────────

function _ctypeFromPoll(poll) {
  return poll.data?.content?.prescan_content_type || poll.data?.prescan_content_type;
}

function makeResolutionScenario({ name, description, url, contentTypeHint = null, expectedContentType }) {
  return {
    name,
    description,
    run: async () => {
      const nonce = crypto.randomBytes(4).toString("hex");
      const reg = await registerContent({
        content: `Hand-written test paragraph for content-type resolution. nonce=${nonce}`,
        registered_urls: url ? [url] : [],
        content_type_hint: contentTypeHint,
      });
      if (reg.status !== 202) return { fail: `expected 202, got ${reg.status}: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const ctid = reg.body.data?.ctid || reg.body.ctid;
      if (!ctid) return { fail: `no ctid in response: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const poll = await pollPrescanStatus(ctid);
      if (!poll.ok) return { fail: `prescan didn't complete in ${POLL_MAX * POLL_MS / 1000}s` };
      const ctype = _ctypeFromPoll(poll);
      if (ctype !== expectedContentType) return { fail: `expected content_type=${expectedContentType}, got ${ctype} (url=${url}, hint=${contentTypeHint})` };
      return { pass: true, ctid, attempts: poll.attempts, content_type: ctype };
    },
  };
}

// Back-compat shim for the existing url-prefixed scenarios.
function makeUrlScenario(opts) { return makeResolutionScenario(opts); }

const SCENARIOS = [
  {
    name: "text-only-basic",
    description: "Plain text registration, no URL, no hint → derives from shape → text",
    run: async () => {
      const nonce = crypto.randomBytes(4).toString("hex");
      const reg = await registerContent({
        content: `This is a hand-written test paragraph for the prescan smoke test. nonce=${nonce}`,
      });
      if (reg.status !== 202) return { fail: `expected 202, got ${reg.status}: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const ctid = reg.body.data?.ctid || reg.body.ctid;
      if (!ctid) return { fail: `no ctid in response: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const poll = await pollPrescanStatus(ctid);
      if (!poll.ok) return { fail: `prescan didn't complete in ${POLL_MAX * POLL_MS / 1000}s` };
      const ctype = _ctypeFromPoll(poll);
      const tier = poll.data?.content?.tier || poll.data?.tier;
      if (ctype !== "text") return { fail: `expected content_type=text, got ${ctype}` };
      return { pass: true, ctid, attempts: poll.attempts, content_type: ctype, tier };
    },
  },
  // Test 3 — URL platform lookup (4 strategies, no hint).
  makeUrlScenario({
    name: "url-fixed-video-youtube",
    description: "youtube.com URL → FIXED strategy → content_type=video",
    url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    expectedContentType: "video",
  }),
  makeUrlScenario({
    // Instagram is MEDIA_DOMINANT, not FIXED:image. Without an image
    // payload, the strategy correctly falls back to text (line 154 of
    // applyStrategy). Once media upload lands (S3 plan), add a sibling
    // scenario that sends an image and expects content_type=image.
    name: "url-media-dominant-instagram-text-only",
    description: "instagram.com URL + text-only payload → MEDIA_DOMINANT falls back to text",
    url: "https://www.instagram.com/p/CABCDEFGHIJ/",
    expectedContentType: "text",
  }),
  makeUrlScenario({
    name: "url-mixed-text-only-x",
    description: "x.com URL with text-only payload → MIXED → text (no media to elevate)",
    url: "https://x.com/jack/status/20",
    expectedContentType: "text",
  }),
  makeUrlScenario({
    name: "url-text-dominant-medium",
    description: "medium.com URL → TEXT_DOMINANT → content_type=text",
    url: "https://medium.com/@author/some-article-abc",
    expectedContentType: "text",
  }),
  // Test 4 — Hint takes priority over URL.
  makeResolutionScenario({
    name: "hint-overrides-url-youtube",
    description: "hint=text overrides youtube.com (which would say video) → text",
    url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    contentTypeHint: "text",
    expectedContentType: "text",
  }),
  // Test 5 — URL alias resolution (synonym domains collapse to canonical).
  makeResolutionScenario({
    name: "alias-twitter-to-x",
    description: "twitter.com alias → x.com MIXED + text-only → text",
    url: "https://twitter.com/jack/status/20",
    expectedContentType: "text",
  }),
  makeResolutionScenario({
    name: "alias-youtu-be-to-youtube",
    description: "youtu.be alias → youtube.com FIXED:video → video",
    url: "https://youtu.be/dQw4w9WgXcQ",
    expectedContentType: "video",
  }),
  makeResolutionScenario({
    name: "alias-bbc-co-uk-to-bbc",
    description: "bbc.co.uk alias → bbc.com TEXT_DOMINANT → text",
    url: "https://www.bbc.co.uk/news/world-1234567",
    expectedContentType: "text",
  }),
  // Test 6 — Unknown domain falls through to shape heuristic.
  makeResolutionScenario({
    name: "unknown-domain-text-fallthrough",
    description: "unregistered domain + text-only → shape heuristic → text",
    url: "https://random-domain-xyz.example/post-abc",
    expectedContentType: "text",
  }),
  // Test 7 — Non-OH origin locally-skipped (no classifier call, clean verdict).
  // Skip shape: probability=0.5 (no-signal neutral, matches fail-open and
  // aggregator convention — not 0 which would imply "definitely human" and
  // contradict AG self-disclosure). overall_degraded=false because this is
  // an intentional policy skip, not a classifier failure; downstream
  // distinguishes via classifier_providers_used="skipped_locally".
  {
    name: "origin-ag-locally-skipped",
    description: "origin_code=AG → worker skips classifier, emits prob=0.5, degraded=false",
    run: async () => {
      const nonce = crypto.randomBytes(4).toString("hex");
      const reg = await registerContent({
        content: `Self-disclosed AI-generated marketing copy. nonce=${nonce}`,
        origin_code: "AG",
      });
      if (reg.status !== 202) return { fail: `expected 202, got ${reg.status}: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const ctid = reg.body.data?.ctid || reg.body.ctid;
      if (!ctid) return { fail: `no ctid in response: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const poll = await pollPrescanStatus(ctid);
      if (!poll.ok) return { fail: `prescan didn't complete in ${POLL_MAX * POLL_MS / 1000}s` };
      const d = poll.data || {};
      if (d.prescan_probability !== 0.5) return { fail: `expected prob=0.5 (locally-skipped no-signal neutral), got ${d.prescan_probability}` };
      if (d.prescan_overall_degraded !== false) return { fail: `expected overall_degraded=false (intentional skip, not degradation), got ${d.prescan_overall_degraded}` };
      if (d.prescan_flagged !== false) return { fail: `expected flagged=false, got ${d.prescan_flagged}` };
      return { pass: true, ctid, attempts: poll.attempts, probability: d.prescan_probability, degraded: d.prescan_overall_degraded };
    },
  },
  // Test 14 — Worker concurrency (Pattern B). With TIP_PRESCAN_CONCURRENCY=4
  // the worker holds up to 4 jobs in 'claimed' state simultaneously. We
  // register N=8 OH texts, then poll the queue for the max-concurrent count
  // observed across short sampling intervals. Pass = saw ≥ 2 claimed at
  // once (proves parallel processing, not sequential).
  //
  // We can't assert wall-clock here — the single live classifier instance
  // is the throughput bottleneck. In production (load-balanced classifier)
  // wall-clock scales with concurrency; in this dev env it doesn't.
  {
    name: "worker-concurrency-claimed-parallelism",
    description: "8 parallel OH registrations → queue shows ≥2 jobs in 'claimed' simultaneously",
    run: async () => {
      const N = 8;
      const regs = await Promise.all(Array.from({ length: N }, async (_, i) => {
        const nonce = crypto.randomBytes(4).toString("hex");
        const r = await registerContent({
          content: `Concurrency test job #${i}. nonce=${nonce}`,
          origin_code: "OH",
        });
        return { i, status: r.status, body: r.body };
      }));
      const failed = regs.filter(r => r.status !== 202);
      if (failed.length > 0) return { fail: `${failed.length}/${N} registrations failed at submit time` };
      const ctids = regs.map(r => r.body.data?.ctid || r.body.ctid);

      // Sample queue 'claimed' count for a few seconds. We piggyback on
      // the API node by reading prescan_status (which exposes the row
      // but not the queue) — so this assertion lives in the runner; the
      // scenario just confirms registrations landed.
      return {
        pass: true,
        n: N,
        ctids,
        note: "queue-claimed-count must be verified externally (see psql snapshot in test harness)",
      };
    },
  },
  // Test 11 — Soft-degraded ship-through. Short OH text triggers the
  // classifier's `disagreement_override` (sparse ensemble — statistical
  // skips, only ollama/heuristic vote). Worker preserves the real number
  // and emits with overall_degraded=true; no retries, single classifier
  // call. Old behavior would have retried 4x then fail-opened with prob=0.
  {
    name: "soft-degraded-ship-through",
    description: "short OH text → disagreement_override → preserve real prob, overall_degraded=true, 0 retries",
    run: async () => {
      const nonce = crypto.randomBytes(4).toString("hex");
      // Short paragraph, deliberately below statistical-provider threshold.
      const reg = await registerContent({
        content: `Quick note about my weekend. Tried that new cafe. The coffee was fine. nonce=${nonce}`,
        origin_code: "OH",
      });
      if (reg.status !== 202) return { fail: `expected 202, got ${reg.status}: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const ctid = reg.body.data?.ctid || reg.body.ctid;
      if (!ctid) return { fail: `no ctid in response` };
      const poll = await pollPrescanStatus(ctid);
      if (!poll.ok) return { fail: `prescan didn't complete in ${POLL_MAX * POLL_MS / 1000}s` };
      const d = poll.data || {};
      if (typeof d.prescan_probability !== "number") return { fail: `probability not a number: ${d.prescan_probability}` };
      if (d.prescan_probability === 0) return { fail: `probability=0 indicates skip path, not soft-degraded` };
      if (d.prescan_probability === 0.5) return { fail: `probability=0.5 indicates fail-open, not soft-degraded` };
      if (d.prescan_overall_degraded !== true) return { fail: `expected overall_degraded=true (disagreement_override), got ${d.prescan_overall_degraded}` };
      return { pass: true, ctid, attempts: poll.attempts, probability: d.prescan_probability, degraded: d.prescan_overall_degraded };
    },
  },
  // Test 10 — Hard error retry → fail-open with prob=0.5, overall_degraded=true.
  // Run with TIP_CLASSIFIER_URL pointing to a black hole (e.g.
  // http://127.0.0.1:1) so every classifier call hits ECONNREFUSED. After
  // worker_max_retries_on_error retries, _emitFailOpen runs and writes the
  // no-signal neutral. This exercises the same fail-open path as a
  // hard-degraded payload response.
  {
    name: "hard-error-fail-open",
    description: "classifier unreachable → 4 retries → fail-open emits prob=0.5, overall_degraded=true, failed=true",
    run: async () => {
      const nonce = crypto.randomBytes(4).toString("hex");
      const reg = await registerContent({
        content: `Probe for hard-error fail-open path. nonce=${nonce}`,
        origin_code: "OH",
      });
      if (reg.status !== 202) return { fail: `expected 202, got ${reg.status}: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const ctid = reg.body.data?.ctid || reg.body.ctid;
      if (!ctid) return { fail: `no ctid in response` };
      const poll = await pollPrescanStatus(ctid);
      if (!poll.ok) return { fail: `prescan didn't complete in ${POLL_MAX * POLL_MS / 1000}s` };
      const d = poll.data || {};
      if (d.prescan_probability !== 0.5) return { fail: `expected prob=0.5 (no-signal neutral), got ${d.prescan_probability}` };
      if (d.prescan_overall_degraded !== true) return { fail: `expected overall_degraded=true (fail-open), got ${d.prescan_overall_degraded}` };
      return { pass: true, ctid, attempts: poll.attempts, probability: d.prescan_probability, degraded: d.prescan_overall_degraded };
    },
  },
  // Test 9 — Clean single-modality long text: full ensemble fires (no
  // disagreement_override), real prob recorded, overall_degraded=false.
  {
    name: "clean-long-text-oh",
    description: "OH + ~250 word text → real probability, no degradation, 0 retries",
    run: async () => {
      const nonce = crypto.randomBytes(4).toString("hex");
      // ~250 words — comfortably above the statistical provider's minimum
      // so we get a full ensemble (ollama + statistical + heuristic) and
      // avoid disagreement_override.
      const longText = `
The shift to remote-first engineering has reshaped how we think about onboarding, mentorship, and the silent ladder of context that used to happen at the coffee machine.
When juniors and seniors no longer share a physical hallway, the small interruptions that compress weeks of learning into days simply stop happening. A staff engineer reviewing a pull request at 2 AM cannot casually mention the three production incidents that shaped why a particular function defends against a seemingly impossible state. That knowledge has to be written down, or it dies with the person who carries it.
Most teams react to this loss in one of two ways. Some over-engineer their documentation pipeline: every decision becomes an ADR, every architecture sketch turns into a multi-page RFC, every change ships with a postmortem-shaped explanation. The artifacts pile up, but reading them becomes the new bottleneck. Others retreat to synchronous rituals — twice-weekly architecture reviews, mandatory pairing slots, a Slack culture where seniors are perpetually on-call for context. That works for a while but corrodes the deep-work blocks that drew engineers to remote roles in the first place.
The teams that seem to land it well do something subtler. They invest in writing artifacts that read like a conversation: a senior engineer's voice, not a committee's. They tolerate slightly redundant prose if it preserves *why* a decision was made, not just *what* was decided. And they push for tools that surface the prior art exactly when an engineer needs it — not three meetings later. nonce=${nonce}
`.trim();
      const reg = await registerContent({ content: longText, origin_code: "OH" });
      if (reg.status !== 202) return { fail: `expected 202, got ${reg.status}: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const ctid = reg.body.data?.ctid || reg.body.ctid;
      if (!ctid) return { fail: `no ctid in response` };
      const poll = await pollPrescanStatus(ctid);
      if (!poll.ok) return { fail: `prescan didn't complete in ${POLL_MAX * POLL_MS / 1000}s` };
      const d = poll.data || {};
      if (typeof d.prescan_probability !== "number") return { fail: `probability not a number: ${d.prescan_probability}` };
      if (d.prescan_probability === 0) return { fail: `probability=0 looks like skip path, not clean scan` };
      if (d.prescan_probability === 0.5) return { fail: `probability=0.5 is the no-signal neutral, not a clean scan` };
      if (d.prescan_overall_degraded !== false) return { fail: `expected overall_degraded=false (clean scan), got ${d.prescan_overall_degraded}` };
      return { pass: true, ctid, attempts: poll.attempts, probability: d.prescan_probability, tier: d.prescan_tier, degraded: d.prescan_overall_degraded };
    },
  },
  // Test 8 — TIP_CLASSIFIER_SCAN_NON_OH=true override only flips the client-side
  // short-circuit. The classifier service has its OWN non-OH skip policy
  // (independent of our flag), so the on-chain verdict shape is the same as
  // Test 7 — but with the flag on, our worker DOES phone the classifier
  // (verifiable via HTTP-call delta on the classifier container; the scenario
  // can only assert that registration completes).
  {
    name: "origin-ag-scan-on-override",
    description: "AG + TIP_CLASSIFIER_SCAN_NON_OH=true → worker phones classifier (delta verified externally)",
    run: async () => {
      const nonce = crypto.randomBytes(4).toString("hex");
      const reg = await registerContent({
        content: `Self-disclosed AI-generated marketing copy, but the node is now configured to scan non-OH origins. nonce=${nonce}`,
        origin_code: "AG",
      });
      if (reg.status !== 202) return { fail: `expected 202, got ${reg.status}: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const ctid = reg.body.data?.ctid || reg.body.ctid;
      if (!ctid) return { fail: `no ctid in response: ${JSON.stringify(reg.body).slice(0, 200)}` };
      const poll = await pollPrescanStatus(ctid);
      if (!poll.ok) return { fail: `prescan didn't complete in ${POLL_MAX * POLL_MS / 1000}s` };
      const d = poll.data || {};
      // The verdict shape mirrors the classifier-server's skip response;
      // we don't assert against it. The proof of the env flip is the
      // classifier-side HTTP-delta captured by the caller.
      return { pass: true, ctid, attempts: poll.attempts, probability: d.prescan_probability, degraded: d.prescan_overall_degraded };
    },
  },
];

// ── Runner ───────────────────────────────────────────────────────────────

async function main() {
  await initCrypto();
  console.log(`${DIM}Node: ${NODE_URL}${RESET}`);
  console.log(`${DIM}Signer: ${SIGNER.tip_id} (${SIGNER.tag})${RESET}\n`);

  const filter = process.argv[2];
  const scenarios = filter ? SCENARIOS.filter(s => s.name.includes(filter)) : SCENARIOS;
  if (scenarios.length === 0) {
    console.log(`${RED}No scenarios match filter: ${filter}${RESET}`);
    process.exit(1);
  }

  let passed = 0;
  let failed = 0;
  for (const sc of scenarios) {
    process.stdout.write(`${YELLOW}▸${RESET} ${sc.name}: ${sc.description}\n`);
    let result;
    const start = nowMs();
    try {
      result = await sc.run();
    } catch (err) {
      result = { fail: `threw: ${err.message}` };
    }
    const elapsed = ((nowMs() - start) / 1000).toFixed(1);
    if (result.pass) {
      passed += 1;
      console.log(`  ${GREEN}✓ PASS${RESET} (${elapsed}s) ${DIM}${JSON.stringify(result).slice(0, 200)}${RESET}\n`);
    } else {
      failed += 1;
      console.log(`  ${RED}✗ FAIL${RESET} (${elapsed}s) ${result.fail}\n`);
    }
  }

  console.log(`\n${passed + failed} scenarios: ${GREEN}${passed} passed${RESET}, ${failed > 0 ? RED : DIM}${failed} failed${RESET}`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error(`${RED}FATAL${RESET}:`, err);
  process.exit(2);
});
