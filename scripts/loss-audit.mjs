#!/usr/bin/env node
/**
 * @file scripts/loss-audit.mjs
 * @description Zero-loss acceptance gate: submit N ledger-recorded content
 * registrations, then audit that EVERY accepted ctid is retrievable from
 * EVERY node. The ledger is the client's own receipt (202 + ctid), so no
 * server-side accounting bug can mask a loss , this is the check that
 * caught (and now guards) the 2026-07-12 orphaned-duplicate loss class.
 *
 * HTTP-only: works against the local cluster and prod alike. Run chaos
 * (node restarts, load) alongside it manually or from a wrapper.
 *
 * Usage:
 *   node scripts/loss-audit.mjs                                  # local 3-node defaults
 *   COUNT=2000 CONC=8 node scripts/loss-audit.mjs
 *   SUBMIT_URL=http://host:4000 AUDIT_URLS=http://host:4000,http://host2:4000 node scripts/loss-audit.mjs
 *
 * Exit code 0 = zero loss on every node; 1 = any accepted ctid missing.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

import { createRequire } from "module";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const ROOT = path.resolve(__dirname, "..");

const { initCrypto, shake256, tipNormalize } = require(path.join(ROOT, "shared/crypto"));
const contentRegisterSchema = require(path.join(ROOT, "node/src/schemas/content-register"));
const PC = require(path.join(ROOT, "shared/protocol-constants"));
const { getGenesisPayload } = require(path.join(ROOT, "node/src/genesis"));
const { nowMs } = require(path.join(ROOT, "shared/time"));

const SUBMIT_URL = process.env.SUBMIT_URL || "http://localhost:4000";
const AUDIT_URLS = (process.env.AUDIT_URLS || "http://localhost:4000,http://localhost:4100,http://localhost:4200").split(",");
const COUNT = parseInt(process.env.COUNT || "500", 10);
const CONC = parseInt(process.env.CONC || "8", 10);
const SETTLE_TIMEOUT_MS = parseInt(process.env.SETTLE_TIMEOUT_MS || "600000", 10);

await initCrypto();
try { PC._resetForTesting(); } catch { /* fresh process */ }
PC.init(getGenesisPayload().protocol_constants);

const backupDir = path.join(ROOT, "genesis-data", "backups");
const signers = fs.readdirSync(backupDir).filter(n => n.startsWith("tip-id"))
  .map(n => JSON.parse(fs.readFileSync(path.join(backupDir, n), "utf8")));
if (signers.length === 0) { console.error("no signer keys in genesis-data/backups"); process.exit(1); }

function signContent(signer, text) {
  const body = {
    signer_tip_id: signer.tip_id, origin_code: "OH", content: text,
    media_canonical_hash: null, content_type_hint: null, cna_version: "2.2",
    attribution_mode: "self",
    authors: [{ tip_id: signer.tip_id, tip_id_type: signer.tip_id_type || "personal", contribution_role: "creator" }],
    extras: {}, registered_urls: [`https://loss-audit.test/${nowMs()}-${Math.random().toString(36).slice(2, 9)}`],
  };
  const canonical = contentRegisterSchema.buildSigningPayload(body, shake256(tipNormalize(text)));
  body.signature = contentRegisterSchema.sign(canonical, signer.private_key);
  return body;
}

console.log(`loss-audit: ${COUNT} registrations -> ${SUBMIT_URL}, audit across ${AUDIT_URLS.length} node(s)`);
const payloads = [];
for (let i = 0; i < COUNT; i++) {
  payloads.push(signContent(signers[i % signers.length], `loss-audit ${i} ${nowMs()} ${Math.random()}`));
}

const ledger = [];
let ok = 0, fail = 0;
const errs = {};
async function submitWorker(startIdx) {
  for (let i = startIdx; i < COUNT; i += CONC) {
    try {
      const r = await fetch(`${SUBMIT_URL}/v1/content/register`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payloads[i]), signal: AbortSignal.timeout(30000),
      });
      if (r.status === 202) {
        ok++;
        const body = await r.json().catch(() => null);
        const d = body && (body.data || body);
        if (d && d.ctid) ledger.push(d.ctid);
      } else { fail++; errs[r.status] = (errs[r.status] || 0) + 1; }
    } catch (e) { fail++; errs[e.name || "err"] = (errs[e.name || "err"] || 0) + 1; }
  }
}
await Promise.all(Array.from({ length: CONC }, (_, k) => submitWorker(k)));
console.log(`accepted ${ok}/${COUNT} (failed ${fail} ${JSON.stringify(errs)}), ledger ${ledger.length} ctids`);
if (ledger.length !== ok) { console.error("LEDGER GAP: accepted count != recorded ctids"); process.exit(1); }

async function presentOn(url, ctid) {
  try {
    const r = await fetch(`${url}/v1/content/${encodeURIComponent(ctid)}`, { signal: AbortSignal.timeout(8000) });
    return r.status === 200;
  } catch { return false; }
}

// Poll until every ledger ctid resolves on every node (accepted txs can take
// rounds to commit; a restart mid-run adds catch-up time), then final verdict.
const deadline = nowMs() + SETTLE_TIMEOUT_MS;
let missingByNode = new Map();
while (true) {
  missingByNode = new Map();
  for (const url of AUDIT_URLS) {
    const missing = [];
    for (const ctid of ledger) {
      if (!(await presentOn(url, ctid))) missing.push(ctid);
    }
    missingByNode.set(url, missing);
  }
  const total = [...missingByNode.values()].reduce((n, m) => n + m.length, 0);
  if (total === 0) break;
  if (nowMs() > deadline) break;
  console.log(`waiting: ${[...missingByNode.entries()].map(([u, m]) => `${u.replace(/^https?:\/\//, "")}=${m.length}`).join(" ")} missing , settling...`);
  await new Promise(r => setTimeout(r, 15000));
}

let lost = 0;
for (const [url, missing] of missingByNode) {
  console.log(`${url}: ${ledger.length - missing.length}/${ledger.length} present, MISSING=${missing.length}`);
  for (const m of missing.slice(0, 5)) console.log(`  missing: ${m}`);
  lost += missing.length;
}
console.log(lost === 0 ? "\nLOSS AUDIT: PASS , zero accepted registrations lost" : "\nLOSS AUDIT: FAIL");
process.exit(lost === 0 ? 0 : 1);
