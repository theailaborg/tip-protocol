/**
 * Independent Node cryptographic consistency check of a saved Python simulation.
 *
 * node examples/agentic-provenance/verify_simulation.js bundle.json
 *
 * Uses TIP's shared ML-DSA-65, SHAKE-256 and Merkle implementations. This is
 * crypto-only cross-language consistency, not an independent policy evaluator
 * or external identity proof. Run Python replay for the policy decisions.
 * A self-contained bundle can be wholly replaced and re-signed with new keys;
 * retain an independently trusted digest when that threat matters.
 * License: TIPCL-1.0 (see ../../LICENSE.txt).
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const tip = require(path.join(__dirname, "../../shared/crypto"));
const merkle = require(path.join(__dirname, "../../shared/merkle"));
const MAX_BYTES = 20 * 1024 * 1024;
const SCHEMA = "tip-simulation-run/v1";
const canonical = value => tip.canonicalJson(value);
const same = (a, b) => canonical(a) === canonical(b);
const recordId = record => tip.shake256(canonical(record.body));
const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value);

// A small bounded-depth JSON reader rejects duplicate names and unsafe numbers
// rather than letting JSON.parse silently replace or round signed input fields.
function strictJson(text) {
  let at = 0;
  function space() { while (/[ \t\r\n]/.test(text[at] || "") && at < text.length) at++; }
  function string() {
    const start = at++;
    while (at < text.length) {
      const char = text[at++];
      if (char === "\\") at++;
      else if (char === '"') return JSON.parse(text.slice(start, at));
    }
    throw Error("unterminated JSON string");
  }
  function value(depth) {
    if (depth > 100) throw Error("JSON nesting exceeds 100 levels");
    space();
    if (text[at] === '"') return string();
    if (text[at] === "{") {
      at++; space(); const result = Object.create(null), names = new Set();
      if (text[at] === "}") { at++; return result; }
      while (true) {
        space(); if (text[at] !== '"') throw Error("expected JSON field name");
        const key = string(); if (names.has(key)) throw Error("duplicate JSON field"); names.add(key);
        space(); if (text[at++] !== ":") throw Error("expected colon");
        result[key] = value(depth + 1); space();
        const end = text[at++]; if (end === "}") return result;
        if (end !== ",") throw Error("expected object separator");
      }
    }
    if (text[at] === "[") {
      at++; space(); const result = [];
      if (text[at] === "]") { at++; return result; }
      while (true) {
        result.push(value(depth + 1)); space();
        const end = text[at++]; if (end === "]") return result;
        if (end !== ",") throw Error("expected array separator");
      }
    }
    const match = /^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));
    if (!match) throw Error("invalid JSON value");
    at += match[0].length;
    const result = JSON.parse(match[0]);
    if (typeof result === "number" && (!/^-?(0|[1-9][0-9]*)$/.test(match[0]) || !Number.isSafeInteger(result))) {
      throw Error("simulation numbers must be safely representable integers");
    }
    return result;
  }
  const result = value(0); space();
  if (at !== text.length) throw Error("trailing JSON content");
  return result;
}

function fields(object, names, context) {
  if (!isObject(object) || !same(Object.keys(object).sort(), names.split(" ").sort())) throw Error(`${context}: unexpected or missing fields`);
}
function hex(value, bytes) { return typeof value === "string" && value.length === bytes * 2 && /^[0-9a-f]+$/.test(value); }
function signed(record, key, context) {
  fields(record, "body sig", context);
  if (!isObject(record.body) || record.body.sig_alg !== "ML-DSA-65" || record.body.hash_alg !== "SHAKE-256") throw Error(`${context}: unsupported or missing signed algorithm labels`);
  if (!hex(key, 1952) || !hex(record.sig, 3309)) throw Error(`${context}: invalid key or signature encoding`);
  if (!tip.mldsaVerify(recordId(record), record.sig, key)) throw Error(`${context}: signature verification failed`);
}

function verifyBundle(bundle) {
  const checks = [];
  function check(label, test) { if (!test) throw Error(label); checks.push(label); }
  try {
    fields(bundle, "schema run_id created_at scenario trace summary manifest signed_events receipts checkpoint", "bundle");
    check("supported bundle schema", bundle.schema === SCHEMA);
    check("run identifier and creation time present", typeof bundle.run_id === "string" && bundle.run_id.length > 0 && typeof bundle.created_at === "string" && bundle.created_at.length > 0);
    const scenario = bundle.scenario;
    fields(scenario, "schema id title domain seed policy events", "scenario");
    check("supported input schema", scenario.schema === "tip-simulation/v1");
    check("bounded nonempty event list", Array.isArray(scenario.events) && scenario.events.length >= 1 && scenario.events.length <= 200);
    const n = scenario.events.length;
    check("one ordered event, receipt and trace per input", ["signed_events", "receipts", "trace"].every(key => Array.isArray(bundle[key]) && bundle[key].length === n));
    const mb = bundle.manifest?.body;
    check("manifest body present", isObject(mb));
    signed(bundle.manifest, mb.principal_key, "manifest");
    check("manifest signature and scenario binding", mb.schema === SCHEMA && mb.type === "simulation_manifest" && mb.run_id === bundle.run_id && mb.created_at === bundle.created_at && mb.scenario_hash === tip.shake256(canonical(scenario)) && mb.generator === "python-random-v1");
    check("manifest key catalogue present", isObject(mb.agent_keys) && hex(mb.site_key, 1952) && Array.isArray(scenario.policy?.agents));
    const names = new Set(scenario.policy.agents.map(agent => agent.id));
    for (const event of scenario.events) {
      if (!isObject(event) || !["request", "revoke", "stop_all", "resume", "counter"].includes(event.kind)) throw Error("unsupported event structure");
      if (event.kind === "request") names.add(event.agent);
    }
    check("agent key catalogue matches scenario", same(Object.keys(mb.agent_keys).sort(), [...names].sort()) && Object.values(mb.agent_keys).every(key => hex(key, 1952)));
    const ids = [];
    for (let i = 0; i < n; i++) {
      const event = scenario.events[i], signedEvent = bundle.signed_events[i], receipt = bundle.receipts[i];
      const key = event.kind === "request" ? mb.agent_keys[event.agent] : mb.principal_key;
      signed(signedEvent, key, `event ${i}`);
      const eb = signedEvent.body;
      check(`event ${i}: signature, index and input binding`, eb.schema === SCHEMA && eb.type === "simulation_event" && eb.run_id === bundle.run_id && Number.isSafeInteger(eb.index) && eb.index === i && eb.event_key === key && same(eb.event, event));
      signed(receipt, mb.site_key, `receipt ${i}`);
      const rb = receipt.body;
      check(`receipt ${i}: signature, index and decision binding`, rb.schema === SCHEMA && rb.type === "simulation_receipt" && rb.run_id === bundle.run_id && Number.isSafeInteger(rb.index) && rb.index === i && rb.site_key === mb.site_key && rb.event_hash === recordId(signedEvent) && same(rb.trace, bundle.trace[i]));
      ids.push(recordId(receipt));
    }
    signed(bundle.checkpoint, mb.site_key, "checkpoint");
    const cb = bundle.checkpoint.body;
    check("checkpoint signature and manifest binding", cb.schema === SCHEMA && cb.type === "simulation_checkpoint" && cb.run_id === bundle.run_id && cb.manifest_hash === recordId(bundle.manifest) && cb.site_key === mb.site_key);
    check("checkpoint covers the exact ordered receipt log", Number.isSafeInteger(cb.size) && cb.size === n && cb.root === merkle.computeRoot(ids));
    check("displayed summary matches the signed checkpoint", same(cb.summary, bundle.summary));
    return {valid: true, checks, errors: []};
  } catch (error) {
    return {valid: false, checks, errors: [error.message || "invalid evidence"]};
  }
}

function readBounded(file) {
  const fd = fs.openSync(file, "r");
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw Error("input must be a regular local file");
    if (stat.size > MAX_BYTES) throw Error("bundle exceeds 20 MiB");
    const buffer = Buffer.alloc(MAX_BYTES + 1); let size = 0;
    while (size < buffer.length) {
      const n = fs.readSync(fd, buffer, size, buffer.length - size, null);
      if (!n) break;
      size += n;
    }
    if (size > MAX_BYTES) throw Error("bundle exceeds 20 MiB");
    return new TextDecoder("utf-8", {fatal: true}).decode(buffer.subarray(0, size));
  } finally { fs.closeSync(fd); }
}

async function main() {
  if (process.argv.length !== 3) { console.error("Usage: node verify_simulation.js <local-bundle.json>"); process.exitCode = 2; return; }
  let raw;
  try { raw = readBounded(process.argv[2]); } catch (error) { console.error(`ERROR: ${error.message}`); process.exitCode = 2; return; }
  await tip.initCrypto();
  let result;
  try { result = verifyBundle(strictJson(raw)); } catch (error) { result = {valid: false, checks: [], errors: [error.message]}; }
  for (const item of result.checks) console.log(`PASS  ${item}`);
  for (const item of result.errors) console.error(`FAIL  ${item}`);
  console.log(`${result.valid ? "VALID" : "INVALID"}: crypto-only cross-language consistency.`);
  console.log("Keys are self-contained simulation keys, not external identity proof. Use Python replay for policy evaluation; this checker does not recompute policy decisions or validate the recorded code version.");
  process.exitCode = result.valid ? 0 : 1;
}
if (require.main === module) main().catch(error => { console.error(`ERROR: ${error.message}`); process.exitCode = 2; });
module.exports = {verifyBundle, strictJson, readBounded};
