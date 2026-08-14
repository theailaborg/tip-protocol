/**
 * @file scripts/node-env-template.js
 * @description Render a node .env from .env.example + known per-node values.
 *
 * .env.example is the single source of truth for the format, comments, and full
 * var set. Generators (register-node.js, seed.js --local-cluster) pass only the
 * values they know; every other var keeps its example default. When .env.example
 * gains a var, generated envs inherit it automatically, no template to sync.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_EXAMPLE = path.resolve(__dirname, "../.env.example");

// A generated env is routinely handed to another node operator, so a real value
// for any of these means the generating machine's credentials travel with it.
// Backstop only: generators are expected not to supply them in the first place.
const NEVER_EMIT = new Set([
  "TIP_CLASSIFIER_KEY",
  "TIP_METRICS_TOKEN",
  "TIP_NODE_PRIVATE_KEY",
  "DATABASE_URL",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
]);

// Overlay `overrides` (KEY -> value) onto .env.example: replace each key's
// assignment line (active or commented) with `KEY=value`; keys absent from the
// example are appended so a known value is never silently dropped.
function renderEnvFromExample(overrides, opts = {}) {
  const exPath = opts.examplePath || DEFAULT_EXAMPLE;
  let text = fs.readFileSync(exPath, "utf8");
  const isCredential = ([k, v]) =>
    NEVER_EMIT.has(k) && v !== undefined && v !== null && String(v) !== "";
  const entries = Object.entries(overrides);
  const dropped = entries.filter(isCredential).map(([k]) => k);
  if (dropped.length) {
    console.warn(
      `node-env-template: refused to write credential(s) into the generated env: ${dropped.join(", ")}. ` +
      `Set them by hand on the target host.`,
    );
  }
  const safe = Object.fromEntries(entries.filter((e) => !isCredential(e)));
  const applied = new Set();
  for (const [key, val] of Object.entries(safe)) {
    if (val === undefined || val === null) continue;
    // [ \t#] not \s: \s matches newlines and would absorb a preceding blank line.
    const re = new RegExp(`^[ \\t#]*${key}=.*$`, "m");
    if (re.test(text)) {
      text = text.replace(re, () => `${key}=${val}`);   // fn form: no $-substitution in val
      applied.add(key);
    }
  }
  const extra = Object.entries(safe)
    .filter(([k, v]) => v !== undefined && v !== null && !applied.has(k));
  if (extra.length) {
    text = text.replace(/\s*$/, "\n");
    text += "\n# ─── Values not documented in .env.example ──────────────────────────────────\n" +
      extra.map(([k, v]) => `${k}=${v}`).join("\n") + "\n";
  }
  const notes = Array.isArray(opts.headerNotes) ? opts.headerNotes : [];
  return notes.length ? notes.map((l) => `# ${l}`).join("\n") + "\n" + text : text;
}

module.exports = { renderEnvFromExample };
