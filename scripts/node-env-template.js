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

// Overlay `overrides` (KEY -> value) onto .env.example: replace each key's
// assignment line (active or commented) with `KEY=value`; keys absent from the
// example are appended so a known value is never silently dropped.
function renderEnvFromExample(overrides, opts = {}) {
  const exPath = opts.examplePath || DEFAULT_EXAMPLE;
  let text = fs.readFileSync(exPath, "utf8");
  const applied = new Set();
  for (const [key, val] of Object.entries(overrides)) {
    if (val === undefined || val === null) continue;
    // [ \t#] not \s: \s matches newlines and would absorb a preceding blank line.
    const re = new RegExp(`^[ \\t#]*${key}=.*$`, "m");
    if (re.test(text)) {
      text = text.replace(re, () => `${key}=${val}`);   // fn form: no $-substitution in val
      applied.add(key);
    }
  }
  const extra = Object.entries(overrides)
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
