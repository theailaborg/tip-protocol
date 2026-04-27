/**
 * @file @tip-protocol/node/src/lib/prom-format.js
 * @description Pure helpers for the Prometheus text exposition format
 * (v0.0.4). Knows nothing about TIP — usable from any emitter that needs
 * to write `# HELP / # TYPE / metric{label="..."} value` lines.
 *
 *   line(name, value, labels?)            → "name{k=\"v\"} 123"
 *   block(name, type, help, value, ...)   → HELP + TYPE + value (joined)
 *   gauge(name, help, value, labels?)     → block, type=gauge
 *   counter(name, help, value, labels?)   → block, type=counter
 *
 * NaN / null / undefined values become 0 — Prometheus would reject NaN
 * and we'd rather emit a defensible zero than break the scrape.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

/** One metric value line: `metric_name{k="v",...} 123`. NaN / null → 0. */
function line(name, value, labels) {
  const num = Number.isFinite(Number(value)) ? Number(value) : 0;
  if (!labels || Object.keys(labels).length === 0) return `${name} ${num}`;
  const labelStr = Object.entries(labels)
    .map(([k, v]) => `${k}="${String(v).replace(/"/g, '\\"')}"`)
    .join(",");
  return `${name}{${labelStr}} ${num}`;
}

/** A full HELP + TYPE + value block. */
function block(name, type, help, value, labels) {
  return [
    `# HELP ${name} ${help}`,
    `# TYPE ${name} ${type}`,
    line(name, value, labels),
  ].join("\n");
}

/** Read more like prose at call sites than `block(..., "gauge", ...)`. */
const gauge = (name, help, value, labels) => block(name, "gauge", help, value, labels);
const counter = (name, help, value, labels) => block(name, "counter", help, value, labels);

module.exports = { line, block, gauge, counter };
