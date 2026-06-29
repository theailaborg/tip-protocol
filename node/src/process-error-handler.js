/**
 * @file @tip-protocol/node/src/process-error-handler.js
 * @description Process-level error capture, classification, and counters for the
 * node's long-running internal loops (consensus ticks, p2p streams, anti-entropy,
 * snapshot streamer). Distinct from `middleware/error-handler.js`, which only
 * normalizes Express HTTP error responses and never sees these out-of-request
 * throws.
 *
 * Policy: OBSERVE-ONLY. This boundary classifies, counts, and loudly logs; it
 * NEVER shuts the node down. A BFT node staying alive keeps its liveness, and a
 * genuinely-divergent node is handled at the consensus layer (anti-entropy +
 * threshold-halt), not by guessing from a process-level error. The `fatal`
 * severity flag is set from driver CODES only, never message text (a peer
 * controls message strings and could craft one to trip the counter fleet-wide).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const crypto = require("crypto");
const { getLogger } = require("./logger");

const log = getLogger("tip.errors");

let _nodeId = null;

const _uncaught = new Map(); // category -> count
const _unhandled = new Map();
const _timer = new Map(); // label -> count
const _fatal = new Map(); // category -> count

function _bump(map, key) {
  map.set(key, (map.get(key) || 0) + 1);
}

// `fatal` is decided by driver CODE only (never message text). Everything else
// is transient and purely informational — no path here halts the node.
function classify(err) {
  const code = (err && err.code) || "";
  const msg = String((err && (err.message || err)) || "");
  if (code === "SQLITE_CORRUPT" || code === "SQLITE_NOTADB") {
    return { category: "store_corruption", fatal: true };
  }
  if (code === "ERR_WORKER_OUT_OF_MEMORY") return { category: "oom", fatal: false };
  if (code === "SQLITE_BUSY" || code === "SQLITE_LOCKED" || /database is (busy|locked)/i.test(msg)) {
    return { category: "store_contention", fatal: false };
  }
  if (/ECONNRESET|EPIPE|ECONNREFUSED|ETIMEDOUT|stream (reset|closed|aborted)|aborted/i.test(msg) || String(code).startsWith("ERR_STREAM")) {
    return { category: "network", fatal: false };
  }
  if (/decode|protobuf|invalid wire|index out of range|RangeError/i.test(msg) || err instanceof RangeError) {
    return { category: "decode", fatal: false };
  }
  return { category: "unknown", fatal: false };
}

function init({ nodeId } = {}) {
  if (nodeId) _nodeId = nodeId;
}

function captureError(err, { origin = "uncaughtException", module: mod = null, label = null } = {}) {
  const { category, fatal } = classify(err);
  if (origin === "unhandledRejection") _bump(_unhandled, category);
  else if (origin === "timer") _bump(_timer, label || "unlabeled");
  else _bump(_uncaught, category);

  const record = {
    error_id: crypto.randomUUID(),
    category,
    fatal,
    type: (err && err.constructor && err.constructor.name) || typeof err,
    message: (err && err.message) || String(err),
    origin,
    module: mod,
    label,
    node_id: _nodeId,
    stack: (err && err.stack) || null,
  };
  log.error(`${fatal ? "FATAL" : "ERROR"} (${origin}${label ? `:${label}` : ""}) [${category}] ${record.message}`, record);

  if (fatal) _bump(_fatal, category); // observe-only: counted + logged, never halts
  return record;
}

function _toObj(map) {
  const o = {};
  for (const [k, v] of map) o[k] = v;
  return o;
}

function getMetrics() {
  return {
    uncaught: _toObj(_uncaught),
    unhandled: _toObj(_unhandled),
    timer: _toObj(_timer),
    fatal: _toObj(_fatal),
  };
}

module.exports = { init, classify, captureError, getMetrics };
